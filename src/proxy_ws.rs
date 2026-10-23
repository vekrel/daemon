use crate::{
    auth::dpop,
    config::Mode,
    handlers::auth_session::WsSession,
    http_auth::DpopCtx,
    proxy_http::{add_forwarded, error, strip_hop_by_hop},
    rpc_seam::{Conn, Fwd, Out},
    server::Upstream,
    supervisor::State,
};
use axum::{
    body::Body,
    extract::{
        ConnectInfo, Extension, State as AxState, WebSocketUpgrade,
        ws::{CloseFrame as AxClose, Message as AxMsg, WebSocket},
    },
    http::{HeaderMap, StatusCode, Uri, header},
    response::Response,
};
use futures_util::{FutureExt, SinkExt, StreamExt};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        Error as WsError, Message,
        client::IntoClientRequest,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    C2s,
    S2c,
}

/// Sees every proxied frame; `conn` is unique per proxied WS connection within the process.
pub trait FrameTap: Send + Sync {
    fn on_frame(&self, _conn: u64, _dir: Dir, _frame: &Message) {}
}

static NEXT_CONN: AtomicU64 = AtomicU64::new(0);

pub struct NoTap;
impl FrameTap for NoTap {}

#[derive(Clone)]
pub struct Ctx {
    pub upstream: Upstream,
    pub state: Arc<State>,
    pub tap: Arc<dyn FrameTap>,
}

const FORWARDED: [header::HeaderName; 5] = [
    header::COOKIE,
    header::AUTHORIZATION,
    header::ORIGIN,
    header::SEC_WEBSOCKET_PROTOCOL,
    header::HeaderName::from_static("dpop"),
];

/// Dials the engine's /ws first so its handshake rejection (401/426...) reaches the client as is.
pub async fn handler(
    ws: WebSocketUpgrade,
    AxState(ctx): AxState<Ctx>,
    uri: Uri,
    headers: HeaderMap,
    conn: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    // Subscribed before dialing: a restart during the handshake still closes the socket.
    let generation = ctx.state.generation_tx.subscribe();
    let shutdown = ctx.state.shutdown_tx.subscribe();
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let url = format!("ws://{}:{}/ws{query}", ctx.upstream.host, ctx.upstream.port);
    let mut req = url
        .as_str()
        .into_client_request()
        .expect("valid upstream ws url");
    for name in FORWARDED {
        for v in headers.get_all(&name) {
            req.headers_mut().append(name.clone(), v.clone());
        }
    }
    add_forwarded(
        req.headers_mut(),
        headers.get(header::HOST).cloned(),
        ctx.upstream.public_port,
        conn.map(|c| c.0.0.ip()),
    );

    // The session Node sees on this upgrade; only computed when Rust claims some RPC tag.
    let rpc = ctx.upstream.rpc.clone();
    let path = uri.path_and_query().map_or("/ws", |p| p.as_str());
    let client_url =
        crate::proxy_http::client_url(headers.get(header::HOST), ctx.upstream.public_port, path);
    // Converts a DPoP upgrade into a Rust ticket for Node: Node behind the proxy builds `htu` from
    // the rewritten Host and would reject every valid proof. Only for a trusted origin (above) and
    // a session Node's ticket verifier sees the same way (`http_auth::check`).
    let dctx = DpopCtx {
        url: client_url.clone().filter(|_| rpc.dpop_mode() != Mode::Off),
        serve: rpc.dpop_mode() == Mode::Serve,
        for_ticket: true,
        ..DpopCtx::default()
    };
    let session = rpc.session(req.headers(), uri.query(), &dctx).await;
    let consumed = dctx.consumed.lock().expect("lock").clone();
    if let Some((_, sid)) = consumed {
        // Rust consumed the proof, so Node must never see it: it gets a ticket for the session.
        match rpc.node_ticket(&sid) {
            Some(t) => {
                let sep = if query.is_empty() { "?" } else { "&" };
                *req.uri_mut() = format!("{url}{sep}wsTicket={t}")
                    .parse()
                    .expect("ticket uri");
                req.headers_mut().remove(header::AUTHORIZATION);
                req.headers_mut().remove("dpop");
            }
            None => dctx.roll_back(),
        }
    }

    let ticket =
        crate::auth::ticket::from_query(uri.query()) != crate::auth::ticket::InQuery::Absent;
    // Which verdict to log: a ticket wins over every header, as in Node.
    let verdict = if ticket {
        Some(("ws ticket verdict", false))
    } else if headers
        .get(header::AUTHORIZATION)
        .is_some_and(|v| v.as_bytes().starts_with(b"DPoP "))
    {
        let node_url = format!("http://{}:{}{path}", ctx.upstream.host, ctx.upstream.port);
        let htu = match (
            headers.get("dpop").and_then(|p| p.to_str().ok()),
            &client_url,
        ) {
            (Some(p), Some(c)) => dpop::node_htu_host_mismatch(p, c, &node_url),
            _ => false,
        };
        Some(("ws dpop verdict", htu))
    } else {
        None
    };

    let dial = tokio::time::timeout(ctx.upstream.dial_timeout, connect_async(req));
    let (up, res) = match dial.await {
        Err(_) => return error(StatusCode::GATEWAY_TIMEOUT, "engine_timeout"),
        Ok(Ok(ok)) => {
            if let Some(v) = verdict {
                ticket_verdict(v, &session, 101);
            }
            ok
        }
        Ok(Err(WsError::Http(res))) => {
            if let Some(v) = verdict {
                ticket_verdict(v, &session, res.status().as_u16());
            }
            let (mut parts, body) = res.into_parts();
            strip_hop_by_hop(&mut parts.headers);
            return Response::from_parts(parts, Body::from(body.unwrap_or_default()));
        }
        Ok(Err(e)) => {
            // Never log `e` itself: tungstenite's UnableToConnect embeds the URL, which can carry a wsTicket.
            let kind = match &e {
                WsError::Url(_) => "url",
                WsError::Io(_) => "io",
                WsError::Protocol(_) => "protocol",
                _ => "other",
            };
            tracing::warn!(kind, "engine ws dial failed");
            return error(StatusCode::BAD_GATEWAY, "engine_unreachable");
        }
    };
    let ws = match res.headers().get(header::SEC_WEBSOCKET_PROTOCOL) {
        Some(p) => ws.protocols(p.to_str().ok().map(str::to_owned)),
        None => ws,
    };
    ws.on_upgrade(move |client| {
        let conn = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
        let (done_tx, done) = mpsc::unbounded_channel();
        let rpc = Conn::new(rpc, session, done_tx, ctx.upstream.shadow.clone());
        pump(client, up, generation, shutdown, ctx.tap, conn, (rpc, done))
    })
}

/// Shadow log: Rust's `wsTicket` or DPoP verdict against Node's handshake status (Node decides,
/// unless Rust consumed a DPoP proof and handed Node a ticket). `htu`: Node rejects the proof
/// only because it builds `htu` from the proxy's rewritten Host (expected, not a Rust bug).
fn ticket_verdict((msg, htu): (&'static str, bool), session: &WsSession, node: u16) {
    let rust = match session {
        WsSession::Verified(_) => "verified",
        WsSession::Rejected(why) => why,
        WsSession::Deferred => "deferred",
    };
    let outcome = match (session, node) {
        (WsSession::Deferred, _) => "deferred",
        // 426 (protocol) and 500 come before or beside auth: nothing to compare.
        (_, n) if n != 101 && n != 401 => "not_compared",
        (WsSession::Verified(_), 101) | (WsSession::Rejected(_), 401) => "match",
        (WsSession::Verified(_), 401) if htu => "node_htu_host_mismatch",
        _ => "mismatch",
    };
    if outcome == "mismatch" {
        tracing::warn!(rust, node, outcome, "{msg}");
    } else {
        tracing::info!(rust, node, outcome, "{msg}");
    }
}

async fn pump<U>(
    mut client: WebSocket,
    mut up: U,
    mut generation: watch::Receiver<u64>,
    mut shutdown: watch::Receiver<bool>,
    tap: Arc<dyn FrameTap>,
    conn: u64,
    // Routing state, and where its spawned handlers report back.
    (mut rpc, mut done): (Conn, mpsc::UnboundedReceiver<crate::rpc_seam::Done>),
) where
    U: StreamExt<Item = Result<Message, WsError>> + SinkExt<Message, Error = WsError> + Unpin,
{
    // One loop, no buffering: each frame is written the moment it is read (Effect pings every 5 s).
    // This loop is the client socket's only writer, so Rust's frames and Node's never interleave.
    let rust = |m: String| {
        let m = Message::text(m);
        tap.on_frame(conn, Dir::S2c, &m);
        to_axum(m)
    };
    loop {
        tokio::select! {
            m = client.next() => {
                let Some(Ok(m)) = m else { break };
                let m = from_axum(m);
                tap.on_frame(conn, Dir::C2s, &m);
                let close = m.is_close();
                let (fwd, local) = match &m {
                    Message::Text(t) => rpc.c2s(t.as_str()),
                    _ => (Fwd::Original, Vec::new()),
                };
                let mut gone = false;
                for f in local {
                    if client.send(rust(f)).await.is_err() { gone = true; break }
                }
                if gone { break }
                let sent = match fwd {
                    Fwd::Original => up.send(m).await,
                    Fwd::Text(t) => up.send(Message::text(t)).await,
                    Fwd::Nothing => Ok(()),
                };
                if sent.is_err() || close { break }
            }
            m = up.next() => {
                let Some(Ok(m)) = m else {
                    // Ended or errored without a close frame.
                    let f = AxClose { code: 1011, reason: "engine connection lost".into() };
                    let _ = client.send(AxMsg::Close(Some(f))).await;
                    break;
                };
                tap.on_frame(conn, Dir::S2c, &m);
                if let Message::Text(t) = &m {
                    rpc.s2c(t.as_str());
                }
                let close = m.is_close();
                if client.send(to_axum(m)).await.is_err() || close { break }
            }
            Some(d) = done.recv() => {
                let sent = match rpc.done(d) {
                    Some(Out::Client(f)) => client.send(rust(f)).await.map_err(drop),
                    Some(Out::Node(t)) => up.send(Message::text(t)).await.map_err(drop),
                    None => Ok(()),
                };
                if sent.is_err() { break }
            }
            _ = generation.changed() => {
                let f = AxClose { code: 1012, reason: "engine restarted".into() };
                let _ = client.send(AxMsg::Close(Some(f))).await;
                break;
            }
            _ = shutdown.wait_for(|&s| s).map(drop) => {
                let f = AxClose { code: 1001, reason: "going away".into() };
                let _ = client.send(AxMsg::Close(Some(f))).await;
                break;
            }
        }
    }
    // Flushes any pending close reply; errors just mean the peer is already gone.
    let _ = client.close().await;
    let _ = up.close().await;
}

fn from_axum(m: AxMsg) -> Message {
    match m {
        AxMsg::Text(t) => Message::text(t.as_str()),
        AxMsg::Binary(b) => Message::Binary(b),
        AxMsg::Ping(b) => Message::Ping(b),
        AxMsg::Pong(b) => Message::Pong(b),
        AxMsg::Close(f) => Message::Close(f.map(|f| CloseFrame {
            code: CloseCode::from(f.code),
            reason: f.reason.as_str().into(),
        })),
    }
}

fn to_axum(m: Message) -> AxMsg {
    match m {
        Message::Text(t) => AxMsg::Text(t.as_str().into()),
        Message::Binary(b) => AxMsg::Binary(b),
        Message::Ping(b) => AxMsg::Ping(b),
        Message::Pong(b) => AxMsg::Pong(b),
        Message::Close(f) => AxMsg::Close(f.map(|f| AxClose {
            code: f.code.into(),
            reason: f.reason.as_str().into(),
        })),
        // Only produced by raw frame reads, which this proxy never does.
        Message::Frame(_) => AxMsg::Binary(Default::default()),
    }
}
