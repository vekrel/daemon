use crate::{
    proxy_http::{add_forwarded, error, strip_hop_by_hop},
    rpc_seam::{Conn, Fwd},
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

const FORWARDED: [header::HeaderName; 4] = [
    header::COOKIE,
    header::AUTHORIZATION,
    header::ORIGIN,
    header::SEC_WEBSOCKET_PROTOCOL,
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
    let mut req = url.into_client_request().expect("valid upstream ws url");
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
    let session = rpc.session(req.headers(), uri.query()).await;

    let dial = tokio::time::timeout(ctx.upstream.dial_timeout, connect_async(req));
    let (up, res) = match dial.await {
        Err(_) => return error(StatusCode::GATEWAY_TIMEOUT, "engine_timeout"),
        Ok(Ok(ok)) => ok,
        Ok(Err(WsError::Http(res))) => {
            let (mut parts, body) = res.into_parts();
            strip_hop_by_hop(&mut parts.headers);
            return Response::from_parts(parts, Body::from(body.unwrap_or_default()));
        }
        Ok(Err(e)) => {
            tracing::warn!("engine ws dial failed: {e}");
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
                for f in local {
                    if client.send(rust(f)).await.is_err() { break }
                }
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
                if let Some(f) = rpc.done(d)
                    && client.send(rust(f)).await.is_err() { break }
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
