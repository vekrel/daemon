use crate::{
    proxy_http::{add_forwarded, error, strip_hop_by_hop},
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
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::watch;
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

/// Sees every proxied frame; Task 4's recorder implements this.
pub trait FrameTap: Send + Sync {
    fn on_frame(&self, _dir: Dir, _frame: &Message) {}
}

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

    let (up, res) = match connect_async(req).await {
        Ok(ok) => ok,
        Err(WsError::Http(res)) => {
            let (mut parts, body) = res.into_parts();
            strip_hop_by_hop(&mut parts.headers);
            return Response::from_parts(parts, Body::from(body.unwrap_or_default()));
        }
        Err(e) => {
            tracing::warn!("engine ws dial failed: {e}");
            return error(StatusCode::BAD_GATEWAY, "engine_unreachable");
        }
    };
    let ws = match res.headers().get(header::SEC_WEBSOCKET_PROTOCOL) {
        Some(p) => ws.protocols(p.to_str().ok().map(str::to_owned)),
        None => ws,
    };
    ws.on_upgrade(move |client| pump(client, up, generation, shutdown, ctx.tap))
}

async fn pump<U>(
    mut client: WebSocket,
    mut up: U,
    mut generation: watch::Receiver<u64>,
    mut shutdown: watch::Receiver<bool>,
    tap: Arc<dyn FrameTap>,
) where
    U: StreamExt<Item = Result<Message, WsError>> + SinkExt<Message, Error = WsError> + Unpin,
{
    // One loop, no buffering: each frame is written the moment it is read (Effect pings every 5 s).
    loop {
        tokio::select! {
            m = client.next() => {
                let Some(Ok(m)) = m else { break };
                let m = from_axum(m);
                tap.on_frame(Dir::C2s, &m);
                let close = m.is_close();
                if up.send(m).await.is_err() || close { break }
            }
            m = up.next() => {
                let Some(Ok(m)) = m else { break };
                tap.on_frame(Dir::S2c, &m);
                let close = m.is_close();
                if client.send(to_axum(m)).await.is_err() || close { break }
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
