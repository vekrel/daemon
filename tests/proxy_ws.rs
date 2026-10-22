use axum::{
    Router,
    extract::{
        RawQuery, WebSocketUpgrade,
        ws::{CloseFrame as AxClose, Message as AxMsg},
    },
    http::HeaderMap,
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task::JoinHandle,
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use vekrel::{server, supervisor::State};

/// Aborts the server task when the test ends.
struct Guard(JoinHandle<()>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn serve(app: Router) -> (u16, Guard) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        axum::serve(
            l,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    (port, Guard(h))
}

/// Fake engine: echoes text as "echo:<t>", reports everything it sees on `ev`,
/// and closes with 4002 "later" right away when the query contains `closeme`.
async fn fake_upstream(ev: UnboundedSender<String>) -> (u16, Guard) {
    let app = Router::new().route(
        "/ws",
        get(
            move |ws: WebSocketUpgrade, RawQuery(q): RawQuery, h: HeaderMap| async move {
                let q = q.unwrap_or_default();
                ev.send(format!("query:{q}")).unwrap();
                let cookie = h.get("cookie").map(|v| v.to_str().unwrap().to_owned());
                ev.send(format!("cookie:{}", cookie.unwrap_or_default()))
                    .unwrap();
                if q.contains("fwd") {
                    let g = |n: &str| h.get(n).map_or("", |v| v.to_str().unwrap()).to_owned();
                    ev.send(format!(
                        "fwd:{}|{}|{}",
                        g("x-forwarded-host"),
                        g("x-forwarded-proto"),
                        g("x-forwarded-for")
                    ))
                    .unwrap();
                }
                ws.on_upgrade(move |mut s| async move {
                    if q.contains("closeme") {
                        let f = AxClose {
                            code: 4002,
                            reason: "later".into(),
                        };
                        let _ = s.send(AxMsg::Close(Some(f))).await;
                    }
                    while let Some(Ok(m)) = s.next().await {
                        match m {
                            AxMsg::Text(t) => {
                                let _ = ev.send(format!("text:{}", t.as_str()));
                                let _ = s
                                    .send(AxMsg::Text(format!("echo:{}", t.as_str()).into()))
                                    .await;
                            }
                            AxMsg::Ping(p) => {
                                let _ = ev.send(format!("ping:{}", String::from_utf8_lossy(&p)));
                            }
                            AxMsg::Close(f) => {
                                let f = f.map(|f| format!("{}:{}", f.code, f.reason.as_str()));
                                let _ = ev.send(format!("close:{}", f.unwrap_or_default()));
                            }
                            _ => {}
                        }
                    }
                })
            },
        ),
    );
    serve(app).await
}

struct Rig {
    state: Arc<State>,
    ev: UnboundedReceiver<String>,
    proxy: u16,
    _guards: (Guard, Guard),
}

async fn rig() -> Rig {
    let (tx, ev) = unbounded_channel();
    let (up, g1) = fake_upstream(tx).await;
    let state = Arc::new(State::default());
    let (proxy, g2) = serve(server::build(state.clone(), server::Upstream::loopback(up))).await;
    Rig {
        state,
        ev,
        proxy,
        _guards: (g1, g2),
    }
}

type Client = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(port: u16, query: &str, cookie: Option<&str>) -> Client {
    let mut req = format!("ws://127.0.0.1:{port}/ws{query}")
        .into_client_request()
        .unwrap();
    if let Some(c) = cookie {
        req.headers_mut().insert("cookie", c.parse().unwrap());
    }
    connect_async(req).await.expect("handshake through proxy").0
}

async fn event(ev: &mut UnboundedReceiver<String>) -> String {
    tokio::time::timeout(Duration::from_secs(5), ev.recv())
        .await
        .expect("upstream event in time")
        .unwrap()
}

/// Next data/close frame from the proxy, skipping control frames.
async fn recv(c: &mut Client) -> Option<Message> {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), c.next())
            .await
            .expect("frame in time");
        match m {
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(m)) => return Some(m),
            _ => return None,
        }
    }
}

fn close_of(m: Option<Message>) -> (u16, String) {
    match m {
        Some(Message::Close(Some(f))) => (f.code.into(), f.reason.as_str().to_owned()),
        other => panic!("expected close frame, got {other:?}"),
    }
}

#[tokio::test]
async fn text_frames_round_trip_both_directions_in_order() {
    let mut r = rig().await;
    let mut c = connect(r.proxy, "", None).await;
    for t in ["a", "b", "c"] {
        c.send(Message::text(t)).await.unwrap();
    }
    for t in ["a", "b", "c"] {
        assert_eq!(recv(&mut c).await, Some(Message::text(format!("echo:{t}"))));
    }
    let _ = (event(&mut r.ev).await, event(&mut r.ev).await);
    for t in ["a", "b", "c"] {
        assert_eq!(event(&mut r.ev).await, format!("text:{t}"));
    }
}

#[tokio::test]
async fn query_string_and_cookie_header_reach_upstream() {
    let mut r = rig().await;
    let _c = connect(
        r.proxy,
        "?orchestrationProtocol=2&wsTicket=abc",
        Some("t3_session_1=zzz"),
    )
    .await;
    assert_eq!(
        event(&mut r.ev).await,
        "query:orchestrationProtocol=2&wsTicket=abc"
    );
    assert_eq!(event(&mut r.ev).await, "cookie:t3_session_1=zzz");
}

#[tokio::test]
async fn client_close_propagates_code_and_reason_to_upstream() {
    let mut r = rig().await;
    let mut c = connect(r.proxy, "", None).await;
    let _ = (event(&mut r.ev).await, event(&mut r.ev).await);
    c.close(Some(CloseFrame {
        code: CloseCode::from(4001),
        reason: "bye".into(),
    }))
    .await
    .unwrap();
    assert_eq!(event(&mut r.ev).await, "close:4001:bye");
}

#[tokio::test]
async fn upstream_close_propagates_to_client() {
    let r = rig().await;
    let mut c = connect(r.proxy, "?closeme", None).await;
    assert_eq!(close_of(recv(&mut c).await), (4002, "later".into()));
}

#[tokio::test]
async fn engine_generation_bump_closes_client_with_1012() {
    let mut r = rig().await;
    let mut c = connect(r.proxy, "", None).await;
    c.send(Message::text("x")).await.unwrap();
    assert_eq!(recv(&mut c).await, Some(Message::text("echo:x")));
    // Failed respawns bump several times; the client still gets exactly one close.
    r.state.bump_generation();
    r.state.bump_generation();
    assert_eq!(
        close_of(recv(&mut c).await),
        (1012, "engine restarted".into())
    );
    assert_eq!(recv(&mut c).await, None);
    let _ = (
        event(&mut r.ev).await,
        event(&mut r.ev).await,
        event(&mut r.ev).await,
    );
    assert!(event(&mut r.ev).await.starts_with("close:"));
}

#[tokio::test]
async fn ping_from_client_is_forwarded_not_answered_locally() {
    let mut r = rig().await;
    let mut c = connect(r.proxy, "", None).await;
    let _ = (event(&mut r.ev).await, event(&mut r.ev).await);
    // Effect RPC heartbeat is a text frame: the reply must come from upstream.
    c.send(Message::text(r#"{"_tag":"Ping"}"#)).await.unwrap();
    assert_eq!(
        recv(&mut c).await,
        Some(Message::text(r#"echo:{"_tag":"Ping"}"#))
    );
    assert_eq!(event(&mut r.ev).await, r#"text:{"_tag":"Ping"}"#);
    c.send(Message::Ping("hb".into())).await.unwrap();
    assert_eq!(event(&mut r.ev).await, "ping:hb");
}

#[tokio::test]
async fn ws_upgrade_carries_forwarded_host() {
    let mut r = rig().await;
    let _c = connect(r.proxy, "?fwd=1", None).await;
    event(&mut r.ev).await; // query
    event(&mut r.ev).await; // cookie
    assert_eq!(
        event(&mut r.ev).await,
        format!("fwd:127.0.0.1:{}|http|127.0.0.1", r.proxy)
    );
}
