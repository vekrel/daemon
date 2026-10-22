//! The WS takeover seam for unary RPCs (`rpc_seam`): serve/shadow routing, fail-closed scope
//! checks, raw passthrough, Interrupt, the single client writer and array splitting.
//!
//! Expected error bytes come from encoding `rpcAuthorizationError("filesystem:read")` with the
//! engine's own `Rpc.exitSchema(projects.readFile)` + `Schema.toCodecJson` (effect 4.0.5).
use axum::{
    Router,
    extract::{WebSocketUpgrade, ws::Message as AxMsg},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use futures_util::{FutureExt, SinkExt, StreamExt, future::BoxFuture};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    io::Write,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use vekrel::{
    auth::shadow::AuthFiles,
    config::Mode,
    handlers::{
        HandlerCtx,
        auth_session::{AuthSession, Descriptor},
    },
    http_seam::ShadowLimit,
    proxy_ws::{Dir, FrameTap},
    rpc_seam::{Seam, UnaryHandler},
    server,
    supervisor::State,
};

const KEY: [u8; 32] = [9; 32];
const SID: &str = "6f1c0d3e-0000-4000-8000-000000000001";
const STATE_DIR: &str = "/tmp/vk/userdata";
const COOKIE: &str = "t3_session_3789_fb52c29e3256";

const AUTH_ERROR: &str = r#"{"_tag":"Failure","cause":[{"_tag":"Fail","error":{"_tag":"MachineAuthorizationError","message":"The authenticated token is missing required scope: filesystem:read.","requiredScope":"orchestration:read","requiredPermission":"filesystem:read"}}]}"#;

fn exit(id: u64, exit: &str) -> String {
    format!(r#"{{"_tag":"Exit","requestId":{id},"exit":{exit}}}"#)
}

fn request(id: u64, tag: &str, payload: Value) -> String {
    json!({"_tag":"Request","id":id,"tag":tag,"payload":payload,"headers":[]}).to_string()
}

// ---- auth fixture (same token format as tests/auth_session.rs) ----

const DDL: &str = "CREATE TABLE auth_sessions (
      session_id TEXT PRIMARY KEY, subject TEXT NOT NULL, scopes TEXT NOT NULL, method TEXT NOT NULL,
      issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT);";

fn token(scopes: &[&str]) -> String {
    let c = json!({"v":1,"kind":"session","sid":SID,"sub":"browser","scopes":scopes,
        "method":"browser-session-cookie","iat":1,"exp":1_893_456_000_123i64});
    let enc = B64.encode(c.to_string());
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(enc.as_bytes());
    format!("{enc}.{}", B64.encode(mac.finalize().into_bytes()))
}

fn cookie(scopes: &[&str]) -> String {
    format!("{COOKIE}={}", token(scopes))
}

struct Env {
    dir: PathBuf,
    files: Arc<AuthFiles>,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Key + DB with one live row for `SID` whose (ignored, like Node) scopes are `row_scopes`.
fn env(name: &str, row_scopes: &str) -> Env {
    let dir = std::env::temp_dir().join(format!("vekrel-rpcseam-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("key.bin"), KEY).unwrap();
    let c = rusqlite::Connection::open(dir.join("db.sqlite")).unwrap();
    c.execute_batch(DDL).unwrap();
    c.execute(
        "INSERT INTO auth_sessions VALUES (?1, 'browser', ?2, 'browser-session-cookie',
         '2026-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z', NULL)",
        [SID, row_scopes],
    )
    .unwrap();
    let files = Arc::new(AuthFiles::new(dir.join("key.bin"), dir.join("db.sqlite")));
    Env { dir, files }
}

fn auth(e: &Env) -> Arc<AuthSession> {
    Arc::new(AuthSession::new(
        Descriptor::web("127.0.0.1", 3789, STATE_DIR, ""),
        e.files.clone(),
    ))
}

// ---- the test-only handler ----

/// `test.echo` (`filesystem:read`): answers its payload; `{"fail":..}` fails with it;
/// `{"wait":true}` waits for cancellation.
#[derive(Default)]
struct Echo {
    cancelled: Arc<AtomicBool>,
}

impl UnaryHandler for Echo {
    fn tag(&self) -> &'static str {
        "test.echo"
    }
    fn required_scope(&self) -> &'static str {
        "filesystem:read"
    }
    fn handle<'a>(
        &'a self,
        payload: Value,
        ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Result<Value, Value>> {
        async move {
            assert!(
                ctx.session.is_some(),
                "handlers only run for verified sessions"
            );
            if payload.get("wait").is_some() {
                ctx.cancel.cancelled().await;
                self.cancelled.store(true, Ordering::SeqCst);
                return Ok(json!("too late"));
            }
            match payload.get("fail") {
                Some(e) => Err(e.clone()),
                None => Ok(payload),
            }
        }
        .boxed()
    }
}

// ---- rig ----

/// Fake engine: reports every text frame it receives as `text:<raw>` and answers each
/// Request (also inside arrays) with `Exit Success` of `payload.node` (else the payload).
/// A `spam` request first gets `payload.n` chunks of `payload.size` bytes.
async fn upstream(ev: UnboundedSender<String>) -> u16 {
    let app = Router::new().route(
        "/ws",
        get(move |ws: WebSocketUpgrade| async move {
            ws.on_upgrade(move |mut s| async move {
                while let Some(Ok(AxMsg::Text(t))) = s.next().await {
                    let _ = ev.send(format!("text:{}", t.as_str()));
                    let items = match serde_json::from_str::<Value>(t.as_str()) {
                        Ok(Value::Array(a)) => a,
                        Ok(v) => vec![v],
                        Err(_) => vec![],
                    };
                    for r in items.iter().filter(|r| r["_tag"] == "Request") {
                        let p = &r["payload"];
                        if r["tag"] == "spam" {
                            let blob = "x".repeat(p["size"].as_u64().unwrap() as usize);
                            for i in 0..p["n"].as_u64().unwrap() {
                                let c = json!({"_tag":"Chunk","requestId":r["id"],"values":[{"i":i,"blob":blob}]});
                                s.send(AxMsg::Text(c.to_string().into())).await.unwrap();
                            }
                        }
                        let value = p.get("node").unwrap_or(p);
                        let e = json!({"_tag":"Exit","requestId":r["id"],"exit":{"_tag":"Success","value":value}});
                        s.send(AxMsg::Text(e.to_string().into())).await.unwrap();
                    }
                }
            })
        }),
    );
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    port
}

#[derive(Default)]
struct Tap(Mutex<Vec<(u64, Dir, String)>>);
impl FrameTap for Tap {
    fn on_frame(&self, conn: u64, dir: Dir, frame: &Message) {
        if let Message::Text(t) = frame {
            self.0
                .lock()
                .unwrap()
                .push((conn, dir, t.as_str().to_owned()));
        }
    }
}

struct Rig {
    ev: UnboundedReceiver<String>,
    proxy: u16,
    tap: Arc<Tap>,
}

async fn rig(seam: Seam) -> Rig {
    rig_with(seam, ShadowLimit::default()).await
}

async fn rig_with(seam: Seam, limit: ShadowLimit) -> Rig {
    let (tx, ev) = unbounded_channel();
    let up = upstream(tx).await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = l.local_addr().unwrap().port();
    let tap = Arc::new(Tap::default());
    let app = server::build_with_tap(
        Arc::new(State::default()),
        server::Upstream::loopback(up)
            .with_public_port(proxy)
            .with_rpc_seam(seam)
            .with_shadow_limit(limit),
        tap.clone(),
    );
    tokio::spawn(async move {
        axum::serve(
            l,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    Rig { ev, proxy, tap }
}

fn seam(mode: Mode, echo: Arc<Echo>, auth: Option<Arc<AuthSession>>) -> Seam {
    let h: Arc<dyn UnaryHandler> = echo;
    let s = Seam::new(vec![(h, mode)]);
    match auth {
        Some(a) => s.with_auth(a),
        None => s,
    }
}

type Client = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(port: u16, query: &str, headers: &[(&'static str, String)]) -> Client {
    let mut req = format!("ws://127.0.0.1:{port}/ws{query}")
        .into_client_request()
        .unwrap();
    for (k, v) in headers {
        req.headers_mut().insert(*k, v.parse().unwrap());
    }
    connect_async(req).await.expect("handshake").0
}

async fn send(c: &mut Client, t: &str) {
    c.send(Message::text(t)).await.unwrap();
}

async fn recv(c: &mut Client) -> String {
    match tokio::time::timeout(Duration::from_secs(5), c.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => t.as_str().to_owned(),
        other => panic!("expected a text frame, got {other:?}"),
    }
}

async fn next_ev(r: &mut Rig) -> String {
    tokio::time::timeout(Duration::from_secs(5), r.ev.recv())
        .await
        .expect("upstream event")
        .unwrap()
}

/// A request Rust does not own, used as a barrier: once its answer arrives, every earlier
/// frame on this socket has been routed.
async fn barrier(r: &mut Rig, c: &mut Client, id: u64) {
    let req = request(id, "other", json!({}));
    send(c, &req).await;
    assert_eq!(next_ev(r).await, format!("text:{req}"));
    assert_eq!(recv(c).await, exit(id, r#"{"_tag":"Success","value":{}}"#));
}

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);
impl Write for Logs {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Logs {
    fn capture() -> (Logs, tracing::subscriber::DefaultGuard) {
        let logs = Logs::default();
        let l = logs.clone();
        let sub = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || l.clone())
            .finish();
        (logs, tracing::subscriber::set_default(sub))
    }
    fn lines(&self, needle: &str) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|l| l.contains(needle))
            .map(String::from)
            .collect()
    }
}

// ---- tests ----

#[tokio::test]
async fn serve_answers_locally_and_upstream_never_sees_request() {
    let e = env("serve", r#"["filesystem:read"]"#);
    let mut r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    let req = request(1, "test.echo", json!({"a":[1,"two"]}));
    send(&mut c, &req).await;
    let want = exit(1, r#"{"_tag":"Success","value":{"a":[1,"two"]}}"#);
    assert_eq!(recv(&mut c).await, want);
    send(
        &mut c,
        &request(
            2,
            "test.echo",
            json!({"fail":{"_tag":"EchoError","message":"m"}}),
        ),
    )
    .await;
    assert_eq!(
        recv(&mut c).await,
        exit(
            2,
            r#"{"_tag":"Failure","cause":[{"_tag":"Fail","error":{"_tag":"EchoError","message":"m"}}]}"#
        )
    );
    barrier(&mut r, &mut c, 3).await;
    assert!(r.ev.try_recv().is_err(), "upstream saw only the barrier");

    // The recorder sees the client's request and Rust's Exit, on the same connection.
    let tap = r.tap.0.lock().unwrap().clone();
    let conn_of = |dir: Dir, t: &str| tap.iter().find(|f| f.1 == dir && f.2 == t).map(|f| f.0);
    let c2s = conn_of(Dir::C2s, &req).expect("request tapped");
    assert_eq!(conn_of(Dir::S2c, &want), Some(c2s), "{tap:?}");
}

#[tokio::test]
async fn serve_without_verified_session_returns_authorization_error() {
    let e = env("nosession", r#"["filesystem:read"]"#);
    let mut r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    // No credential at all (Node may still accept the socket, e.g. a dev cookie).
    let mut c = connect(r.proxy, "", &[]).await;
    send(&mut c, &request(1, "test.echo", json!({}))).await;
    assert_eq!(recv(&mut c).await, exit(1, AUTH_ERROR));
    // A forged signature.
    let bad = cookie(&["filesystem:read"]).replace('.', ".AAAA");
    let mut c = connect(r.proxy, "", &[("cookie", bad)]).await;
    send(&mut c, &request(2, "test.echo", json!({}))).await;
    assert_eq!(recv(&mut c).await, exit(2, AUTH_ERROR));
    assert!(r.ev.try_recv().is_err(), "never falls back to Node");

    // Key/DB unavailable.
    let gone = env("gone", "[]");
    std::fs::remove_file(gone.dir.join("key.bin")).unwrap();
    let r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&gone)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    send(&mut c, &request(3, "test.echo", json!({}))).await;
    assert_eq!(recv(&mut c).await, exit(3, AUTH_ERROR));

    // No verifier configured (engine config Rust cannot reproduce).
    let r = rig(seam(Mode::Serve, Arc::default(), None)).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    send(&mut c, &request(4, "test.echo", json!({}))).await;
    assert_eq!(recv(&mut c).await, exit(4, AUTH_ERROR));
}

#[tokio::test]
async fn serve_with_session_missing_scope_returns_authorization_error() {
    // Node checks the TOKEN's scopes, exact string match: the row's scopes don't count and
    // `orchestration:read` (filesystem:read's legacy parent) does not grant it.
    let e = env("scope", r#"["orchestration:read","filesystem:read"]"#);
    let mut r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["orchestration:read"]))]).await;
    send(&mut c, &request(1, "test.echo", json!({}))).await;
    assert_eq!(recv(&mut c).await, exit(1, AUTH_ERROR));
    assert!(r.ev.try_recv().is_err());

    // The reverse: the token grants it, a narrowed row does not matter (as in Node). Bearer too.
    let e = env("scope2", "[]");
    let r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    let bearer = format!("Bearer {}", token(&["filesystem:read"]));
    let mut c = connect(r.proxy, "", &[("authorization", bearer)]).await;
    send(&mut c, &request(2, "test.echo", json!(1))).await;
    assert_eq!(
        recv(&mut c).await,
        exit(2, r#"{"_tag":"Success","value":1}"#)
    );
}

#[tokio::test]
async fn serve_with_unverifiable_credential_defers_to_node() {
    let (logs, _g) = Logs::capture();
    let e = env("defer", r#"["filesystem:read"]"#);
    let mut r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    // A wsTicket (even next to a cookie Rust could verify) and a DPoP credential: Node decides.
    for (q, h) in [
        ("?wsTicket=abc", ("cookie", cookie(&[]))),
        (
            "",
            (
                "authorization",
                format!("DPoP {}", token(&["filesystem:read"])),
            ),
        ),
    ] {
        let mut c = connect(r.proxy, q, &[h]).await;
        let req = request(1, "test.echo", json!({"node":"from node"}));
        send(&mut c, &req).await;
        assert_eq!(next_ev(&mut r).await, format!("text:{req}"));
        assert_eq!(
            recv(&mut c).await,
            exit(1, r#"{"_tag":"Success","value":"from node"}"#)
        );
    }
    let lines = logs.lines("deferred_unverifiable_credential");
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("test.echo"), "{lines:?}");
}

#[tokio::test]
async fn shadow_forwards_and_logs_match() {
    let (logs, _g) = Logs::capture();
    let e = env("shadow", "[]");
    let mut r = rig(seam(Mode::Shadow, Arc::default(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    let req = request(1, "test.echo", json!({"a":1}));
    send(&mut c, &req).await;
    assert_eq!(
        next_ev(&mut r).await,
        format!("text:{req}"),
        "Node gets the original bytes"
    );
    assert_eq!(
        recv(&mut c).await,
        exit(1, r#"{"_tag":"Success","value":{"a":1}}"#)
    );
    // Without the scope, Rust's answer is the authorization error: Node answering differently shows.
    let mut c2 = connect(r.proxy, "", &[("cookie", cookie(&[]))]).await;
    send(&mut c2, &request(2, "test.echo", json!({"a":1}))).await;
    let _ = next_ev(&mut r).await;
    assert_eq!(
        recv(&mut c2).await,
        exit(2, r#"{"_tag":"Success","value":{"a":1}}"#)
    );
    barrier(&mut r, &mut c, 3).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let lines = logs.lines("rust shadow");
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[0].contains("test.echo") && lines[0].contains("outcome=\"match\""),
        "{lines:?}"
    );
    assert!(
        lines[1].contains("mismatch") && lines[1].contains("$._tag"),
        "{lines:?}"
    );
}

#[tokio::test]
async fn shadow_logs_mismatch_path_without_values() {
    let (logs, _g) = Logs::capture();
    let e = env("mismatch", "[]");
    let mut r = rig(seam(Mode::Shadow, Arc::default(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    let payload = json!({"x":{"v":"rust-secret"},"node":{"x":{"v":"node-secret"}}});
    send(&mut c, &request(1, "test.echo", payload)).await;
    let _ = next_ev(&mut r).await;
    // The client gets Node's answer.
    assert_eq!(
        recv(&mut c).await,
        exit(1, r#"{"_tag":"Success","value":{"x":{"v":"node-secret"}}}"#)
    );
    barrier(&mut r, &mut c, 2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let lines = logs.lines("rust shadow");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("mismatch") && lines[0].contains("$.value.x.v"),
        "{lines:?}"
    );
    assert!(!lines[0].contains("secret"), "{lines:?}");
}

#[tokio::test]
async fn ack_and_interrupt_for_unowned_ids_pass_through_byte_identical() {
    let e = env("passthru", "[]");
    let mut r = rig(seam(Mode::Serve, Arc::new(Echo::default()), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    // Own one id so the owned map is not empty.
    send(&mut c, &request(1, "test.echo", json!({"wait":true}))).await;
    for raw in [
        r#"{ "_tag" : "Ack", "requestId" : 5 }"#,
        r#"{"_tag":"Interrupt","requestId":6,"extra":true}"#,
        r#"{"_tag":"Ack","requestId":"1"}"#,
        r#"{"_tag":"Ping"}"#,
        "not json",
        r#"[ {"_tag":"Ack","requestId":7} ]"#,
    ] {
        send(&mut c, raw).await;
        assert_eq!(next_ev(&mut r).await, format!("text:{raw}"));
    }
}

#[tokio::test]
async fn interrupt_for_owned_request_cancels_and_exits_interrupt() {
    let e = env("interrupt", "[]");
    let echo = Arc::new(Echo::default());
    let mut r = rig(seam(Mode::Serve, echo.clone(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    send(&mut c, &request(7, "test.echo", json!({"wait":true}))).await;
    send(&mut c, r#"{"_tag":"Ack","requestId":7}"#).await;
    send(&mut c, r#"{"_tag":"Interrupt","requestId":7}"#).await;
    assert_eq!(
        recv(&mut c).await,
        exit(
            7,
            r#"{"_tag":"Failure","cause":[{"_tag":"Interrupt","fiberId":0}]}"#
        )
    );
    for _ in 0..50 {
        if echo.cancelled.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        echo.cancelled.load(Ordering::SeqCst),
        "handler was cancelled"
    );
    // The cancelled handler's late answer is dropped; Node saw none of it.
    barrier(&mut r, &mut c, 8).await;
    assert!(r.ev.try_recv().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_frames_never_interleave_with_upstream_frames() {
    let e = env("interleave", "[]");
    let r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    let c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    let (mut tx, mut rx) = c.split();
    const N: u64 = 200;
    let writer = tokio::spawn(async move {
        tx.send(Message::text(request(
            0,
            "spam",
            json!({"n":N,"size":65536}),
        )))
        .await
        .unwrap();
        for i in 1..=N {
            tx.send(Message::text(request(
                i,
                "test.echo",
                json!({"i":i,"pad":"y".repeat(4096)}),
            )))
            .await
            .unwrap();
        }
        tx
    });
    let (mut exits, mut chunks) = (0, 0);
    while exits < N + 1 {
        let m = tokio::time::timeout(Duration::from_secs(20), rx.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_str(m.to_text().unwrap()).expect("every frame parses");
        match v["_tag"].as_str().unwrap() {
            "Exit" => exits += 1,
            "Chunk" => chunks += 1,
            t => panic!("unexpected {t}"),
        }
    }
    assert_eq!(chunks, N);
    let _ = writer.await.unwrap();
}

#[tokio::test]
async fn array_frame_with_one_claimed_element_is_split() {
    let e = env("array", "[]");
    let mut r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    let frame = format!(
        "[{},{{\"_tag\":\"Ack\", \"requestId\":9}},{}]",
        request(1, "test.echo", json!({"e":1})),
        request(2, "other", json!({"o":2}))
    );
    send(&mut c, &frame).await;
    let rest = format!(
        "text:[{{\"_tag\":\"Ack\",\"requestId\":9}},{}]",
        request(2, "other", json!({"o":2}))
    );
    assert_eq!(next_ev(&mut r).await, rest);
    let mut got = vec![recv(&mut c).await, recv(&mut c).await];
    got.sort();
    assert_eq!(
        got,
        vec![
            exit(1, r#"{"_tag":"Success","value":{"e":1}}"#),
            exit(2, r#"{"_tag":"Success","value":{"o":2}}"#),
        ]
    );
    // All claimed: nothing is forwarded.
    send(&mut c, &format!("[{}]", request(3, "test.echo", json!(3)))).await;
    assert_eq!(
        recv(&mut c).await,
        exit(3, r#"{"_tag":"Success","value":3}"#)
    );
    barrier(&mut r, &mut c, 4).await;
    assert!(r.ev.try_recv().is_err());
}

#[tokio::test]
async fn shadow_is_skipped_when_the_limiter_is_full() {
    let (logs, _g) = Logs::capture();
    let e = env("busy", "[]");
    let limit = ShadowLimit::new(1, Duration::from_secs(10));
    let mut r = rig_with(seam(Mode::Shadow, Arc::default(), Some(auth(&e))), limit).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    // A slow Rust handler holds the only permit; Node still answers at once.
    send(
        &mut c,
        &request(1, "test.echo", json!({"wait":true,"node":1})),
    )
    .await;
    let _ = next_ev(&mut r).await;
    assert_eq!(
        recv(&mut c).await,
        exit(1, r#"{"_tag":"Success","value":1}"#)
    );
    let req = request(2, "test.echo", json!({"a":2}));
    send(&mut c, &req).await;
    assert_eq!(next_ev(&mut r).await, format!("text:{req}"));
    assert_eq!(
        recv(&mut c).await,
        exit(2, r#"{"_tag":"Success","value":{"a":2}}"#)
    );
    barrier(&mut r, &mut c, 3).await;
    let busy = logs.lines("shadow_skipped_busy");
    assert_eq!(busy.len(), 1, "{busy:?}");
    assert!(busy[0].contains("test.echo"), "{busy:?}");
    assert!(
        logs.lines("outcome=\"match\"").is_empty(),
        "nothing was compared"
    );
}
