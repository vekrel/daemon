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
    config::{Mode, RustConfig},
    handlers::{
        HandlerCtx,
        auth_session::{AuthSession, Descriptor},
        browse::Browse,
        read_file::ReadFile,
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

/// `test.echo` (`filesystem:read`): answers its payload (or `payload.value`); `{"fail":..}`
/// fails with it; `{"wait":true}` waits for cancellation; `{"sleep":true}` ignores the token and
/// sleeps 5 s (`dropped` is set when the seam drops it); `{"decline":true}` declines (Node answers);
/// `{"panic":true}` panics.
#[derive(Default)]
struct Echo {
    started: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl Echo {
    /// Waits until a handler call has begun (an Interrupt before that never runs it at all).
    async fn started(&self) {
        for _ in 0..200 {
            if self.started.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("handler never started");
    }
}

struct SetOnDrop(Arc<AtomicBool>);
impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
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
    ) -> BoxFuture<'a, Option<Result<Value, Value>>> {
        async move {
            assert!(
                ctx.session.is_some(),
                "handlers only run for verified sessions"
            );
            self.started.store(true, Ordering::SeqCst);
            if payload.get("wait").is_some() {
                // Set when cancelled, whether the token wakes it or the seam drops it first.
                let _guard = SetOnDrop(self.cancelled.clone());
                ctx.cancel.cancelled().await;
                return Some(Ok(json!("too late")));
            }
            if payload.get("sleep").is_some() {
                let _guard = SetOnDrop(self.dropped.clone());
                tokio::time::sleep(Duration::from_secs(5)).await;
                return Some(Ok(json!("slept")));
            }
            if let Some(v) = payload.get("value") {
                return Some(Ok(v.clone()));
            }
            if payload.get("panic").is_some() {
                panic!("echo asked to panic");
            }
            if payload.get("decline").is_some() {
                tokio::time::sleep(Duration::from_millis(20)).await;
                return None;
            }
            Some(match payload.get("fail") {
                Some(e) => Err(e.clone()),
                None => Ok(payload),
            })
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
                        let mut e = json!({"_tag":"Exit","requestId":r["id"],"exit":{"_tag":"Success","value":value}}).to_string();
                        // `nodeRaw`: Node's exit as exact text (spellings serde would not write).
                        if let Some(raw) = p["nodeRaw"].as_str() {
                            e = format!(r#"{{"_tag":"Exit","requestId":{},"exit":{raw}}}"#, r["id"]);
                        }
                        s.send(AxMsg::Text(e.into())).await.unwrap();
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

/// Sends a request on a fresh socket and asserts Node, not Rust, answers it.
async fn assert_node_answers(
    r: &mut Rig,
    query: &str,
    headers: &[(&'static str, String)],
    id: u64,
) {
    let mut c = connect(r.proxy, query, headers).await;
    let req = request(id, "test.echo", json!({"node":"from node"}));
    send(&mut c, &req).await;
    assert_eq!(next_ev(r).await, format!("text:{req}"));
    assert_eq!(
        recv(&mut c).await,
        exit(id, r#"{"_tag":"Success","value":"from node"}"#)
    );
}

#[tokio::test]
async fn serve_with_unverifiable_session_defers_to_node() {
    // Node accepted each of these sockets, so a session Rust cannot verify is Rust's blind spot.
    let (logs, _g) = Logs::capture();
    let e = env("nosession", r#"["filesystem:read"]"#);
    let mut r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    // No credential at all (Node never accepts that upgrade, so Rust's view is incomplete).
    assert_node_answers(&mut r, "", &[], 1).await;
    // A signature Rust cannot verify (e.g. the key changed since Node checked it).
    let bad = cookie(&["filesystem:read"]).replace('.', ".AAAA");
    assert_node_answers(&mut r, "", &[("cookie", bad)], 2).await;

    // Key file missing.
    let gone = env("gone", "[]");
    std::fs::remove_file(gone.dir.join("key.bin")).unwrap();
    let mut r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&gone)))).await;
    assert_node_answers(&mut r, "", &[("cookie", cookie(&["filesystem:read"]))], 3).await;
    assert_eq!(logs.lines("deferred_unverifiable_credential").len(), 3);
}

#[cfg(unix)]
#[tokio::test]
async fn serve_with_unreadable_key_file_defers_to_node() {
    use std::os::unix::fs::PermissionsExt;
    let e = env("unreadable", r#"["filesystem:read"]"#);
    let key = e.dir.join("key.bin");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&key).is_ok() {
        eprintln!("running as root: the key stays readable; skipping");
        return;
    }
    let mut r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    assert_node_answers(&mut r, "", &[("cookie", cookie(&["filesystem:read"]))], 1).await;
}

#[tokio::test]
async fn serve_with_unsupported_engine_config_defers_to_node() {
    // `main` attaches no verifier when `unsupported_engine` names a flag (--mode, --host, dev auth,
    // bootstrap fd), a non-UTF-8 home or a state dir it cannot resolve.
    let mut r = rig(seam(Mode::Serve, Arc::default(), None)).await;
    assert_node_answers(&mut r, "", &[("cookie", cookie(&["filesystem:read"]))], 1).await;
}

#[tokio::test]
async fn serve_with_verified_session_missing_scope_returns_authorization_error() {
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
    // A ticket Rust rejects (Node accepted it here: a mismatch, so Node decides), even next to a
    // cookie Rust could verify, and a DPoP credential.
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
    echo.started().await;
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

#[tokio::test]
async fn shadow_compares_node_exit_bytes_exactly() {
    let (logs, _g) = Logs::capture();
    let e = env("rawexit", "[]");
    let mut r = rig(seam(Mode::Shadow, Arc::default(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    // Equal as numbers, but spelled differently (serde writes `1e+21`): a real byte mismatch that
    // re-serializing Node's exit would hide.
    let raw = r#"{"_tag":"Success","value":{"n":1e21}}"#;
    send(
        &mut c,
        &request(1, "test.echo", json!({"value":{"n":1e21},"nodeRaw":raw})),
    )
    .await;
    let _ = next_ev(&mut r).await;
    assert_eq!(
        recv(&mut c).await,
        exit(1, raw),
        "the client gets Node's bytes"
    );
    barrier(&mut r, &mut c, 2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let lines = logs.lines("rust shadow");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("mismatch") && lines[0].contains("$ (formatting)"),
        "{lines:?}"
    );
}

#[tokio::test]
async fn interrupt_drops_a_handler_that_ignores_the_token() {
    let e = env("sleepy", "[]");
    let echo = Arc::new(Echo::default());
    let mut r = rig(seam(Mode::Serve, echo.clone(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    send(&mut c, &request(1, "test.echo", json!({"sleep":true}))).await;
    echo.started().await;
    let t = std::time::Instant::now();
    send(&mut c, r#"{"_tag":"Interrupt","requestId":1}"#).await;
    assert_eq!(
        recv(&mut c).await,
        exit(
            1,
            r#"{"_tag":"Failure","cause":[{"_tag":"Interrupt","fiberId":0}]}"#
        )
    );
    assert!(t.elapsed() < Duration::from_secs(1));
    for _ in 0..50 {
        if echo.dropped.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        echo.dropped.load(Ordering::SeqCst),
        "the handler future was dropped"
    );
    // No later Success: the next frame is the barrier's answer.
    barrier(&mut r, &mut c, 2).await;
}

#[tokio::test]
async fn duplicate_owned_id_is_dropped_like_node() {
    let e = env("dup", "[]");
    let echo = Arc::new(Echo::default());
    let mut r = rig(seam(Mode::Serve, echo.clone(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    send(&mut c, &request(1, "test.echo", json!({"wait":true}))).await;
    echo.started().await;
    // Same id while the first still runs: consumed, unanswered, the first keeps its token.
    send(&mut c, &request(1, "test.echo", json!({"a":1}))).await;
    barrier(&mut r, &mut c, 2).await;
    assert!(r.ev.try_recv().is_err(), "Node never sees the duplicate");
    send(&mut c, r#"{"_tag":"Interrupt","requestId":1}"#).await;
    assert_eq!(
        recv(&mut c).await,
        exit(
            1,
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
        "the first request's token was cancelled"
    );
}

#[tokio::test]
async fn serve_decline_forwards_the_original_request_to_node() {
    let (logs, _g) = Logs::capture();
    let e = env("decline", "[]");
    let mut r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    // Odd spacing proves Node gets the client's bytes, not a re-serialization.
    let req =
        r#"{"_tag":"Request", "id":4,"tag":"test.echo","payload":{"decline":true},"headers":[]}"#;
    send(&mut c, req).await;
    assert_eq!(next_ev(&mut r).await, format!("text:{req}"));
    assert_eq!(
        recv(&mut c).await,
        exit(4, r#"{"_tag":"Success","value":{"decline":true}}"#)
    );
    // Rust no longer owns id 4: its Ack and Interrupt reach Node byte for byte.
    for f in [
        r#"{"_tag":"Ack","requestId":4}"#,
        r#"{"_tag":"Interrupt", "requestId":4}"#,
    ] {
        send(&mut c, f).await;
        assert_eq!(next_ev(&mut r).await, format!("text:{f}"));
    }
    let lines = logs.lines("rust handler declined");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("mode=\"serve\""), "{lines:?}");
    assert!(logs.lines("rust shadow").is_empty());
}

#[tokio::test]
async fn shadow_decline_logs_declined_without_comparing() {
    let (logs, _g) = Logs::capture();
    let e = env("shadow-decline", "[]");
    let mut r = rig(seam(Mode::Shadow, Arc::default(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    send(&mut c, &request(1, "test.echo", json!({"decline":true}))).await;
    let _ = next_ev(&mut r).await;
    assert_eq!(
        recv(&mut c).await,
        exit(1, r#"{"_tag":"Success","value":{"decline":true}}"#)
    );
    barrier(&mut r, &mut c, 2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let lines = logs.lines("rust handler declined");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("outcome=\"declined\""), "{lines:?}");
    assert!(lines[0].contains("mode=\"shadow\""), "{lines:?}");
}

#[tokio::test]
async fn serve_panic_forwards_the_request_to_node() {
    let e = env("panic", "[]");
    let mut r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    let req = request(1, "test.echo", json!({"panic":true,"node":"from node"}));
    send(&mut c, &req).await;
    assert_eq!(next_ev(&mut r).await, format!("text:{req}"));
    assert_eq!(
        recv(&mut c).await,
        exit(1, r#"{"_tag":"Success","value":"from node"}"#)
    );
}

#[tokio::test]
async fn handler_without_config_entry_runs_in_shadow() {
    let (logs, _g) = Logs::capture();
    let e = env("default-mode", "[]");
    let h: Arc<dyn UnaryHandler> = Arc::new(Echo::default());
    assert_eq!(h.default_mode(), Mode::Shadow);
    // The proven handlers opt in to serve.
    assert_eq!(ReadFile.default_mode(), Mode::Serve);
    assert_eq!(Browse::from_env().default_mode(), Mode::Serve);
    let mut r = rig(Seam::from_config(vec![h], &RustConfig::default()).with_auth(auth(&e))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    let req = request(1, "test.echo", json!({"a":1}));
    send(&mut c, &req).await;
    assert_eq!(next_ev(&mut r).await, format!("text:{req}"), "Node answers");
    assert_eq!(
        recv(&mut c).await,
        exit(1, r#"{"_tag":"Success","value":{"a":1}}"#)
    );
    barrier(&mut r, &mut c, 2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let lines = logs.lines("rust shadow");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("outcome=\"match\""), "{lines:?}");

    // A config entry still overrides the default.
    let cfg: RustConfig = toml::from_str("[handlers]\n\"test.echo\" = \"serve\"\n").unwrap();
    let h: Arc<dyn UnaryHandler> = Arc::new(Echo::default());
    let mut r = rig(Seam::from_config(vec![h], &cfg).with_auth(auth(&e))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    send(&mut c, &request(1, "test.echo", json!(7))).await;
    assert_eq!(
        recv(&mut c).await,
        exit(1, r#"{"_tag":"Success","value":7}"#)
    );
    barrier(&mut r, &mut c, 2).await;
}

#[tokio::test]
async fn spaced_frames_are_still_routed_and_pings_pass_through() {
    let e = env("spaced", "[]");
    let echo = Arc::new(Echo::default());
    let mut r = rig(seam(Mode::Serve, echo.clone(), Some(auth(&e)))).await;
    let mut c = connect(r.proxy, "", &[("cookie", cookie(&["filesystem:read"]))]).await;
    // Whitespace around `:` and an escaped tag still reach the handler.
    for (id, f) in [
        (
            1,
            r#"{ "_tag" : "Request" , "id" : 1, "tag": "test.echo", "payload": 1, "headers": [] }"#,
        ),
        (
            2,
            r#"{"_tag":"Requ\u0065st","id":2,"tag":"test.echo","payload":2,"headers":[]}"#,
        ),
    ] {
        send(&mut c, f).await;
        assert_eq!(
            recv(&mut c).await,
            exit(id, &format!(r#"{{"_tag":"Success","value":{id}}}"#))
        );
    }
    send(
        &mut c,
        r#"{"_tag":"Request","id":3,"tag":"test.echo","payload":{"wait":true},"headers":[]}"#,
    )
    .await;
    echo.started().await;
    send(&mut c, r#"{ "_tag" : "Interrupt", "requestId" : 3 }"#).await;
    assert!(recv(&mut c).await.contains(r#""requestId":3"#));
    let ping = r#"{"_tag":"Ping"}"#;
    send(&mut c, ping).await;
    assert_eq!(next_ev(&mut r).await, format!("text:{ping}"));
    barrier(&mut r, &mut c, 4).await;
}

/// `SessionStore.issueWebSocketToken`'s format, valid for 5 minutes.
fn ws_ticket() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let json = format!(
        r#"{{"v":1,"kind":"websocket","sid":"{SID}","iat":{now},"exp":{}}}"#,
        now + 300_000
    );
    let enc = B64.encode(json);
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(enc.as_bytes());
    format!("{enc}.{}", B64.encode(mac.finalize().into_bytes()))
}

#[tokio::test]
async fn serve_with_ws_ticket_answers_with_row_scopes_and_logs_verdict() {
    let (logs, _g) = Logs::capture();
    // The ROW grants filesystem:read (a ticket carries no scopes).
    let e = env("ticket", r#"["filesystem:read"]"#);
    let mut r = rig(seam(Mode::Serve, Arc::default(), Some(auth(&e)))).await;
    let q = format!("?wsTicket={}&orchestrationProtocol=2", ws_ticket());
    let mut c = connect(r.proxy, &q, &[]).await;
    send(&mut c, &request(1, "test.echo", json!(1))).await;
    assert_eq!(
        recv(&mut c).await,
        exit(1, r#"{"_tag":"Success","value":1}"#)
    );
    barrier(&mut r, &mut c, 2).await;
    assert!(r.ev.try_recv().is_err(), "upstream saw only the barrier");
    let v = logs.lines("ws ticket verdict");
    assert!(
        v.len() == 1 && v[0].contains("rust=\"verified\" node=101 outcome=\"match\""),
        "{v:?}"
    );
    assert!(logs.lines("deferred_unverifiable_credential").is_empty());
}
