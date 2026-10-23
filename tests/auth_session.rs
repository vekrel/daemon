//! `GET /api/auth/session`: exact bytes per outcome class, and the HTTP seam's shadow/serve modes.
//!
//! Expected bytes follow `MachineAuth.getSessionState` (engine `auth/MachineAuth.ts`): any
//! credential error gives `{"authenticated":false,"auth":<descriptor>}`; a verified token gives
//! `{"authenticated":true,"auth","scopes","permissions","sessionMethod","expiresAt"}` in the
//! `AuthSessionState` schema order, with scopes/method/expiry from the TOKEN claims
//! (`SessionStore.verify` reads the row only for existence and `revoked_at`).
use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderMap, Response},
    routing::any,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    io::Write,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::net::TcpListener;
use vekrel::{
    auth::shadow::AuthFiles,
    config::Mode,
    handlers::{
        HandlerCtx,
        auth_session::{AuthSession, Descriptor, VerifiedSession, WsSession},
    },
    http_seam::{RouteHandler, Seam},
    server,
    supervisor::State,
};

const KEY: [u8; 32] = [9; 32];
const SID: &str = "6f1c0d3e-0000-4000-8000-000000000001";
const STATE_DIR: &str = "/tmp/vk/userdata";
/// `sha256("/tmp/vk/userdata").hex.slice(0, 12)` computed with Node's crypto.
const COOKIE: &str = "t3_session_3789_fb52c29e3256";
/// 2030-01-01T00:00:00.123Z.
const EXP: i64 = 1_893_456_000_123;

const DESC: &str = r#"{"policy":"loopback-browser","bootstrapMethods":["one-time-token"],"sessionMethods":["browser-session-cookie","bearer-access-token","dpop-access-token"],"sessionCookieName":"t3_session_3789_fb52c29e3256","serverUpdateScope":"machine:maintain"}"#;

fn unauth() -> String {
    format!(r#"{{"authenticated":false,"auth":{DESC}}}"#)
}

/// Copied from the engine's migrations 031 + 041.
const DDL: &str = "
    CREATE TABLE auth_sessions (
      session_id TEXT PRIMARY KEY, subject TEXT NOT NULL, scopes TEXT NOT NULL, method TEXT NOT NULL,
      client_label TEXT, client_ip_address TEXT, client_user_agent TEXT,
      client_device_type TEXT NOT NULL DEFAULT 'unknown', client_os TEXT, client_browser TEXT,
      issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, last_connected_at TEXT, revoked_at TEXT,
      client_surface TEXT, client_app_version TEXT
    );";

fn claims() -> Value {
    json!({"v":1,"kind":"session","sid":SID,"sub":"browser",
        "scopes":["orchestration:read","filesystem:read","access:read"],
        "method":"browser-session-cookie","iat":1,"exp":EXP})
}

/// The engine's `SessionStore.issue` format.
fn mint_with(c: &Value, key: &[u8; 32]) -> String {
    let enc = B64.encode(c.to_string());
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(enc.as_bytes());
    format!("{enc}.{}", B64.encode(mac.finalize().into_bytes()))
}

fn mint(c: &Value) -> String {
    mint_with(c, &KEY)
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

impl Env {
    /// Key + DB holding one row for `SID` with `scopes`, `expires_at`, `revoked_at`.
    fn new(name: &str, scopes: &str, expires_at: &str, revoked_at: Option<&str>) -> Env {
        let dir =
            std::env::temp_dir().join(format!("vekrel-authsess-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("secrets")).unwrap();
        std::fs::write(dir.join("secrets/server-signing-key.bin"), KEY).unwrap();
        let c = rusqlite::Connection::open(dir.join("statev2.sqlite")).unwrap();
        c.execute_batch(DDL).unwrap();
        c.execute(
            "INSERT INTO auth_sessions (session_id, subject, scopes, method, issued_at, expires_at, revoked_at)
             VALUES (?1, 'browser', ?2, 'browser-session-cookie', '2026-01-01T00:00:00.000Z', ?3, ?4)",
            rusqlite::params![SID, scopes, expires_at, revoked_at],
        )
        .unwrap();
        let files = Arc::new(AuthFiles::new(
            dir.join("secrets/server-signing-key.bin"),
            dir.join("statev2.sqlite"),
        ));
        Env { dir, files }
    }

    fn ok(name: &str) -> Env {
        Env::new(
            name,
            r#"["orchestration:read","filesystem:read","access:read"]"#,
            "2099-01-01T00:00:00.000Z",
            None,
        )
    }

    fn handler(&self) -> AuthSession {
        AuthSession::new(
            Descriptor::web("127.0.0.1", 3789, STATE_DIR, ""),
            self.files.clone(),
        )
    }
}

/// Headers as Node sees them behind the proxy (Host rewritten to the engine's authority).
async fn ask(env: &Env, headers: &[(&str, &str)]) -> Option<(u16, String, String)> {
    let mut b = Request::builder()
        .uri("http://127.0.0.1:3789/api/auth/session")
        .header("host", "127.0.0.1:3789");
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let (parts, _) = b.body(()).unwrap().into_parts();
    let r = env.handler().handle(&parts, &HandlerCtx::default()).await?;
    let ct = r.headers()["content-type"].to_str().unwrap().to_owned();
    Some((
        r.status().as_u16(),
        ct,
        String::from_utf8(r.body().to_vec()).unwrap(),
    ))
}

async fn body(env: &Env, headers: &[(&str, &str)]) -> String {
    let (status, ct, body) = ask(env, headers).await.expect("rust answers");
    assert_eq!((status, ct.as_str()), (200, "application/json"));
    body
}

fn cookie(token: &str) -> String {
    format!("{COOKIE}={token}")
}

const VERIFIED: &str = r#"{"authenticated":true,"auth":DESC,"scopes":["orchestration:read","access:read"],"permissions":["orchestration:read","filesystem:read","access:read"],"sessionMethod":"browser-session-cookie","expiresAt":"2030-01-01T00:00:00.123Z"}"#;

fn verified() -> String {
    VERIFIED.replace("DESC", DESC)
}

#[tokio::test]
async fn no_credential() {
    let e = Env::ok("none");
    assert_eq!(body(&e, &[]).await, unauth());
    // Another server's cookie on the same host is not this engine's credential.
    let other = format!("t3_session_3999_aaaaaaaaaaaa={}", mint(&claims()));
    assert_eq!(body(&e, &[("cookie", &other)]).await, unauth());
    // An empty cookie value is "missing" (`!credential?.token`).
    assert_eq!(
        body(&e, &[("cookie", &format!("{COOKIE}="))]).await,
        unauth()
    );
    // Unknown Authorization scheme selects nothing.
    assert_eq!(body(&e, &[("authorization", "Basic abc")]).await, unauth());
}

#[tokio::test]
async fn verified_cookie() {
    let e = Env::ok("verified");
    let c = cookie(&mint(&claims()));
    assert_eq!(body(&e, &[("cookie", &c)]).await, verified());
    // Cookie parsing as Effect's `Cookies.parseHeader`: quotes stripped, first wins...
    let t = mint(&claims());
    let c = format!("a=1;  {COOKIE}=\"{t}\"; {COOKIE}=junk");
    assert_eq!(body(&e, &[("cookie", &c)]).await, verified());
    // ...but a space before `;` keeps the closing quote, which Node's lenient base64 decode of
    // the signature then skips, so it still verifies.
    let c = format!("{COOKIE}=\"{t}\" ;");
    assert_eq!(body(&e, &[("cookie", &c)]).await, verified());
}

#[tokio::test]
async fn bad_signature() {
    let e = Env::ok("badsig");
    let c = cookie(&mint_with(&claims(), &[1; 32]));
    assert_eq!(body(&e, &[("cookie", &c)]).await, unauth());
    let c = cookie("no-dot");
    assert_eq!(body(&e, &[("cookie", &c)]).await, unauth());
}

#[tokio::test]
async fn token_expired() {
    let e = Env::ok("tokexp");
    let mut c = claims();
    c["exp"] = json!(1000);
    assert_eq!(body(&e, &[("cookie", &cookie(&mint(&c)))]).await, unauth());
}

#[tokio::test]
async fn expired_row_with_live_token_is_authenticated_like_node() {
    // `SessionStore.verify` never reads the row's expires_at; only the token's exp.
    let e = Env::new(
        "rowexp",
        r#"["orchestration:read","filesystem:read","access:read"]"#,
        "2000-01-01T00:00:00.000Z",
        None,
    );
    let c = cookie(&mint(&claims()));
    assert_eq!(body(&e, &[("cookie", &c)]).await, verified());
}

#[tokio::test]
async fn revoked() {
    let e = Env::new(
        "revoked",
        r#"["orchestration:read"]"#,
        "2099-01-01T00:00:00.000Z",
        Some("2026-02-01T00:00:00.000Z"),
    );
    let c = cookie(&mint(&claims()));
    assert_eq!(body(&e, &[("cookie", &c)]).await, unauth());
}

#[tokio::test]
async fn unknown_session() {
    let e = Env::ok("unknown");
    let mut c = claims();
    c["sid"] = json!("another");
    assert_eq!(body(&e, &[("cookie", &cookie(&mint(&c)))]).await, unauth());
}

#[tokio::test]
async fn narrowed_row_scopes_still_answer_token_scopes_like_node() {
    // Node returns `claims.scopes`; the row's (narrower) scopes are not consulted.
    let e = Env::new(
        "narrow",
        r#"["orchestration:read"]"#,
        "2099-01-01T00:00:00.000Z",
        None,
    );
    let c = cookie(&mint(&claims()));
    assert_eq!(body(&e, &[("cookie", &c)]).await, verified());
    // `scopes` keeps only the legacy scopes, in token order; `permissions` is all of them.
    let mut c = claims();
    c["scopes"] = json!(["filesystem:read"]);
    let want = format!(
        r#"{{"authenticated":true,"auth":{DESC},"scopes":[],"permissions":["filesystem:read"],"sessionMethod":"browser-session-cookie","expiresAt":"2030-01-01T00:00:00.123Z"}}"#
    );
    assert_eq!(body(&e, &[("cookie", &cookie(&mint(&c)))]).await, want);
}

#[tokio::test]
async fn mcp_client_subject_is_rejected() {
    let e = Env::ok("mcp");
    let mut c = claims();
    c["sub"] = json!("mcp-client");
    assert_eq!(body(&e, &[("cookie", &cookie(&mint(&c)))]).await, unauth());
}

#[tokio::test]
async fn bearer_token() {
    let e = Env::ok("bearer");
    let mut c = claims();
    c["method"] = json!("bearer-access-token");
    let h = format!("Bearer {}", mint(&c));
    let want = verified().replace(
        "browser-session-cookie\",\"expiresAt",
        "bearer-access-token\",\"expiresAt",
    );
    assert_eq!(body(&e, &[("authorization", &h)]).await, want);
}

#[tokio::test]
async fn dpop_bound_session_without_proof_is_rejected_and_with_proof_goes_to_node() {
    let e = Env::ok("dpop");
    let mut c = claims();
    c["jkt"] = json!("thumb");
    let t = mint(&c);
    assert_eq!(
        body(&e, &[("authorization", &format!("Bearer {t}"))]).await,
        unauth()
    );
    // Without the proxy's client URL (see `tests/dpop.rs`) Rust cannot check the proof.
    assert!(
        ask(&e, &[("authorization", &format!("DPoP {t}"))])
            .await
            .is_none()
    );
    // A DPoP header on a session that is not proof-bound is rejected.
    let plain = mint(&claims());
    assert_eq!(
        body(&e, &[("authorization", &format!("DPoP {plain}"))]).await,
        unauth()
    );
}

#[tokio::test]
async fn cookie_from_foreign_origin_is_rejected() {
    let e = Env::ok("origin");
    let c = cookie(&mint(&claims()));
    let foreign = [("cookie", c.as_str()), ("origin", "http://evil.test:3779")];
    assert_eq!(body(&e, &foreign).await, unauth());
    // Same host as X-Forwarded-Host (the proxy's public authority), or same-origin fetch, passes.
    let fwd = [
        ("cookie", c.as_str()),
        ("origin", "http://LOCALHOST:3779"),
        ("x-forwarded-host", "localhost:3779"),
    ];
    assert_eq!(body(&e, &fwd).await, verified());
    let sfs = [
        ("cookie", c.as_str()),
        ("origin", "http://evil.test"),
        ("sec-fetch-site", "same-origin"),
    ];
    assert_eq!(body(&e, &sfs).await, verified());
    assert_eq!(
        body(&e, &[("cookie", &c), ("origin", "vekrel://app")]).await,
        verified()
    );
    // Origins Rust cannot parse exactly like WHATWG URL go to Node.
    assert!(
        ask(&e, &[("cookie", &c), ("origin", "http://127.1:3779")])
            .await
            .is_none()
    );
}

#[tokio::test]
async fn unavailable_key_or_db_goes_to_node() {
    let e = Env::ok("nokey");
    let c = cookie(&mint(&claims()));
    std::fs::remove_file(e.dir.join("statev2.sqlite")).unwrap();
    assert!(ask(&e, &[("cookie", &c)]).await.is_none());
    std::fs::remove_file(e.dir.join("secrets/server-signing-key.bin")).unwrap();
    assert!(ask(&e, &[("cookie", &c)]).await.is_none());
    // No credential needs neither file.
    assert_eq!(body(&e, &[]).await, unauth());
}

#[tokio::test]
async fn percent_encoded_cookie_goes_to_node() {
    let e = Env::ok("pct");
    assert!(ask(&e, &[("cookie", &cookie("a%2Eb"))]).await.is_none());
}

#[test]
fn descriptor_for_remote_host_uses_machine_id_and_legacy_cookie() {
    let d = Descriptor::web("0.0.0.0", 3789, STATE_DIR, "machine-1");
    assert_eq!(
        serde_json::to_string(&d).unwrap(),
        r#"{"policy":"remote-reachable","bootstrapMethods":["one-time-token"],"sessionMethods":["browser-session-cookie","bearer-access-token","dpop-access-token"],"sessionCookieName":"t3_session_f7a7266df8b4","serverUpdateScope":"machine:maintain"}"#
    );
}

// ---- seam ----

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
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|l| l.contains("rust shadow"))
            .map(String::from)
            .collect()
    }

    /// The comparison runs after the response, so wait for it (up to 5 s).
    async fn wait(&self, n: usize) -> Vec<String> {
        for _ in 0..100 {
            if self.lines().len() >= n {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        self.lines()
    }
}

fn capture() -> (Logs, tracing::subscriber::DefaultGuard) {
    let logs = Logs::default();
    let l = logs.clone();
    let sub = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || l.clone())
        .finish();
    // Tests run on current-thread runtimes, so spawned tasks log on this thread.
    (logs, tracing::subscriber::set_default(sub))
}

/// Fake engine answering every request with `status`/`body` as JSON; counts hits.
async fn engine(status: u16, body: String) -> (u16, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let app = Router::new().fallback(any(move |_: Request| {
        let (h, body) = (h.clone(), body.clone());
        async move {
            h.fetch_add(1, Ordering::SeqCst);
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        }
    }));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (port, hits)
}

async fn proxy(up: u16, mode: Mode, desc: Descriptor, files: Arc<AuthFiles>) -> String {
    proxy_with(up, mode, Arc::new(AuthSession::new(desc, files))).await
}

async fn proxy_with(up: u16, mode: Mode, h: Arc<dyn RouteHandler>) -> String {
    let seam = Seam::new(HandlerCtx::default()).with(mode, h);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let app = server::build(
        Arc::new(State::default()),
        server::Upstream::loopback(up)
            .with_public_port(port)
            .with_seam(seam),
    );
    tokio::spawn(async move {
        axum::serve(
            l,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    format!("http://127.0.0.1:{port}/api/auth/session")
}

fn desc() -> Descriptor {
    Descriptor::web("127.0.0.1", 3789, STATE_DIR, "")
}

async fn get(url: &str, h: &[(&str, &str)]) -> (u16, HeaderMap, String) {
    let mut r = reqwest::Client::new().get(url);
    for (k, v) in h {
        r = r.header(*k, *v);
    }
    let r = r.send().await.unwrap();
    let (s, hd) = (r.status().as_u16(), r.headers().clone());
    (s, hd, r.text().await.unwrap())
}

#[tokio::test]
async fn serve_sets_served_by_header() {
    let e = Env::ok("serve");
    let (up, hits) = engine(200, "node".into()).await;
    let url = proxy(up, Mode::Serve, desc(), e.files.clone()).await;
    let (s, h, b) = get(&url, &[]).await;
    assert_eq!((s, b), (200, unauth()));
    assert_eq!(h["x-vekrel-served-by"], "rust");
    assert_eq!(h["content-type"], "application/json");
    let (_, _, b) = get(&url, &[("cookie", &cookie(&mint(&claims())))]).await;
    assert_eq!(b, verified());
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "Node never sees the request"
    );
}

#[tokio::test]
async fn legacy_cookie_goes_to_node_in_serve_mode() {
    let e = Env::ok("legacy");
    let (up, hits) = engine(200, "node".into()).await;
    let remote = Descriptor::web("0.0.0.0", 3789, STATE_DIR, "machine-1");
    let url = proxy(up, Mode::Serve, remote, e.files.clone()).await;
    let (s, h, b) = get(
        &url,
        &[("cookie", &format!("t3_session={}", mint(&claims())))],
    )
    .await;
    assert_eq!((s, b.as_str()), (200, "node"));
    assert!(h.get("x-vekrel-served-by").is_none());
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn shadow_compares_http_bytes() {
    let (logs, _g) = capture();
    let e = Env::ok("shadow");

    // Node's bytes equal Rust's: the client gets Node's, the log says match.
    let (up, hits) = engine(200, unauth()).await;
    let url = proxy(up, Mode::Shadow, desc(), e.files.clone()).await;
    let (s, h, b) = get(&url, &[]).await;
    assert_eq!((s, b), (200, unauth()));
    assert!(h.get("x-vekrel-served-by").is_none());
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let lines = logs.wait(1).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("match") && !lines[0].contains("mismatch"),
        "{lines:?}"
    );

    // A different cookie name: mismatch names the JSON path, never the values.
    let node = unauth().replace(COOKIE, "t3_session_1_000000000000");
    let (up, _) = engine(200, node.clone()).await;
    let url = proxy(up, Mode::Shadow, desc(), e.files.clone()).await;
    assert_eq!(get(&url, &[]).await.2, node);
    let lines = logs.wait(2).await;
    assert!(
        lines[1].contains("mismatch") && lines[1].contains("$.auth.sessionCookieName"),
        "{lines:?}"
    );
    assert!(!lines[1].contains("t3_session"), "{lines:?}");

    // Status difference.
    let (up, _) = engine(500, unauth()).await;
    let url = proxy(up, Mode::Shadow, desc(), e.files.clone()).await;
    assert_eq!(get(&url, &[]).await.0, 500);
    let lines = logs.wait(3).await;
    assert!(
        lines[2].contains("mismatch") && lines[2].contains("status"),
        "{lines:?}"
    );

    // Over 1 MiB: passed through untouched, no comparison.
    let big = "x".repeat((1 << 20) + 1);
    let (up, _) = engine(200, big.clone()).await;
    let url = proxy(up, Mode::Shadow, desc(), e.files.clone()).await;
    assert_eq!(get(&url, &[]).await.2.len(), big.len());
    let lines = logs.wait(4).await;
    assert!(lines[3].contains("skipped_large"), "{lines:?}");
}

#[tokio::test]
async fn off_mode_and_other_routes_go_to_node() {
    let e = Env::ok("off");
    let (up, hits) = engine(200, "node".into()).await;
    let url = proxy(up, Mode::Off, desc(), e.files.clone()).await;
    assert_eq!(get(&url, &[]).await.2, "node");
    let url = proxy(up, Mode::Serve, desc(), e.files.clone()).await;
    assert_eq!(get(&url.replace("session", "other"), &[]).await.2, "node");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

/// Answers like Node would, but only after 2 s.
struct Slow;
impl RouteHandler for Slow {
    fn method_path(&self) -> (axum::http::Method, &'static str) {
        (axum::http::Method::GET, "/api/auth/session")
    }
    fn handle<'a>(
        &'a self,
        _: &'a axum::http::request::Parts,
        _: &'a HandlerCtx,
    ) -> futures_util::future::BoxFuture<'a, Option<Response<axum::body::Bytes>>> {
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            Some(
                Response::builder()
                    .header("content-type", "application/json")
                    .body(unauth().into())
                    .unwrap(),
            )
        })
    }
}

#[tokio::test]
async fn shadow_never_waits_for_rust() {
    let (logs, _g) = capture();
    let (up, _) = engine(200, unauth()).await;
    let url = proxy_with(up, Mode::Shadow, Arc::new(Slow)).await;
    let t = std::time::Instant::now();
    let (s, _, b) = get(&url, &[]).await;
    let took = t.elapsed();
    assert_eq!((s, b), (200, unauth()));
    assert!(
        took < std::time::Duration::from_millis(300),
        "took {took:?}"
    );
    assert!(logs.lines().is_empty(), "compared before Rust finished?");
    let lines = logs.wait(1).await;
    assert!(
        lines.len() == 1 && lines[0].contains("\"match\""),
        "{lines:?}"
    );
}

#[tokio::test]
async fn shadow_passes_node_body_errors_through() {
    let (logs, _g) = capture();
    // An engine that promises 100 bytes, sends 3, and hangs up.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut c, _) = l.accept().await.unwrap();
        let mut buf = vec![0; 4096];
        let _ = c.read(&mut buf).await;
        c.write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\nabc",
        )
        .await
        .unwrap();
    });
    let e = Env::ok("bodyerr");
    let url = proxy(up, Mode::Shadow, desc(), e.files.clone()).await;
    let r = reqwest::get(&url).await.unwrap();
    assert_eq!(r.status(), 200, "Node's status, not a 502");
    assert!(r.text().await.is_err(), "the body error reaches the client");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(logs.lines().is_empty(), "no comparison on a broken body");
}

// --- `wsTicket` on `/ws` upgrades (`MachineAuth.authenticateWebSocketUpgrade`,
// `SessionStore.verifyWebSocketToken`). Scopes, method and expiry come from the ROW.

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// `SessionStore.issueWebSocketToken`: `WebSocketClaims` JSON in schema order, base64url, then
/// `base64url(HMAC-SHA256(key, encodedPayload))`.
fn ticket_with(kind: &str, sid: &str, exp: i64, key: &[u8; 32]) -> String {
    let iat = now_ms();
    let json = format!(r#"{{"v":1,"kind":"{kind}","sid":"{sid}","iat":{iat},"exp":{exp}}}"#);
    let enc = B64.encode(json);
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(enc.as_bytes());
    format!("{enc}.{}", B64.encode(mac.finalize().into_bytes()))
}

fn ticket() -> String {
    ticket_with("websocket", SID, now_ms() + 300_000, &KEY)
}

async fn ws(env: &Env, query: &str) -> WsSession {
    env.handler()
        .ws_session(&HeaderMap::new(), Some(query), &Default::default())
        .await
}

fn q(t: &str) -> String {
    format!("wsTicket={t}&orchestrationProtocol=2")
}

#[tokio::test]
async fn valid_ticket_verifies_with_row_session() {
    let e = Env::new(
        "tk-ok",
        r#"["orchestration:read","filesystem:read"]"#,
        "2099-01-01T00:00:00.000Z",
        None,
    );
    assert_eq!(
        ws(&e, &q(&ticket())).await,
        WsSession::Verified(VerifiedSession {
            sid: SID.into(),
            scopes: vec!["orchestration:read".into(), "filesystem:read".into()],
            method: "browser-session-cookie".into(),
            exp: 4_070_908_800_000,
        })
    );
    // Node reads only the ticket: a DPoP header or a bad cookie beside it changes nothing.
    let mut h = HeaderMap::new();
    h.insert("authorization", "DPoP x".parse().unwrap());
    h.insert("cookie", cookie("junk").parse().unwrap());
    let s = e
        .handler()
        .ws_session(&h, Some(&q(&ticket())), &Default::default())
        .await;
    assert!(matches!(s, WsSession::Verified(_)), "{s:?}");
}

#[tokio::test]
async fn bad_tickets_are_rejected_like_node() {
    let e = Env::ok("tk-bad");
    let (enc, sig) = ticket()
        .split_once('.')
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .unwrap();
    let mut forged = B64.decode(&enc).unwrap();
    let n = forged.len();
    forged[n - 2] = if forged[n - 2] == b'9' { b'8' } else { b'9' }; // another exp digit
    let cases = [
        ("expired", ticket_with("websocket", SID, now_ms() - 1, &KEY)),
        (
            "wrong kind",
            ticket_with("session", SID, now_ms() + 300_000, &KEY),
        ),
        (
            "wrong key",
            ticket_with("websocket", SID, now_ms() + 300_000, &[8; 32]),
        ),
        ("tampered", format!("{}.{sig}", B64.encode(forged))),
        ("no signature", enc.clone()),
        (
            "unknown sid",
            ticket_with("websocket", "nope", now_ms() + 300_000, &KEY),
        ),
    ];
    for (what, t) in cases {
        let s = ws(&e, &q(&t)).await;
        assert!(matches!(s, WsSession::Rejected(_)), "{what}: {s:?}");
    }
}

#[tokio::test]
async fn revoked_expired_or_mcp_rows_are_rejected() {
    let revoked = Env::new(
        "tk-rev",
        r#"["a"]"#,
        "2099-01-01T00:00:00.000Z",
        Some("2026-01-02T00:00:00.000Z"),
    );
    let expired = Env::new("tk-exp", r#"["a"]"#, "2026-01-02T00:00:00.000Z", None);
    let mcp = Env::new("tk-mcp", r#"["a"]"#, "2099-01-01T00:00:00.000Z", None);
    rusqlite::Connection::open(mcp.dir.join("statev2.sqlite"))
        .unwrap()
        .execute("UPDATE auth_sessions SET subject = 'mcp-client'", [])
        .unwrap();
    for (what, e) in [("revoked", revoked), ("expired row", expired), ("mcp", mcp)] {
        let s = ws(&e, &q(&ticket())).await;
        assert!(matches!(s, WsSession::Rejected(_)), "{what}: {s:?}");
    }
}

#[tokio::test]
async fn unsure_tickets_defer_to_node() {
    let e = Env::ok("tk-defer");
    let t = ticket();
    let dev = ticket_with("websocket", "dev-auth-x", now_ms() + 300_000, &KEY);
    for query in [
        // `URLSearchParams` decodes these; Rust does not reproduce it.
        format!("wsTicket={}", t.replacen('.', "%2E", 1)),
        format!("ws%54icket={t}"),
        format!("wsTicket={t}+"),
        // `searchParams.get` takes the first; Rust defers rather than pick.
        format!("wsTicket={t}&wsTicket=x"),
        // Blank: Node falls back to the cookie/bearer path.
        "wsTicket=&orchestrationProtocol=2".into(),
        "wsTicket".into(),
        q(&dev),
    ] {
        assert_eq!(ws(&e, &query).await, WsSession::Deferred, "{query}");
    }
    std::fs::remove_file(e.dir.join("statev2.sqlite")).unwrap();
    assert_eq!(ws(&e, &q(&t)).await, WsSession::Deferred, "db gone");
    std::fs::remove_file(e.dir.join("secrets/server-signing-key.bin")).unwrap();
    assert_eq!(ws(&e, &q(&t)).await, WsSession::Deferred, "key gone");
}

// ---- dry runs (pairing writers): the prediction never holds Node's answer up for long ----

/// A dry-run handler for `POST /api/auth/browser-session` that takes 2 s to predict.
struct SlowDryRun;
impl RouteHandler for SlowDryRun {
    fn method_path(&self) -> (axum::http::Method, &'static str) {
        (axum::http::Method::POST, "/api/auth/browser-session")
    }
    fn dry_run(&self) -> bool {
        true
    }
    fn handle<'a>(
        &'a self,
        _: &'a axum::http::request::Parts,
        _: &'a HandlerCtx,
    ) -> futures_util::future::BoxFuture<'a, Option<Response<axum::body::Bytes>>> {
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            None
        })
    }
}

async fn post_timed(url: &str, body: &str) -> (u16, String, std::time::Duration) {
    let t = std::time::Instant::now();
    let r = reqwest::Client::new()
        .post(url.replace("/api/auth/session", "/api/auth/browser-session"))
        .header("content-type", "application/json")
        .body(body.to_owned())
        .send()
        .await
        .unwrap();
    let s = r.status().as_u16();
    (s, r.text().await.unwrap(), t.elapsed())
}

#[tokio::test]
async fn a_slow_dry_run_is_skipped_after_250_ms() {
    let (logs, _g) = capture();
    let (up, hits) = engine(200, "node".into()).await;
    let url = proxy_with(up, Mode::Shadow, Arc::new(SlowDryRun)).await;
    let (s, b, took) = post_timed(&url, r#"{"credential":"X"}"#).await;
    assert_eq!(
        (s, b.as_str(), hits.load(Ordering::SeqCst)),
        (200, "node", 1)
    );
    // Clearly under the dry run's 2 s stall, so it fails without the 250 ms cap, yet loose
    // enough for a loaded machine.
    assert!(
        took < std::time::Duration::from_millis(1500),
        "took {took:?}"
    );
    let lines = logs.wait(1).await;
    assert!(
        lines.iter().any(|l| l.contains("shadow_skipped_busy")),
        "{lines:?}"
    );
}

#[tokio::test]
async fn a_locked_db_skips_the_dry_run_at_once() {
    use vekrel::{
        auth::registry::Registry,
        handlers::{auth_access::AuthAccess, pairing::BrowserSession, pairing_links::Writer},
    };
    let (logs, _g) = capture();
    let e = Env::ok("dry-run-locked");
    let db = rusqlite::Connection::open(e.dir.join("statev2.sqlite")).unwrap();
    db.execute_batch(
        "CREATE TABLE auth_pairing_links (id TEXT PRIMARY KEY, credential TEXT NOT NULL UNIQUE,
           method TEXT NOT NULL, scopes TEXT NOT NULL, subject TEXT NOT NULL, label TEXT,
           created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT, revoked_at TEXT,
           proof_key_thumbprint TEXT);
         INSERT INTO auth_pairing_links (id, credential, method, scopes, subject, created_at, expires_at)
           VALUES ('l', 'CRED', 'one-time-token', '[]', 'one-time-token', 'x', '2099-01-01T00:00:00.000Z');
         BEGIN EXCLUSIVE;",
    )
    .unwrap();
    let access = Arc::new(AuthAccess::new(
        e.files.clone(),
        Arc::new(Registry::default()),
        false,
    ));
    let h = Arc::new(BrowserSession(Writer {
        auth: Arc::new(e.handler()),
        access,
        serve: false,
    }));
    let (up, hits) = engine(200, "node".into()).await;
    let url = proxy_with(up, Mode::Shadow, h).await;
    let (s, b, took) = post_timed(&url, r#"{"credential":"CRED"}"#).await;
    assert_eq!(
        (s, b.as_str(), hits.load(Ordering::SeqCst)),
        (200, "node", 1)
    );
    // Node is not held up by the lock (the 250 ms cap alone would allow that); that the dry
    // run's SQLite does not wait at all is `pairing::tests::a_dry_run_on_a_locked_db_gives_up_at_once`.
    assert!(
        took < std::time::Duration::from_millis(1500),
        "took {took:?}"
    );
    let lines = logs.wait(1).await;
    assert!(
        lines.iter().any(|l| l.contains("shadow_skipped_busy")),
        "{lines:?}"
    );
    db.execute_batch("ROLLBACK").unwrap();
}
