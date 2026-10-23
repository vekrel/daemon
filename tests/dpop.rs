//! DPoP through the proxy: Rust builds `htu` from the client's Host, Node (behind the proxy) from
//! the rewritten one; serve consumes a proof once, shadow never writes; a `/ws` DPoP upgrade in
//! serve becomes `Verified` and Node only ever sees a Rust ticket.
//!
//! The fake engine applies Node's own `htu` rule (`HttpServerRequest.toURL`: `http://<Host><url>`,
//! query stripped) so the test shows which side accepts which proof; the live test confirms it
//! against the real engine.
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, WebSocketUpgrade, ws::Message as AxMsg},
    http::{HeaderMap, Method, Response, Uri, request::Parts},
    routing::{any, get},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use futures_util::{FutureExt, SinkExt, StreamExt, future::BoxFuture};
use hmac::{Hmac, KeyInit, Mac};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
use vekrel::{
    auth::shadow::AuthFiles,
    config::Mode,
    handlers::{
        HandlerCtx,
        auth_session::{AuthSession, Descriptor},
        read_file::ReadFile,
    },
    http_auth,
    http_seam::{RouteHandler, Seam},
    rpc_seam::{self, UnaryHandler},
    server,
    supervisor::State,
};

const KEY: [u8; 32] = [9; 32];
const SID: &str = "6f1c0d3e-0000-4000-8000-000000000001";
/// A reusable dev-token session: never converted to a ticket.
const DEV_SID: &str = "dev-auth-1";
/// A session whose row grants fewer scopes than its token claims.
const NARROW_SID: &str = "6f1c0d3e-0000-4000-8000-000000000002";
const DESC: &str = r#"{"policy":"loopback-browser","bootstrapMethods":["one-time-token"],"sessionMethods":["browser-session-cookie","bearer-access-token","dpop-access-token"],"sessionCookieName":"t3_session_3789_fb52c29e3256","serverUpdateScope":"machine:maintain"}"#;

fn b64_sha256(s: &str) -> String {
    B64.encode(Sha256::digest(s.as_bytes()))
}

// ---- client: key, proofs, token ----

struct Client(SigningKey);

impl Client {
    fn xy(&self) -> (String, String) {
        let p = self.0.verifying_key().to_sec1_point(false);
        let b = p.as_bytes();
        (B64.encode(&b[1..33]), B64.encode(&b[33..65]))
    }
    /// RFC 7638, as `computeDpopJwkThumbprint` (keys in code-unit order).
    fn thumbprint(&self) -> String {
        let (x, y) = self.xy();
        b64_sha256(&format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#
        ))
    }
    fn proof(&self, htm: &str, htu: &str, jti: &str, token: &str) -> String {
        let (x, y) = self.xy();
        let h = format!(
            r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}}}"#
        );
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let p = format!(
            r#"{{"htm":"{htm}","htu":"{htu}","jti":"{jti}","iat":{iat},"ath":"{}"}}"#,
            b64_sha256(token)
        );
        let hp = format!("{}.{}", B64.encode(h), B64.encode(p));
        let sig: Signature = self.0.sign(hp.as_bytes());
        format!("{hp}.{}", B64.encode(sig.to_bytes()))
    }
}

fn client() -> Client {
    Client(SigningKey::from_slice(&[5; 32]).unwrap())
}

/// The engine's `SessionStore.issue` format for a DPoP-bound session.
fn token() -> String {
    token_for(SID)
}

/// `token()` for another session id (the rows in `home()`).
fn token_for(sid: &str) -> String {
    let c = json!({"v":1,"kind":"session","sid":sid,"sub":"native",
        "scopes":["orchestration:read","filesystem:read"],"method":"dpop-access-token",
        "jkt":client().thumbprint(),"iat":1,"exp":1_893_456_000_123i64});
    let enc = B64.encode(c.to_string());
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(enc.as_bytes());
    format!("{enc}.{}", B64.encode(mac.finalize().into_bytes()))
}

const VERIFIED: &str = r#"{"authenticated":true,"auth":DESC,"scopes":["orchestration:read"],"permissions":["orchestration:read","filesystem:read"],"sessionMethod":"dpop-access-token","expiresAt":"2030-01-01T00:00:00.123Z"}"#;

fn verified() -> String {
    VERIFIED.replace("DESC", DESC)
}

fn unauth() -> String {
    format!(r#"{{"authenticated":false,"auth":{DESC}}}"#)
}

// ---- engine files ----

/// `<userdata>/secrets/server-signing-key.bin` + `statev2.sqlite` with one live row for `SID`.
fn home() -> (tempfile::TempDir, Arc<AuthFiles>) {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("secrets")).unwrap();
    std::fs::write(d.path().join("secrets/server-signing-key.bin"), KEY).unwrap();
    let c = rusqlite::Connection::open(d.path().join("statev2.sqlite")).unwrap();
    c.execute_batch(
        "CREATE TABLE auth_sessions (session_id TEXT PRIMARY KEY, subject TEXT NOT NULL,
         scopes TEXT NOT NULL, method TEXT NOT NULL, issued_at TEXT NOT NULL,
         expires_at TEXT NOT NULL, revoked_at TEXT);",
    )
    .unwrap();
    c.execute(
        "INSERT INTO auth_sessions VALUES (?1, 'native', '[\"orchestration:read\",\"filesystem:read\"]',
         'dpop-access-token', '2026-01-01T00:00:00.000Z', '2030-01-01T00:00:00.123Z', NULL),
         (?2, 'native', '[\"orchestration:read\",\"filesystem:read\"]',
         'dpop-access-token', '2026-01-01T00:00:00.000Z', '2030-01-01T00:00:00.123Z', NULL),
         (?3, 'native', '[\"orchestration:read\"]',
         'dpop-access-token', '2026-01-01T00:00:00.000Z', '2030-01-01T00:00:00.123Z', NULL)",
        [SID, DEV_SID, NARROW_SID],
    )
    .unwrap();
    let files = Arc::new(AuthFiles::new(
        d.path().join("secrets/server-signing-key.bin"),
        d.path().join("statev2.sqlite"),
    ));
    (d, files)
}

fn markers(home: &Path) -> Vec<String> {
    std::fs::read_dir(home.join("secrets"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("dpop-proof-"))
        .collect()
}

// ---- fake engine ----

#[derive(Default, Clone)]
struct Seen(Arc<Mutex<Vec<HeaderMap>>>);

/// `GET /api/auth/session` the way Node judges `htu` (from the Host it receives); records headers.
async fn engine(seen: Seen) -> u16 {
    let app = Router::new().fallback(any(move |req: Request| {
        let seen = seen.clone();
        async move {
            let h = req.headers().clone();
            seen.0.lock().unwrap().push(h.clone());
            let node_url = format!("http://{}{}", h["host"].to_str().unwrap(), req.uri().path());
            let htu = h
                .get("dpop")
                .and_then(|p| p.to_str().unwrap().split('.').nth(1).map(str::to_owned))
                .map(|p| {
                    serde_json::from_slice::<Value>(&B64.decode(p).unwrap()).unwrap()["htu"].clone()
                });
            let body = if htu == Some(json!(node_url)) {
                verified()
            } else {
                unauth()
            };
            Response::builder()
                .header("content-type", "application/json")
                .header("vary", "Accept-Encoding")
                .header("access-control-allow-origin", "*")
                .body(Body::from(body))
                .unwrap()
        }
    }));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    port
}

async fn serve_app(l: TcpListener, app: Router) {
    axum::serve(
        l,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap()
}

/// The proxy with `h` in `mode` over the fake engine; returns (proxy port, engine port).
async fn proxy(mode: Mode, h: Arc<dyn RouteHandler>, seen: Seen) -> (u16, u16) {
    let up = engine(seen).await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let app = server::build(
        Arc::new(State::default()),
        server::Upstream::loopback(up)
            .with_public_port(port)
            .with_seam(Seam::new(HandlerCtx::default()).with(mode, h)),
    );
    tokio::spawn(serve_app(l, app));
    (port, up)
}

fn session_handler(files: &Arc<AuthFiles>) -> Arc<AuthSession> {
    Arc::new(AuthSession::new(
        Descriptor::web("127.0.0.1", 3789, "/tmp/vk/userdata", ""),
        files.clone(),
    ))
}

/// (status, served by Rust, body).
async fn fetch(port: u16, proof: &str) -> (u16, bool, String) {
    fetch_as(port, None, proof).await
}

/// `fetch` with an explicit `Host` header.
async fn fetch_as(port: u16, host: Option<&str>, proof: &str) -> (u16, bool, String) {
    let mut r = reqwest::Client::new().get(format!("http://127.0.0.1:{port}/api/auth/session?x=1"));
    if let Some(h) = host {
        r = r.header("host", h);
    }
    let r = r
        .header("authorization", format!("DPoP {}", token()))
        .header("dpop", proof)
        .send()
        .await
        .unwrap();
    let rust = r.headers().contains_key("x-vekrel-served-by");
    (r.status().as_u16(), rust, r.text().await.unwrap())
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
    async fn wait(&self, needle: &str, n: usize) -> Vec<String> {
        for _ in 0..100 {
            if self.lines(needle).len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.lines(needle)
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

/// Review Focus 5: which side accepts a proof signed for the public URL.
#[tokio::test]
async fn htu_through_the_proxy_rust_accepts_the_public_url_node_the_rewritten_one() {
    let (logs, _g) = Logs::capture();
    let (home, files) = home();
    let seen = Seen::default();
    let (port, engine_port) = proxy(Mode::Shadow, session_handler(&files), seen.clone()).await;
    let public = format!("http://127.0.0.1:{port}/api/auth/session");
    let internal = format!("http://127.0.0.1:{engine_port}/api/auth/session");

    // Signed for the URL the client used: Node (shadow answers) says unauthenticated, because it
    // sees `Host: 127.0.0.1:<engine>`; Rust accepts. Classified, not counted as a Rust bug.
    let (s, rust, body) = fetch(port, &client().proof("GET", &public, "p1", &token())).await;
    assert_eq!((s, rust, body), (200, false, unauth()));
    assert_eq!(
        seen.0.lock().unwrap()[0]["host"],
        format!("127.0.0.1:{engine_port}").as_str()
    );
    let l = logs.wait("rust shadow", 1).await;
    assert!(
        l.len() == 1 && l[0].contains("outcome=\"node_htu_host_mismatch\""),
        "{l:?}"
    );

    // Signed for the engine's internal URL (which no correct client knows): Node accepts, Rust
    // rejects. A real mismatch.
    let (_, _, body) = fetch(port, &client().proof("GET", &internal, "p2", &token())).await;
    assert_eq!(body, verified());
    let l = logs.wait("rust shadow", 2).await;
    assert!(
        l.len() == 2 && l[1].contains("outcome=\"mismatch\""),
        "{l:?}"
    );
    assert!(markers(home.path()).is_empty(), "shadow never writes");
}

#[tokio::test]
async fn serve_answers_a_public_url_proof_once_and_node_never_sees_it() {
    let (home, files) = home();
    let seen = Seen::default();
    let (port, _) = proxy(Mode::Serve, session_handler(&files), seen.clone()).await;
    let proof = client().proof(
        "GET",
        &format!("http://127.0.0.1:{port}/api/auth/session"),
        "s1",
        &token(),
    );
    assert_eq!(fetch(port, &proof).await, (200, true, verified()));
    let name = format!(
        "dpop-proof-{}.bin",
        b64_sha256(&format!("{}:s1", client().thumbprint()))
    );
    assert_eq!(markers(home.path()), [name]);
    // Replayed: `getSessionState` turns the replay into unauthenticated.
    assert_eq!(fetch(port, &proof).await, (200, true, unauth()));
    assert!(seen.0.lock().unwrap().is_empty());
}

/// Authenticates (consuming the proof) and then declines.
struct DeclineAfterAuth(Arc<AuthSession>);
impl RouteHandler for DeclineAfterAuth {
    fn method_path(&self) -> (Method, &'static str) {
        (Method::GET, "/api/auth/session")
    }
    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        async move {
            assert!(http_auth::authenticate(&self.0, req).await?.is_ok());
            None
        }
        .boxed()
    }
}

#[tokio::test]
async fn a_decline_after_consuming_rolls_the_marker_back_before_node_sees_the_proof() {
    let (home, files) = home();
    let seen = Seen::default();
    let h = Arc::new(DeclineAfterAuth(session_handler(&files)));
    let (port, _) = proxy(Mode::Serve, h, seen.clone()).await;
    let proof = client().proof(
        "GET",
        &format!("http://127.0.0.1:{port}/api/auth/session"),
        "r1",
        &token(),
    );
    let (_, rust, _) = fetch(port, &proof).await;
    assert!(!rust);
    assert_eq!(seen.0.lock().unwrap()[0]["dpop"], proof.as_str());
    assert!(
        markers(home.path()).is_empty(),
        "Node can consume it afresh"
    );
}

// ---- /ws ----

/// Fake engine `/ws`: records each upgrade's query and headers, answers every Request with
/// `Exit Success "node"`.
async fn ws_engine(seen: Arc<Mutex<Vec<(String, HeaderMap)>>>) -> u16 {
    let app = Router::new().route(
        "/ws",
        get(move |ws: WebSocketUpgrade, uri: Uri, headers: HeaderMap| {
            let seen = seen.clone();
            async move {
                let q = uri.query().unwrap_or("").to_owned();
                seen.lock().unwrap().push((q, headers));
                ws.on_upgrade(|mut s| async move {
                    while let Some(Ok(AxMsg::Text(t))) = s.next().await {
                        let v: Value = serde_json::from_str(t.as_str()).unwrap();
                        let e = json!({"_tag":"Exit","requestId":v["id"],"exit":{"_tag":"Success","value":"node"}});
                        s.send(AxMsg::Text(e.to_string().into())).await.unwrap();
                    }
                })
            }
        }),
    );
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    port
}

#[tokio::test]
async fn ws_dpop_upgrade_in_serve_is_verified_and_read_file_is_served_by_rust() {
    let (logs, _g) = Logs::capture();
    let (home, files) = home();
    let ws_dir = tempfile::tempdir().unwrap();
    std::fs::write(ws_dir.path().join("small.txt"), "hello\n").unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let up = ws_engine(seen.clone()).await;
    let handlers: Vec<(Arc<dyn UnaryHandler>, Mode)> = vec![(Arc::new(ReadFile), Mode::Serve)];
    let rpc = rpc_seam::Seam::new(handlers)
        .with_auth(session_handler(&files))
        .with_dpop_mode(Mode::Serve);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let app = server::build(
        Arc::new(State::default()),
        server::Upstream::loopback(up)
            .with_public_port(port)
            .with_rpc_seam(rpc),
    );
    tokio::spawn(serve_app(l, app));

    let url = format!("ws://127.0.0.1:{port}/ws?orchestrationProtocol=2");
    let htu = format!("http://127.0.0.1:{port}/ws");
    let mut req = url.as_str().into_client_request().unwrap();
    let h = req.headers_mut();
    h.insert(
        "authorization",
        format!("DPoP {}", token()).parse().unwrap(),
    );
    h.insert(
        "dpop",
        client().proof("GET", &htu, "w1", &token()).parse().unwrap(),
    );
    let (mut c, res) = tokio_tungstenite::connect_async(req)
        .await
        .expect("upgrade");
    assert_eq!(res.status(), 101);

    // Node got a Rust ticket for the session and never the proof.
    let (q, h) = seen.lock().unwrap()[0].clone();
    let t = q.split("wsTicket=").nth(1).expect("ticket");
    assert!(q.starts_with("orchestrationProtocol=2&wsTicket="), "{q}");
    assert!(
        !h.contains_key("authorization") && !h.contains_key("dpop"),
        "{h:?}"
    );
    let enc = t.split('.').next().unwrap();
    let claims: Value = serde_json::from_slice(&B64.decode(enc).unwrap()).unwrap();
    assert_eq!(
        (claims["kind"].as_str(), claims["sid"].as_str()),
        (Some("websocket"), Some(SID))
    );
    assert_eq!(markers(home.path()).len(), 1, "Rust consumed the proof");

    let m = json!({"_tag":"Request","id":7,"tag":"projects.readFile",
        "payload":{"cwd": ws_dir.path(), "relativePath":"small.txt"},"headers":[]});
    c.send(Message::text(m.to_string())).await.unwrap();
    let Some(Ok(Message::Text(t))) = c.next().await else {
        panic!("no answer")
    };
    let v: Value = serde_json::from_str(t.as_str()).unwrap();
    assert_eq!(v["exit"]["_tag"], "Success", "{v}");
    assert_ne!(v["exit"]["value"], "node", "Rust answered");
    let l = logs.lines("ws dpop verdict");
    assert!(
        l.len() == 1 && l[0].contains("rust=\"verified\" node=101 outcome=\"match\""),
        "{l:?}"
    );
}

#[tokio::test]
async fn ws_dpop_in_shadow_forwards_the_proof_and_writes_nothing() {
    let (home, files) = home();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let up = ws_engine(seen.clone()).await;
    let handlers: Vec<(Arc<dyn UnaryHandler>, Mode)> = vec![(Arc::new(ReadFile), Mode::Serve)];
    let rpc = rpc_seam::Seam::new(handlers).with_auth(session_handler(&files));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let app = server::build(
        Arc::new(State::default()),
        server::Upstream::loopback(up)
            .with_public_port(port)
            .with_rpc_seam(rpc),
    );
    tokio::spawn(serve_app(l, app));
    let mut req = format!("ws://127.0.0.1:{port}/ws")
        .into_client_request()
        .unwrap();
    let proof = client().proof(
        "GET",
        &format!("http://127.0.0.1:{port}/ws"),
        "w2",
        &token(),
    );
    req.headers_mut().insert(
        "authorization",
        format!("DPoP {}", token()).parse().unwrap(),
    );
    req.headers_mut().insert("dpop", proof.parse().unwrap());
    tokio_tungstenite::connect_async(req)
        .await
        .expect("upgrade");
    let (q, h) = seen.lock().unwrap()[0].clone();
    assert_eq!(q, "");
    assert_eq!(h["dpop"], proof.as_str(), "Node judges the proof itself");
    assert!(markers(home.path()).is_empty());
}

#[tokio::test]
async fn a_foreign_host_is_never_verified_and_goes_to_node() {
    let (home, files) = home();
    let seen = Seen::default();
    let (port, _) = proxy(Mode::Serve, session_handler(&files), seen.clone()).await;
    // A proof that is right for the URL the (rebinding) client claims.
    let host = format!("evil.example:{port}");
    let proof = client().proof(
        "GET",
        &format!("http://{host}/api/auth/session"),
        "e1",
        &token(),
    );
    let (_, rust, _) = fetch_as(port, Some(&host), &proof).await;
    assert!(!rust, "declined to Node");
    assert_eq!(seen.0.lock().unwrap()[0]["dpop"], proof.as_str());
    assert!(
        markers(home.path()).is_empty(),
        "never verified, never consumed"
    );
    // The daemon's own origins, any case.
    let host = format!("LocalHost:{port}");
    let proof = client().proof(
        "GET",
        &format!("http://localhost:{port}/api/auth/session"),
        "e2",
        &token(),
    );
    assert_eq!(
        fetch_as(port, Some(&host), &proof).await,
        (200, true, verified())
    );
}

/// A `/ws` proxy over `ws_engine` with ReadFile served and DPoP in serve; returns the port.
async fn ws_proxy(files: &Arc<AuthFiles>, seen: Arc<Mutex<Vec<(String, HeaderMap)>>>) -> u16 {
    let up = ws_engine(seen).await;
    let handlers: Vec<(Arc<dyn UnaryHandler>, Mode)> = vec![(Arc::new(ReadFile), Mode::Serve)];
    let rpc = rpc_seam::Seam::new(handlers)
        .with_auth(session_handler(files))
        .with_dpop_mode(Mode::Serve);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let app = server::build(
        Arc::new(State::default()),
        server::Upstream::loopback(up)
            .with_public_port(port)
            .with_rpc_seam(rpc),
    );
    tokio::spawn(serve_app(l, app));
    port
}

#[tokio::test]
async fn ws_conversion_only_for_trusted_origins_and_sessions_node_sees_the_same() {
    let (home, files) = home();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = ws_proxy(&files, seen.clone()).await;
    let cases = [
        // (Host, token, converted)
        (format!("evil.example:{port}"), token(), false),
        (format!("127.0.0.1:{port}"), token_for(NARROW_SID), false),
        (format!("127.0.0.1:{port}"), token_for(DEV_SID), false),
        (format!("[::1]:{port}"), token(), true),
    ];
    for (i, (host, tok, converted)) in cases.iter().enumerate() {
        let mut req = format!("ws://127.0.0.1:{port}/ws")
            .into_client_request()
            .unwrap();
        let proof = client().proof("GET", &format!("http://{host}/ws"), &format!("c{i}"), tok);
        let h = req.headers_mut();
        h.insert("host", host.parse().unwrap());
        h.insert("authorization", format!("DPoP {tok}").parse().unwrap());
        h.insert("dpop", proof.parse().unwrap());
        let (_, res) = tokio_tungstenite::connect_async(req)
            .await
            .expect("upgrade");
        assert_eq!(res.status(), 101);
        let (q, h) = seen.lock().unwrap()[i].clone();
        assert_eq!(q.contains("wsTicket="), *converted, "{host} {q}");
        // Deferred: Node gets the original credentials, unchanged.
        assert_eq!(h.contains_key("dpop"), !converted, "{host}");
        assert_eq!(
            markers(home.path()).len(),
            usize::from(*converted),
            "{host}"
        );
    }
}
