use axum::{Router, extract::Request, response::Response, routing::any};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;
use std::{
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use vekrel::{auth::shadow, server, supervisor::State};

const KEY: [u8; 32] = [9; 32];
const SID: &str = "6f1c0d3e-0000-4000-8000-000000000001";

/// Copied from Vekrel-Engine `apps/server/src/persistence/Migrations/031_AuthAuthorizationScopes.ts`
/// plus the columns added by `041_AuthSessionClientConnection.ts`.
const DDL: &str = "
    CREATE TABLE auth_sessions (
      session_id TEXT PRIMARY KEY,
      subject TEXT NOT NULL,
      scopes TEXT NOT NULL,
      method TEXT NOT NULL,
      client_label TEXT,
      client_ip_address TEXT,
      client_user_agent TEXT,
      client_device_type TEXT NOT NULL DEFAULT 'unknown',
      client_os TEXT,
      client_browser TEXT,
      issued_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      last_connected_at TEXT,
      revoked_at TEXT,
      client_surface TEXT,
      client_app_version TEXT
    );";

/// The engine's `SessionStore.issue` format.
fn mint(exp: i64) -> String {
    let claims = json!({"v":1,"kind":"session","sid":SID,"sub":"browser","scopes":["a"],
        "method":"browser-session-cookie","iat":1,"exp":exp});
    let enc = B64.encode(claims.to_string());
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(enc.as_bytes());
    format!("{enc}.{}", B64.encode(mac.finalize().into_bytes()))
}

fn state(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("vekrel-shadow-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("secrets")).unwrap();
    let key = dir.join("secrets/server-signing-key.bin");
    std::fs::write(&key, KEY).unwrap();
    let db = dir.join("statev2.sqlite");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(DDL).unwrap();
    c.execute(
        "INSERT INTO auth_sessions (session_id, subject, scopes, method, issued_at, expires_at)
         VALUES (?1, 'browser', '[\"a\"]', 'browser-session-cookie', '2026-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z')",
        [SID],
    )
    .unwrap();
    (key, db)
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
    fn warns(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|l| l.contains("WARN"))
            .map(String::from)
            .collect()
    }
}

/// Sends one request with `cookie` through proxy+shadow to an echo upstream; returns
/// (status, body, the cookie the upstream saw, warn lines).
async fn run(name: &str, cookie: Option<String>) -> (u16, String, Option<String>, Vec<String>) {
    let logs = Logs::default();
    let l = logs.clone();
    let sub = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || l.clone())
        .finish();
    // Tests run on current-thread runtimes, so the spawned servers log on this thread.
    let _g = tracing::subscriber::set_default(sub);

    let seen = Arc::new(Mutex::new(None));
    let s = seen.clone();
    let up = Router::new().fallback(any(move |req: Request| {
        let s = s.clone();
        async move {
            *s.lock().unwrap() = req
                .headers()
                .get("cookie")
                .map(|v| v.to_str().unwrap().to_owned());
            Response::builder()
                .status(203)
                .body(axum::body::Body::from("up"))
                .unwrap()
        }
    }));
    let ul = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = ul.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(ul, up).await.unwrap() });

    let (key, db) = state(name);
    let pl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = pl.local_addr().unwrap().port();
    let app = shadow::apply(
        server::build(
            Arc::new(State::default()),
            server::Upstream::loopback(up_port).with_public_port(port),
        ),
        key.clone(),
        db,
    );
    tokio::spawn(async move {
        axum::serve(
            pl,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });

    let mut rb = reqwest::Client::new().get(format!("http://127.0.0.1:{port}/api/x"));
    if let Some(c) = &cookie {
        rb = rb.header("cookie", c);
    }
    let r = rb.send().await.unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap();
    let _ = std::fs::remove_dir_all(key.parent().unwrap().parent().unwrap());
    let got = seen.lock().unwrap().clone();
    assert_eq!(got, cookie, "upstream must see the cookie unchanged");
    (status, body, got, logs.warns())
}

#[tokio::test]
async fn valid_token_passes_silently() {
    let c = format!("other=1; t3_session_3789={}", mint(i64::MAX));
    let (status, body, _, warns) = run("valid", Some(c)).await;
    assert_eq!((status, body.as_str()), (203, "up"));
    assert!(warns.is_empty(), "{warns:?}");
}

#[tokio::test]
async fn tampered_token_warns_bad_signature() {
    let t = mint(i64::MAX);
    let tampered = format!("{}x", &t[..t.len() - 1]);
    let tampered = if tampered == t {
        format!("{}y", &t[..t.len() - 1])
    } else {
        tampered
    };
    let (status, body, _, warns) = run(
        "tampered",
        Some(format!("t3_session_3789_abcdef012345={tampered}")),
    )
    .await;
    assert_eq!((status, body.as_str()), (203, "up"));
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("BadSignature") && warns[0].contains("/api/x"));
    assert!(!warns[0].contains(&tampered), "token must not be logged");
}

#[tokio::test]
async fn no_credential_is_silent() {
    let (status, _, _, warns) = run("none", Some("theme=dark".into())).await;
    assert_eq!(status, 203);
    assert!(warns.is_empty(), "{warns:?}");
}

#[tokio::test]
async fn expired_token_warns_expired() {
    let (status, _, _, warns) = run("expired", Some(format!("t3_session_3789={}", mint(1)))).await;
    assert_eq!(status, 203);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("Expired"));
}

#[tokio::test]
async fn bearer_token_for_unknown_session_warns() {
    let t = mint(i64::MAX); // its row is deleted below
    let (key, db) = state("unknown-db");
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute("DELETE FROM auth_sessions", [])
        .unwrap();
    let app = shadow::apply(
        Router::new().fallback(any(|| async { "ok" })),
        key.clone(),
        db,
    );
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let logs = Logs::default();
    let lw = logs.clone();
    let _g = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || lw.clone())
            .finish(),
    );
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let r = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/ws"))
        .header("authorization", format!("Bearer {t}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.text().await.unwrap(), "ok");
    let _ = std::fs::remove_dir_all(key.parent().unwrap().parent().unwrap());
    let warns = logs.warns();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("UnknownSession"));
}
