//! Observe-only middleware: verifies the engine's session credential on every request, records the
//! outcome as a request extension and a warning, and never changes the request or the response.
use super::{
    sessions::{SessionRow, Store},
    token,
};
use axum::{
    Router,
    extract::Request,
    http::{HeaderMap, header},
    middleware::{self, Next},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Verified {
        scopes: Vec<String>,
    },
    Expired,
    Revoked,
    Malformed,
    BadSignature,
    UnknownSession,
    /// Token claims disagree with the session row (subject, method, or scopes the row lacks).
    Mismatch,
    NoCredential,
    DbUnavailable,
    KeyUnavailable,
}

/// Request extension set on every request.
#[derive(Debug, Clone)]
pub struct ShadowAuth {
    pub outcome: Outcome,
}

/// The engine's signing key and session DB, shared by shadow auth and Rust handlers.
pub struct AuthFiles {
    key_path: PathBuf,
    db_path: PathBuf,
    // The engine creates both on first boot, possibly after us, so they load lazily and reload
    // when the file changes (key rotated, DB replaced).
    key: Mutex<Option<(FileId, [u8; 32])>>,
    db: Mutex<Option<(FileId, Store)>>,
}

/// Inode (unix) and mtime: changes when the file is rewritten or replaced.
type FileId = (u64, Option<SystemTime>);

fn file_id(p: &std::path::Path) -> Option<FileId> {
    let m = std::fs::metadata(p).ok()?;
    #[cfg(unix)]
    let ino = std::os::unix::fs::MetadataExt::ino(&m);
    #[cfg(not(unix))]
    let ino = 0;
    Some((ino, m.modified().ok()))
}

/// Wraps every route of `router` (HTTP proxy and the `/ws` upgrade).
pub fn apply(router: Router, key_path: PathBuf, db_path: PathBuf) -> Router {
    apply_shared(router, Arc::new(AuthFiles::new(key_path, db_path)))
}

/// `apply` over files the caller also hands to Rust handlers.
pub fn apply_shared(router: Router, s: Arc<AuthFiles>) -> Router {
    router.layer(middleware::from_fn(move |mut req: Request, next: Next| {
        let s = s.clone();
        async move {
            let creds = credentials(req.headers());
            // File and SQLite I/O (busy timeout included) must not block a runtime worker.
            let outcome = if creds.is_empty() {
                Ok(Outcome::NoCredential)
            } else {
                tokio::task::spawn_blocking(move || s.check(creds)).await
            };
            match outcome {
                Ok(outcome) => {
                    if !matches!(outcome, Outcome::Verified { .. } | Outcome::NoCredential) {
                        tracing::warn!(path = %req.uri().path(), outcome = ?outcome, "shadow auth");
                    }
                    req.extensions_mut().insert(ShadowAuth { outcome });
                }
                // Observe only: a failed check never affects the request.
                Err(e) => tracing::warn!(path = %req.uri().path(), "shadow auth check failed: {e}"),
            }
            next.run(req).await
        }
    }))
}

/// Session cookies (`t3_session`, `t3_session_<port>[_<hash12>]`, `t3_session_<hash12>`, see the
/// engine's `auth/utils.ts`) and `Authorization: Bearer|DPoP` tokens.
fn credentials(h: &HeaderMap) -> Vec<String> {
    let cookies = h
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .filter(|(n, _)| *n == "t3_session" || n.starts_with("t3_session_"))
        .map(|(_, v)| v);
    let auth = h
        .get_all(header::AUTHORIZATION)
        .iter()
        .filter_map(|v| v.to_str().ok()?.split_once(' '))
        .filter(|(s, _)| s.eq_ignore_ascii_case("bearer") || s.eq_ignore_ascii_case("dpop"))
        .map(|(_, t)| t.trim());
    cookies
        .chain(auth)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

impl AuthFiles {
    pub fn new(key_path: PathBuf, db_path: PathBuf) -> Self {
        AuthFiles {
            key_path,
            db_path,
            key: Mutex::new(None),
            db: Mutex::new(None),
        }
    }

    fn check(&self, creds: Vec<String>) -> Outcome {
        if creds.is_empty() {
            return Outcome::NoCredential;
        }
        let Some(key) = self.key() else {
            return Outcome::KeyUnavailable;
        };
        // Browsers send every server's cookie on a host (cookies ignore ports), so one match wins.
        let mut first = None;
        for t in creds {
            let o = self.verify(&t, &key);
            if matches!(o, Outcome::Verified { .. }) {
                return o;
            }
            first.get_or_insert(o);
        }
        first.expect("creds is non-empty")
    }

    /// The engine's 32-byte signing key; `None` until the engine has written it.
    pub fn key(&self) -> Option<[u8; 32]> {
        let id = file_id(&self.key_path)?;
        let mut cached = self.key.lock().unwrap_or_else(|e| e.into_inner());
        match *cached {
            Some((cid, k)) if cid == id => Some(k),
            _ => {
                let k: [u8; 32] = std::fs::read(&self.key_path).ok()?.try_into().ok()?;
                *cached = Some((id, k));
                Some(k)
            }
        }
    }

    /// The engine's `SessionStore.verify` order, then the row is the source of truth: row expiry
    /// (as `loadActiveSession` and the dev-token path check) and row scopes.
    fn verify(&self, t: &str, key: &[u8; 32]) -> Outcome {
        let p = match token::verify(t, key) {
            Ok(p) => p,
            Err(token::TokenError::Malformed) => return Outcome::Malformed,
            Err(token::TokenError::BadSignature) => return Outcome::BadSignature,
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64);
        if p.exp <= now_ms {
            return Outcome::Expired;
        }
        match self.lookup(&p.sid) {
            None => Outcome::DbUnavailable,
            Some(None) => Outcome::UnknownSession,
            Some(Some(row)) if row.revoked_at.is_some() => Outcome::Revoked,
            // Row scopes may narrow the token's, never widen them.
            Some(Some(row))
                if row.subject != p.sub
                    || row.method != p.method
                    || !row.scopes.iter().all(|s| p.scopes.contains(s)) =>
            {
                Outcome::Mismatch
            }
            Some(Some(row)) if row.expires_at_ms <= now_ms => Outcome::Expired,
            Some(Some(row)) => Outcome::Verified { scopes: row.scopes },
        }
    }

    /// The `auth_sessions` row for `sid`; `None` when the DB is missing or the read fails.
    pub fn lookup(&self, sid: &str) -> Option<Option<SessionRow>> {
        let id = file_id(&self.db_path)?;
        let mut db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        if db.as_ref().is_none_or(|(cid, _)| *cid != id) {
            *db = Store::open_readonly(&self.db_path).ok().map(|s| (id, s));
        }
        let (_, store) = db.as_ref()?;
        match store.lookup(sid) {
            Ok(r) => Some(r),
            Err(_) => {
                *db = None; // reopen next time
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        sessions::tests::DDL,
        token::tests::{mint, payload},
    };

    const K: [u8; 32] = [7; 32];

    /// A Shadow over a temp DB holding one row for `payload().sid`.
    fn shadow(
        name: &str,
        subject: &str,
        scopes: &str,
        expires_at: &str,
    ) -> (AuthFiles, tempfile::TempDir) {
        let t = tempfile::Builder::new()
            .prefix(&format!("vekrel-shadow-unit-{name}-"))
            .tempdir()
            .unwrap();
        let dir = t.path().to_path_buf();
        let db = dir.join("statev2.sqlite");
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(DDL).unwrap();
        c.execute(
            "INSERT INTO auth_sessions (session_id, subject, scopes, method, issued_at, expires_at)
             VALUES (?1, ?2, ?3, 'browser-session-cookie', '2026-01-01T00:00:00.000Z', ?4)",
            [payload().sid.as_str(), subject, scopes, expires_at],
        )
        .unwrap();
        let s = AuthFiles::new(dir.join("server-signing-key.bin"), db);
        (s, t)
    }

    fn check(name: &str, subject: &str, scopes: &str, expires_at: &str) -> Outcome {
        let (s, _dir) = shadow(name, subject, scopes, expires_at);
        s.verify(&mint(&payload(), &K), &K)
    }

    #[test]
    fn matching_row_verifies() {
        let o = check(
            "ok",
            "browser",
            r#"["orchestration:read"]"#,
            "2099-01-01T00:00:00.000Z",
        );
        assert_eq!(
            o,
            Outcome::Verified {
                scopes: vec!["orchestration:read".into()]
            }
        );
    }

    #[test]
    fn row_expired_but_token_not() {
        // payload().exp is i64::MAX; the row expired in 2026-01.
        let o = check(
            "rowexp",
            "browser",
            r#"["orchestration:read"]"#,
            "2026-01-02T00:00:00.000Z",
        );
        assert_eq!(o, Outcome::Expired);
    }

    #[test]
    fn row_scopes_override_token_scopes() {
        // Row narrowed to a subset of the token's scopes (e.g. a later downgrade): row wins.
        let (s, _dir) = shadow(
            "scopes",
            "browser",
            r#"["orchestration:read"]"#,
            "2099-01-01T00:00:00.000Z",
        );
        let mut p = payload();
        p.scopes.push("orchestration:write".into());
        let o = s.verify(&mint(&p, &K), &K);
        assert_eq!(
            o,
            Outcome::Verified {
                scopes: vec!["orchestration:read".into()]
            }
        );
    }

    #[test]
    fn row_has_scope_token_lacks_is_mismatch() {
        let o = check(
            "widen",
            "browser",
            r#"["orchestration:read","admin"]"#,
            "2099-01-01T00:00:00.000Z",
        );
        assert_eq!(o, Outcome::Mismatch);
    }

    #[test]
    fn method_mismatch_is_mismatch() {
        let (s, _dir) = shadow(
            "method",
            "browser",
            r#"["orchestration:read"]"#,
            "2099-01-01T00:00:00.000Z",
        );
        let mut p = payload();
        p.method = "bearer-access-token".into();
        let o = s.verify(&mint(&p, &K), &K);
        assert_eq!(o, Outcome::Mismatch);
    }

    #[test]
    fn key_is_reread_when_its_mtime_changes() {
        let (s, _dir) = shadow(
            "rekey",
            "browser",
            r#"["orchestration:read"]"#,
            "2099-01-01T00:00:00.000Z",
        );
        let set = |k: [u8; 32], t: u64| {
            std::fs::write(&s.key_path, k).unwrap();
            std::fs::File::options()
                .write(true)
                .open(&s.key_path)
                .unwrap()
                .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(t))
                .unwrap();
        };
        set([1; 32], 1_000);
        assert_eq!(s.key(), Some([1; 32]));
        set(K, 2_000);
        let t = mint(&payload(), &K);
        assert!(matches!(s.check(vec![t]), Outcome::Verified { .. }));
    }

    #[test]
    fn subject_mismatch() {
        let o = check(
            "sub",
            "someone-else",
            r#"["orchestration:read"]"#,
            "2099-01-01T00:00:00.000Z",
        );
        assert_eq!(o, Outcome::Mismatch);
    }
}
