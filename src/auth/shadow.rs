//! Observe-only middleware: verifies the engine's session credential on every request, records the
//! outcome as a request extension and a warning, and never changes the request or the response.
use super::{sessions::Store, token};
use axum::{
    Router,
    extract::Request,
    http::{HeaderMap, header},
    middleware::{self, Next},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
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

struct Shadow {
    key_path: PathBuf,
    db_path: PathBuf,
    // The engine creates both on first boot, possibly after us, so they load lazily.
    key: OnceLock<[u8; 32]>,
    db: Mutex<Option<Store>>,
}

/// Wraps every route of `router` (HTTP proxy and the `/ws` upgrade).
pub fn apply(router: Router, key_path: PathBuf, db_path: PathBuf) -> Router {
    let s = Arc::new(Shadow {
        key_path,
        db_path,
        key: OnceLock::new(),
        db: Mutex::new(None),
    });
    router.layer(middleware::from_fn(move |mut req: Request, next: Next| {
        let s = s.clone();
        async move {
            let outcome = s.check(req.headers());
            if !matches!(outcome, Outcome::Verified { .. } | Outcome::NoCredential) {
                tracing::warn!(path = %req.uri().path(), outcome = ?outcome, "shadow auth");
            }
            req.extensions_mut().insert(ShadowAuth { outcome });
            next.run(req).await
        }
    }))
}

/// Session cookies (`t3_session`, `t3_session_<port>[_<hash12>]`, `t3_session_<hash12>`, see the
/// engine's `auth/utils.ts`) and `Authorization: Bearer|DPoP` tokens.
fn credentials(h: &HeaderMap) -> Vec<&str> {
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
    cookies.chain(auth).filter(|t| !t.is_empty()).collect()
}

impl Shadow {
    fn check(&self, h: &HeaderMap) -> Outcome {
        let creds = credentials(h);
        if creds.is_empty() {
            return Outcome::NoCredential;
        }
        let Some(key) = self.key() else {
            return Outcome::KeyUnavailable;
        };
        // Browsers send every server's cookie on a host (cookies ignore ports), so one match wins.
        let mut first = None;
        for t in creds {
            let o = self.verify(t, &key);
            if matches!(o, Outcome::Verified { .. }) {
                return o;
            }
            first.get_or_insert(o);
        }
        first.expect("creds is non-empty")
    }

    fn key(&self) -> Option<[u8; 32]> {
        if let Some(k) = self.key.get() {
            return Some(*k);
        }
        let k: [u8; 32] = std::fs::read(&self.key_path).ok()?.try_into().ok()?;
        Some(*self.key.get_or_init(|| k))
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
        let mut db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        if db.is_none() {
            *db = Store::open_readonly(&self.db_path).ok();
        }
        let Some(store) = db.as_ref() else {
            return Outcome::DbUnavailable;
        };
        match store.lookup(&p.sid) {
            Ok(None) => Outcome::UnknownSession,
            Ok(Some(row)) if row.revoked_at.is_some() => Outcome::Revoked,
            // Row scopes may narrow the token's, never widen them.
            Ok(Some(row))
                if row.subject != p.sub
                    || row.method != p.method
                    || !row.scopes.iter().all(|s| p.scopes.contains(s)) =>
            {
                Outcome::Mismatch
            }
            Ok(Some(row)) if row.expires_at_ms <= now_ms => Outcome::Expired,
            Ok(Some(row)) => Outcome::Verified { scopes: row.scopes },
            Err(_) => {
                *db = None; // reopen next time
                Outcome::DbUnavailable
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
    fn shadow(name: &str, subject: &str, scopes: &str, expires_at: &str) -> (Shadow, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("vekrel-shadow-unit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("statev2.sqlite");
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(DDL).unwrap();
        c.execute(
            "INSERT INTO auth_sessions (session_id, subject, scopes, method, issued_at, expires_at)
             VALUES (?1, ?2, ?3, 'browser-session-cookie', '2026-01-01T00:00:00.000Z', ?4)",
            [payload().sid.as_str(), subject, scopes, expires_at],
        )
        .unwrap();
        let s = Shadow {
            key_path: dir.join("unused"),
            db_path: db,
            key: OnceLock::new(),
            db: Mutex::new(None),
        };
        (s, dir)
    }

    fn check(name: &str, subject: &str, scopes: &str, expires_at: &str) -> Outcome {
        let (s, dir) = shadow(name, subject, scopes, expires_at);
        let o = s.verify(&mint(&payload(), &K), &K);
        std::fs::remove_dir_all(dir).unwrap();
        o
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
        let (s, dir) = shadow(
            "scopes",
            "browser",
            r#"["orchestration:read"]"#,
            "2099-01-01T00:00:00.000Z",
        );
        let mut p = payload();
        p.scopes.push("orchestration:write".into());
        let o = s.verify(&mint(&p, &K), &K);
        std::fs::remove_dir_all(dir).unwrap();
        assert_eq!(
            o,
            Outcome::Verified {
                scopes: vec!["orchestration:read".into()]
            }
        );
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
