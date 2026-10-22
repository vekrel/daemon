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
    Verified { scopes: Vec<String> },
    Expired,
    Revoked,
    Malformed,
    BadSignature,
    UnknownSession,
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

    /// Same order of checks as the engine's `SessionStore.verify`.
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
            Ok(Some(_)) => Outcome::Verified { scopes: p.scopes },
            Err(_) => {
                *db = None; // reopen next time
                Outcome::DbUnavailable
            }
        }
    }
}
