//! Node's `layerAuthenticatedAuth` (`auth/http.ts:229-260`) and `requireMachineScope` for Rust seam
//! handlers. Node runs this middleware before decoding the body, so handlers authenticate first.
use crate::{
    handlers::auth_session::{AuthSession, Cred, verify_claims},
    http_errors,
};
use axum::{
    body::Bytes,
    http::{HeaderValue, Response, header, request::Parts},
};

/// `MachineAuthenticatedPrincipal`: the session as Node's `authenticateToken` returns it (claims).
#[derive(Debug, Clone, PartialEq)]
pub struct Principal {
    pub session_id: String,
    pub subject: String,
    pub scopes: Vec<String>,
    pub method: String,
    /// Epoch milliseconds.
    pub expires_at_ms: i64,
}

/// `None`: Node answers (DPoP until Task 4, legacy cookie, unsure header or origin, key or DB
/// unreadable). `Err`: Node's exact 401.
pub async fn authenticate(
    auth: &AuthSession,
    req: &Parts,
) -> Option<Result<Principal, Response<Bytes>>> {
    // shortcut: every `Authorization: DPoP` request is Node's until DPoP proofs land (Task 4).
    if dpop_authorization(req) {
        return None;
    }
    let verdict = match auth.credential(&req.headers)? {
        Cred::Missing => Err(("missing_credential", None)),
        Cred::Rejected => Err(("invalid_credential", None)),
        Cred::Token { token, dpop } => {
            let files = auth.files().clone();
            tokio::task::spawn_blocking(move || verify_claims(&files, &token, dpop.as_deref()))
                .await
                .ok()??
                .map_err(|dpop| ("invalid_credential", dpop))
        }
    };
    Some(
        verdict
            .map(|p| Principal {
                session_id: p.sid,
                subject: p.sub,
                scopes: p.scopes,
                method: p.method,
                expires_at_ms: p.exp,
            })
            .map_err(|(reason, dpop)| unauthorized(req, reason, dpop)),
    )
}

/// `requireMachineScope`: an exact grant (`session.scopes.has`); `Some` is Node's 403.
pub fn require_scope(p: &Principal, scope: &str) -> Option<Response<Bytes>> {
    (!p.scopes.iter().any(|s| s == scope)).then(|| http_errors::scope_required(scope))
}

/// 401 `MachineAuthInvalidError` plus `appendDpopChallengeOnUnauthorized`'s header.
pub fn unauthorized(req: &Parts, reason: &str, dpop: Option<&str>) -> Response<Bytes> {
    let mut r = http_errors::auth_invalid(reason, dpop);
    let token_route = req
        .uri
        .path_and_query()
        .is_some_and(|p| p.as_str().starts_with("/oauth/token"));
    if (token_route && req.headers.contains_key("dpop")) || dpop_authorization(req) {
        r.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("DPoP"));
    }
    r
}

/// `request.headers.authorization?.startsWith("DPoP ")` (Node keeps the first `Authorization`).
fn dpop_authorization(req: &Parts) -> bool {
    req.headers
        .get(header::AUTHORIZATION)
        .is_some_and(|v| v.as_bytes().starts_with(b"DPoP "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{
            sessions::tests::DDL,
            shadow::AuthFiles,
            token::tests::{mint, payload},
        },
        handlers::auth_session::Descriptor,
    };
    use axum::http::Request;
    use std::{path::PathBuf, sync::Arc};

    const KEY: [u8; 32] = [7; 32];
    const COOKIE: &str = "t3_session_3789_fb52c29e3256";

    /// Key + DB with one live row for `payload().sid`; deleted on drop.
    struct Env(PathBuf, AuthSession);
    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn env(name: &str) -> Env {
        let dir =
            std::env::temp_dir().join(format!("vekrel-httpauth-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("key.bin"), KEY).unwrap();
        let c = rusqlite::Connection::open(dir.join("db.sqlite")).unwrap();
        c.execute_batch(DDL).unwrap();
        c.execute(
            "INSERT INTO auth_sessions (session_id, subject, scopes, method, issued_at, expires_at)
             VALUES (?1, 'browser', '[]', 'browser-session-cookie', '2026-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z')",
            [&payload().sid],
        )
        .unwrap();
        let files = Arc::new(AuthFiles::new(dir.join("key.bin"), dir.join("db.sqlite")));
        let desc = Descriptor::web("127.0.0.1", 3789, "/tmp/vk/userdata", "");
        Env(dir, AuthSession::new(desc, files))
    }

    fn req(path: &str, h: &[(&str, &str)]) -> Parts {
        let mut b =
            Request::post(format!("http://127.0.0.1:3789{path}")).header("host", "127.0.0.1:3789");
        for (k, v) in h {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn principal() -> Principal {
        let p = payload();
        Principal {
            session_id: p.sid,
            subject: p.sub,
            scopes: p.scopes,
            method: p.method,
            expires_at_ms: p.exp,
        }
    }

    /// (status, body without its traceId, www-authenticate).
    fn rejected(r: Response<Bytes>) -> (u16, String, Option<String>) {
        let body = String::from_utf8(r.body().to_vec()).unwrap();
        let body = body.split(r#","traceId""#).next().unwrap().to_owned();
        let www = r
            .headers()
            .get("www-authenticate")
            .map(|v| v.to_str().unwrap().to_owned());
        (r.status().as_u16(), body, www)
    }

    const AUTH: &str = r#"{"_tag":"MachineAuthInvalidError","code":"auth_invalid","reason":"#;

    #[tokio::test]
    async fn cookie_and_bearer_authenticate() {
        let e = env("ok");
        let t = mint(&payload(), &KEY);
        let cookie = format!("{COOKIE}={t}");
        let bearer = format!("Bearer {t}");
        for h in [
            ("cookie", cookie.as_str()),
            ("authorization", bearer.as_str()),
        ] {
            let got = authenticate(&e.1, &req("/x", &[h])).await.unwrap().unwrap();
            assert_eq!(got, principal());
        }
    }

    #[tokio::test]
    async fn credential_errors_are_nodes_401() {
        let e = env("401");
        let e = &e;
        let ask = |h: Vec<(&'static str, String)>| {
            let p = req(
                "/x",
                &h.iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>(),
            );
            async move { rejected(authenticate(&e.1, &p).await.unwrap().unwrap_err()) }
        };
        let missing = (401, format!(r#"{AUTH}"missing_credential""#), None);
        let invalid = (401, format!(r#"{AUTH}"invalid_credential""#), None);
        assert_eq!(ask(vec![]).await, missing);
        assert_eq!(
            ask(vec![("authorization", "Basic x".into())]).await,
            missing
        );
        assert_eq!(
            ask(vec![("authorization", "Bearer nope.nope".into())]).await,
            invalid
        );
        let wrong_key = mint(&payload(), &[8; 32]);
        assert_eq!(
            ask(vec![("cookie", format!("{COOKIE}={wrong_key}"))]).await,
            invalid
        );
        // A cookie from a foreign origin.
        let t = mint(&payload(), &KEY);
        let foreign = vec![
            ("cookie", format!("{COOKIE}={t}")),
            ("origin", "http://evil.test".into()),
        ];
        assert_eq!(ask(foreign).await, invalid);
        // A proof-bound token without DPoP authorization.
        let mut bound = payload();
        bound.jkt = Some("thumb".into());
        let bound = mint(&bound, &KEY);
        assert_eq!(
            ask(vec![("authorization", format!("Bearer {bound}"))]).await,
            (
                401,
                format!(r#"{AUTH}"invalid_credential","dpopFailureReason":"invalid_proof""#),
                None
            )
        );
    }

    #[tokio::test]
    async fn dpop_authorization_declines() {
        let e = env("dpop");
        let t = mint(&payload(), &KEY);
        let p = req(
            "/x",
            &[("authorization", &format!("DPoP {t}")), ("dpop", "proof")],
        );
        assert!(authenticate(&e.1, &p).await.is_none());
    }

    #[test]
    fn dpop_challenge_header_rule() {
        let www = |path: &str, h: &[(&str, &str)]| {
            rejected(unauthorized(&req(path, h), "invalid_credential", None)).2
        };
        assert_eq!(www("/oauth/token", &[("dpop", "p")]), Some("DPoP".into()));
        assert_eq!(www("/oauth/token", &[]), None);
        assert_eq!(www("/api/x", &[("dpop", "p")]), None);
        assert_eq!(
            www("/api/x", &[("authorization", "DPoP t")]),
            Some("DPoP".into())
        );
        assert_eq!(www("/api/x", &[("authorization", "Bearer t")]), None);
    }

    #[test]
    fn insufficient_scope_is_nodes_403() {
        assert!(require_scope(&principal(), "orchestration:read").is_none());
        let (status, body, _) = rejected(require_scope(&principal(), "access:write").unwrap());
        assert_eq!(
            (status, body.as_str()),
            (
                403,
                r#"{"_tag":"MachineScopeRequiredError","code":"insufficient_scope","requiredScope":"access:write","requiredPermission":"access:write""#
            )
        );
    }
}
