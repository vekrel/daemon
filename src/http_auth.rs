//! Node's `layerAuthenticatedAuth` (`auth/http.ts:229-260`) and `requireMachineScope` for Rust seam
//! handlers. Node runs this middleware before decoding the body, so handlers authenticate first.
use crate::{
    auth::{
        dpop::{self, Verdict},
        replay::{self, Created},
        shadow::AuthFiles,
        token::Payload,
    },
    handlers::auth_session::{AuthSession, Cred, verify_claims},
    http_errors,
};
use axum::{
    body::Bytes,
    http::{HeaderMap, HeaderValue, Response, header, request::Parts},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
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

/// `None`: Node answers (legacy cookie, unsure header, origin or DPoP proof, key, DB or replay
/// marker unusable). `Err`: Node's exact 401. With a DPoP proof in `serve` mode this consumes it
/// (writes the replay marker), so the caller must answer; a later decline rolls the marker back.
pub async fn authenticate(
    auth: &AuthSession,
    req: &Parts,
) -> Option<Result<Principal, Response<Bytes>>> {
    let verdict = match auth.credential(&req.headers)? {
        Cred::Missing => Err(("missing_credential", None)),
        Cred::Rejected => Err(("invalid_credential", None)),
        Cred::Token { token, dpop } => {
            let files = auth.files().clone();
            let proof = proof_header(&req.headers)?;
            let ctx = req.extensions.get::<DpopCtx>().cloned().unwrap_or_default();
            let method = req.method.as_str().to_owned();
            tokio::task::spawn_blocking(move || {
                check(
                    &files,
                    &token,
                    dpop.as_deref(),
                    proof.as_deref(),
                    &method,
                    &ctx,
                )
            })
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

/// What the DPoP checks need beyond the request Node sees. The proxy sets it on every request it
/// hands to a handler (and on `/ws` upgrades); without it Rust only checks markers, never writes.
#[derive(Debug, Clone)]
pub struct DpopCtx {
    /// The URL the client used (its own `Host`): what a correct proof signs. Node builds `htu`
    /// from the proxy's rewritten `Host` instead. `None`: Rust cannot tell, Node answers.
    pub url: Option<String>,
    /// `serve`: Rust consumes the proof. `shadow`: it only checks for an older replay marker.
    pub serve: bool,
    /// When the proxy received the request (shadow: markers newer than this are Node's own).
    pub arrived: SystemTime,
    /// `/ws`: Rust hands Node a ticket for the session instead of the proof, so the claims must be
    /// what Node's ticket verifier reads from the row; anything else stays Node's.
    pub for_ticket: bool,
    /// The marker Rust published and the session it authenticated, once it has.
    pub consumed: Arc<Mutex<Option<(PathBuf, String)>>>,
}

impl Default for DpopCtx {
    fn default() -> Self {
        DpopCtx {
            url: None,
            serve: false,
            for_ticket: false,
            arrived: SystemTime::now(),
            consumed: Arc::default(),
        }
    }
}

impl DpopCtx {
    /// A marker this request consumed that must be undone because Rust then declined it: Node
    /// verifies the proof afresh instead of calling it a replay.
    pub fn roll_back(&self) {
        if let Some((path, _)) = self.consumed.lock().expect("lock").take() {
            tracing::warn!("handler declined after consuming a DPoP proof; marker rolled back");
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Node's `verifyWebSocketToken` takes scopes, method and expiry from the row: they must equal
/// the token's claims, and reusable dev-token sessions stay Node's (as in `WsTicket::handle`).
fn ticket_sees_the_same(files: &AuthFiles, p: &Payload) -> bool {
    if p.sid.starts_with("dev-auth-") {
        return false;
    }
    matches!(files.lookup(&p.sid), Some(Some(r))
        if r.revoked_at.is_none() && r.subject == p.sub && r.scopes == p.scopes && r.method == p.method && r.expires_at_ms == p.exp)
}

/// `request.headers.dpop`: `Some(None)` when absent; `None` (Node's) when repeated or not ASCII.
pub(crate) fn proof_header(h: &HeaderMap) -> Option<Option<String>> {
    let mut v = h.get_all("dpop").iter();
    match (v.next(), v.next()) {
        (None, _) => Some(None),
        (Some(p), None) => Some(Some(p.to_str().ok()?.to_owned())),
        _ => None,
    }
}

/// `authenticateToken` + the DPoP binding (`MachineAuth.ts` `authenticateRequest`): the claims,
/// or the credential error's `dpopFailureReason`. Blocking (files, SQLite).
pub(crate) fn check(
    files: &AuthFiles,
    token: &str,
    dpop: Option<&str>,
    proof: Option<&str>,
    method: &str,
    ctx: &DpopCtx,
) -> Option<Result<Payload, Option<&'static str>>> {
    let p = match verify_claims(files, token, dpop)? {
        Ok(p) => p,
        Err(e) => return Some(Err(e)),
    };
    let Some(jkt) = p.jkt.as_deref() else {
        return Some(Ok(p));
    };
    // Node treats an empty `jkt` as unbound; its tokens never carry one.
    if jkt.is_empty() {
        return None;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let verdict = dpop::verify(
        proof,
        method,
        ctx.url.as_deref()?,
        now.as_secs() as i64,
        Some(jkt),
        Some(token),
    );
    let proof = match verdict {
        Verdict::Ok(proof) => proof,
        Verdict::Fail(why) => return Some(Err(Some(why))),
        Verdict::Decline => return None,
    };
    if ctx.for_ticket && !ticket_sees_the_same(files, &p) {
        return None;
    }
    let secrets = files.secrets_dir()?;
    let replay = if ctx.serve {
        match replay::create(secrets, &proof, now.as_millis() as i64) {
            Created::Yes(path) => {
                *ctx.consumed.lock().expect("lock") = Some((path, p.sid.clone()));
                false
            }
            Created::Replay => true,
            Created::Failed => return None,
        }
    } else {
        replay::seen_before(secrets, &proof, ctx.arrived)?
    };
    Some(if replay { Err(Some("replay")) } else { Ok(p) })
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
pub(crate) mod tests {
    use super::*;
    use crate::{
        auth::{
            dpop::tests::Client,
            sessions::tests::DDL,
            shadow::AuthFiles,
            token::tests::{mint, payload},
        },
        handlers::auth_session::Descriptor,
    };
    use axum::http::Request;
    use std::sync::Arc;

    pub(crate) const KEY: [u8; 32] = [7; 32];
    pub(crate) const COOKIE: &str = "vekrel_session_3789_fb52c29e3256";

    /// Key + DB with one live row for `payload().sid`, in a temp dir removed on drop.
    pub(crate) struct Env(pub tempfile::TempDir, pub Arc<AuthSession>);
    pub(crate) fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("key.bin"), KEY).unwrap();
        let c = rusqlite::Connection::open(dir.path().join("db.sqlite")).unwrap();
        c.execute_batch(DDL).unwrap();
        c.execute(
            "INSERT INTO auth_sessions (session_id, subject, scopes, method, issued_at, expires_at)
             VALUES (?1, 'browser', '[]', 'browser-session-cookie', '2026-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z')",
            [&payload().sid],
        )
        .unwrap();
        let files = Arc::new(AuthFiles::new(
            dir.path().join("key.bin"),
            dir.path().join("db.sqlite"),
        ));
        let desc = Descriptor::web("127.0.0.1", 3789, "/tmp/vk/userdata", "");
        Env(dir, Arc::new(AuthSession::new(desc, files)))
    }

    pub(crate) fn req(path: &str, h: &[(&str, &str)]) -> Parts {
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
    pub(crate) fn rejected(r: Response<Bytes>) -> (u16, String, Option<String>) {
        let body = String::from_utf8(r.body().to_vec()).unwrap();
        let body = body.split(r#","traceId""#).next().unwrap().to_owned();
        let www = r
            .headers()
            .get("www-authenticate")
            .map(|v| v.to_str().unwrap().to_owned());
        (r.status().as_u16(), body, www)
    }

    pub(crate) const AUTH: &str =
        r#"{"_tag":"MachineAuthInvalidError","code":"auth_invalid","reason":"#;

    #[tokio::test]
    async fn cookie_and_bearer_authenticate() {
        let e = env();
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
        let e = env();
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
    async fn dpop_on_an_unbound_token_is_nodes_invalid_proof() {
        let e = env();
        let t = mint(&payload(), &KEY);
        let p = req(
            "/x",
            &[("authorization", &format!("DPoP {t}")), ("dpop", "proof")],
        );
        let r = authenticate(&e.1, &p).await.unwrap().unwrap_err();
        assert_eq!(
            rejected(r),
            (
                401,
                format!(r#"{AUTH}"invalid_credential","dpopFailureReason":"invalid_proof""#),
                Some("DPoP".into())
            )
        );
    }

    /// A proof-bound token for `Client::new(5)` and a request carrying `proof` with `ctx`.
    fn bound(proof: Option<&str>, ctx: Option<DpopCtx>) -> (String, Parts) {
        let mut c = payload();
        c.jkt = Some(Client::new(5).thumbprint());
        c.method = "dpop-access-token".into();
        let t = mint(&c, &KEY);
        let authz = format!("DPoP {t}");
        let mut h = vec![("authorization", authz.as_str())];
        if let Some(p) = proof {
            h.push(("dpop", p));
        }
        let mut p = req("/api/x", &h);
        if let Some(ctx) = ctx {
            p.extensions.insert(ctx);
        }
        (t, p)
    }

    const PUBLIC: &str = "http://127.0.0.1:3773/api/x";

    fn ctx(serve: bool) -> DpopCtx {
        DpopCtx {
            url: Some(format!("{PUBLIC}?q=1")),
            serve,
            ..DpopCtx::default()
        }
    }

    fn markers(e: &Env) -> usize {
        std::fs::read_dir(e.0.path())
            .unwrap()
            .filter(|f| {
                f.as_ref()
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .starts_with("dpop-proof-")
            })
            .count()
    }

    async fn reason(e: &Env, p: &Parts) -> Option<String> {
        let r = authenticate(&e.1, p).await.unwrap().unwrap_err();
        let (status, body, www) = rejected(r);
        assert_eq!((status, www.as_deref()), (401, Some("DPoP")));
        let v: serde_json::Value = serde_json::from_str(&format!("{body}}}")).unwrap();
        v["dpopFailureReason"].as_str().map(str::to_owned)
    }

    #[tokio::test]
    async fn serve_consumes_a_valid_proof_once() {
        let e = env();
        let (t, _) = bound(None, None);
        let proof = Client::new(5).proof("POST", PUBLIC, "j1", &t);
        let (_, p) = bound(Some(&proof), Some(ctx(true)));
        let got = authenticate(&e.1, &p).await.unwrap().unwrap();
        assert_eq!(got.method, "dpop-access-token");
        assert_eq!(markers(&e), 1);
        let consumed = p
            .extensions
            .get::<DpopCtx>()
            .unwrap()
            .consumed
            .lock()
            .unwrap()
            .clone();
        assert_eq!(consumed.unwrap().1, payload().sid);
        // The same proof again (any process): replay.
        let (_, again) = bound(Some(&proof), Some(ctx(true)));
        assert_eq!(reason(&e, &again).await.as_deref(), Some("replay"));
        // A decline after consuming rolls the marker back, so Node can verify it afresh.
        p.extensions.get::<DpopCtx>().unwrap().roll_back();
        assert_eq!(markers(&e), 0);
    }

    #[tokio::test]
    async fn shadow_never_writes_and_sees_older_markers() {
        let e = env();
        let (t, _) = bound(None, None);
        let proof = Client::new(5).proof("POST", PUBLIC, "j2", &t);
        let (_, p) = bound(Some(&proof), Some(ctx(false)));
        assert!(authenticate(&e.1, &p).await.unwrap().is_ok());
        assert_eq!(markers(&e), 0, "shadow only checks");
        // Consumed before this request arrived (by Node or Rust): replay.
        let (_, served) = bound(Some(&proof), Some(ctx(true)));
        assert!(authenticate(&e.1, &served).await.unwrap().is_ok());
        let late = DpopCtx {
            arrived: SystemTime::now() + std::time::Duration::from_secs(1),
            ..ctx(false)
        };
        let (_, p) = bound(Some(&proof), Some(late));
        assert_eq!(reason(&e, &p).await.as_deref(), Some("replay"));
    }

    #[tokio::test]
    async fn proof_failures_are_nodes_reasons_and_write_nothing() {
        let e = env();
        let (t, _) = bound(None, None);
        let c = Client::new(5);
        let cases = [
            (
                Some(c.proof("POST", "http://127.0.0.1:3783/api/x", "a", &t)),
                "request_mismatch",
            ),
            (Some(c.proof("GET", PUBLIC, "b", &t)), "request_mismatch"),
            (
                Some(c.proof("POST", PUBLIC, "c", "other-token")),
                "token_mismatch",
            ),
            (
                Some(Client::new(6).proof("POST", PUBLIC, "d", &t)),
                "key_mismatch",
            ),
            (None, "invalid_proof"),
            (Some("a.b".into()), "invalid_proof"),
        ];
        for (proof, want) in cases {
            let (_, p) = bound(proof.as_deref(), Some(ctx(true)));
            assert_eq!(reason(&e, &p).await.as_deref(), Some(want), "{proof:?}");
        }
        assert_eq!(markers(&e), 0);
    }

    #[tokio::test]
    async fn unsure_proofs_decline_before_any_write() {
        let e = env();
        let (t, _) = bound(None, None);
        let c = Client::new(5);
        let good = c.proof("POST", PUBLIC, "z", &t);
        // No client URL (no proxy context), an unknown alg, a repeated `dpop` header.
        let (_, p) = bound(Some(&good), None);
        assert!(authenticate(&e.1, &p).await.is_none());
        let es384 = c.proof_with("ES384", r#"{"htm":"POST","htu":"x","jti":"y","iat":1}"#);
        let (_, p) = bound(Some(&es384), Some(ctx(true)));
        assert!(authenticate(&e.1, &p).await.is_none());
        let (_, mut p) = bound(Some(&good), Some(ctx(true)));
        p.headers.append("dpop", good.parse().unwrap());
        assert!(authenticate(&e.1, &p).await.is_none());
        assert_eq!(markers(&e), 0);
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
