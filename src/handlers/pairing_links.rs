//! `POST /api/auth/pairing-token`, `GET /api/auth/pairing-links` and
//! `POST /api/auth/pairing-links/revoke` (`auth/http.ts` `pairingCredential`, `pairingLinks`,
//! `revokePairingLink`; `PairingGrantStore.issueOneTimeToken` / `revoke`).
//!
//! Create and revoke write `auth_pairing_links` only in `serve` (one statement each, as Node's
//! repository does); in `shadow` they predict Node's answer without writing. Rust's
//! `subscribeAuthAccess` sees Rust's writes through `data_version`; Node's own stream does not,
//! so while a socket may bypass the daemon (`auth::bypass`) the writes stay Node's.
use super::{
    HandlerCtx,
    auth_access::{AuthAccess, SCOPES, open_db, read_links},
    auth_session::{AuthSession, iso_millis},
};
use crate::{
    http_auth::{self, DpopCtx, Principal},
    http_errors,
    http_seam::{self, Compare, RouteHandler},
    machine::normalize,
};
use axum::{
    body::Bytes,
    http::{Method, Response, StatusCode, request::Parts},
};
use futures_util::{FutureExt, future::BoxFuture};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{Map, Value, json};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// `AuthStandardClientScopes` (contracts `auth.ts`), in order: the default delegation.
const STANDARD_SCOPES: [&str; 16] = [
    "orchestration:read",
    "orchestration:operate",
    "settings:write",
    "providers:manage",
    "machine:maintain",
    "preview:operate",
    "diagnostics:read",
    "terminal:read",
    "terminal:operate",
    "source-control:write",
    "filesystem:read",
    "filesystem:write",
    "relay:read",
    "access:read",
    "access:write",
    "relay:write",
];

const ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const CODE_LEN: usize = 12;
// Node rejects bytes >= floor(256 / 32) * 32 = 256, i.e. none: every byte maps uniformly.
const _: () = assert!(256 % ALPHABET.len() == 0);
/// `DEFAULT_ONE_TIME_TOKEN_TTL_MINUTES`.
const TTL_MS: i64 = 5 * 60_000;

/// `generatePairingToken`: 12 symbols, one CSPRNG byte each.
fn pairing_code() -> Option<String> {
    let mut b = [0u8; CODE_LEN];
    getrandom::fill(&mut b).ok()?;
    Some(
        b.iter()
            .map(|x| ALPHABET[*x as usize % ALPHABET.len()] as char)
            .collect(),
    )
}

/// `crypto.randomUUIDv4()`: lowercase, hyphenated.
pub(crate) fn uuid_v4() -> Option<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).ok()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

pub(crate) fn now_ms() -> Option<i64> {
    Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis() as i64,
    )
}

/// What a writer needs besides the session: whether its route is configured `serve` (and the
/// proxy says so too), and whether Node's own stream may have clients.
#[derive(Clone)]
pub struct Writer {
    pub auth: Arc<AuthSession>,
    /// Asked only for its bypass check.
    pub access: Arc<AuthAccess>,
    pub serve: bool,
}

impl Writer {
    /// Whether to write; `None` when the proxy says serve but the route is configured otherwise,
    /// so only a genuine shadow run returns a prediction.
    pub(crate) fn serving(&self, req: &Parts) -> Option<bool> {
        let proxy = req.extensions.get::<DpopCtx>().is_some_and(|d| d.serve);
        (!proxy || self.serve).then_some(proxy)
    }
}

pub const CREATE_KEY: &str = "POST /api/auth/pairing-token";
pub const REVOKE_KEY: &str = "POST /api/auth/pairing-links/revoke";

/// The middleware's principal, or its 401; `None` for callers Node keeps (dev-token sessions too).
pub(crate) async fn caller(
    auth: &AuthSession,
    req: &Parts,
) -> Option<Result<Principal, Response<Bytes>>> {
    let p = http_auth::authenticate(auth, req).await?;
    if p.as_ref()
        .is_ok_and(|p| p.session_id.starts_with("dev-auth-"))
    {
        return None;
    }
    Some(p)
}

/// The JSON body as an object; `None` (Effect's 400, Node's) for anything else.
pub(crate) fn body(req: &Parts) -> Option<Map<String, Value>> {
    match http_seam::json_body(req)? {
        Value::Object(o) => Some(o),
        _ => None,
    }
}

/// An `optionalKey(TrimmedNonEmptyString)`: absent is `Some(None)`; `None` fails the decode.
pub(crate) fn opt_trimmed(o: &Map<String, Value>, k: &str) -> Option<Option<String>> {
    match o.get(k) {
        None => Some(None),
        Some(v) => Some(Some(normalize(v.as_str()?)?.to_owned())),
    }
}

pub(crate) fn write_db(auth: &AuthSession) -> rusqlite::Result<Connection> {
    let c = Connection::open_with_flags(
        auth.files().db_path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // Node's own busy_timeout.
    c.busy_timeout(Duration::from_secs(5))?;
    Ok(c)
}

pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    tokio::task::spawn_blocking(f).await.ok().flatten()
}

/// `AuthAccess::bypass` off the async threads (it touches the filesystem).
pub(crate) async fn bypassed(a: &Arc<AuthAccess>) -> Option<&'static str> {
    let a = a.clone();
    blocking(move || Some(a.bypass()))
        .await
        .unwrap_or(Some("bypass_check_failed"))
}

fn declined(route: &str, why: &str) -> Option<Response<Bytes>> {
    tracing::info!(route, why, outcome = "declined", "rust pairing links");
    None
}

pub struct CreatePairingToken(pub Writer);

impl RouteHandler for CreatePairingToken {
    fn default_mode(&self) -> crate::config::Mode {
        crate::config::Mode::Serve
    }

    fn method_path(&self) -> (Method, &'static str) {
        (Method::POST, "/api/auth/pairing-token")
    }

    fn wants_body(&self) -> bool {
        true
    }

    fn compare(&self) -> Compare {
        Compare {
            ignore: &["$.id", "$.credential"],
            times: &["$.expiresAt"],
            headers: Compare::AUTH_HEADERS,
        }
    }

    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        async move {
            const ROUTE: &str = CREATE_KEY;
            let w = &self.0;
            let p = match caller(&w.auth, req).await? {
                Ok(p) => p,
                Err(r) => return Some(r),
            };
            // `AuthCreatePairingCredentialInput`.
            let Some(o) = body(req) else {
                return declined(ROUTE, "body");
            };
            let Some(label) = opt_trimmed(&o, "label") else {
                return declined(ROUTE, "label");
            };
            let scopes: Vec<String> = match o.get("scopes") {
                None => STANDARD_SCOPES.map(str::to_owned).to_vec(),
                Some(v) => {
                    let Some(a) = v.as_array().and_then(|a| {
                        a.iter()
                            .map(|s| s.as_str().filter(|s| grant_scope(s)).map(str::to_owned))
                            .collect::<Option<Vec<_>>>()
                    }) else {
                        return declined(ROUTE, "scopes");
                    };
                    a
                }
            };
            if let Some(r) = http_auth::require_scope(&p, "access:write") {
                return Some(r);
            }
            if scopes.is_empty() || scopes.iter().collect::<HashSet<_>>().len() != scopes.len() {
                return Some(http_errors::invalid_request("invalid_scope"));
            }
            if let Some(r) = scopes.iter().find_map(|s| http_auth::require_scope(&p, s)) {
                return Some(r);
            }
            let (Some(id), Some(credential), Some(now)) = (uuid_v4(), pairing_code(), now_ms())
            else {
                return declined(ROUTE, "random");
            };
            let expires_at = iso_millis(now + TTL_MS);
            let Some(serve) = w.serving(req) else {
                return declined(ROUTE, "mode_mismatch");
            };
            if serve {
                if let Some(why) = bypassed(&w.access).await {
                    return declined(ROUTE, why);
                }
                let (auth, id, credential, label, expires_at) = (
                    w.auth.clone(),
                    id.clone(),
                    credential.clone(),
                    label.clone(),
                    expires_at.clone(),
                );
                let scopes = serde_json::to_string(&scopes).ok()?;
                let wrote = blocking(move || {
                    write_db(&auth)
                        .and_then(|c| {
                            c.execute(
                                "INSERT INTO auth_pairing_links (id, credential, method, scopes,
                                   subject, label, proof_key_thumbprint, created_at, expires_at,
                                   consumed_at, revoked_at)
                                 VALUES (?1, ?2, 'one-time-token', ?3, 'one-time-token', ?4, NULL,
                                   ?5, ?6, NULL, NULL)",
                                rusqlite::params![
                                    id,
                                    credential,
                                    scopes,
                                    label,
                                    iso_millis(now),
                                    expires_at
                                ],
                            )
                        })
                        .map_err(|e| tracing::warn!(error = %e, "pairing link insert failed"))
                        .ok()
                })
                .await;
                // Nothing was written: Node can still answer.
                wrote?;
            }
            let mut out = Map::new();
            out.insert("id".into(), json!(id));
            out.insert("credential".into(), json!(credential));
            if let Some(l) = label {
                out.insert("label".into(), json!(l));
            }
            out.insert("expiresAt".into(), json!(expires_at));
            Some(http_errors::json(StatusCode::OK, &Value::Object(out)))
        }
        .boxed()
    }
}

/// `AuthGrantScope`: every machine scope except `review:write`.
fn grant_scope(s: &str) -> bool {
    s != "review:write" && SCOPES.contains(&s)
}

pub struct ListPairingLinks(pub Arc<AuthSession>);

impl RouteHandler for ListPairingLinks {
    fn default_mode(&self) -> crate::config::Mode {
        crate::config::Mode::Serve
    }

    fn method_path(&self) -> (Method, &'static str) {
        (Method::GET, "/api/auth/pairing-links")
    }

    fn compare(&self) -> Compare {
        Compare {
            headers: Compare::AUTH_HEADERS,
            ..Compare::DEFAULT
        }
    }

    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        async move {
            let p = match caller(&self.0, req).await? {
                Ok(p) => p,
                Err(r) => return Some(r),
            };
            if let Some(r) = http_auth::require_scope(&p, "access:read") {
                return Some(r);
            }
            let path = self.0.files().db_path().to_path_buf();
            let now = iso_millis(now_ms()?);
            let links = blocking(move || {
                // A row Node cannot decode is Node's 500.
                read_links(&open_db(&path).ok()?, &now)
                    .map_err(|e| tracing::info!(why = e, "pairing links read declined"))
                    .ok()
            })
            .await?;
            let list: Vec<Value> = links.into_iter().map(|l| l.1).collect();
            Some(http_errors::json(StatusCode::OK, &list))
        }
        .boxed()
    }
}

pub struct RevokePairingLink(pub Writer);

impl RouteHandler for RevokePairingLink {
    fn default_mode(&self) -> crate::config::Mode {
        crate::config::Mode::Serve
    }

    fn method_path(&self) -> (Method, &'static str) {
        (Method::POST, "/api/auth/pairing-links/revoke")
    }

    fn wants_body(&self) -> bool {
        true
    }

    fn compare(&self) -> Compare {
        Compare {
            headers: Compare::AUTH_HEADERS,
            ..Compare::DEFAULT
        }
    }

    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        async move {
            const ROUTE: &str = REVOKE_KEY;
            let w = &self.0;
            let p = match caller(&w.auth, req).await? {
                Ok(p) => p,
                Err(r) => return Some(r),
            };
            // `AuthRevokePairingLinkInput`.
            let Some(Some(id)) = body(req).and_then(|o| opt_trimmed(&o, "id")) else {
                return declined(ROUTE, "body");
            };
            if let Some(r) = http_auth::require_scope(&p, "access:write") {
                return Some(r);
            }
            let now = now_ms()?;
            let auth = w.auth.clone();
            let Some(serve) = w.serving(req) else {
                return declined(ROUTE, "mode_mismatch");
            };
            let revoked = if serve {
                if let Some(why) = bypassed(&w.access).await {
                    return declined(ROUTE, why);
                }
                blocking(move || {
                    let c = write_db(&auth).ok()?;
                    c.query_row(
                        "UPDATE auth_pairing_links SET revoked_at = ?2
                         WHERE id = ?1 AND revoked_at IS NULL AND consumed_at IS NULL
                         RETURNING id",
                        [&id, &iso_millis(now)],
                        |_| Ok(()),
                    )
                    .optional()
                    .map_err(|e| tracing::warn!(error = %e, "pairing link revoke failed"))
                    .ok()
                    .map(|r| r.is_some())
                })
                .await?
            } else {
                // Node revokes concurrently: a revocation stamped after this request arrived is
                // Node's own answer to it.
                let arrived = req
                    .extensions
                    .get::<DpopCtx>()
                    .and_then(|d| d.arrived.duration_since(UNIX_EPOCH).ok())
                    .map_or(now, |d| d.as_millis() as i64);
                let path = auth.files().db_path().to_path_buf();
                blocking(move || predict_revoke(&open_db(&path).ok()?, &id, &iso_millis(arrived)))
                    .await?
            };
            Some(http_errors::json(
                StatusCode::OK,
                &json!({ "revoked": revoked }),
            ))
        }
        .boxed()
    }
}

/// Shadow's `{revoked}`: Node's UPDATE matches an unconsumed row it has not revoked before
/// `arrived`.
fn predict_revoke(c: &Connection, id: &str, arrived: &str) -> Option<bool> {
    let row: Option<(Option<String>, Option<String>)> = c
        .query_row(
            "SELECT consumed_at, revoked_at FROM auth_pairing_links WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .ok()?;
    Some(matches!(row, Some((None, r)) if r.as_ref().is_none_or(|r| r.as_str() >= arrived)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::token::tests::{mint, payload},
        handlers::auth_access::tests::LINKS_DDL,
        http_auth::tests::{COOKIE, Env, KEY, env, rejected},
        http_seam::RequestBody,
    };

    const CREATE: &str = "/api/auth/pairing-token";
    const REVOKE: &str = "/api/auth/pairing-links/revoke";
    const SCOPE: &str = r#"{"_tag":"MachineScopeRequiredError","code":"insufficient_scope","#;

    fn setup(scopes: &[&str]) -> (Env, String) {
        let e = env();
        let c = Connection::open(e.0.path().join("db.sqlite")).unwrap();
        c.execute_batch(LINKS_DDL).unwrap();
        let mut p = payload();
        p.scopes = scopes.iter().map(|s| s.to_string()).collect();
        (e, format!("{COOKIE}={}", mint(&p, &KEY)))
    }

    fn req(method: &str, path: &str, cookie: &str, body: Option<&str>, serve: bool) -> Parts {
        let mut b = axum::http::Request::builder()
            .method(method)
            .uri(format!("http://127.0.0.1:3789{path}"))
            .header("host", "127.0.0.1:3789")
            .header("cookie", cookie);
        if body.is_some() {
            b = b.header("content-type", "application/json");
        }
        let mut parts = b.body(()).unwrap().into_parts().0;
        if let Some(body) = body {
            parts
                .extensions
                .insert(RequestBody(Bytes::from(body.to_owned())));
        }
        parts.extensions.insert(DpopCtx {
            serve,
            ..DpopCtx::default()
        });
        parts
    }

    fn writer(e: &Env, serve: bool) -> Writer {
        let files = e.1.files().clone();
        Writer {
            auth: e.1.clone(),
            access: Arc::new(AuthAccess::new(files, Arc::default(), false)),
            serve,
        }
    }

    fn rows(e: &Env) -> Vec<Vec<Option<String>>> {
        let c = Connection::open(e.0.path().join("db.sqlite")).unwrap();
        let mut q = c
            .prepare(
                "SELECT id, credential, method, scopes, subject, label, proof_key_thumbprint,
                   created_at, expires_at, consumed_at, revoked_at FROM auth_pairing_links",
            )
            .unwrap();
        q.query_map([], |r| (0..11).map(|i| r.get(i)).collect())
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    async fn create(e: &Env, cookie: &str, body: &str, serve: bool) -> Option<Response<Bytes>> {
        CreatePairingToken(writer(e, true))
            .handle(
                &req("POST", CREATE, cookie, Some(body), serve),
                &HandlerCtx::default(),
            )
            .await
    }

    async fn revoke(e: &Env, cookie: &str, id: &str, serve: bool) -> Option<Response<Bytes>> {
        let body = json!({ "id": id }).to_string();
        RevokePairingLink(writer(e, true))
            .handle(
                &req("POST", REVOKE, cookie, Some(&body), serve),
                &HandlerCtx::default(),
            )
            .await
    }

    #[test]
    fn codes_use_nodes_alphabet_and_ids_are_v4() {
        let mut seen = HashSet::new();
        for _ in 0..2000 {
            let c = pairing_code().unwrap();
            assert_eq!(c.len(), 12);
            assert!(c.bytes().all(|b| ALPHABET.contains(&b)), "{c}");
            seen.extend(c.into_bytes());
        }
        assert_eq!(seen.len(), 32, "every symbol appears");
        let u = uuid_v4().unwrap();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert!(b"89ab".contains(&u.as_bytes()[19]));
        assert_eq!(u, u.to_lowercase());
    }

    #[tokio::test]
    async fn serve_creates_nodes_row_and_response() {
        let (e, cookie) = setup(&STANDARD_SCOPES);
        let before = now_ms().unwrap();
        let r = create(&e, &cookie, r#"{"label":"  Phone ","extra":1}"#, true)
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let h: Vec<_> = r.headers().keys().map(|k| k.as_str()).collect();
        assert_eq!(
            h,
            ["content-type", "vary", "access-control-allow-origin"],
            "no no-store on this route"
        );
        let b: Value = serde_json::from_slice(r.body()).unwrap();
        let keys: Vec<_> = b.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["id", "credential", "label", "expiresAt"]);
        let row = rows(&e).remove(0);
        let s = |i: usize| row[i].clone().unwrap_or_default();
        assert_eq!(
            (s(0), s(1)),
            (
                b["id"].as_str().unwrap().into(),
                b["credential"].as_str().unwrap().into()
            )
        );
        assert_eq!(
            (s(2), s(4), s(5)),
            (
                "one-time-token".into(),
                "one-time-token".into(),
                "Phone".into()
            )
        );
        assert_eq!(s(3), serde_json::to_string(&STANDARD_SCOPES).unwrap());
        assert_eq!((&row[6], &row[9], &row[10]), (&None, &None, &None));
        let created = http_seam::parse_iso(&s(7)).unwrap();
        assert!((before..=before + 2000).contains(&created));
        assert_eq!(s(8), iso_millis(created + TTL_MS));
        assert_eq!(b["expiresAt"], s(8));
        // No label: the key is omitted and the column is NULL.
        let r = create(&e, &cookie, r#"{"scopes":["access:read"]}"#, true)
            .await
            .unwrap();
        let b: Value = serde_json::from_slice(r.body()).unwrap();
        assert!(b.get("label").is_none());
        let row = rows(&e)
            .into_iter()
            .find(|r| r[0].as_deref() == b["id"].as_str())
            .unwrap();
        assert_eq!(
            (row[3].as_deref(), row[5].as_deref()),
            (Some(r#"["access:read"]"#), None)
        );
    }

    #[tokio::test]
    async fn shadow_create_predicts_without_writing() {
        let (e, cookie) = setup(&STANDARD_SCOPES);
        let r = create(&e, &cookie, "{}", false).await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(rows(&e).is_empty());
    }

    #[tokio::test]
    async fn create_errors_are_nodes() {
        let (e, cookie) = setup(&["access:write", "orchestration:read"]);
        // Default scopes delegate more than the caller holds: the first one it lacks.
        let r = create(&e, &cookie, "{}", true).await.unwrap();
        assert_eq!(
            rejected(r).1,
            format!(
                r#"{SCOPE}"requiredScope":"orchestration:operate","requiredPermission":"orchestration:operate""#
            )
        );
        let r = create(
            &e,
            &cookie,
            r#"{"scopes":["orchestration:read","filesystem:read"]}"#,
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            rejected(r).1,
            format!(
                r#"{SCOPE}"requiredScope":"orchestration:read","requiredPermission":"filesystem:read""#
            )
        );
        let bad = r#"{"_tag":"MachineRequestInvalidError","code":"invalid_request","reason":"invalid_scope""#;
        for b in [
            r#"{"scopes":[]}"#,
            r#"{"scopes":["orchestration:read","orchestration:read"]}"#,
        ] {
            let r = create(&e, &cookie, b, true).await.unwrap();
            assert_eq!((r.status().as_u16(), rejected(r).1), (400, bad.into()));
        }
        // Without access:write, that 403 comes first.
        let (e2, reader) = setup(&["orchestration:read"]);
        let r = create(&e2, &reader, r#"{"scopes":[]}"#, true)
            .await
            .unwrap();
        assert_eq!(
            rejected(r).1,
            format!(r#"{SCOPE}"requiredScope":"access:write","requiredPermission":"access:write""#)
        );
        let r = create(&e, &cookie, r#"{"scopes":["orchestration:read"]}"#, true)
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(rows(&e).len(), 1, "only the success wrote");
    }

    #[tokio::test]
    async fn undecodable_bodies_and_dev_sessions_decline() {
        let (e, cookie) = setup(&STANDARD_SCOPES);
        for b in [
            "[]",
            "nope",
            r#"{"label":null}"#,
            r#"{"label":"   "}"#,
            r#"{"label":3}"#,
            r#"{"scopes":"access:read"}"#,
            r#"{"scopes":["review:write"]}"#,
            r#"{"scopes":["nope"]}"#,
        ] {
            assert!(create(&e, &cookie, b, true).await.is_none(), "{b}");
        }
        let r = RevokePairingLink(writer(&e, true))
            .handle(
                &req("POST", REVOKE, &cookie, Some(r#"{"id":" "}"#), true),
                &HandlerCtx::default(),
            )
            .await;
        assert!(r.is_none());
        assert!(rows(&e).is_empty());

        // Reusable dev-token sessions stay on Node.
        let mut dev = payload();
        dev.sid = "dev-auth-1".into();
        dev.scopes = STANDARD_SCOPES.map(str::to_owned).to_vec();
        Connection::open(e.0.path().join("db.sqlite"))
            .unwrap()
            .execute(
                "INSERT INTO auth_sessions (session_id, subject, scopes, method, issued_at, expires_at)
                 VALUES ('dev-auth-1', 'browser', '[]', 'browser-session-cookie', '2026-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z')",
                [],
            )
            .unwrap();
        let dev = format!("{COOKIE}={}", mint(&dev, &KEY));
        assert!(create(&e, &dev, "{}", true).await.is_none());
        assert!(create(&e, &cookie, "{}", true).await.is_some());
        assert_eq!(rows(&e).len(), 1);
        // Unauthenticated: the middleware 401 comes before the body.
        let r = create(&e, "", "nope", true).await.unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn list_is_newest_first_without_the_bootstrap_subject() {
        let (e, cookie) = setup(&["access:read"]);
        let c = Connection::open(e.0.path().join("db.sqlite")).unwrap();
        for (id, subject, created) in [
            ("a", "one-time-token", "2026-01-01T00:00:00.000Z"),
            ("b", "administrative-bootstrap", "2026-01-03T00:00:00.000Z"),
            ("c", "one-time-token", "2026-01-02T00:00:00.000Z"),
        ] {
            c.execute(
                "INSERT INTO auth_pairing_links (id, credential, method, scopes, subject, created_at, expires_at)
                 VALUES (?1, ?1, 'one-time-token', '[\"access:read\"]', ?2, ?3, '2099-01-01T00:00:00.000Z')",
                [id, subject, created],
            )
            .unwrap();
        }
        let r = ListPairingLinks(e.1.clone())
            .handle(
                &req("GET", "/api/auth/pairing-links", &cookie, None, false),
                &HandlerCtx::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            std::str::from_utf8(r.body()).unwrap(),
            r#"[{"id":"c","scopes":["access:read"],"permissions":["access:read"],"subject":"one-time-token","createdAt":"2026-01-02T00:00:00.000Z","expiresAt":"2099-01-01T00:00:00.000Z"},{"id":"a","scopes":["access:read"],"permissions":["access:read"],"subject":"one-time-token","createdAt":"2026-01-01T00:00:00.000Z","expiresAt":"2099-01-01T00:00:00.000Z"}]"#
        );
        let (e2, writer) = setup(&["access:write"]);
        let r = ListPairingLinks(e2.1.clone())
            .handle(
                &req("GET", "/api/auth/pairing-links", &writer, None, false),
                &HandlerCtx::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            rejected(r).1,
            format!(r#"{SCOPE}"requiredScope":"access:read","requiredPermission":"access:read""#)
        );
    }

    #[tokio::test]
    async fn revoke_matches_only_unconsumed_unrevoked_rows() {
        let (e, cookie) = setup(&STANDARD_SCOPES);
        let c = Connection::open(e.0.path().join("db.sqlite")).unwrap();
        c.execute_batch(
            "INSERT INTO auth_pairing_links (id, credential, method, scopes, subject, created_at, expires_at, consumed_at)
             VALUES ('open', 'x1', 'one-time-token', '[]', 's', '2026-01-01T00:00:00.000Z', '2026-01-01T00:05:00.000Z', NULL),
                    ('used', 'x2', 'one-time-token', '[]', 's', '2026-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z', '2026-01-01T00:01:00.000Z');",
        )
        .unwrap();
        let ans = |r: Response<Bytes>| String::from_utf8(r.body().to_vec()).unwrap();
        // Shadow predicts and writes nothing; an expired link still counts, as in Node.
        assert_eq!(
            ans(revoke(&e, &cookie, "open", false).await.unwrap()),
            r#"{"revoked":true}"#
        );
        assert_eq!(rows(&e)[0][10], None);
        assert_eq!(
            ans(revoke(&e, &cookie, "open", true).await.unwrap()),
            r#"{"revoked":true}"#
        );
        assert!(rows(&e)[0][10].is_some());
        // Revoked before this request arrived: false in both modes.
        assert_eq!(
            ans(revoke(&e, &cookie, "open", false).await.unwrap()),
            r#"{"revoked":false}"#
        );
        assert_eq!(
            ans(revoke(&e, &cookie, "open", true).await.unwrap()),
            r#"{"revoked":false}"#
        );
        for serve in [false, true] {
            for id in ["used", "missing"] {
                assert_eq!(
                    ans(revoke(&e, &cookie, id, serve).await.unwrap()),
                    r#"{"revoked":false}"#
                );
            }
        }
        assert_eq!(rows(&e)[1][10], None);
        // Shadow sees Node's own concurrent revocation as true.
        let late = iso_millis(now_ms().unwrap() + 60_000);
        c.execute(
            "UPDATE auth_pairing_links SET revoked_at = ?1 WHERE id = 'open'",
            [&late],
        )
        .unwrap();
        assert_eq!(
            ans(revoke(&e, &cookie, "open", false).await.unwrap()),
            r#"{"revoked":true}"#
        );
        let (e2, reader) = setup(&["access:read"]);
        let r = revoke(&e2, &reader, "open", true).await.unwrap();
        assert_eq!(r.status(), 403);
    }

    #[tokio::test]
    async fn writes_go_to_node_while_a_socket_may_bypass_the_daemon() {
        let (e, cookie) = setup(&STANDARD_SCOPES);
        let c = Connection::open(e.0.path().join("db.sqlite")).unwrap();
        c.execute(
            "INSERT INTO auth_pairing_links (id, credential, method, scopes, subject, created_at, expires_at)
             VALUES ('open', 'x1', 'one-time-token', '[]', 's', '2026-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        let cloud = e.0.path().join("cloud-relay-url.bin");
        std::fs::write(&cloud, "x").unwrap();
        assert!(create(&e, &cookie, "{}", true).await.is_none());
        assert!(revoke(&e, &cookie, "open", true).await.is_none());
        assert_eq!(rows(&e).len(), 1);
        assert_eq!(rows(&e)[0][10], None, "no Rust write");
        // Errors write nothing, so Rust still answers them.
        let r = create(&e, &cookie, r#"{"scopes":[]}"#, true).await.unwrap();
        assert_eq!(r.status(), 400);
        // Shadow predictions write nothing either.
        assert!(create(&e, &cookie, "{}", false).await.is_some());
        std::fs::remove_file(&cloud).unwrap();
        // A socket whose access stream Node took is still open: Node still writes.
        let w = writer(&e, true);
        let held = w.access.registry().node_stream();
        assert!(make(w.clone(), &cookie, true).await.is_none());
        assert_eq!(rows(&e).len(), 1);
        drop(held);
        assert_eq!(make(w, &cookie, true).await.unwrap().status(), 200);
        assert_eq!(
            revoke(&e, &cookie, "open", true).await.unwrap().status(),
            200
        );
        assert_eq!(rows(&e).len(), 2);
        assert!(rows(&e)[0][10].is_some() || rows(&e)[1][10].is_some());
    }

    async fn make(w: Writer, cookie: &str, serve: bool) -> Option<Response<Bytes>> {
        CreatePairingToken(w)
            .handle(
                &req("POST", CREATE, cookie, Some("{}"), serve),
                &HandlerCtx::default(),
            )
            .await
    }

    #[tokio::test]
    async fn only_a_route_configured_serve_writes() {
        let (e, cookie) = setup(&STANDARD_SCOPES);
        // The proxy says serve, the route's configured mode does not: Node's, nothing stored.
        assert!(make(writer(&e, false), &cookie, true).await.is_none());
        let revoke = RevokePairingLink(writer(&e, false))
            .handle(
                &req("POST", REVOKE, &cookie, Some(r#"{"id":"x"}"#), true),
                &HandlerCtx::default(),
            )
            .await;
        assert!(revoke.is_none());
        // A genuine shadow run predicts; a serve route stores.
        assert_eq!(
            make(writer(&e, false), &cookie, false)
                .await
                .unwrap()
                .status(),
            200
        );
        assert!(rows(&e).is_empty());
        assert_eq!(
            make(writer(&e, true), &cookie, true)
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(rows(&e).len(), 1);
        let keys = [
            http_seam::key(&CreatePairingToken(writer(&e, true))),
            http_seam::key(&RevokePairingLink(writer(&e, true))),
        ];
        assert_eq!(keys, [CREATE_KEY, REVOKE_KEY]);
    }
}
