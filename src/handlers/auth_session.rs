//! `GET /api/auth/session`, byte-compatible with the engine's `MachineAuth.getSessionState`.
use super::HandlerCtx;
use crate::{
    auth::{shadow::AuthFiles, ticket, token},
    http_auth::{self, DpopCtx},
    http_seam::RouteHandler,
};
use axum::{
    body::Bytes,
    http::{HeaderMap, Method, Response, header, request::Parts},
};
use futures_util::{FutureExt, future::BoxFuture};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// `ServerAuthDescriptor` (contracts `auth.ts`), fields in schema order.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    policy: &'static str,
    bootstrap_methods: [&'static str; 1],
    session_methods: [&'static str; 3],
    session_cookie_name: String,
    server_update_scope: &'static str,
    #[serde(skip)]
    legacy_cookie_name: Option<&'static str>,
}

impl Descriptor {
    /// `MachineAuthPolicy.ts` and `auth/utils.ts` for `mode: "web"` with no dev URL, which is how
    /// the supervisor runs the engine. `port` is the ENGINE port, `state_dir` its `config.stateDir`;
    /// `machine_id` is only used for a remote-reachable host.
    pub fn web(host: &str, port: u16, state_dir: &str, machine_id: &str) -> Self {
        let remote = is_remote_reachable_host(host);
        let hash = hex12(if remote { machine_id } else { state_dir });
        Descriptor {
            policy: if remote {
                "remote-reachable"
            } else {
                "loopback-browser"
            },
            bootstrap_methods: ["one-time-token"],
            session_methods: [
                "browser-session-cookie",
                "bearer-access-token",
                "dpop-access-token",
            ],
            session_cookie_name: if remote {
                format!("vekrel_session_{hash}")
            } else {
                format!("vekrel_session_{port}_{hash}")
            },
            server_update_scope: "machine:maintain",
            legacy_cookie_name: remote.then_some("vekrel_session"),
        }
    }

    pub fn cookie_name(&self) -> &str {
        &self.session_cookie_name
    }
}

fn hex12(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `isRemoteReachableHost` from `auth/utils.ts`.
fn is_remote_reachable_host(host: &str) -> bool {
    if matches!(host, "0.0.0.0" | "::" | "[::]") {
        return true;
    }
    !(host.is_empty()
        || matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
        || host.starts_with("127."))
}

pub struct AuthSession {
    desc: Descriptor,
    files: Arc<AuthFiles>,
}

impl AuthSession {
    pub fn new(desc: Descriptor, files: Arc<AuthFiles>) -> Self {
        AuthSession { desc, files }
    }

    pub(crate) fn files(&self) -> &Arc<AuthFiles> {
        &self.files
    }

    pub(crate) fn cookie_name(&self) -> &str {
        self.desc.cookie_name()
    }

    /// `selectRequestCredential` + `isBrowserCookieCredential` as `browserSession` uses them: the
    /// session cookie's token, `Some(None)` for another or no credential. `None` (Node's): the
    /// legacy cookie, `%` in the token, non-ASCII headers.
    pub(crate) fn browser_cookie(&self, h: &HeaderMap) -> Option<Option<String>> {
        let cookie_header = joined(h, header::COOKIE, "; ")?;
        let cookies = parse_cookies(cookie_header.as_deref().unwrap_or(""));
        let authz = match h.get(header::AUTHORIZATION) {
            Some(v) => Some(v.to_str().ok()?),
            None => None,
        };
        if let Some(t) = cookies.get(self.desc.cookie_name()) {
            return (!t.contains('%')).then(|| Some((*t).to_owned()));
        }
        if prefixed(authz, "Bearer ")
            .or(prefixed(authz, "DPoP "))
            .is_some()
        {
            return Some(None);
        }
        let legacy = self.desc.legacy_cookie_name;
        (!legacy.is_some_and(|n| cookies.contains_key(n))).then_some(None)
    }
}

impl RouteHandler for AuthSession {
    fn default_mode(&self) -> crate::config::Mode {
        crate::config::Mode::Serve
    }
    fn method_path(&self) -> (Method, &'static str) {
        (Method::GET, "/api/auth/session")
    }

    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        async move {
            // `getSessionState`: any credential error is `authenticated: false`.
            let state = http_auth::authenticate(self, req)
                .await?
                .ok()
                .map(|p| VerifiedSession {
                    sid: p.session_id,
                    scopes: p.scopes,
                    method: p.method,
                    exp: p.expires_at_ms,
                });
            Some(self.respond(state))
        }
        .boxed()
    }
}

pub(crate) enum Cred {
    Missing,
    /// A credential Node rejects before verifying it (cookie from a foreign origin).
    Rejected,
    Token {
        token: String,
        dpop: Option<String>,
    },
}

impl AuthSession {
    /// `MachineAuth.authenticateRequest` up to `authenticateToken`. `None`: Node answers.
    pub(crate) fn credential(&self, h: &HeaderMap) -> Option<Cred> {
        let cookie_header = joined(h, header::COOKIE, "; ")?;
        let cookies = parse_cookies(cookie_header.as_deref().unwrap_or(""));
        let authz = match h.get(header::AUTHORIZATION) {
            Some(v) => Some(v.to_str().ok()?),
            None => None,
        };
        let dpop = prefixed(authz, "DPoP ");
        // `selectRequestCredential`'s order.
        let (token, cookie) = if let Some(t) = cookies.get(self.desc.cookie_name()) {
            (*t, true)
        } else if let Some(t) = prefixed(authz, "Bearer ") {
            (t, false)
        } else if let Some(t) = dpop {
            (t, false)
        } else if self
            .desc
            .legacy_cookie_name
            .is_some_and(|n| cookies.contains_key(n))
        {
            // Node may re-issue the cookie under the new name (`auth/http.ts`): its answer.
            return None;
        } else {
            return Some(Cred::Missing);
        };
        if token.is_empty() {
            return Some(Cred::Missing);
        }
        // `tryDecodeURIComponent`: not reproduced; engine tokens never contain `%`.
        if token.contains('%') {
            return None;
        }
        if cookie && !origin_allowed(h)? {
            return Some(Cred::Rejected);
        }
        Some(Cred::Token {
            token: token.to_owned(),
            dpop: dpop.map(str::to_owned),
        })
    }

    /// The session Node's `authenticateWebSocketUpgrade` derives, given the headers and query
    /// Node sees on the proxied upgrade. Anything Rust cannot verify is its blind spot: `Deferred`.
    /// `dctx` carries the client's own URL for a DPoP proof (`GET`, the `/ws` URL).
    pub async fn ws_session(
        &self,
        h: &HeaderMap,
        query: Option<&str>,
        dctx: &DpopCtx,
    ) -> WsSession {
        // A ticket wins over every header, as in Node.
        match ticket::from_query(query) {
            ticket::InQuery::Unsure => return WsSession::Deferred,
            ticket::InQuery::Ticket(t) => {
                let (files, t) = (self.files.clone(), t.to_owned());
                return tokio::task::spawn_blocking(move || verify_ticket(&files, &t))
                    .await
                    .unwrap_or(WsSession::Deferred);
            }
            ticket::InQuery::Absent => {}
        }
        let Some(Cred::Token { token, dpop }) = self.credential(h) else {
            return WsSession::Deferred;
        };
        let Some(proof) = http_auth::proof_header(h) else {
            return WsSession::Deferred;
        };
        let (files, ctx) = (self.files.clone(), dctx.clone());
        let checked = tokio::task::spawn_blocking(move || {
            http_auth::check(
                &files,
                &token,
                dpop.as_deref(),
                proof.as_deref(),
                "GET",
                &ctx,
            )
        });
        match checked.await {
            Ok(Some(Ok(p))) => WsSession::Verified(VerifiedSession {
                sid: p.sid,
                scopes: p.scopes,
                method: p.method,
                exp: p.exp,
            }),
            // A DPoP failure Node must also reject (logged); other credential errors stay Node's.
            Ok(Some(Err(Some(why)))) => WsSession::Rejected(why),
            _ => WsSession::Deferred,
        }
    }

    fn respond(&self, s: Option<VerifiedSession>) -> Response<Bytes> {
        let body = match &s {
            None => serde_json::to_vec(&SessionState {
                authenticated: false,
                auth: &self.desc,
                scopes: None,
                permissions: None,
                session_method: None,
                expires_at: None,
            }),
            Some(v) => serde_json::to_vec(&SessionState {
                authenticated: true,
                auth: &self.desc,
                // `authScopeResponse`.
                scopes: Some(
                    v.scopes
                        .iter()
                        .map(String::as_str)
                        .filter(|s| LEGACY_SCOPES.contains(s))
                        .collect(),
                ),
                permissions: Some(&v.scopes),
                session_method: Some(&v.method),
                expires_at: Some(iso_millis(v.exp)),
            }),
        }
        .expect("serializable");
        // The headers Node sends on this route besides length/date (its CORS layer adds the last two).
        Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::VARY, "Accept-Encoding")
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(Bytes::from(body))
            .expect("valid response")
    }
}

/// `AuthSessionState` (contracts `auth.ts`), fields in schema order.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionState<'a> {
    authenticated: bool,
    auth: &'a Descriptor,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<Vec<&'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

/// `legacyScopes` in contracts `auth.ts`.
pub(crate) const LEGACY_SCOPES: [&str; 8] = [
    "orchestration:read",
    "orchestration:operate",
    "terminal:operate",
    "review:write",
    "access:read",
    "access:write",
    "relay:read",
    "relay:write",
];

/// A verified session: from the token claims for a session token (`SessionStore.verify`), from
/// the row for a `wsTicket` (`verifyWebSocketToken`).
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedSession {
    pub sid: String,
    pub scopes: Vec<String>,
    pub method: String,
    /// Epoch milliseconds.
    pub exp: i64,
}

/// A WS connection's session, from the upgrade request's credentials.
#[derive(Debug, Clone, PartialEq)]
pub enum WsSession {
    /// Rust checks each RPC's scope against it; a missing scope is `MachineAuthorizationError`.
    Verified(VerifiedSession),
    /// Rust cannot evaluate the session Node accepted (an unsure `wsTicket`, a DPoP proof Rust
    /// cannot check, no or rejected credential, key/DB unreadable, engine config Rust cannot
    /// reproduce): Node answers.
    Deferred,
    /// A `wsTicket` Node must reject (401) for this reason. Rust still forwards the upgrade, so if
    /// Node accepts it anyway this acts as `Deferred`.
    Rejected(&'static str),
}

/// `SessionStore.verifyWebSocketToken` + `rejectMcpClientAudience`, in Node's check order.
fn verify_ticket(files: &AuthFiles, t: &str) -> WsSession {
    use WsSession::{Deferred, Rejected};
    let Some(key) = files.key() else {
        return Deferred;
    };
    let c = match ticket::verify(t, &key) {
        Ok(c) => c,
        Err(token::TokenError::BadSignature) => return Rejected("bad_signature"),
        Err(token::TokenError::Malformed) => return Rejected("malformed"),
    };
    // Reusable dev-token sessions stay on Node.
    if c.sid.starts_with("dev-auth-") {
        return Deferred;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    if c.exp <= now {
        return Rejected("ticket_expired");
    }
    match files.lookup(&c.sid) {
        None => Deferred,
        Some(None) => Rejected("unknown_session"),
        Some(Some(r)) if r.expires_at_ms <= now => Rejected("session_expired"),
        Some(Some(r)) if r.revoked_at.is_some() => Rejected("session_revoked"),
        Some(Some(r)) if r.subject == "mcp-client" => Rejected("mcp_client"),
        Some(Some(r)) => WsSession::Verified(VerifiedSession {
            sid: c.sid,
            scopes: r.scopes,
            method: r.method,
            exp: r.expires_at_ms,
        }),
    }
}

/// `SessionStore.verify` + `rejectMcpClientAudience` + the DPoP binding with the token claims, and for a credential error its `dpopFailureReason`. `Ok` with
/// a `jkt`: a proof-bound token presented as DPoP, whose proof the caller must still verify
/// (`http_auth::check`).
pub(crate) fn verify_claims(
    files: &AuthFiles,
    t: &str,
    dpop: Option<&str>,
) -> Option<Result<token::Payload, Option<&'static str>>> {
    let key = files.key()?;
    let Ok(p) = token::verify(t, &key) else {
        return Some(Err(None));
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    if p.exp <= now {
        return Some(Err(None));
    }
    // Only existence and revocation: Node reads scopes, method and expiry from the claims.
    match files.lookup(&p.sid)? {
        Some(row) if row.revoked_at.is_none() => {}
        _ => return Some(Err(None)),
    }
    if p.sub == "mcp-client" {
        return Some(Err(None));
    }
    match (p.jkt.is_some(), dpop) {
        // Proof-bound token presented as DPoP: the caller must verify the proof.
        (true, Some(d)) if d == t => Some(Ok(p)),
        (true, _) | (false, Some(_)) => Some(Err(Some("invalid_proof"))),
        (false, None) => Some(Ok(p)),
    }
}

/// `parseBearerToken` / `parseDpopToken`.
fn prefixed<'a>(authz: Option<&'a str>, prefix: &str) -> Option<&'a str> {
    let t = authz?.strip_prefix(prefix)?.trim();
    (!t.is_empty()).then_some(t)
}

/// Node's `req.headers[name]` for headers it joins; `None` if a value is not ASCII.
fn joined(h: &HeaderMap, name: header::HeaderName, sep: &str) -> Option<Option<String>> {
    let mut vals = h.get_all(name).iter().peekable();
    if vals.peek().is_none() {
        return Some(None);
    }
    let v: Option<Vec<&str>> = vals.map(|v| v.to_str().ok()).collect();
    Some(Some(v?.join(sep)))
}

/// Effect's `Cookies.parseHeader`, minus `%`-decoding (callers decline `%` values).
fn parse_cookies(header: &str) -> HashMap<&str, &str> {
    let mut out = HashMap::new();
    let len = header.len();
    let (mut pos, mut term) = (0, 0);
    while term != len {
        term = header[pos..].find(';').map_or(len, |i| pos + i);
        let Some(eq) = header[pos..].find('=').map(|i| pos + i) else {
            break;
        };
        if eq > term {
            pos = term + 1;
            continue;
        }
        let key = header[pos..eq].trim();
        let v = eq + 1;
        if !out.contains_key(key) {
            let val = if header.as_bytes().get(v) == Some(&b'"') {
                // JS `substring` swaps reversed bounds.
                let (a, b) = (v + 1, term.saturating_sub(1));
                &header[a.min(b)..a.max(b).min(len)]
            } else {
                &header[v..term]
            };
            out.insert(key, val.trim());
        }
        pos = term + 1;
    }
    out
}

/// `DESKTOP_RENDERER_ORIGINS` (`httpCors.ts`); dev origins are unsupported (see `unsupported_engine`).
const TRUSTED_ORIGINS: [&str; 2] = ["vekrel://app", "vekrel-dev://app"];

/// `isBrowserOriginAllowed`; `None` when Rust cannot be sure (Node answers).
fn origin_allowed(h: &HeaderMap) -> Option<bool> {
    let Some(origin) = joined(h, header::ORIGIN, ", ")? else {
        return Some(true);
    };
    if joined(h, header::HeaderName::from_static("sec-fetch-site"), ", ")?.as_deref()
        == Some("same-origin")
        || TRUSTED_ORIGINS.contains(&origin.as_str())
    {
        return Some(true);
    }
    let host = url_host(&origin)?;
    let first = |v: Option<String>| {
        v.and_then(|v| {
            let f = v.split(',').next()?.trim().to_ascii_lowercase();
            (!f.is_empty()).then_some(f)
        })
    };
    let host_hdr = match h.get(header::HOST) {
        Some(v) => Some(v.to_str().ok()?.to_owned()),
        None => None,
    };
    let fwd = joined(h, header::HeaderName::from_static("x-forwarded-host"), ", ")?;
    Some(Some(&host) == first(host_hdr).as_ref() || Some(&host) == first(fwd).as_ref())
}

/// `new URL(origin).host.toLowerCase()` for plain `http(s)://host[:port]` origins; anything
/// WHATWG would normalize further (IPv4 shorthands, IPv6, odd characters) is `None`.
fn url_host(origin: &str) -> Option<String> {
    let (scheme, rest) = origin.split_once("://")?;
    let default = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    let label_ok = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'.';
    if host.is_empty() || !host.bytes().all(label_ok) {
        return None;
    }
    // WHATWG treats a host whose last label is numeric as IPv4 and canonicalizes it.
    let last = host.rsplit('.').next().unwrap_or("");
    if last.is_empty() || last.starts_with(|c: char| c.is_ascii_digit()) {
        let canonical = host.split('.').count() == 4
            && host
                .split('.')
                .all(|p| p.parse::<u8>().is_ok_and(|n| n.to_string() == p));
        if !canonical {
            return None;
        }
    }
    let host = host.to_ascii_lowercase();
    let port = match port {
        None | Some("") => None,
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => Some(p.parse::<u16>().ok()?),
        Some(_) => return None,
    };
    Some(match port {
        Some(p) if p != default => format!("{host}:{p}"),
        _ => host,
    })
}

/// `Date.prototype.toISOString` for epoch milliseconds (years 0000-9999).
pub(crate) fn iso_millis(ms: i64) -> String {
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1000 % 60,
        rem % 1000
    )
}

/// Why Rust cannot reproduce the engine's auth descriptor for this engine config, if it cannot:
/// `Descriptor::web` assumes web mode, the loopback host the supervisor sets, no dev URL or dev
/// auth, the default base dir, and no bootstrap fd.
pub fn unsupported_engine(args: &[String], env: impl Fn(&str) -> Option<String>) -> Option<String> {
    for a in args {
        for f in [
            "--mode",
            "--host",
            "--dev-url",
            "--base-dir",
            "--bootstrap-fd",
        ] {
            if a == f || a.starts_with(&format!("{f}=")) {
                return Some(format!("engine arg {f}"));
            }
        }
    }
    if env("VEKREL_MODE").is_some_and(|m| m != "web") {
        return Some("VEKREL_MODE".into());
    }
    // The bootstrap payload on that fd can set mode and base dir.
    for v in [
        "VEKREL_BOOTSTRAP_FD",
        "VITE_DEV_SERVER_URL",
        "VEKREL_DEV_AUTH_TOKEN",
        "VEKREL_DEV_ALLOWED_ORIGINS",
    ] {
        if env(v).is_some_and(|x| !x.trim().is_empty()) {
            return Some(v.into());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_millis_matches_to_iso_string() {
        // Expected values from Node's `new Date(ms).toISOString()`.
        assert_eq!(iso_millis(1_893_456_000_123), "2030-01-01T00:00:00.123Z");
        assert_eq!(iso_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_millis(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn url_host_matches_whatwg_for_plain_origins() {
        assert_eq!(
            url_host("http://LocalHost:80").as_deref(),
            Some("localhost")
        );
        assert_eq!(url_host("https://a.b:443").as_deref(), Some("a.b"));
        assert_eq!(
            url_host("http://127.0.0.1:03779").as_deref(),
            Some("127.0.0.1:3779")
        );
        assert_eq!(url_host("http://x:").as_deref(), Some("x"));
        for bad in [
            "http://127.1",
            "http://[::1]:1",
            "null",
            "http://a_b",
            "http://a:99999",
            "ftp://a",
        ] {
            assert_eq!(url_host(bad), None, "{bad}");
        }
    }

    #[test]
    fn cookies_parse_like_effect() {
        // Expected maps from running Effect's `parseHeader` on the same strings.
        let c = parse_cookies(r#"a=1; b="x y" ;c=; a=2;bad; d=q=r"#);
        let want = [("a", "1"), ("b", "x y\""), ("c", ""), ("d", "q=r")];
        assert_eq!(c, HashMap::from(want));
        assert_eq!(parse_cookies(r#"a=""#), HashMap::from([("a", "\"")]));
        assert_eq!(
            parse_cookies(r#"a=1;  t="tok" ; t=junk"#),
            HashMap::from([("a", "1"), ("t", "tok\"")])
        );
    }

    #[test]
    fn unsupported_engine_configs() {
        let none = |_: &str| None;
        assert_eq!(unsupported_engine(&["bin.mjs".into()], none), None);
        assert!(unsupported_engine(&["--host=0.0.0.0".into()], none).is_some());
        assert!(unsupported_engine(&["--mode".into(), "desktop".into()], none).is_some());
        assert!(unsupported_engine(&["--bootstrap-fd=3".into()], none).is_some());
        let fd = |k: &str| (k == "VEKREL_BOOTSTRAP_FD").then(|| "3".to_owned());
        assert!(unsupported_engine(&[], fd).is_some());
        let dev = |k: &str| (k == "VITE_DEV_SERVER_URL").then(|| "http://x".to_owned());
        assert!(unsupported_engine(&[], dev).is_some());
        let web = |k: &str| (k == "VEKREL_MODE").then(|| "web".to_owned());
        assert_eq!(unsupported_engine(&[], web), None);
    }
}
