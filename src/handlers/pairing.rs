//! `POST /api/auth/browser-session` and `POST /oauth/token` (`auth/http.ts` `browserSession` /
//! `token`, `MachineAuth.createBrowserSession` / `exchangeBootstrapCredentialForAccessToken`):
//! consume a one-time pairing credential and issue a session.
//!
//! `serve` writes `auth_pairing_links` (Node's consume UPDATE, same WHERE) and `auth_sessions`
//! (the insert, plus revoking the replaced cookie session) in one short transaction. `shadow` is
//! a dry run: the same WHERE as SELECTs, before Node's write; the proxy then checks Node's real
//! write against the prediction (`http_seam::DryRun`).
//!
//! Node's: anything that does not decode, a credential with no `auth_pairing_links` row (desktop
//! bootstrap, the dev token) or a non-`one-time-token` row, the legacy cookie, DPoP proofs Rust
//! cannot judge. Every decline comes before any write.
//!
//! Deliberate difference: `client_ip_address` is the client's address; Node behind the proxy
//! stores the proxy's `127.0.0.1`.
use super::{
    HandlerCtx,
    auth_access::AuthAccess,
    auth_session::{AuthSession, LEGACY_SCOPES, iso_millis},
    pairing_links::uuid_v4,
};
use crate::{
    auth::{
        dpop::{self, Proof, Verdict},
        replay::{self, Created},
        shadow::AuthFiles,
        token::{self, Payload},
    },
    cookies,
    http_auth::{self, DpopCtx},
    http_errors,
    http_seam::{self, Compare, DryRun, RouteHandler},
    machine::normalize,
};
use axum::{
    body::Bytes,
    extract::ConnectInfo,
    http::{HeaderMap, Method, Response, StatusCode, header, request::Parts},
};
use futures_util::{FutureExt, future::BoxFuture};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use serde_json::Value;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const DAY_MS: i64 = 86_400_000;
/// `DEFAULT_SESSION_TTL`.
const SESSION_TTL_MS: i64 = 30 * DAY_MS;
/// `ttl: Duration.hours(1)` for DPoP-bound sessions.
const DPOP_TTL_MS: i64 = 3_600_000;
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// `AuthGrantScope`: every `AuthMachineScope` but `review:write`.
const GRANT_SCOPES: [&str; 16] = [
    "orchestration:read",
    "orchestration:operate",
    "settings:write",
    "providers:manage",
    "machine:maintain",
    "preview:operate",
    "diagnostics:read",
    "terminal:read",
    "terminal:operate",
    "filesystem:read",
    "filesystem:write",
    "source-control:write",
    "access:read",
    "access:write",
    "relay:read",
    "relay:write",
];

/// The `AuthAccess` handler is only asked for its bypass check: while Node's own access stream
/// may serve a client (Tailscale Serve, a cloud link, an unverified socket), `serve` declines so
/// Node writes and publishes the change itself.
pub struct BrowserSession(pub Arc<AuthSession>, pub Arc<AuthAccess>);
pub struct Token(pub Arc<AuthSession>, pub Arc<AuthAccess>);

/// `AuthClientMetadata` as `SessionStore.issue` stores it (`client_*` columns).
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Client {
    pub label: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub device_type: String,
    pub os: Option<String>,
    pub browser: Option<String>,
}

/// What the client presented (`/oauth/token` only).
#[derive(Debug, Default)]
struct Presented {
    label: Option<String>,
    device_type: Option<String>,
    os: Option<String>,
}

/// One consume request, as both routes hand it over.
struct Ask {
    credential: String,
    /// `/oauth/token`'s parsed `scope`; `None` when absent (and always for browser-session).
    requested: Option<Vec<String>>,
    /// A verified DPoP proof (`/oauth/token`); its marker is written before the consume.
    proof: Option<Proof>,
    /// browser-session: the session id of a valid `browser-session-cookie` cookie, to replace.
    replace: Option<String>,
    client: Client,
    browser: bool,
}

/// The session row written (serve) or predicted (shadow).
#[derive(Debug, Clone, PartialEq)]
struct Row {
    subject: String,
    scopes: Vec<String>,
    method: &'static str,
    client: Client,
    issued_ms: i64,
    expires_ms: i64,
}

#[derive(Debug)]
enum Outcome {
    Issued {
        token: String,
        row: Box<Row>,
        replaced: Option<String>,
        link_id: String,
    },
    InvalidCredential,
    ScopeNotGranted,
    /// The proof's marker already exists.
    Replay,
    /// A write failed (Node: its issuance error, 500).
    Failed,
}

/// `TrimmedNonEmptyString`.
fn trimmed_non_empty(v: &Value) -> Option<String> {
    normalize(v.as_str()?).map(str::to_owned)
}

/// `parseOAuthScope` then `filter(Schema.is(AuthGrantScope))`; `None` is Node's `invalid_scope`.
fn requested_scopes(scope: &str) -> Option<Vec<String>> {
    let token_char = |c: char| matches!(c, '\u{21}' | '\u{23}'..='\u{5b}' | '\u{5d}'..='\u{7e}');
    if scope.is_empty()
        || scope
            .split(' ')
            .any(|t| t.is_empty() || !t.chars().all(token_char))
    {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    for t in scope.split(' ') {
        if !out.iter().any(|o| o == t) && GRANT_SCOPES.contains(&t) {
            out.push(t.to_owned());
        }
    }
    (!out.is_empty()).then_some(out)
}

/// `deriveAuthClientMetadata` (`auth/utils.ts`). `ua`: the first `user-agent`, trimmed.
fn client_metadata(ua: Option<String>, ip: Option<String>, presented: Presented) -> Client {
    let lower = ua.as_deref().map(str::to_ascii_lowercase);
    let has = |s: &str| lower.as_deref().is_some_and(|l| l.contains(s));
    let device = match &lower {
        None => "unknown",
        Some(_)
            if ["bot", "crawler", "spider", "slurp", "curl", "wget"]
                .iter()
                .any(|s| has(s)) =>
        {
            "bot"
        }
        Some(_) if has("ipad") || has("tablet") => "tablet",
        // `/iphone|android.+mobile|mobile/`: the middle branch implies the last.
        Some(_) if has("iphone") || has("mobile") => "mobile",
        Some(_) => "desktop",
    };
    let os = lower.as_ref().and_then(|_| {
        Some(if has("iphone") || has("ipad") || has("ipod") {
            "iOS"
        } else if has("android") {
            "Android"
        } else if has("mac os x") || has("macintosh") {
            "macOS"
        } else if has("windows nt") {
            "Windows"
        } else if has("linux") {
            "Linux"
        } else {
            return None;
        })
    });
    let browser = lower.as_ref().and_then(|_| {
        Some(if has("edg/") {
            "Edge"
        } else if has("opr/") {
            "Opera"
        } else if has("firefox/") {
            "Firefox"
        } else if has("electron/") {
            "Electron"
        } else if has("chrome/") || has("crios/") {
            "Chrome"
        } else if has("safari/") {
            "Safari"
        } else {
            return None;
        })
    });
    Client {
        label: presented.label,
        ip,
        user_agent: ua,
        device_type: presented.device_type.unwrap_or_else(|| device.into()),
        os: presented.os.or(os.map(Into::into)),
        browser: browser.map(Into::into),
    }
}

/// `headers["user-agent"]` normalized; `None` (Node's) when it is not ASCII.
fn user_agent(h: &HeaderMap) -> Option<Option<String>> {
    let Some(v) = h.get(header::USER_AGENT) else {
        return Some(None);
    };
    Some(normalize(v.to_str().ok()?).map(str::to_owned))
}

/// The client's own address (Node would see the proxy's).
fn client_ip(req: &Parts) -> Option<String> {
    let ip = req.extensions.get::<ConnectInfo<SocketAddr>>()?.0.ip();
    Some(ip.to_canonical().to_string())
}

fn now_ms() -> Option<i64> {
    Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis() as i64,
    )
}

fn declined(route: &str, why: &str) -> Option<Response<Bytes>> {
    tracing::info!(route, outcome = "declined", why, "rust handler declined");
    None
}

/// Node's consume WHERE (`AuthPairingLinks.consumeAvailablePairingLinkRow`): ?1 credential, ?2 now,
/// ?3 proof thumbprint, ?4 "no scopes requested", ?5 requested scopes JSON.
const AVAILABLE: &str = "credential = ?1
          AND revoked_at IS NULL
          AND consumed_at IS NULL
          AND expires_at > ?2
          AND (proof_key_thumbprint IS NULL OR proof_key_thumbprint = ?3)
          AND (?4 OR EXISTS (
            SELECT 1 FROM json_each(?5) AS requested
            WHERE requested.value IN (SELECT value FROM json_each(auth_pairing_links.scopes))
          ))";

/// `revokeActiveSessionsForReplacement` by session id: ?1 revoked_at, ?2 session id, ?3 method.
const REPLACEABLE: &str =
    "session_id = ?2 AND method = ?3 AND revoked_at IS NULL AND expires_at > ?1";

struct Link {
    method: String,
    scopes: Vec<String>,
    subject: String,
    label: Option<String>,
    jkt: Option<String>,
    revoked: bool,
    consumed: bool,
    expires_at: String,
}

/// SQLite could not take its lock without waiting.
fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

fn link_by_credential(c: &Connection, credential: &str) -> rusqlite::Result<Option<Link>> {
    c.query_row(
        "SELECT method, scopes, subject, label, proof_key_thumbprint,
                revoked_at IS NOT NULL, consumed_at IS NOT NULL, expires_at
         FROM auth_pairing_links WHERE credential = ?1",
        [credential],
        |r| {
            let scopes: String = r.get(1)?;
            Ok(Link {
                method: r.get(0)?,
                scopes: serde_json::from_str(&scopes).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        e.into(),
                    )
                })?,
                subject: r.get(2)?,
                label: r.get(3)?,
                jkt: r.get(4)?,
                revoked: r.get(5)?,
                consumed: r.get(6)?,
                expires_at: r.get(7)?,
            })
        },
    )
    .optional()
}

/// Why nothing matched, in `PairingGrantStore.consume`'s order: only a live, key-matching link
/// whose scopes miss every requested one is `scope_not_granted`.
fn explain(link: Option<&Link>, a: &Ask, now: &str) -> Outcome {
    let Some(l) = link else {
        return Outcome::InvalidCredential;
    };
    let key_ok =
        l.jkt.is_none() || l.jkt.as_deref() == a.proof.as_ref().map(|p| p.thumbprint.as_str());
    let misses = a
        .requested
        .as_ref()
        .is_some_and(|r| !r.iter().any(|s| l.scopes.contains(s)));
    if !l.revoked && !l.consumed && l.expires_at.as_str() > now && key_ok && misses {
        Outcome::ScopeNotGranted
    } else {
        Outcome::InvalidCredential
    }
}

/// The granted scopes: the link's, or the requested ones it holds (requested order, deduped).
fn granted(link_scopes: &[String], a: &Ask) -> Vec<String> {
    match &a.requested {
        None => link_scopes.to_vec(),
        Some(r) => r
            .iter()
            .filter(|s| link_scopes.contains(s))
            .cloned()
            .collect(),
    }
}

/// The consume, in Node's order after the payload checks. `None`: Node answers (decided before
/// any write). Blocking (SQLite, the marker file).
fn consume(
    files: &AuthFiles,
    a: &Ask,
    ctx: &DpopCtx,
    now: i64,
) -> Option<Result<Outcome, &'static str>> {
    let key = files.key()?;
    let flags = if ctx.serve {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let mut c =
        Connection::open_with_flags(files.db_path(), flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .ok()?;
    // Serve: Node's own busy_timeout, waiting out its writes as it waits out ours. A dry run
    // holds up Node's answer, so it never waits: busy means no comparison.
    let busy = if ctx.serve { 5000 } else { 0 };
    c.busy_timeout(Duration::from_millis(busy)).ok()?;
    let now_iso = iso_millis(now);
    // Only a credential with a one-time link row is Rust's (seeded desktop grants, the rotating
    // desktop token and the dev token have none).
    let link = match link_by_credential(&c, &a.credential) {
        Ok(l) => l,
        Err(e) if !ctx.serve && is_busy(&e) => return Some(Err("shadow_skipped_busy")),
        Err(_) => return None,
    };
    let Some(link) = link else {
        return Some(Err("not_a_pairing_link"));
    };
    if link.method != "one-time-token" {
        return Some(Err("link_method"));
    }
    // `SessionStore.verify` of the previous cookie: valid claims, live and unrevoked row.
    let replace = match &a.replace {
        None => None,
        Some(t) => match token::verify(t, &key) {
            Ok(p) if p.exp > now => {
                let row = files.lookup(&p.sid)?;
                (row.is_some_and(|r| r.revoked_at.is_none())
                    && p.method == "browser-session-cookie")
                    .then_some(p.sid)
            }
            _ => None,
        },
    };
    // The DPoP marker (Node's `verifyRequestDpopProof`, before the consume). Shadow only looks.
    if let Some(p) = &a.proof {
        let secrets = files.secrets_dir()?;
        let replayed = if ctx.serve {
            match replay::create(secrets, p, now) {
                Created::Yes(_) => false,
                Created::Replay => true,
                Created::Failed => return Some(Err("marker")),
            }
        } else {
            replay::seen_before(secrets, p, ctx.arrived)?
        };
        if replayed {
            return Some(Ok(Outcome::Replay));
        }
    }
    let requested = a
        .requested
        .as_ref()
        .map_or("[]".into(), |r| serde_json::to_string(r).expect("json"));
    let jkt = a.proof.as_ref().map(|p| p.thumbprint.clone());
    let none_requested = a.requested.is_none();
    let args = rusqlite::params![a.credential, now_iso, jkt, none_requested, requested];
    let method = match (&a.proof, a.browser) {
        (_, true) => "browser-session-cookie",
        (Some(_), false) => "dpop-access-token",
        (None, false) => "bearer-access-token",
    };
    let ttl = if a.proof.is_some() {
        DPOP_TTL_MS
    } else {
        SESSION_TTL_MS
    };
    let make_row = |l: &Link, scopes: Vec<String>| Row {
        subject: l.subject.clone(),
        scopes,
        method,
        client: Client {
            // `{...requestMetadata, ...(grant.label ? {label} : {})}`.
            label: l
                .label
                .clone()
                .filter(|s| !s.is_empty())
                .or(a.client.label.clone()),
            ..a.client.clone()
        },
        issued_ms: now,
        expires_ms: now + ttl,
    };
    if !ctx.serve {
        // Dry run: would the UPDATE match, and which session would it replace?
        let hit: Option<String> = c
            .query_row(
                &format!("SELECT id FROM auth_pairing_links WHERE {AVAILABLE}"),
                args,
                |r| r.get(0),
            )
            .optional()
            .ok()?;
        let Some(link_id) = hit else {
            return Some(Ok(explain(Some(&link), a, &now_iso)));
        };
        let scopes = granted(&link.scopes, a);
        // `exchangeBootstrapCredentialForAccessToken` rejects no scopes after the consume;
        // `createBrowserSession` issues a session with none.
        if scopes.is_empty() && !a.browser {
            return Some(Ok(Outcome::ScopeNotGranted));
        }
        let replaced = match &replace {
            None => None,
            Some(sid) => c
                .query_row(
                    &format!("SELECT session_id FROM auth_sessions WHERE {REPLACEABLE}"),
                    rusqlite::params![now_iso, sid, method],
                    |r| r.get(0),
                )
                .optional()
                .ok()?,
        };
        return Some(Ok(Outcome::Issued {
            token: "dry-run".into(),
            row: Box::new(make_row(&link, scopes)),
            replaced,
            link_id,
        }));
    }
    // From here on the marker may be written: answer, never decline.
    let tx = (|| -> rusqlite::Result<Outcome> {
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let hit: Option<String> = tx
            .query_row(
                &format!(
                    "UPDATE auth_pairing_links SET consumed_at = ?2 WHERE {AVAILABLE} RETURNING id"
                ),
                args,
                |r| r.get(0),
            )
            .optional()?;
        let Some(link_id) = hit else {
            let again = link_by_credential(&tx, &a.credential)?;
            return Ok(explain(again.as_ref(), a, &now_iso));
        };
        let scopes = granted(&link.scopes, a);
        if scopes.is_empty() && !a.browser {
            // Node's consume has committed by now too.
            tx.commit()?;
            return Ok(Outcome::ScopeNotGranted);
        }
        let row = make_row(&link, scopes);
        let replaced = match &replace {
            None => None,
            Some(sid) => tx
                .query_row(
                    &format!("UPDATE auth_sessions SET revoked_at = ?1 WHERE {REPLACEABLE} RETURNING session_id"),
                    rusqlite::params![now_iso, sid, method],
                    |r| r.get(0),
                )
                .optional()?,
        };
        let Some(sid) = uuid_v4() else {
            return Ok(Outcome::Failed);
        };
        let claims = Payload {
            v: 1,
            kind: "session".into(),
            sid: sid.clone(),
            sub: row.subject.clone(),
            scopes: row.scopes.clone(),
            method: method.into(),
            jkt: jkt.clone(),
            rtc: None,
            iat: row.issued_ms,
            exp: row.expires_ms,
        };
        let token = token::sign(&serde_json::to_vec(&claims).expect("json"), &key);
        let cl = &row.client;
        tx.execute(
            "INSERT INTO auth_sessions (session_id, subject, scopes, method, client_label,
               client_ip_address, client_user_agent, client_device_type, client_os, client_browser,
               issued_at, expires_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL)",
            rusqlite::params![
                sid,
                row.subject,
                serde_json::to_string(&row.scopes).expect("json"),
                method,
                cl.label,
                cl.ip,
                cl.user_agent,
                cl.device_type,
                cl.os,
                cl.browser,
                iso_millis(row.issued_ms),
                iso_millis(row.expires_ms),
            ],
        )?;
        tx.commit()?;
        Ok(Outcome::Issued {
            token,
            row: Box::new(row),
            replaced,
            link_id,
        })
    })();
    Some(Ok(tx.unwrap_or_else(|e| {
        tracing::warn!("pairing consume failed: {e}");
        Outcome::Failed
    })))
}

/// `AuthBrowserSessionResult`, fields in schema order.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserResult<'a> {
    authenticated: bool,
    scopes: Vec<&'a str>,
    permissions: &'a [String],
    session_method: &'a str,
    expires_at: String,
}

/// `AuthAccessTokenResult`, fields in schema order.
#[derive(Serialize)]
struct TokenResult<'a> {
    access_token: &'a str,
    issued_token_type: &'a str,
    token_type: &'a str,
    expires_in: i64,
    scope: String,
}

fn no_store(mut r: Response<Bytes>) -> Response<Bytes> {
    cookies::no_store(r.headers_mut());
    r
}

fn dpop_challenge(mut r: Response<Bytes>) -> Response<Bytes> {
    r.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("DPoP"),
    );
    r
}

/// Runs `consume` and answers as the route does; in shadow a predicted success carries the
/// `DryRun` check of Node's write.
async fn run(
    auth: &AuthSession,
    access: &Arc<AuthAccess>,
    req: &Parts,
    a: Ask,
    route: &'static str,
) -> Option<Response<Bytes>> {
    let ctx = req.extensions.get::<DpopCtx>().cloned().unwrap_or_default();
    let now = now_ms()?;
    let files = auth.files().clone();
    let a = Arc::new(a);
    let (f, a2, c2, acc) = (files.clone(), a.clone(), ctx.clone(), access.clone());
    let joined = tokio::task::spawn_blocking(move || {
        // Before any write (the DPoP marker included).
        match acc.bypass().filter(|_| c2.serve) {
            Some(why) => Some(Err(why)),
            None => consume(&f, &a2, &c2, now),
        }
    })
    .await;
    let issued = if a.browser {
        "browser_session_issuance_failed"
    } else {
        "access_token_issuance_failed"
    };
    let out = match joined {
        // A panic may have come after a write: serve must answer, as Node would.
        Err(_) if ctx.serve => {
            let r = http_errors::internal_error(issued);
            return Some(if a.browser { r } else { no_store(r) });
        }
        Err(_) => return None,
        Ok(o) => o,
    };
    let out = match out {
        None => return declined(route, "unreadable"),
        Some(Err("shadow_skipped_busy")) => {
            tracing::info!(route, outcome = "shadow_skipped_busy", "rust shadow");
            return None;
        }
        Some(Err(why)) => return declined(route, why),
        Some(Ok(o)) => o,
    };
    let browser = a.browser;
    // Node's browser-session sets no-store only on success; /oauth/token before the exchange.
    let errors = |r| if browser { r } else { no_store(r) };
    let (token, row, replaced, link_id) = match out {
        Outcome::Issued {
            token,
            row,
            replaced,
            link_id,
        } => (token, row, replaced, link_id),
        Outcome::InvalidCredential => {
            return Some(errors(http_errors::auth_invalid(
                "invalid_credential",
                None,
            )));
        }
        Outcome::ScopeNotGranted => {
            return Some(errors(http_errors::invalid_request("scope_not_granted")));
        }
        Outcome::Replay => {
            return Some(dpop_challenge(http_errors::auth_invalid(
                "invalid_credential",
                Some("replay"),
            )));
        }
        Outcome::Failed => return Some(errors(http_errors::internal_error(issued))),
    };
    let after = now_ms().unwrap_or(now);
    let expires_in = ((row.expires_ms - after) / 1000).max(0);
    let mut r = if browser {
        let body = BrowserResult {
            authenticated: true,
            scopes: row
                .scopes
                .iter()
                .map(String::as_str)
                .filter(|s| LEGACY_SCOPES.contains(s))
                .collect(),
            permissions: &row.scopes,
            session_method: row.method,
            expires_at: iso_millis(row.expires_ms),
        };
        let mut r = http_errors::json(StatusCode::OK, &body);
        r.headers_mut().insert(
            header::SET_COOKIE,
            cookies::session_cookie(auth.cookie_name(), &token, row.expires_ms),
        );
        no_store(r)
    } else {
        let body = TokenResult {
            access_token: &token,
            issued_token_type: ACCESS_TOKEN_TYPE,
            token_type: if a.proof.is_some() { "DPoP" } else { "Bearer" },
            expires_in,
            scope: row.scopes.join(" "),
        };
        no_store(http_errors::json(StatusCode::OK, &body))
    };
    if !ctx.serve {
        let cookie = auth.cookie_name().to_owned();
        let jkt = a.proof.as_ref().map(|p| p.thumbprint.clone());
        r.extensions_mut().insert(DryRun(Arc::new(move |h, b| {
            check_node_write(
                &files,
                &cookie,
                &row,
                jkt.as_deref(),
                replaced.as_deref(),
                &link_id,
                expires_in,
                h,
                b,
            )
        })));
    }
    Some(r)
}

/// The dry run's comparison: the session Node issued (its token's claims and its new row) and
/// its consume/replace writes against the prediction; ids, tokens and times (±2 s) aside, and
/// the IP address (Node's is the proxy's). `None` when they agree.
#[allow(clippy::too_many_arguments)]
fn check_node_write(
    files: &AuthFiles,
    cookie: &str,
    want: &Row,
    jkt: Option<&str>,
    replaced: Option<&str>,
    link_id: &str,
    expires_in: i64,
    h: &HeaderMap,
    body: &[u8],
) -> Option<String> {
    let near = |a: i64, b: i64, skew: i64| (a - b).abs() <= skew;
    let v: Value = serde_json::from_slice(body).ok()?;
    let token = match v.get("access_token") {
        Some(t) => {
            if !v["expires_in"]
                .as_i64()
                .is_some_and(|n| near(n, expires_in, 2))
            {
                return Some("$.expires_in".into());
            }
            t.as_str()?.to_owned()
        }
        None => h
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|c| {
                c.to_str()
                    .ok()?
                    .strip_prefix(&format!("{cookie}="))?
                    .split(';')
                    .next()
            })
            .next()?
            .to_owned(),
    };
    let Some(key) = files.key() else {
        return Some("key".into());
    };
    let Ok(p) = token::verify(&token, &key) else {
        return Some("token".into());
    };
    let claims_ok = p.sub == want.subject
        && p.scopes == want.scopes
        && p.method == want.method
        && p.jkt.as_deref() == jkt
        && p.rtc.is_none()
        && p.exp - p.iat == want.expires_ms - want.issued_ms
        && near(p.iat, want.issued_ms, 2000);
    if !claims_ok {
        return Some("token claims".into());
    }
    let c = Connection::open_with_flags(files.db_path(), OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    let row = c
        .query_row(
            "SELECT subject, scopes, method, client_label, client_ip_address, client_user_agent,
                    client_device_type, client_os, client_browser, issued_at, expires_at, revoked_at
             FROM auth_sessions WHERE session_id = ?1",
            [&p.sid],
            |r| {
                Ok((
                    (
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ),
                    Client {
                        label: r.get(3)?,
                        ip: r.get(4)?,
                        user_agent: r.get(5)?,
                        device_type: r.get(6)?,
                        os: r.get(7)?,
                        browser: r.get(8)?,
                    },
                    (
                        r.get::<_, String>(9)?,
                        r.get::<_, String>(10)?,
                        r.get::<_, Option<String>>(11)?,
                    ),
                ))
            },
        )
        .optional()
        .ok()?;
    let Some(((subject, scopes, method), client, (issued, expires, revoked))) = row else {
        return Some("auth_sessions row missing".into());
    };
    let times_ok =
        |s: &str, want: i64| http_seam::parse_iso(s).is_some_and(|t| near(t, want, 2000));
    if (subject.as_str(), method.as_str()) != (want.subject.as_str(), want.method)
        || scopes != serde_json::to_string(&want.scopes).expect("json")
    {
        return Some("auth_sessions subject/scopes/method".into());
    }
    if client
        != (Client {
            ip: client.ip.clone(),
            ..want.client.clone()
        })
    {
        return Some("auth_sessions client".into());
    }
    if !times_ok(&issued, want.issued_ms)
        || !times_ok(&expires, want.expires_ms)
        || revoked.is_some()
    {
        return Some("auth_sessions times".into());
    }
    let consumed: Option<String> = c
        .query_row(
            "SELECT consumed_at FROM auth_pairing_links WHERE id = ?1",
            [link_id],
            |r| r.get(0),
        )
        .ok()?;
    if consumed.is_none() {
        return Some("auth_pairing_links consumed_at".into());
    }
    if let Some(sid) = replaced {
        let revoked: Option<String> = c
            .query_row(
                "SELECT revoked_at FROM auth_sessions WHERE session_id = ?1",
                [sid],
                |r| r.get(0),
            )
            .ok()?;
        if revoked.is_none() {
            return Some("replaced session not revoked".into());
        }
    }
    None
}

impl RouteHandler for BrowserSession {
    fn method_path(&self) -> (Method, &'static str) {
        (Method::POST, "/api/auth/browser-session")
    }
    fn wants_body(&self) -> bool {
        true
    }
    fn dry_run(&self) -> bool {
        true
    }
    fn compare(&self) -> Compare {
        Compare {
            ignore: &[],
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
            const ROUTE: &str = "POST /api/auth/browser-session";
            // `AuthBrowserSessionRequest`; anything else is Effect's 400.
            let Some(credential) = http_seam::json_body(req)
                .as_ref()
                .and_then(|b| trimmed_non_empty(b.as_object()?.get("credential")?))
            else {
                return declined(ROUTE, "body");
            };
            let Some(previous) = self.0.browser_cookie(&req.headers) else {
                return declined(ROUTE, "cookie");
            };
            let Some(ua) = user_agent(&req.headers) else {
                return declined(ROUTE, "user_agent");
            };
            let ask = Ask {
                credential,
                requested: None,
                proof: None,
                replace: previous,
                client: client_metadata(ua, client_ip(req), Presented::default()),
                browser: true,
            };
            run(&self.0, &self.1, req, ask, ROUTE).await
        }
        .boxed()
    }
}

impl RouteHandler for Token {
    fn method_path(&self) -> (Method, &'static str) {
        (Method::POST, "/oauth/token")
    }
    fn wants_body(&self) -> bool {
        true
    }
    fn dry_run(&self) -> bool {
        true
    }
    fn compare(&self) -> Compare {
        Compare {
            ignore: &["$.access_token", "$.expires_in"],
            times: &[],
            headers: Compare::AUTH_HEADERS,
        }
    }

    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        async move {
            const ROUTE: &str = "POST /oauth/token";
            let Some(form) = http_seam::form_body(req) else {
                return declined(ROUTE, "body");
            };
            // `AuthTokenExchangeRequest`: `Some(None)` absent, `None` a value the schema rejects.
            let field = |k: &str, decode: fn(&Value) -> Option<String>| match form.get(k) {
                None => Some(None),
                Some(v) => decode(v).map(Some),
            };
            let literal = |k: &str, want: &str| form.get(k).and_then(Value::as_str) == Some(want);
            let device = |v: &Value| {
                let s = v.as_str()?;
                ["desktop", "mobile", "tablet", "bot", "unknown"]
                    .contains(&s)
                    .then(|| s.to_owned())
            };
            let (
                Some(Some(credential)),
                Some(scope),
                Some(label),
                Some(device_type),
                Some(os),
                true,
                true,
                true,
            ) = (
                field("subject_token", trimmed_non_empty),
                field("scope", trimmed_non_empty),
                field("client_label", trimmed_non_empty),
                field("client_device_type", device),
                field("client_os", trimmed_non_empty),
                literal(
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                literal(
                    "subject_token_type",
                    "urn:t3:params:oauth:token-type:machine-bootstrap",
                ),
                literal("requested_token_type", ACCESS_TOKEN_TYPE),
            )
            else {
                return declined(ROUTE, "body");
            };
            let Some(proof) = http_auth::proof_header(&req.headers) else {
                return declined(ROUTE, "dpop_header");
            };
            let Some(ua) = user_agent(&req.headers) else {
                return declined(ROUTE, "user_agent");
            };
            // Before the DPoP check and the no-store headers.
            let requested = match scope.as_deref().map(requested_scopes) {
                Some(None) => return Some(http_errors::invalid_request("invalid_scope")),
                r => r.flatten(),
            };
            // `args.headers.dpop ? verify : undefined`; a failure skips the no-store headers.
            let proof = match proof.filter(|p| !p.is_empty()) {
                None => None,
                Some(p) => {
                    let ctx = req.extensions.get::<DpopCtx>();
                    let Some(url) = ctx.and_then(|c| c.url.clone()) else {
                        return declined(ROUTE, "dpop_url");
                    };
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
                    match dpop::verify(Some(&p), "POST", &url, now, None, None) {
                        Verdict::Ok(proof) => Some(proof),
                        Verdict::Fail(why) => {
                            return Some(dpop_challenge(http_errors::auth_invalid(
                                "invalid_credential",
                                Some(why),
                            )));
                        }
                        Verdict::Decline => return declined(ROUTE, "dpop_proof"),
                    }
                }
            };
            let presented = Presented {
                label,
                device_type,
                os,
            };
            let ask = Ask {
                credential,
                requested,
                proof,
                replace: None,
                client: client_metadata(ua, client_ip(req), presented),
                browser: false,
            };
            run(&self.0, &self.1, req, ask, ROUTE).await
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{
            dpop::tests::Client as Key,
            token::tests::{mint, payload},
        },
        handlers::auth_access::tests::LINKS_DDL,
        http_auth::tests::{COOKIE, Env, KEY, env},
        http_seam::RequestBody,
    };
    use axum::http::Request;

    const URL: &str = "http://127.0.0.1:3789/oauth/token";
    const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/141.0 Safari/537.36";
    const FUTURE: &str = "2099-01-01T00:00:00.000Z";

    fn home() -> Env {
        let e = env();
        db(&e).execute_batch(LINKS_DDL).unwrap();
        e
    }

    fn db(e: &Env) -> Connection {
        Connection::open(e.0.path().join("db.sqlite")).unwrap()
    }

    fn link(
        e: &Env,
        cred: &str,
        scopes: &str,
        label: Option<&str>,
        jkt: Option<&str>,
        expires: &str,
    ) {
        db(e).execute(
            "INSERT INTO auth_pairing_links (id, credential, method, scopes, subject, label, created_at, expires_at, proof_key_thumbprint)
             VALUES ('id-' || ?1, ?1, 'one-time-token', ?2, 'one-time-token', ?3, '2026-01-01T00:00:00.000Z', ?4, ?5)",
            rusqlite::params![cred, scopes, label, expires, jkt],
        )
        .unwrap();
    }

    fn consumed(e: &Env, cred: &str) -> bool {
        db(e)
            .query_row(
                "SELECT consumed_at IS NOT NULL FROM auth_pairing_links WHERE credential = ?1",
                [cred],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn sessions(e: &Env) -> i64 {
        db(e)
            .query_row("SELECT count(*) FROM auth_sessions", [], |r| r.get(0))
            .unwrap()
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

    fn request(path: &str, h: &[(&str, &str)], body: &str, serve: bool) -> Parts {
        let mut b =
            Request::post(format!("http://127.0.0.1:3789{path}")).header("host", "127.0.0.1:3789");
        for (k, v) in h {
            b = b.header(*k, *v);
        }
        let mut p = b.body(()).unwrap().into_parts().0;
        p.extensions
            .insert(RequestBody(Bytes::from(body.to_owned())));
        p.extensions
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 5], 4242))));
        p.extensions.insert(DpopCtx {
            url: Some(URL.into()),
            serve,
            ..DpopCtx::default()
        });
        p
    }

    async fn browser(
        e: &Env,
        h: &[(&str, &str)],
        body: &str,
        serve: bool,
    ) -> Option<Response<Bytes>> {
        let mut h = h.to_vec();
        h.push(("content-type", "application/json"));
        let p = request("/api/auth/browser-session", &h, body, serve);
        BrowserSession(e.1.clone(), access(&e.0))
            .handle(&p, &HandlerCtx::default())
            .await
    }

    /// The bypass check over the env's secrets dir, with an empty socket registry.
    fn access(dir: &tempfile::TempDir) -> Arc<AuthAccess> {
        let files = Arc::new(AuthFiles::new(
            dir.path().join("key.bin"),
            dir.path().join("db.sqlite"),
        ));
        Arc::new(AuthAccess::new(files, Arc::default(), false))
    }

    fn form(cred: &str, extra: &[(&str, &str)]) -> String {
        let mut f = url::form_urlencoded::Serializer::new(String::new());
        f.append_pair(
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        )
        .append_pair("subject_token", cred)
        .append_pair(
            "subject_token_type",
            "urn:t3:params:oauth:token-type:machine-bootstrap",
        )
        .append_pair("requested_token_type", ACCESS_TOKEN_TYPE);
        f.extend_pairs(extra.iter().copied());
        f.finish()
    }

    async fn token(
        e: &Env,
        proof: Option<&str>,
        body: &str,
        serve: bool,
    ) -> Option<Response<Bytes>> {
        let mut h = vec![
            ("content-type", "application/x-www-form-urlencoded"),
            ("user-agent", "curl/8.7.1"),
        ];
        if let Some(p) = proof {
            h.push(("dpop", p));
        }
        let p = request("/oauth/token", &h, body, serve);
        Token(e.1.clone(), access(&e.0))
            .handle(&p, &HandlerCtx::default())
            .await
    }

    /// An `/oauth/token` proof (no `ath`) for `htu`, issued now.
    fn proof(k: &Key, htu: &str, jti: &str) -> String {
        let iat = now_ms().unwrap() / 1000;
        k.proof_with(
            "ES256",
            &format!(r#"{{"htm":"POST","htu":"{htu}","jti":"{jti}","iat":{iat}}}"#),
        )
    }

    fn text(r: &Response<Bytes>) -> String {
        String::from_utf8(r.body().to_vec()).unwrap()
    }

    fn header<'a>(r: &'a Response<Bytes>, k: &str) -> Option<&'a str> {
        r.headers().get(k).map(|v| v.to_str().unwrap())
    }

    /// The claims JSON of a token Rust issued, checked against the key.
    fn claims(t: &str) -> String {
        String::from_utf8(token::signed_json(t, &KEY).unwrap()).unwrap()
    }

    #[test]
    fn scope_parsing_matches_parse_oauth_scope_and_grant_filter() {
        let s = |v: &str| requested_scopes(v);
        assert_eq!(
            s("orchestration:read access:read orchestration:read"),
            Some(vec!["orchestration:read".into(), "access:read".into()])
        );
        // Unknown but well-formed tokens are dropped; review:write is not grantable.
        assert_eq!(
            s("x:y orchestration:read review:write"),
            Some(vec!["orchestration:read".into()])
        );
        for bad in ["", "a  b", " a", "a\"b", "a\\b", "x:y", "review:write", "é"] {
            assert_eq!(s(bad), None, "{bad:?}");
        }
        let t = |v: &str| trimmed_non_empty(&Value::from(v));
        assert_eq!(t("\u{feff}\u{a0} x \u{2028}").as_deref(), Some("x"));
        assert_eq!(t("\u{85}x").as_deref(), Some("\u{85}x"));
        assert_eq!(t(" \u{3000}"), None);
    }

    #[test]
    fn client_metadata_matches_derive_auth_client_metadata() {
        let m = |ua: &str| client_metadata(Some(ua.into()), None, Presented::default());
        let c = m(UA);
        assert_eq!(
            (
                c.device_type.as_str(),
                c.os.as_deref(),
                c.browser.as_deref()
            ),
            ("desktop", Some("macOS"), Some("Chrome"))
        );
        let c = m("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Version/17.0 Mobile Safari/604.1");
        assert_eq!(
            (
                c.device_type.as_str(),
                c.os.as_deref(),
                c.browser.as_deref()
            ),
            ("mobile", Some("iOS"), Some("Safari"))
        );
        let c = m("curl/8.7.1");
        assert_eq!(
            (c.device_type.as_str(), c.os, c.browser),
            ("bot", None, None)
        );
        let c = m("Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/130.0");
        assert_eq!(
            (c.os.as_deref(), c.browser.as_deref()),
            (Some("Linux"), Some("Firefox"))
        );
        assert_eq!(
            client_metadata(None, None, Presented::default()).device_type,
            "unknown"
        );
        let p = Presented {
            label: Some("L".into()),
            device_type: Some("tablet".into()),
            os: Some("Plan9".into()),
        };
        let c = client_metadata(Some("curl/8".into()), Some("10.0.0.5".into()), p);
        assert_eq!(
            c,
            Client {
                label: Some("L".into()),
                ip: Some("10.0.0.5".into()),
                user_agent: Some("curl/8".into()),
                device_type: "tablet".into(),
                os: Some("Plan9".into()),
                browser: None,
            }
        );
        let u = uuid_v4().unwrap();
        assert!(
            u.len() == 36 && &u[14..15] == "4" && "89ab".contains(&u[19..20]),
            "{u}"
        );
    }

    #[tokio::test]
    async fn browser_session_consumes_issues_and_replaces_the_cookie_session() {
        let e = home();
        link(
            &e,
            "CRED1",
            r#"["orchestration:read","filesystem:read","access:read"]"#,
            Some("Lab"),
            None,
            FUTURE,
        );
        let old = format!("{COOKIE}={}", mint(&payload(), &KEY));
        let before = now_ms().unwrap();
        let r = browser(
            &e,
            &[("cookie", &old), ("user-agent", UA)],
            r#"{"credential":"  CRED1 ","x":1}"#,
            true,
        )
        .await
        .unwrap();
        assert_eq!(r.status(), 200);
        let body = text(&r);
        let exp = body
            .split(r#""expiresAt":""#)
            .nth(1)
            .unwrap()
            .trim_end_matches("\"}");
        let exp_ms = http_seam::parse_iso(exp).unwrap();
        assert!(exp_ms - SESSION_TTL_MS >= before && exp_ms - SESSION_TTL_MS <= now_ms().unwrap());
        assert_eq!(
            body,
            format!(
                r#"{{"authenticated":true,"scopes":["orchestration:read","access:read"],"permissions":["orchestration:read","filesystem:read","access:read"],"sessionMethod":"browser-session-cookie","expiresAt":"{exp}"}}"#
            )
        );
        assert_eq!(
            (header(&r, "cache-control"), header(&r, "pragma")),
            (Some("no-store"), Some("no-cache"))
        );
        let cookie = header(&r, "set-cookie").unwrap();
        let t = cookie
            .strip_prefix(&format!("{COOKIE}="))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert_eq!(
            cookie,
            cookies::session_cookie(COOKIE, t, exp_ms).to_str().unwrap()
        );
        let sid = token::verify(t, &KEY).unwrap().sid;
        assert_eq!(
            claims(t),
            format!(
                r#"{{"v":1,"kind":"session","sid":"{sid}","sub":"one-time-token","scopes":["orchestration:read","filesystem:read","access:read"],"method":"browser-session-cookie","iat":{},"exp":{exp_ms}}}"#,
                exp_ms - SESSION_TTL_MS
            )
        );
        // One transaction: link consumed, the old cookie session revoked at issue time, the new row.
        assert!(consumed(&e, "CRED1"));
        let c = db(&e);
        let (revoked, consumed_at): (String, String) = c
            .query_row(
                "SELECT s.revoked_at, l.consumed_at FROM auth_sessions s, auth_pairing_links l WHERE s.session_id = ?1",
                [&payload().sid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(revoked, consumed_at);
        let row: Vec<Option<String>> = c
            .query_row(
                "SELECT subject, scopes, method, client_label, client_ip_address, client_user_agent, client_device_type,
                        client_os, client_browser, issued_at, expires_at, revoked_at FROM auth_sessions WHERE session_id = ?1",
                [&sid],
                |r| (0..12).map(|i| r.get(i)).collect(),
            )
            .unwrap();
        let s = |v: &str| Some(v.to_owned());
        assert_eq!(
            row,
            vec![
                s("one-time-token"),
                s(r#"["orchestration:read","filesystem:read","access:read"]"#),
                s("browser-session-cookie"),
                s("Lab"),
                s("10.0.0.5"),
                s(UA),
                s("desktop"),
                s("macOS"),
                s("Chrome"),
                s(&iso_millis(exp_ms - SESSION_TTL_MS)),
                s(exp),
                None,
            ]
        );
        // Used once.
        let again = browser(&e, &[], r#"{"credential":"CRED1"}"#, true)
            .await
            .unwrap();
        assert_eq!(
            (again.status().as_u16(), header(&again, "cache-control")),
            (401, None)
        );
        assert!(text(&again).starts_with(r#"{"_tag":"MachineAuthInvalidError","code":"auth_invalid","reason":"invalid_credential","traceId":""#));
    }

    #[tokio::test]
    async fn browser_session_keeps_sessions_it_must_not_replace() {
        let e = home();
        link(&e, "A", r#"["orchestration:read"]"#, None, None, FUTURE);
        link(&e, "B", r#"["orchestration:read"]"#, None, None, FUTURE);
        // A Bearer credential is not a browser cookie; a forged cookie verifies as nothing.
        let bearer = format!("Bearer {}", mint(&payload(), &KEY));
        let forged = format!("{COOKIE}={}", mint(&payload(), &[1; 32]));
        assert_eq!(
            browser(
                &e,
                &[("authorization", &bearer)],
                r#"{"credential":"A"}"#,
                true
            )
            .await
            .unwrap()
            .status(),
            200
        );
        assert_eq!(
            browser(&e, &[("cookie", &forged)], r#"{"credential":"B"}"#, true)
                .await
                .unwrap()
                .status(),
            200
        );
        let revoked: i64 = db(&e)
            .query_row(
                "SELECT count(*) FROM auth_sessions WHERE revoked_at IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(revoked, 0);
    }

    #[tokio::test]
    async fn token_issues_bearer_and_dpop_sessions() {
        let e = home();
        link(
            &e,
            "BEARER",
            r#"["orchestration:read","access:read"]"#,
            None,
            None,
            FUTURE,
        );
        let body = form(
            " BEARER",
            &[
                ("scope", "access:read orchestration:read access:read"),
                ("client_label", " cli "),
                ("client_device_type", "desktop"),
                ("client_os", "Plan9"),
            ],
        );
        let r = token(&e, None, &body, true).await.unwrap();
        assert_eq!(r.status(), 200, "{}", text(&r));
        let v: Value = serde_json::from_slice(r.body()).unwrap();
        let t = v["access_token"].as_str().unwrap();
        assert!([2_591_999, 2_592_000].contains(&v["expires_in"].as_i64().unwrap()));
        assert_eq!(
            text(&r),
            format!(
                r#"{{"access_token":"{t}","issued_token_type":"{ACCESS_TOKEN_TYPE}","token_type":"Bearer","expires_in":{},"scope":"access:read orchestration:read"}}"#,
                v["expires_in"]
            )
        );
        assert_eq!(header(&r, "cache-control"), Some("no-store"));
        let row: (String, String, String, String, String) = db(&e)
            .query_row(
                "SELECT scopes, method, client_label, client_device_type, client_os FROM auth_sessions WHERE session_id = ?1",
                [token::verify(t, &KEY).unwrap().sid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            (
                r#"["access:read","orchestration:read"]"#.into(),
                "bearer-access-token".into(),
                "cli".into(),
                "desktop".into(),
                "Plan9".into()
            )
        );

        // DPoP, on a link bound to the key: 1 h, `jkt` in the claims, the marker written.
        let k = Key::new(3);
        link(
            &e,
            "BOUND",
            r#"["orchestration:read"]"#,
            Some("Phone"),
            Some(&k.thumbprint()),
            FUTURE,
        );
        let p = proof(&k, URL, "j1");
        let r = token(&e, Some(&p), &form("BOUND", &[]), true)
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "{}", text(&r));
        let v: Value = serde_json::from_slice(r.body()).unwrap();
        assert_eq!(
            (v["token_type"].as_str(), v["scope"].as_str()),
            (Some("DPoP"), Some("orchestration:read"))
        );
        assert!([3599, 3600].contains(&v["expires_in"].as_i64().unwrap()));
        let c = token::verify(v["access_token"].as_str().unwrap(), &KEY).unwrap();
        assert_eq!(
            (c.method.as_str(), c.jkt.as_deref(), c.exp - c.iat),
            (
                "dpop-access-token",
                Some(k.thumbprint().as_str()),
                DPOP_TTL_MS
            )
        );
        let label: String = db(&e)
            .query_row(
                "SELECT client_label FROM auth_sessions WHERE session_id = ?1",
                [&c.sid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(label, "Phone");
        assert_eq!(markers(&e), 1);
        // The same proof again: a replay, answered before the consume.
        link(&e, "NEXT", r#"["orchestration:read"]"#, None, None, FUTURE);
        let r = token(&e, Some(&p), &form("NEXT", &[]), true).await.unwrap();
        assert_eq!(
            (
                r.status().as_u16(),
                header(&r, "www-authenticate"),
                header(&r, "cache-control")
            ),
            (401, Some("DPoP"), None)
        );
        assert!(text(&r).contains(r#""dpopFailureReason":"replay""#));
        assert!(!consumed(&e, "NEXT"));
    }

    #[tokio::test]
    async fn token_errors_are_nodes_and_never_consume_wrongly() {
        let e = home();
        let k = Key::new(4);
        link(
            &e,
            "NARROW",
            r#"["orchestration:read"]"#,
            None,
            None,
            FUTURE,
        );
        link(
            &e,
            "BOUND",
            r#"["orchestration:read"]"#,
            None,
            Some(&k.thumbprint()),
            FUTURE,
        );
        link(
            &e,
            "OLD",
            r#"["orchestration:read"]"#,
            None,
            None,
            "2020-01-01T00:00:00.000Z",
        );
        let ask = |p: Option<String>, b: String| {
            let e = &e;
            async move {
                let r = token(e, p.as_deref(), &b, true).await.unwrap();
                let t = text(&r);
                (
                    r.status().as_u16(),
                    t.split(r#","traceId""#).next().unwrap().to_owned(),
                    header(&r, "cache-control").is_some(),
                    header(&r, "www-authenticate").is_some(),
                )
            }
        };
        let inv = |reason: &str| {
            format!(
                r#"{{"_tag":"MachineRequestInvalidError","code":"invalid_request","reason":"{reason}""#
            )
        };
        let auth = r#"{"_tag":"MachineAuthInvalidError","code":"auth_invalid","reason":"invalid_credential""#.to_owned();
        // invalid_scope comes before everything, without no-store.
        assert_eq!(
            ask(None, form("NARROW", &[("scope", "a  b")])).await,
            (400, inv("invalid_scope"), false, false)
        );
        assert_eq!(
            ask(None, form("NARROW", &[("scope", "x:y")])).await,
            (400, inv("invalid_scope"), false, false)
        );
        // No requested scope on the link: the WHERE keeps it unconsumed.
        assert_eq!(
            ask(None, form("NARROW", &[("scope", "access:read")])).await,
            (400, inv("scope_not_granted"), true, false)
        );
        assert!(!consumed(&e, "NARROW"));
        // A bound link needs its key's proof.
        assert_eq!(
            ask(None, form("BOUND", &[])).await,
            (401, auth.clone(), true, false)
        );
        assert_eq!(
            ask(Some(proof(&Key::new(9), URL, "other")), form("BOUND", &[])).await,
            (401, auth.clone(), true, false)
        );
        // A proof Node rejects: its reason, the DPoP challenge, no no-store, no marker, no consume.
        let wrong = proof(&k, "http://127.0.0.1:1/oauth/token", "w");
        assert_eq!(
            ask(Some(wrong), form("BOUND", &[])).await,
            (
                401,
                format!(r#"{auth},"dpopFailureReason":"request_mismatch""#),
                false,
                true
            )
        );
        assert!(!consumed(&e, "BOUND"));
        // Expired.
        assert_eq!(
            ask(None, form("OLD", &[])).await,
            (401, auth.clone(), true, false)
        );
        assert_eq!(
            markers(&e),
            1,
            "only the proof from the other key reached the marker"
        );
        assert_eq!(sessions(&e), 1, "only env()'s row");
    }

    #[tokio::test]
    async fn declines_before_any_write() {
        let e = home();
        link(&e, "LIVE", r#"["orchestration:read"]"#, None, None, FUTURE);
        db(&e)
            .execute("INSERT INTO auth_pairing_links (id, credential, method, scopes, subject, created_at, expires_at) VALUES ('d', 'DESK', 'desktop-bootstrap', '[]', 'desktop-bootstrap', 'x', ?1)", [FUTURE])
            .unwrap();
        let k = Key::new(5);
        // Not a pairing link (dev token, desktop seed): Node checks the proof and writes its marker.
        assert!(
            token(&e, Some(&proof(&k, URL, "u")), &form("UNKNOWN", &[]), true)
                .await
                .is_none()
        );
        assert!(token(&e, None, &form("DESK", &[]), true).await.is_none());
        assert!(
            browser(&e, &[], r#"{"credential":"UNKNOWN"}"#, true)
                .await
                .is_none()
        );
        // Bodies Effect rejects.
        for b in [
            r#"{}"#,
            r#"{"credential":null}"#,
            r#"{"credential":"  "}"#,
            r#"["LIVE"]"#,
            "nope",
        ] {
            assert!(browser(&e, &[], b, true).await.is_none(), "{b}");
        }
        for b in [
            form("LIVE", &[("scope", " ")]),
            form("LIVE", &[("client_device_type", "watch")]),
            form("LIVE", &[("subject_token", "LIVE")]),
            "grant_type=password&subject_token=LIVE".into(),
        ] {
            assert!(token(&e, None, &b, true).await.is_none(), "{b}");
        }
        // A proof Rust cannot judge.
        assert!(
            token(
                &e,
                Some(&k.proof_with("ES384", "{}")),
                &form("LIVE", &[]),
                true
            )
            .await
            .is_none()
        );
        assert!(!consumed(&e, "LIVE"));
        assert_eq!((markers(&e), sessions(&e)), (0, 1));
    }

    #[tokio::test]
    async fn serve_declines_before_any_write_while_nodes_stream_may_serve() {
        let e = home();
        link(&e, "LIVE", r#"["orchestration:read"]"#, None, None, FUTURE);
        let k = Key::new(7);
        // A cloud link: relay sockets reach Node directly and watch Node's own stream.
        std::fs::write(e.0.path().join("cloud-relay-url.bin"), b"wss://relay").unwrap();
        assert!(
            browser(&e, &[], r#"{"credential":"LIVE"}"#, true)
                .await
                .is_none()
        );
        assert!(
            token(&e, Some(&proof(&k, URL, "b")), &form("LIVE", &[]), true)
                .await
                .is_none()
        );
        assert!(!consumed(&e, "LIVE"));
        assert_eq!((markers(&e), sessions(&e)), (0, 1));
        // Shadow writes nothing anyway, so it still dry-runs.
        assert_eq!(
            browser(&e, &[], r#"{"credential":"LIVE"}"#, false)
                .await
                .unwrap()
                .status(),
            200
        );
        // Gone: Rust serves again.
        std::fs::remove_file(e.0.path().join("cloud-relay-url.bin")).unwrap();
        assert_eq!(
            browser(&e, &[], r#"{"credential":"LIVE"}"#, true)
                .await
                .unwrap()
                .status(),
            200
        );
        assert!(consumed(&e, "LIVE"));
    }

    #[tokio::test]
    async fn an_empty_scope_link_is_nodes_answer_per_route() {
        let e = home();
        link(&e, "EMPTY1", "[]", None, None, FUTURE);
        link(&e, "EMPTY2", "[]", None, None, FUTURE);
        // `createBrowserSession` issues a session with no scopes.
        let predicted = browser(&e, &[], r#"{"credential":"EMPTY1"}"#, false)
            .await
            .unwrap();
        let r = browser(&e, &[], r#"{"credential":"EMPTY1"}"#, true)
            .await
            .unwrap();
        assert_eq!(
            (predicted.status(), r.status()),
            (StatusCode::OK, StatusCode::OK)
        );
        assert!(text(&r).starts_with(r#"{"authenticated":true,"scopes":[],"permissions":[],"#));
        assert!(consumed(&e, "EMPTY1"));
        // The token exchange consumes, then answers scope_not_granted (as Node's separate steps do).
        let r = token(&e, None, &form("EMPTY2", &[]), true).await.unwrap();
        assert_eq!(r.status(), 400);
        assert!(text(&r).contains(r#""reason":"scope_not_granted""#));
        assert!(consumed(&e, "EMPTY2"));
    }

    #[tokio::test]
    async fn shadow_predicts_without_writing_and_checks_nodes_write() {
        let e = home();
        link(
            &e,
            "CRED",
            r#"["orchestration:read","access:read"]"#,
            None,
            None,
            FUTURE,
        );
        let old = format!("{COOKIE}={}", mint(&payload(), &KEY));
        let h = [("cookie", old.as_str()), ("user-agent", UA)];
        let body = r#"{"credential":"CRED"}"#;
        let predicted = browser(&e, &h, body, false).await.unwrap();
        assert_eq!(predicted.status(), 200);
        assert!(!consumed(&e, "CRED"));
        assert_eq!(sessions(&e), 1);
        let DryRun(check) = predicted.extensions().get::<DryRun>().cloned().unwrap();
        // Node's real write, played here by serve.
        let node = browser(&e, &h, body, true).await.unwrap();
        assert_eq!(
            http_seam::diff(
                &BrowserSession(e.1.clone(), access(&e.0)).compare(),
                node.status(),
                node.headers(),
                node.body(),
                &predicted
            ),
            None
        );
        assert_eq!(check(node.headers(), node.body()), None);
        // Node storing something else is a mismatch.
        db(&e).execute("UPDATE auth_sessions SET client_device_type = 'bot' WHERE revoked_at IS NULL AND subject = 'one-time-token'", []).unwrap();
        assert_eq!(
            check(node.headers(), node.body()).as_deref(),
            Some("auth_sessions client")
        );

        // Token: a predicted failure has nothing to check; a DPoP success is predicted from the proof too.
        let k = Key::new(6);
        link(
            &e,
            "DP",
            r#"["orchestration:read"]"#,
            None,
            Some(&k.thumbprint()),
            FUTURE,
        );
        let p = proof(&k, URL, "s1");
        let predicted = token(&e, Some(&p), &form("DP", &[]), false).await.unwrap();
        assert_eq!(markers(&e), 0, "shadow never writes a marker");
        let DryRun(check) = predicted.extensions().get::<DryRun>().cloned().unwrap();
        let node = token(&e, Some(&p), &form("DP", &[]), true).await.unwrap();
        assert_eq!(
            http_seam::diff(
                &Token(e.1.clone(), access(&e.0)).compare(),
                node.status(),
                node.headers(),
                node.body(),
                &predicted
            ),
            None
        );
        assert_eq!(check(node.headers(), node.body()), None);
        let failed = token(&e, None, &form("DP", &[]), false).await.unwrap();
        assert_eq!(failed.status(), 401);
        assert!(failed.extensions().get::<DryRun>().is_none());
    }
}
