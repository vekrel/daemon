//! `subscribeAuthAccess` (`ws.ts` `loadAuthAccessSnapshot` and `toAuthAccessStreamEvent`): the
//! snapshot from SQL plus the socket registry for `connected`, then events found by re-reading
//! both lists whenever `PRAGMA data_version` (any other connection's commit: Node, the CLI, Rust's
//! writers) or the registry changes, diffed by id.
//!
//! `connected` comes from the registry, which only sees sockets that pass through Rust. When
//! sockets may reach Node another way (Tailscale Serve, a cloud link) or a socket's session is
//! unknown to Rust, the stream is declined to Node.
use super::{HandlerCtx, auth_session::LEGACY_SCOPES};
use crate::{
    auth::{registry::Registry, shadow::AuthFiles},
    config::Mode,
    http_seam::parse_iso,
    machine::normalize,
    rpc_seam::{Chunks, HANDOFF, StreamHandler},
};
use futures_util::{FutureExt, future::BoxFuture};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Map, Value, json};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// `AuthMachineScope` (contracts `auth.ts`): rows with any other scope fail Node's decode.
pub(crate) const SCOPES: [&str; 17] = [
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
    "review:write",
    "source-control:write",
    "access:read",
    "access:write",
    "relay:read",
    "relay:write",
];

pub struct AuthAccess {
    inputs: Arc<Inputs>,
    poll: Duration,
}

/// What a stream reads: the DB, the registry, and what says whether the registry sees everything.
struct Inputs {
    files: Arc<AuthFiles>,
    registry: Arc<Registry>,
    /// The engine runs Tailscale Serve, which proxies to Node's own port.
    tailscale: bool,
}

impl AuthAccess {
    pub fn new(files: Arc<AuthFiles>, registry: Arc<Registry>, tailscale: bool) -> Self {
        let inputs = Arc::new(Inputs {
            files,
            registry,
            tailscale,
        });
        AuthAccess {
            inputs,
            poll: Duration::from_millis(250),
        }
    }
}

impl AuthAccess {
    /// Why Node's own `subscribeAuthAccess` may be serving some client (`auth::bypass::active`):
    /// then only Node's writes reach that stream, so Rust's auth writes must decline.
    pub fn bypass(&self) -> Option<&'static str> {
        self.inputs.bypass()
    }

    pub(crate) fn registry(&self) -> &Arc<Registry> {
        &self.inputs.registry
    }
}

impl Inputs {
    /// Why some socket may be invisible to the registry, if one may be. Checked at subscribe and
    /// on every wake of a live stream (which then hands the request to Node).
    fn bypass(&self) -> Option<&'static str> {
        crate::auth::bypass::active(&self.files, &self.registry, self.tailscale)
    }
}

/// Whether the engine config turns on Tailscale Serve (`--tailscale-serve` or
/// `VEKREL_TAILSCALE_SERVE`); any spelling counts, even `false`, to stay on the safe side.
pub fn tailscale_serve(args: &[String], env: impl Fn(&str) -> Option<String>) -> bool {
    args.iter().any(|a| a.starts_with("--tailscale-serve"))
        || env("VEKREL_TAILSCALE_SERVE").is_some_and(|v| !v.trim().is_empty())
}

impl StreamHandler for AuthAccess {
    fn tag(&self) -> &'static str {
        "subscribeAuthAccess"
    }
    fn default_mode(&self) -> Mode {
        Mode::Shadow
    }
    fn required_scope(&self) -> &'static str {
        "access:read"
    }
    fn open<'a>(&'a self, payload: Value, ctx: &'a HandlerCtx) -> BoxFuture<'a, Option<Chunks>> {
        async move {
            // `Schema.Struct({})`: anything but an object is Node's decode error.
            let current = ctx.session.as_ref()?.sid.clone();
            if !payload.is_object() {
                return None;
            }
            let inputs = &self.inputs;
            if let Some(why) = inputs.bypass() {
                tracing::info!(why, "subscribeAuthAccess declined");
                return None;
            }
            let mut watch = inputs.registry.subscribe();
            watch.mark_unchanged();
            let (db, reg, cur) = (
                inputs.files.db_path().to_owned(),
                inputs.registry.clone(),
                current.clone(),
            );
            let first = tokio::task::spawn_blocking(move || {
                let c = open_db(&db)?;
                let dv = data_version(&c)?;
                let lists = read(&c, &reg.connected_ids(), &cur, now_ms())?;
                Ok::<_, String>((c, dv, lists))
            })
            .await
            .ok()?;
            let (conn, dv, lists) = match first {
                Ok(f) => f,
                Err(e) => {
                    tracing::info!(error = e, "subscribeAuthAccess declined: snapshot read");
                    return None;
                }
            };
            let snapshot = snapshot(&lists);
            let st = Live {
                conn: Some(conn),
                dv,
                prev: lists,
                revision: 1,
                watch,
                current,
                inputs: inputs.clone(),
                poll: self.poll,
                pending: false,
            };
            let first = futures_util::stream::once(async move { Ok(vec![snapshot]) });
            let live = futures_util::stream::unfold(st, |mut st| async move {
                let events = st.next().await?;
                Some((events, st))
            });
            Some(Box::pin(futures_util::StreamExt::chain(first, live)) as Chunks)
        }
        .boxed()
    }
}

/// The stream after the snapshot.
struct Live {
    /// Moved into `spawn_blocking` for each read.
    conn: Option<Connection>,
    dv: i64,
    prev: Lists,
    revision: u64,
    watch: tokio::sync::watch::Receiver<()>,
    current: String,
    inputs: Arc<Inputs>,
    poll: Duration,
    /// A socket change whose re-read failed: re-read on the next poll even if `data_version`
    /// has not moved.
    pending: bool,
}

/// What one wake found.
enum Wake {
    Same,
    Lists(i64, Lists),
    /// A socket may now bypass the registry: hand the request to Node.
    Bypass(&'static str),
}

impl Live {
    /// The next batch of events (one Chunk); `Some(Err)` ends the stream, an empty `Ok` hands it
    /// to Node. Polled only after the client acked the previous Chunk, so a handoff never leaves
    /// a Rust Chunk unacked.
    async fn next(&mut self) -> Option<Result<Vec<Value>, Value>> {
        loop {
            let sockets = tokio::select! {
                _ = tokio::time::sleep(self.poll) => false,
                r = self.watch.changed() => r.is_ok(),
            };
            self.pending |= sockets;
            let (conn, inputs, cur, dv, reread) = (
                self.conn.take()?,
                self.inputs.clone(),
                self.current.clone(),
                self.dv,
                self.pending,
            );
            let r = tokio::task::spawn_blocking(move || {
                let r = (|| -> Result<Wake, String> {
                    if let Some(why) = inputs.bypass() {
                        return Ok(Wake::Bypass(why));
                    }
                    let v = data_version(&conn)?;
                    if v == dv && !reread {
                        return Ok(Wake::Same);
                    }
                    let ids = inputs.registry.connected_ids();
                    Ok(Wake::Lists(v, read(&conn, &ids, &cur, now_ms())?))
                })();
                (conn, r)
            })
            .await;
            let Ok((conn, r)) = r else {
                let e =
                    json!({"_tag": "AuthAccessStreamError", "message": "auth access read failed"});
                return Some(Err(e));
            };
            self.conn = Some(conn);
            match r {
                Ok(Wake::Same) => {}
                Ok(Wake::Bypass(why)) => {
                    tracing::info!(why, outcome = "auth_access_handoff", "subscribeAuthAccess");
                    return Some(Ok(HANDOFF));
                }
                Ok(Wake::Lists(v, next)) => {
                    (self.dv, self.pending) = (v, false);
                    let events = diff(&self.prev, &next, &mut self.revision);
                    self.prev = next;
                    if !events.is_empty() {
                        return Some(Ok(events));
                    }
                }
                // shortcut: a row Node could not decode either stalls the stream (logged, retried
                // on every poll); upgrade if that ever shows up in logs.
                Err(e) => tracing::warn!(error = e, "subscribeAuthAccess re-read failed"),
            }
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

pub(crate) fn open_db(path: &PathBuf) -> Result<Connection, String> {
    let c = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;
    c.busy_timeout(Duration::from_millis(500))
        .map_err(|e| e.to_string())?;
    Ok(c)
}

fn data_version(c: &Connection) -> Result<i64, String> {
    c.query_row("PRAGMA data_version", [], |r| r.get(0))
        .map_err(|e| e.to_string())
}

/// Both lists, in Node's order, each entry `(id, encoded value)`.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Lists {
    pub links: Vec<(String, Value)>,
    pub clients: Vec<(String, Value)>,
}

/// A `DateTimeUtcFromString` column, re-encoded; only `toISOString` text is accepted.
fn time(s: &str) -> Result<(i64, String), String> {
    let ms = parse_iso(s).ok_or("time")?;
    let iso = super::auth_session::iso_millis(ms);
    if iso != s {
        return Err("time".into());
    }
    Ok((ms, iso))
}

/// A `TrimmedNonEmptyString` as Schema encodes it: trimmed, and blank fails.
fn trimmed(s: &str) -> Result<String, String> {
    normalize(s)
        .map(str::to_owned)
        .ok_or_else(|| "blank".into())
}

/// `AuthMachineScopes` from the JSON column, then `authScopeResponse` into `obj`.
fn scopes(raw: &str, obj: &mut Map<String, Value>) -> Result<Vec<String>, String> {
    let all: Vec<String> = serde_json::from_str(raw).map_err(|_| "scopes")?;
    if !all.iter().all(|s| SCOPES.contains(&s.as_str())) {
        return Err("scopes".into());
    }
    let legacy: Vec<&String> = all
        .iter()
        .filter(|s| LEGACY_SCOPES.contains(&s.as_str()))
        .collect();
    obj.insert("scopes".into(), json!(legacy));
    obj.insert("permissions".into(), json!(all));
    Ok(all)
}

/// `MachineAuth.listPairingLinks()` and `listClientSessions(current)`, encoded like the stream
/// (contracts schema order, optional keys omitted where Node omits them).
pub(crate) fn read(
    c: &Connection,
    connected: &[String],
    current: &str,
    now: i64,
) -> Result<Lists, String> {
    let now = super::auth_session::iso_millis(now);
    let links = read_links(c, &now)?;
    let e = |e: rusqlite::Error| e.to_string();

    let mut clients = Vec::new();
    let mut q = c
        .prepare_cached(
            "SELECT session_id, subject, scopes, method, client_label, client_ip_address,
                    client_user_agent, client_device_type, client_os, client_browser,
                    issued_at, expires_at, last_connected_at
             FROM auth_sessions
             WHERE revoked_at IS NULL
               AND (expires_at > ?1 OR session_id IN (SELECT value FROM json_each(?2)))
             ORDER BY issued_at DESC, session_id DESC",
        )
        .map_err(e)?;
    let ids = serde_json::to_string(connected).map_err(|e| e.to_string())?;
    let mut rows = q.query([&now, &ids]).map_err(e)?;
    while let Some(r) = rows.next().map_err(e)? {
        let g = |i| r.get::<_, String>(i).map_err(e);
        let opt = |i| r.get::<_, Option<String>>(i).map_err(e);
        let raw_id = g(0)?;
        let sid = trimmed(&raw_id)?;
        let mut o = Map::new();
        o.insert("sessionId".into(), json!(sid));
        o.insert("subject".into(), json!(trimmed(&g(1)?)?));
        let all = scopes(&g(2)?, &mut o)?;
        let method = g(3)?;
        if !matches!(
            method.as_str(),
            "browser-session-cookie" | "bearer-access-token" | "dpop-access-token"
        ) {
            return Err("method".into());
        }
        o.insert("method".into(), json!(method));
        // `toClientMetadata`: falsy (null or empty) fields are omitted.
        let mut client = Map::new();
        for (k, i) in [("label", 4), ("ipAddress", 5), ("userAgent", 6)] {
            if let Some(v) = opt(i)?.filter(|v| !v.is_empty()) {
                client.insert(k.into(), json!(trimmed(&v)?));
            }
        }
        let device = g(7)?;
        if !matches!(
            device.as_str(),
            "desktop" | "mobile" | "tablet" | "bot" | "unknown"
        ) {
            return Err("deviceType".into());
        }
        client.insert("deviceType".into(), json!(device));
        for (k, i) in [("os", 8), ("browser", 9)] {
            if let Some(v) = opt(i)?.filter(|v| !v.is_empty()) {
                client.insert(k.into(), json!(trimmed(&v)?));
            }
        }
        o.insert("client".into(), Value::Object(client));
        let (issued, i_iso) = time(&g(10)?)?;
        o.insert("issuedAt".into(), json!(i_iso));
        o.insert("expiresAt".into(), json!(time(&g(11)?)?.1));
        let last = opt(12)?.map(|t| time(&t).map(|t| t.1)).transpose()?;
        o.insert("lastConnectedAt".into(), json!(last));
        // Node's map is keyed by the id as authenticated (the raw row id).
        let is_connected = connected.contains(&raw_id);
        o.insert("connected".into(), json!(is_connected));
        o.insert("current".into(), json!(sid == current));
        let manage = all.iter().any(|s| s == "access:write");
        clients.push(((manage, is_connected, issued), sid, Value::Object(o)));
    }
    // `bySessionPriority`: access:write holders, then connected, then issuedAt descending.
    clients.sort_by(|a, b| {
        let ((ma, ca, ia), (mb, cb, ib)) = (a.0, b.0);
        mb.cmp(&ma).then(cb.cmp(&ca)).then(ib.cmp(&ia))
    });
    Ok(Lists {
        links,
        clients: clients.into_iter().map(|c| (c.1, c.2)).collect(),
    })
}

/// `MachineAuth.listPairingLinks()` at `now` (ISO text), encoded in contracts schema order.
pub(crate) fn read_links(c: &Connection, now: &str) -> Result<Vec<(String, Value)>, String> {
    let e = |e: rusqlite::Error| e.to_string();
    let mut links = Vec::new();

    let mut q = c
        .prepare_cached(
            "SELECT id, credential, method, scopes, subject, label, created_at, expires_at
             FROM auth_pairing_links
             WHERE revoked_at IS NULL AND consumed_at IS NULL AND expires_at > ?1
             ORDER BY created_at DESC, id DESC",
        )
        .map_err(e)?;
    let mut rows = q.query([now]).map_err(e)?;
    while let Some(r) = rows.next().map_err(e)? {
        let g = |i| r.get::<_, String>(i).map_err(e);
        let _credential = g(1)?;
        if !matches!(g(2)?.as_str(), "desktop-bootstrap" | "one-time-token") {
            return Err("method".into());
        }
        let subject = g(4)?;
        // `INTERNAL_ADMINISTRATIVE_BOOTSTRAP_SUBJECT` (compared before encoding).
        if subject == "administrative-bootstrap" {
            continue;
        }
        let id = trimmed(&g(0)?)?;
        let mut o = Map::new();
        o.insert("id".into(), json!(id));
        scopes(&g(3)?, &mut o)?;
        o.insert("subject".into(), json!(trimmed(&subject)?));
        let label: Option<String> = r.get(5).map_err(e)?;
        if let Some(l) = label.filter(|l| !l.is_empty()) {
            o.insert("label".into(), json!(trimmed(&l)?));
        }
        let (created, c_iso) = time(&g(6)?)?;
        o.insert("createdAt".into(), json!(c_iso));
        o.insert("expiresAt".into(), json!(time(&g(7)?)?.1));
        links.push((created, id, Value::Object(o)));
    }
    // `toSorted` by createdAt descending (stable over the SQL order).
    links.sort_by_key(|l| std::cmp::Reverse(l.0));
    Ok(links.into_iter().map(|l| (l.1, l.2)).collect())
}

/// The stream's first item.
fn snapshot(l: &Lists) -> Value {
    json!({
        "version": 1,
        "revision": 1,
        "type": "snapshot",
        "payload": {
            "pairingLinks": l.links.iter().map(|l| &l.1).collect::<Vec<_>>(),
            "clientSessions": l.clients.iter().map(|c| &c.1).collect::<Vec<_>>(),
        },
    })
}

/// Events taking a client from `prev` to `next`, `revision` +1 each: pairing links first (as a
/// consumed link is removed before its new session appears), removals before upserts.
pub(crate) fn diff(prev: &Lists, next: &Lists, revision: &mut u64) -> Vec<Value> {
    let mut out = Vec::new();
    let mut emit = |ty: &str, payload: Value| {
        *revision += 1;
        out.push(json!({"version": 1, "revision": *revision, "type": ty, "payload": payload}));
    };
    let gone = |a: &[(String, Value)], b: &[(String, Value)]| {
        a.iter()
            .filter(|x| !b.iter().any(|y| y.0 == x.0))
            .map(|x| x.0.clone())
            .collect::<Vec<_>>()
    };
    let changed = |a: &[(String, Value)], b: &[(String, Value)]| {
        b.iter()
            .filter(|y| !a.iter().any(|x| x == *y))
            .map(|y| y.1.clone())
            .collect::<Vec<_>>()
    };
    for id in gone(&prev.links, &next.links) {
        emit("pairingLinkRemoved", json!({"id": id}));
    }
    for v in changed(&prev.links, &next.links) {
        emit("pairingLinkUpserted", v);
    }
    for id in gone(&prev.clients, &next.clients) {
        emit("clientRemoved", json!({"sessionId": id}));
    }
    for v in changed(&prev.clients, &next.clients) {
        emit("clientUpserted", v);
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const LINKS_DDL: &str = "
        CREATE TABLE auth_pairing_links (
          id TEXT PRIMARY KEY, credential TEXT NOT NULL UNIQUE, method TEXT NOT NULL,
          scopes TEXT NOT NULL, subject TEXT NOT NULL, label TEXT, created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL, consumed_at TEXT, revoked_at TEXT, proof_key_thumbprint TEXT
        );";

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::auth::sessions::tests::DDL).unwrap();
        c.execute_batch(LINKS_DDL).unwrap();
        c
    }

    const NOW: i64 = 1_893_456_000_000; // 2030-01-01

    fn link(c: &Connection, id: &str, subject: &str, label: Option<&str>, created: &str) {
        c.execute(
            "INSERT INTO auth_pairing_links (id, credential, method, scopes, subject, label, created_at, expires_at)
             VALUES (?1, ?1 || 'cred', 'one-time-token', '[\"orchestration:read\",\"filesystem:read\"]', ?2, ?3, ?4, '2031-01-01T00:00:00.000Z')",
            rusqlite::params![id, subject, label, created],
        )
        .unwrap();
    }

    fn session(c: &Connection, sid: &str, scopes: &str, issued: &str, expires: &str) {
        c.execute(
            "INSERT INTO auth_sessions (session_id, subject, scopes, method, client_label, client_ip_address,
               client_user_agent, client_device_type, client_os, client_browser, issued_at, expires_at)
             VALUES (?1, 'browser', ?2, 'browser-session-cookie', 'Lab', '', NULL, 'desktop', 'macOS', NULL, ?3, ?4)",
            rusqlite::params![sid, scopes, issued, expires],
        )
        .unwrap();
    }

    #[test]
    fn lists_follow_node_filters_order_and_encoding() {
        let c = db();
        link(
            &c,
            "l-old",
            "one-time-token",
            None,
            "2029-01-01T00:00:00.000Z",
        );
        link(
            &c,
            "l-new",
            "one-time-token",
            Some("Phone"),
            "2029-06-01T00:00:00.000Z",
        );
        link(
            &c,
            "l-admin",
            "administrative-bootstrap",
            None,
            "2029-07-01T00:00:00.000Z",
        );
        link(
            &c,
            "l-empty-label",
            "one-time-token",
            Some(""),
            "2029-02-01T00:00:00.000Z",
        );
        c.execute("UPDATE auth_pairing_links SET expires_at = '2029-12-31T00:00:00.000Z' WHERE id = 'l-old'", []).unwrap();
        let w = r#"["access:read","access:write","settings:write"]"#;
        let r = r#"["orchestration:read"]"#;
        session(
            &c,
            "s-a",
            r,
            "2029-05-01T00:00:00.000Z",
            "2031-01-01T00:00:00.000Z",
        );
        session(
            &c,
            "s-b",
            r,
            "2029-06-01T00:00:00.000Z",
            "2031-01-01T00:00:00.000Z",
        );
        session(
            &c,
            "s-w",
            w,
            "2029-01-01T00:00:00.000Z",
            "2031-01-01T00:00:00.000Z",
        );
        // Expired: listed only while connected.
        session(
            &c,
            "s-exp",
            r,
            "2029-01-02T00:00:00.000Z",
            "2029-02-01T00:00:00.000Z",
        );
        session(
            &c,
            "s-gone",
            r,
            "2029-01-03T00:00:00.000Z",
            "2029-02-01T00:00:00.000Z",
        );
        session(
            &c,
            "s-rev",
            r,
            "2029-01-04T00:00:00.000Z",
            "2031-01-01T00:00:00.000Z",
        );
        c.execute("UPDATE auth_sessions SET revoked_at = '2029-01-05T00:00:00.000Z' WHERE session_id = 's-rev'", []).unwrap();
        c.execute("UPDATE auth_sessions SET last_connected_at = '2029-06-02T00:00:00.000Z' WHERE session_id = 's-a'", []).unwrap();

        let l = read(&c, &["s-a".into(), "s-exp".into()], "s-b", NOW).unwrap();
        let ids = |v: &[(String, Value)]| v.iter().map(|x| x.0.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&l.links), ["l-new", "l-empty-label"]);
        assert_eq!(ids(&l.clients), ["s-w", "s-a", "s-exp", "s-b"]);
        assert_eq!(
            serde_json::to_string(&l.links[0].1).unwrap(),
            r#"{"id":"l-new","scopes":["orchestration:read"],"permissions":["orchestration:read","filesystem:read"],"subject":"one-time-token","label":"Phone","createdAt":"2029-06-01T00:00:00.000Z","expiresAt":"2031-01-01T00:00:00.000Z"}"#
        );
        assert!(l.links[1].1.get("label").is_none(), "empty label omitted");
        assert_eq!(
            serde_json::to_string(&l.clients[1].1).unwrap(),
            r#"{"sessionId":"s-a","subject":"browser","scopes":["orchestration:read"],"permissions":["orchestration:read"],"method":"browser-session-cookie","client":{"label":"Lab","deviceType":"desktop","os":"macOS"},"issuedAt":"2029-05-01T00:00:00.000Z","expiresAt":"2031-01-01T00:00:00.000Z","lastConnectedAt":"2029-06-02T00:00:00.000Z","connected":true,"current":false}"#
        );
        assert_eq!(l.clients[3].1["current"], true);
        assert_eq!(l.clients[3].1["lastConnectedAt"], Value::Null);
        assert_eq!(
            l.clients[0].1["scopes"],
            json!(["access:read", "access:write"])
        );
    }

    #[test]
    fn rows_node_cannot_decode_fail_the_read() {
        for bad in [
            "UPDATE auth_sessions SET scopes = '[\"nope\"]'",
            "UPDATE auth_sessions SET client_device_type = 'fridge'",
            "UPDATE auth_sessions SET issued_at = '2029-05-01 00:00:00'",
            "UPDATE auth_sessions SET client_label = '   '",
            "UPDATE auth_sessions SET method = 'x'",
        ] {
            let c = db();
            session(
                &c,
                "s",
                r#"["access:read"]"#,
                "2029-05-01T00:00:00.000Z",
                "2031-01-01T00:00:00.000Z",
            );
            c.execute(bad, []).unwrap();
            assert!(read(&c, &[], "s", NOW).is_err(), "{bad}");
        }
    }

    fn lists(links: &[(&str, Value)], clients: &[(&str, Value)]) -> Lists {
        let own = |v: &[(&str, Value)]| v.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        Lists {
            links: own(links),
            clients: own(clients),
        }
    }

    #[test]
    fn diff_emits_removes_then_upserts_with_rising_revisions() {
        let a = lists(
            &[("l1", json!({"id":"l1"})), ("l2", json!({"id":"l2"}))],
            &[
                ("s1", json!({"sessionId":"s1","connected":false})),
                ("s2", json!({"sessionId":"s2"})),
            ],
        );
        let b = lists(
            &[("l2", json!({"id":"l2"})), ("l3", json!({"id":"l3"}))],
            &[
                ("s1", json!({"sessionId":"s1","connected":true})),
                ("s3", json!({"sessionId":"s3"})),
            ],
        );
        let mut rev = 1;
        let ev = diff(&a, &b, &mut rev);
        let got: Vec<String> = ev.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            got,
            [
                r#"{"version":1,"revision":2,"type":"pairingLinkRemoved","payload":{"id":"l1"}}"#,
                r#"{"version":1,"revision":3,"type":"pairingLinkUpserted","payload":{"id":"l3"}}"#,
                r#"{"version":1,"revision":4,"type":"clientRemoved","payload":{"sessionId":"s2"}}"#,
                r#"{"version":1,"revision":5,"type":"clientUpserted","payload":{"sessionId":"s1","connected":true}}"#,
                r#"{"version":1,"revision":6,"type":"clientUpserted","payload":{"sessionId":"s3"}}"#,
            ]
        );
        assert_eq!(rev, 6);
        assert!(diff(&b, &b, &mut rev).is_empty());
        assert_eq!(rev, 6, "no events, no revisions");
        // Order changes alone (connected sorting) emit nothing.
        let mut c = b.clone();
        c.clients.reverse();
        assert!(diff(&b, &c, &mut rev).is_empty());
    }

    /// `tests/golden/auth_access_snapshot.json`: Node's own first chunk, captured live
    /// (`auth_access_snapshot_shadow_matches_node` with `VEKREL_WRITE_GOLDEN=1`), with the rows
    /// it was read from (pairing credentials redacted).
    #[test]
    fn snapshot_is_byte_exact_with_nodes_golden() {
        let g: Value =
            serde_json::from_str(include_str!("../../tests/golden/auth_access_snapshot.json"))
                .unwrap();
        let c = db();
        for table in ["auth_sessions", "auth_pairing_links"] {
            for row in g[table].as_array().unwrap() {
                let row = row.as_object().unwrap();
                let cols: Vec<&str> = row.keys().map(String::as_str).collect();
                let marks: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
                let sql = format!(
                    "INSERT INTO {table} ({}) VALUES ({})",
                    cols.join(", "),
                    marks.join(", ")
                );
                let vals: Vec<Option<&str>> = row.values().map(Value::as_str).collect();
                c.execute(&sql, rusqlite::params_from_iter(vals)).unwrap();
            }
        }
        let current = g["current"].as_str().unwrap();
        let connected: Vec<String> = serde_json::from_value(g["connected"].clone()).unwrap();
        let l = read(&c, &connected, current, g["now"].as_i64().unwrap()).unwrap();
        let rust = json!([snapshot(&l)]).to_string();
        assert_eq!(rust, g["node_values"].as_str().unwrap());
    }

    #[test]
    fn tailscale_serve_detection() {
        let none = |_: &str| None;
        assert!(!tailscale_serve(&["bin.mjs".into()], none));
        assert!(tailscale_serve(&["--tailscale-serve".into()], none));
        assert!(tailscale_serve(
            &["--tailscale-serve-port=443".into()],
            none
        ));
        let env = |k: &str| (k == "VEKREL_TAILSCALE_SERVE").then(|| "1".to_owned());
        assert!(tailscale_serve(&[], env));
        let empty = |k: &str| (k == "VEKREL_TAILSCALE_SERVE").then(String::new);
        assert!(!tailscale_serve(&[], empty));
    }
}
