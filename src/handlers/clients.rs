//! `GET /api/auth/clients`, `POST /api/auth/clients/revoke` and
//! `POST /api/auth/clients/revoke-others` (`auth/http.ts` `clients`, `revokeClient`,
//! `revokeOtherClients`; `SessionStore.listActive` / `revoke` / `revokeAllExcept`).
//!
//! `connected` comes from the socket registry, which is complete only while no socket can bypass
//! the daemon (`auth::bypass`); otherwise the list goes to Node, whose in-memory map sees them all.
//! The revokes write `auth_sessions` only in `serve` (one `UPDATE … RETURNING`, as Node does), then
//! close both legs of the revoked sessions' proxied sockets; Node's `markDisconnected` then
//! publishes `clientRemoved` itself. Sockets that reach Node directly close on Node's own row
//! re-check.
use super::{
    HandlerCtx,
    auth_access::{AuthAccess, open_db, read},
    auth_session::{AuthSession, iso_millis},
    pairing_links::{
        Writer, blocking, body, bypassed, caller, gate, now_ms, opt_trimmed, write_db,
    },
};
use crate::{
    http_auth::{self, DpopCtx},
    http_errors,
    http_seam::{Compare, RouteHandler},
};
use axum::{
    body::Bytes,
    http::{Method, Response, StatusCode, request::Parts},
};
use futures_util::{FutureExt, future::BoxFuture};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use std::{sync::Arc, time::UNIX_EPOCH};

pub const LIST_KEY: &str = "GET /api/auth/clients";
pub const REVOKE_KEY: &str = "POST /api/auth/clients/revoke";
pub const REVOKE_OTHERS_KEY: &str = "POST /api/auth/clients/revoke-others";

fn declined(route: &str, why: &str) -> Option<Response<Bytes>> {
    tracing::info!(route, why, outcome = "declined", "rust clients");
    None
}

fn compare() -> Compare {
    Compare {
        headers: Compare::AUTH_HEADERS,
        ..Compare::DEFAULT
    }
}

/// When the proxy received the request, in ms: a revocation stamped at or after it is Node's own
/// answer to this request (shadow runs alongside Node's write).
fn arrived(req: &Parts, now: i64) -> String {
    let ms = req
        .extensions
        .get::<DpopCtx>()
        .and_then(|d| d.arrived.duration_since(UNIX_EPOCH).ok())
        .map_or(now, |d| d.as_millis() as i64);
    iso_millis(ms)
}

pub struct ListClients(pub Arc<AuthSession>, pub Arc<AuthAccess>);

impl RouteHandler for ListClients {
    fn default_mode(&self) -> crate::config::Mode {
        crate::config::Mode::Serve
    }

    fn method_path(&self) -> (Method, &'static str) {
        (Method::GET, "/api/auth/clients")
    }

    fn compare(&self) -> Compare {
        compare()
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
            // Only Node's map sees sockets that bypass the daemon.
            if let Some(why) = bypassed(&self.1).await {
                return declined(LIST_KEY, why);
            }
            let ids = self.1.registry().connected_ids();
            let path = self.0.files().db_path().to_path_buf();
            let now = now_ms()?;
            let list = blocking(move || {
                // A row Node cannot decode is Node's 500.
                read(&open_db(&path).ok()?, &ids, &p.session_id, now)
                    .map_err(|e| tracing::info!(why = e, "clients read declined"))
                    .ok()
            })
            .await?;
            let list: Vec<Value> = list.clients.into_iter().map(|c| c.1).collect();
            Some(http_errors::json(StatusCode::OK, &list))
        }
        .boxed()
    }
}

/// Closes both legs of every proxied socket of each revoked session.
fn close(access: &AuthAccess, ids: &[String]) {
    let n: usize = ids
        .iter()
        .map(|id| access.registry().close_session(id))
        .sum();
    tracing::info!(
        sessions = ids.len(),
        sockets = n,
        "rust revoke closed sockets"
    );
}

pub struct RevokeClient(pub Writer);

impl RouteHandler for RevokeClient {
    fn default_mode(&self) -> crate::config::Mode {
        crate::config::Mode::Serve
    }

    fn method_path(&self) -> (Method, &'static str) {
        (Method::POST, "/api/auth/clients/revoke")
    }

    fn wants_body(&self) -> bool {
        true
    }

    fn compare(&self) -> Compare {
        compare()
    }

    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        async move {
            let w = &self.0;
            let p = match caller(&w.auth, req).await? {
                Ok(p) => p,
                Err(r) => return Some(r),
            };
            // `AuthRevokeClientSessionInput`.
            let Some(Some(id)) = body(req).and_then(|o| opt_trimmed(&o, "sessionId")) else {
                return declined(REVOKE_KEY, "body");
            };
            if let Some(r) = http_auth::require_scope(&p, "access:write") {
                return Some(r);
            }
            if id == p.session_id {
                return Some(http_errors::operation_forbidden(
                    "current_session_revoke_not_allowed",
                ));
            }
            let now = now_ms()?;
            let Some(serve) = w.serving(req) else {
                return declined(REVOKE_KEY, "mode_mismatch");
            };
            let revoked = if serve {
                let gate = match gate(&w.access).await {
                    Ok(g) => g,
                    Err(why) => return declined(REVOKE_KEY, why),
                };
                let (auth, id) = (w.auth.clone(), id.clone());
                let ids = blocking(move || {
                    // Owned by the DB work: a dropped request future must not open the gate early.
                    let _gate = gate;
                    revoke(&write_db(&auth).ok()?, Some(&id), None, &iso_millis(now))
                        .map_err(|e| tracing::warn!(error = %e, "client revoke failed"))
                        .ok()
                })
                .await?;
                close(&w.access, &ids);
                !ids.is_empty()
            } else {
                let (path, at) = (w.auth.files().db_path().to_path_buf(), arrived(req, now));
                blocking(move || predict(&open_db(&path).ok()?, Some(&id), None, &at)).await? > 0
            };
            Some(http_errors::json(
                StatusCode::OK,
                &json!({ "revoked": revoked }),
            ))
        }
        .boxed()
    }
}

pub struct RevokeOtherClients(pub Writer);

impl RouteHandler for RevokeOtherClients {
    fn default_mode(&self) -> crate::config::Mode {
        crate::config::Mode::Serve
    }

    fn method_path(&self) -> (Method, &'static str) {
        (Method::POST, "/api/auth/clients/revoke-others")
    }

    fn compare(&self) -> Compare {
        compare()
    }

    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        async move {
            let w = &self.0;
            let p = match caller(&w.auth, req).await? {
                Ok(p) => p,
                Err(r) => return Some(r),
            };
            if let Some(r) = http_auth::require_scope(&p, "access:write") {
                return Some(r);
            }
            let now = now_ms()?;
            let Some(serve) = w.serving(req) else {
                return declined(REVOKE_OTHERS_KEY, "mode_mismatch");
            };
            let cur = p.session_id;
            let count = if serve {
                let gate = match gate(&w.access).await {
                    Ok(g) => g,
                    Err(why) => return declined(REVOKE_OTHERS_KEY, why),
                };
                let auth = w.auth.clone();
                let ids = blocking(move || {
                    // Owned by the DB work: a dropped request future must not open the gate early.
                    let _gate = gate;
                    revoke(&write_db(&auth).ok()?, None, Some(&cur), &iso_millis(now))
                        .map_err(|e| tracing::warn!(error = %e, "other clients revoke failed"))
                        .ok()
                })
                .await?;
                close(&w.access, &ids);
                ids.len()
            } else {
                let (path, at) = (w.auth.files().db_path().to_path_buf(), arrived(req, now));
                blocking(move || predict(&open_db(&path).ok()?, None, Some(&cur), &at)).await?
            };
            Some(http_errors::json(
                StatusCode::OK,
                &json!({ "revokedCount": count }),
            ))
        }
        .boxed()
    }
}

/// `revokeSessionRows` (`only`) or `revokeOtherSessionRows` (`except`): every unrevoked row,
/// expired and MCP ones included. One statement.
fn revoke(
    c: &Connection,
    only: Option<&str>,
    except: Option<&str>,
    at: &str,
) -> rusqlite::Result<Vec<String>> {
    let mut q = c.prepare(
        "UPDATE auth_sessions SET revoked_at = ?3
         WHERE (?1 IS NULL OR session_id = ?1) AND (?2 IS NULL OR session_id <> ?2)
           AND revoked_at IS NULL
         RETURNING session_id",
    )?;
    q.query_map(rusqlite::params![only, except, at], |r| r.get(0))?
        .collect()
}

/// Shadow: how many rows Node's statement matches, counting rows revoked at or after `arrived`
/// as Node's own concurrent write.
fn predict(
    c: &Connection,
    only: Option<&str>,
    except: Option<&str>,
    arrived: &str,
) -> Option<usize> {
    c.query_row(
        "SELECT count(*) FROM auth_sessions
         WHERE (?1 IS NULL OR session_id = ?1) AND (?2 IS NULL OR session_id <> ?2)
           AND (revoked_at IS NULL OR revoked_at >= ?3)",
        rusqlite::params![only, except, arrived],
        |r| r.get::<_, i64>(0),
    )
    .optional()
    .ok()
    .flatten()
    .map(|n| n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{
            registry::Registry,
            token::tests::{mint, payload},
        },
        http_auth::tests::{COOKIE, Env, KEY, env, rejected},
        http_seam::RequestBody,
    };

    const ME: &str = "6f1c0d3e-0000-4000-8000-000000000001";

    /// The caller (`payload().sid`, already in the DB) holding `scopes`, plus a registry.
    fn setup(scopes: &[&str]) -> (Env, String, Arc<Registry>) {
        let e = env();
        // `read` lists links too.
        Connection::open(e.0.path().join("db.sqlite"))
            .unwrap()
            .execute_batch(crate::handlers::auth_access::tests::LINKS_DDL)
            .unwrap();
        let mut p = payload();
        p.scopes = scopes.iter().map(|s| s.to_string()).collect();
        (e, format!("{COOKIE}={}", mint(&p, &KEY)), Arc::default())
    }

    fn session(e: &Env, sid: &str, subject: &str, scopes: &str, issued: &str, expires: &str) {
        Connection::open(e.0.path().join("db.sqlite"))
            .unwrap()
            .execute(
                "INSERT INTO auth_sessions (session_id, subject, scopes, method, client_label,
                   client_device_type, issued_at, expires_at)
                 VALUES (?1, ?2, ?3, 'bearer-access-token', 'L', 'mobile', ?4, ?5)",
                rusqlite::params![sid, subject, scopes, issued, expires],
            )
            .unwrap();
    }

    fn revoked(e: &Env) -> Vec<(String, bool)> {
        let c = Connection::open(e.0.path().join("db.sqlite")).unwrap();
        let mut q = c
            .prepare(
                "SELECT session_id, revoked_at IS NOT NULL FROM auth_sessions ORDER BY session_id",
            )
            .unwrap();
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn req(method: &str, path: &str, cookie: &str, body: Option<&str>, serve: bool) -> Parts {
        let mut parts = axum::http::Request::builder()
            .method(method)
            .uri(format!("http://127.0.0.1:3789{path}"))
            .header("host", "127.0.0.1:3789")
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        if let Some(b) = body {
            parts
                .extensions
                .insert(RequestBody(Bytes::from(b.to_owned())));
        }
        parts.extensions.insert(DpopCtx {
            serve,
            ..DpopCtx::default()
        });
        parts
    }

    fn access(e: &Env, reg: &Arc<Registry>) -> Arc<AuthAccess> {
        Arc::new(AuthAccess::new(e.1.files().clone(), reg.clone(), false))
    }

    fn writer(e: &Env, reg: &Arc<Registry>, serve: bool) -> Writer {
        Writer {
            auth: e.1.clone(),
            access: access(e, reg),
            serve,
        }
    }

    async fn list(e: &Env, reg: &Arc<Registry>, cookie: &str) -> Option<Response<Bytes>> {
        ListClients(e.1.clone(), access(e, reg))
            .handle(
                &req("GET", "/api/auth/clients", cookie, None, false),
                &HandlerCtx::default(),
            )
            .await
    }

    async fn revoke(
        e: &Env,
        reg: &Arc<Registry>,
        cookie: &str,
        sid: &str,
        serve: bool,
    ) -> Option<Response<Bytes>> {
        let body = json!({ "sessionId": sid }).to_string();
        RevokeClient(writer(e, reg, true))
            .handle(
                &req(
                    "POST",
                    "/api/auth/clients/revoke",
                    cookie,
                    Some(&body),
                    serve,
                ),
                &HandlerCtx::default(),
            )
            .await
    }

    async fn others(w: Writer, cookie: &str, serve: bool) -> Option<Response<Bytes>> {
        RevokeOtherClients(w)
            .handle(
                &req(
                    "POST",
                    "/api/auth/clients/revoke-others",
                    cookie,
                    None,
                    serve,
                ),
                &HandlerCtx::default(),
            )
            .await
    }

    fn text(r: Response<Bytes>) -> String {
        String::from_utf8(r.body().to_vec()).unwrap()
    }

    const W: &str = r#"["access:read","access:write"]"#;
    const R: &str = r#"["orchestration:read"]"#;

    #[tokio::test]
    async fn list_is_nodes_order_with_connected_expired_rows_and_current() {
        let (e, cookie, reg) = setup(&["access:read"]);
        session(
            &e,
            "w-old",
            "one-time-token",
            W,
            "2026-01-02T00:00:00.000Z",
            "2099-01-01T00:00:00.000Z",
        );
        session(
            &e,
            "r-new",
            "one-time-token",
            R,
            "2026-03-01T00:00:00.000Z",
            "2099-01-01T00:00:00.000Z",
        );
        session(
            &e,
            "r-conn",
            "one-time-token",
            R,
            "2026-01-03T00:00:00.000Z",
            "2099-01-01T00:00:00.000Z",
        );
        session(
            &e,
            "r-exp-conn",
            "one-time-token",
            R,
            "2026-01-04T00:00:00.000Z",
            "2020-01-01T00:00:00.000Z",
        );
        session(
            &e,
            "r-exp",
            "one-time-token",
            R,
            "2026-01-05T00:00:00.000Z",
            "2020-01-01T00:00:00.000Z",
        );
        let _c = (reg.open(Some("r-conn")), reg.open(Some("r-exp-conn")));
        let r = list(&e, &reg, &cookie).await.unwrap();
        assert_eq!(r.status(), 200);
        let v: Vec<Value> = serde_json::from_slice(r.body()).unwrap();
        let got: Vec<_> = v
            .iter()
            .map(|c| {
                (
                    c["sessionId"].as_str().unwrap(),
                    c["connected"] == true,
                    c["current"] == true,
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("w-old", false, false),
                ("r-exp-conn", true, false),
                ("r-conn", true, false),
                ("r-new", false, false),
                (ME, false, true),
            ]
        );
        assert_eq!(
            serde_json::to_string(&v[0]).unwrap(),
            r#"{"sessionId":"w-old","subject":"one-time-token","scopes":["access:read","access:write"],"permissions":["access:read","access:write"],"method":"bearer-access-token","client":{"label":"L","deviceType":"mobile"},"issuedAt":"2026-01-02T00:00:00.000Z","expiresAt":"2099-01-01T00:00:00.000Z","lastConnectedAt":null,"connected":false,"current":false}"#
        );
        // A socket Rust cannot attribute (or any other bypass): only Node knows `connected`.
        let u = reg.open(None);
        assert!(list(&e, &reg, &cookie).await.is_none());
        drop(u);
        // A socket whose access stream Node serves: the list stays Node's too, like the writes.
        let held = reg.node_stream();
        assert!(list(&e, &reg, &cookie).await.is_none());
        drop(held);
        assert!(list(&e, &reg, &cookie).await.is_some());
        std::fs::write(e.0.path().join("cloud-relay-url.bin"), "x").unwrap();
        assert!(list(&e, &reg, &cookie).await.is_none());
    }

    #[tokio::test]
    async fn scope_and_self_revoke_are_nodes_403s() {
        let (e, cookie, reg) = setup(&["orchestration:read"]);
        let (s, b, _) = rejected(list(&e, &reg, &cookie).await.unwrap());
        assert_eq!(s, 403);
        assert!(b.contains(r#""requiredScope":"access:read""#), "{b}");
        let (s, b, _) = rejected(revoke(&e, &reg, &cookie, "x", true).await.unwrap());
        assert_eq!(s, 403);
        assert!(b.contains(r#""requiredScope":"access:write""#), "{b}");
        let (_, b, _) = rejected(others(writer(&e, &reg, true), &cookie, true).await.unwrap());
        assert!(b.contains(r#""requiredScope":"access:write""#), "{b}");

        let (e, cookie, reg) = setup(&["access:write"]);
        let (s, b, _) = rejected(
            revoke(&e, &reg, &cookie, &format!(" {ME} "), true)
                .await
                .unwrap(),
        );
        assert_eq!(
            (s, b.as_str()),
            (
                403,
                r#"{"_tag":"MachineOperationForbiddenError","code":"operation_forbidden","reason":"current_session_revoke_not_allowed""#
            )
        );
        assert!(revoked(&e).iter().all(|r| !r.1));
        // Bodies Effect would reject stay Node's.
        for b in [r#"{}"#, r#"{"sessionId":" "}"#, r#"{"sessionId":1}"#, "[]"] {
            let r = RevokeClient(writer(&e, &reg, true))
                .handle(
                    &req("POST", "/api/auth/clients/revoke", &cookie, Some(b), true),
                    &HandlerCtx::default(),
                )
                .await;
            assert!(r.is_none(), "{b}");
        }
    }

    #[tokio::test]
    async fn serve_revoke_writes_once_and_closes_the_sessions_sockets() {
        let (e, cookie, reg) = setup(&["access:write"]);
        session(
            &e,
            "a",
            "one-time-token",
            R,
            "2026-01-02T00:00:00.000Z",
            "2099-01-01T00:00:00.000Z",
        );
        session(
            &e,
            "b",
            "one-time-token",
            R,
            "2026-01-02T00:00:00.000Z",
            "2099-01-01T00:00:00.000Z",
        );
        let (a1, a2, b) = (
            reg.open(Some("a")),
            reg.open(Some("a")),
            reg.open(Some("b")),
        );
        // Shadow predicts and writes nothing.
        assert_eq!(
            text(revoke(&e, &reg, &cookie, "a", false).await.unwrap()),
            r#"{"revoked":true}"#
        );
        assert!(revoked(&e).iter().all(|r| !r.1) && !a1.close.is_cancelled());
        let r = revoke(&e, &reg, &cookie, " a", true).await.unwrap();
        assert_eq!(text(r), r#"{"revoked":true}"#);
        assert!(a1.close.is_cancelled() && a2.close.is_cancelled() && !b.close.is_cancelled());
        assert_eq!(revoked(&e).iter().filter(|r| r.1).count(), 1);
        for serve in [true, false] {
            let r = revoke(&e, &reg, &cookie, "a", serve).await.unwrap();
            assert_eq!(text(r), r#"{"revoked":false}"#);
            let r = revoke(&e, &reg, &cookie, "nope", serve).await.unwrap();
            assert_eq!(text(r), r#"{"revoked":false}"#);
        }
    }

    #[tokio::test]
    async fn serve_revoke_declines_on_mode_mismatch_and_bypass() {
        let (e, cookie, reg) = setup(&["access:write"]);
        session(
            &e,
            "a",
            "one-time-token",
            R,
            "2026-01-02T00:00:00.000Z",
            "2099-01-01T00:00:00.000Z",
        );
        let a = reg.open(Some("a"));
        let body = json!({ "sessionId": "a" }).to_string();
        let call = |w: Writer| {
            let r = req(
                "POST",
                "/api/auth/clients/revoke",
                &cookie,
                Some(&body),
                true,
            );
            async move { RevokeClient(w).handle(&r, &HandlerCtx::default()).await }
        };
        // The proxy says serve but the route is not configured serve: Node answers.
        assert!(call(writer(&e, &reg, false)).await.is_none());
        // A bypass: Node must make (and publish) the write.
        let cloud = e.0.path().join("cloud-relay-url.bin");
        std::fs::write(&cloud, "x").unwrap();
        assert!(call(writer(&e, &reg, true)).await.is_none());
        assert!(revoked(&e).iter().all(|r| !r.1) && !a.close.is_cancelled());
        std::fs::remove_file(&cloud).unwrap();
        // A socket whose access stream Node took is still open: Node still writes.
        let held = reg.node_stream();
        assert!(call(writer(&e, &reg, true)).await.is_none());
        assert!(revoked(&e).iter().all(|r| !r.1) && !a.close.is_cancelled());
        drop(held);
        let r = call(writer(&e, &reg, true)).await.unwrap();
        assert_eq!(text(r), r#"{"revoked":true}"#);
        assert!(a.close.is_cancelled());
    }

    #[tokio::test]
    async fn revoke_others_hits_every_unrevoked_row_but_the_callers() {
        let (e, cookie, reg) = setup(&["access:write"]);
        session(
            &e,
            "live",
            "one-time-token",
            R,
            "2026-01-02T00:00:00.000Z",
            "2099-01-01T00:00:00.000Z",
        );
        session(
            &e,
            "expired",
            "one-time-token",
            R,
            "2026-01-02T00:00:00.000Z",
            "2020-01-01T00:00:00.000Z",
        );
        session(
            &e,
            "mcp",
            "mcp-client",
            R,
            "2026-01-02T00:00:00.000Z",
            "2099-01-01T00:00:00.000Z",
        );
        session(
            &e,
            "gone",
            "one-time-token",
            R,
            "2026-01-02T00:00:00.000Z",
            "2099-01-01T00:00:00.000Z",
        );
        Connection::open(e.0.path().join("db.sqlite"))
            .unwrap()
            .execute("UPDATE auth_sessions SET revoked_at = '2026-01-03T00:00:00.000Z' WHERE session_id = 'gone'", [])
            .unwrap();
        let (live, me) = (reg.open(Some("live")), reg.open(Some(ME)));
        let r = others(writer(&e, &reg, true), &cookie, false)
            .await
            .unwrap();
        assert_eq!(text(r), r#"{"revokedCount":3}"#, "shadow prediction");
        assert_eq!(
            revoked(&e).iter().filter(|r| r.1).count(),
            1,
            "shadow writes nothing"
        );
        // The proxy says serve but the route is not configured serve: Node answers.
        assert!(
            others(writer(&e, &reg, false), &cookie, true)
                .await
                .is_none()
        );
        // A bypass: Node must make (and publish) the write.
        let cloud = e.0.path().join("cloud-relay-url.bin");
        std::fs::write(&cloud, "x").unwrap();
        assert!(
            others(writer(&e, &reg, true), &cookie, true)
                .await
                .is_none()
        );
        std::fs::remove_file(&cloud).unwrap();
        assert_eq!(revoked(&e).iter().filter(|r| r.1).count(), 1);

        let r = others(writer(&e, &reg, true), &cookie, true).await.unwrap();
        assert_eq!(text(r), r#"{"revokedCount":3}"#);
        assert!(live.close.is_cancelled() && !me.close.is_cancelled());
        assert_eq!(
            revoked(&e),
            [
                (ME.to_owned(), false),
                ("expired".into(), true),
                ("gone".into(), true),
                ("live".into(), true),
                ("mcp".into(), true),
            ]
        );
        let r = others(writer(&e, &reg, true), &cookie, true).await.unwrap();
        assert_eq!(text(r), r#"{"revokedCount":0}"#);
    }
}
