//! `GET /api/orchestration/shell`, byte-compatible with the engine's `shellSnapshot` handler
//! (`orchestration-v2/http.ts:150-162`, `loadShellSnapshot` `:76-87`, `ShellStream.ts:53-96`).
//!
//! One read transaction: `ProjectStoreV2.listShells()` (`ProjectStore.ts:56-71`, the same rows as
//! `GET /api/projects`), the Task 6 builder's active threads and `latestApplicationSequence`.
//! Every builder decline and every project row Rust cannot reproduce declines the request.
//!
//! Shadow-only (`SHADOW_ONLY`): Node's `enrichProjectShells` fills `repositoryIdentity` from
//! its warm in-memory cache, and the client renders the HTTP snapshot before the stream's
//! enrichment refresh arrives (Vekrel-Web `client-runtime/src/state/shell.ts` `applyItems` on the
//! HTTP snapshot, then `subscribeShell`), so Rust's cold `null` is visible.
use super::{HandlerCtx, auth_session::AuthSession, pairing_links::caller, projects};
use crate::{
    db::read::StateDb,
    http_auth, http_errors,
    http_seam::{Compare, RouteHandler, orchestration_protocol},
    shell::{self, Location},
};
use axum::{
    body::Bytes,
    http::{Method, Response, StatusCode, request::Parts},
};
use futures_util::{FutureExt, future::BoxFuture};
use serde_json::json;
use std::sync::Arc;

pub const KEY: &str = "GET /api/orchestration/shell";

/// `ORCHESTRATION_V2_PROJECTION_SCHEMA_VERSION` (`ProjectionStore.ts:593`).
const SCHEMA_VERSION: i64 = 2;

pub struct Shell {
    pub auth: Arc<AuthSession>,
    pub db: Arc<StateDb>,
}

fn declined(why: &str) -> Option<Response<Bytes>> {
    tracing::info!(route = KEY, why, outcome = "declined", "rust shell");
    None
}

impl RouteHandler for Shell {
    fn method_path(&self) -> (Method, &'static str) {
        (Method::GET, "/api/orchestration/shell")
    }

    fn compare(&self) -> Compare {
        Compare {
            headers: &["content-type", "vary", "access-control-allow-origin"],
            enrich: &["$.projects[*].repositoryIdentity"],
            skew: &["snapshotSequence"],
            // About 5x the owner's 1.43 MB shell; beyond it `shadow_skipped_large`.
            tee_limit: 8 << 20,
            ..Compare::DEFAULT
        }
    }

    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        async move {
            if !orchestration_protocol(req) {
                return declined("protocol_header");
            }
            let p = match caller(&self.auth, req).await? {
                Ok(p) => p,
                Err(r) => return Some(r),
            };
            if let Some(r) = http_auth::require_scope(&p, "orchestration:read") {
                return Some(r);
            }
            let db = self.db.clone();
            match tokio::task::spawn_blocking(move || snapshot(&db))
                .await
                .ok()?
            {
                Ok(body) => Some(http_errors::json_bytes(StatusCode::OK, body)),
                Err(why) => declined(why),
            }
        }
        .boxed()
    }
}

/// Node's `OrchestrationV2ShellSnapshot` bytes, or the decline reason.
pub fn snapshot(db: &StateDb) -> Result<Vec<u8>, &'static str> {
    let (projects, seq, threads) = db
        .read(|c| {
            Ok((
                projects::shells(c)?,
                shell::latest_application_sequence(c)?,
                shell::build_threads(c, Location::Active),
            ))
        })
        .map_err(|d| d.reason())?;
    let threads = threads.map_err(|d| {
        tracing::info!(route = KEY, decline = ?d, "rust shell builder declined");
        d.reason()
    })?;
    let projects = projects.ok_or("row_not_reproducible")?;
    Ok(crate::effect_json::to_vec(&json!({
        "schemaVersion": SCHEMA_VERSION,
        "snapshotSequence": seq,
        "threads": threads,
        "archivedThreads": [],
        "projects": projects,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::read::{StateDb, tests};

    fn fixture(dir: &std::path::Path, sql: &str) -> StateDb {
        tests::fixture(dir, &format!("{}{sql}", shell::tests::INDEXES))
    }

    #[test]
    fn empty_db_is_nodes_empty_shell() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), "");
        assert_eq!(
            String::from_utf8(snapshot(&db).unwrap()).unwrap(),
            r#"{"schemaVersion":2,"snapshotSequence":0,"threads":[],"archivedThreads":[],"projects":[]}"#
        );
    }

    #[test]
    fn projects_in_shell_order_without_deleted_rows() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(
            dir.path(),
            "INSERT INTO projection_projects (project_id, title, workspace_root, \
             default_model_selection_json, default_thread_env_mode, auto_pull, favicon_path, \
             project_icon_json, scripts_json, created_at, updated_at, deleted_at) VALUES \
             ('b', 'B', '/b', NULL, 'local', 1, 'f.png', NULL, '[]', 'c1', 'u1', NULL), \
             ('a', 'A', '/a', NULL, NULL, 0, NULL, NULL, '[]', 'c1', 'u1', NULL), \
             ('gone', 'G', '/g', NULL, NULL, 0, NULL, NULL, '[]', 'c0', 'u0', 'd');",
        );
        assert_eq!(
            String::from_utf8(snapshot(&db).unwrap()).unwrap(),
            concat!(
                r#"{"schemaVersion":2,"snapshotSequence":0,"threads":[],"archivedThreads":[],"projects":["#,
                r#"{"id":"a","title":"A","workspaceRoot":"/a","repositoryIdentity":null,"defaultModelSelection":null,"defaultThreadEnvMode":null,"autoPull":false,"faviconPath":null,"projectIcon":null,"scripts":[],"createdAt":"c1","updatedAt":"u1"},"#,
                r#"{"id":"b","title":"B","workspaceRoot":"/b","repositoryIdentity":null,"defaultModelSelection":null,"defaultThreadEnvMode":"local","autoPull":true,"faviconPath":"f.png","projectIcon":null,"scripts":[],"createdAt":"c1","updatedAt":"u1"}]}"#
            )
        );
    }

    #[test]
    fn a_row_or_thread_rust_cannot_reproduce_declines() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(
            dir.path(),
            "INSERT INTO projection_projects (project_id, title, workspace_root, \
             default_model_selection_json, default_thread_env_mode, auto_pull, favicon_path, \
             project_icon_json, scripts_json, created_at, updated_at, deleted_at) VALUES \
             ('a', ' A', '/a', NULL, NULL, 0, NULL, NULL, '[]', 'c', 'u', NULL);",
        );
        assert_eq!(snapshot(&db), Err("row_not_reproducible"));
        let dir = tempfile::tempdir().unwrap();
        let mut fx = shell::fixture::Fx::default();
        fx.thread("t-drift", 1, json!({"runtimeMode": "turbo"}));
        let db = fixture(dir.path(), &fx.0);
        assert_eq!(snapshot(&db), Err("payload_drift"));
    }
}
