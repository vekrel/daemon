//! `orchestration.getArchivedShellSnapshot` (`orchestration:read`): `ws.ts:1736-1762`.
//!
//! One read transaction (`ShellStream.loadShellSnapshotParts`): the archived thread shells
//! (`shell::build_threads(Archive)`), `ProjectStoreV2.listShells()` and
//! `latestApplicationSequence`; the body is `OrchestrationV2ArchivedShellSnapshot`
//! `{schemaVersion, snapshotSequence, projects, threads}`. Node then fills
//! `projects[*].repositoryIdentity` from its warm enrichment cache (`enrichProjectShells`); Rust
//! answers the cold `null`, so this tag is shadow-only (`handlers::SHADOW_ONLY_KEYS`).
//!
//! Declines (Node answers), logged with a reason: a payload that is not an object, any builder
//! decline (`shell::Decline::reason`), a project row Rust cannot reproduce
//! (`project_not_reproducible`), a value the seam's serde encoding would write unlike
//! `JSON.stringify` (`number_format`), and `db::read`'s `schema_unknown` / `db_busy` / `db_error`.
use crate::{
    db::read::StateDb,
    handlers::{HandlerCtx, projects},
    http_seam::{Compare, ENRICHMENT, diff_body},
    rpc_seam::UnaryHandler,
    shell::{self, Location},
};
use futures_util::{FutureExt, future::BoxFuture};
use serde_json::{Value, json};
use std::sync::{Arc, OnceLock};

pub const TAG: &str = "orchestration.getArchivedShellSnapshot";

/// Shadow compare: Node's warm `repositoryIdentity` against Rust's `null` is a mismatch labelled
/// `enrichment` (it never hides another path).
const COMPARE: Compare = Compare {
    enrich: &["$.value.projects[*].repositoryIdentity"],
    ..Compare::DEFAULT
};

#[derive(Default)]
pub struct ArchivedShell {
    /// Opened on the first request, from `ctx.state_dir`.
    db: OnceLock<Arc<StateDb>>,
}

impl UnaryHandler for ArchivedShell {
    fn tag(&self) -> &'static str {
        TAG
    }
    fn required_scope(&self) -> &'static str {
        "orchestration:read"
    }
    fn handle<'a>(
        &'a self,
        payload: Value,
        ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Result<Value, Value>>> {
        let db = self
            .db
            .get_or_init(|| Arc::new(StateDb::new(&ctx.state_dir)))
            .clone();
        async move {
            let r = tokio::task::spawn_blocking(move || snapshot(&db, &payload)).await;
            match r.ok()? {
                Ok(v) => Some(Ok(v)),
                Err(reason) => {
                    tracing::info!(tag = TAG, reason, "archived shell declined");
                    None
                }
            }
        }
        .boxed()
    }
    fn shadow_diff(&self, node: &str, rust: &str) -> (&'static str, &'static str, String) {
        shadow_diff(node, rust)
    }
}

/// The Exit Success value, or the decline reason.
pub fn snapshot(db: &StateDb, payload: &Value) -> Result<Value, &'static str> {
    // `Schema.Struct({})`: any object (excess keys ignored); anything else is Node's decode error.
    if !payload.is_object() {
        return Err("payload");
    }
    let (threads, projects, sequence) = db
        .read(|c| {
            Ok((
                shell::build_threads(c, Location::Archive),
                projects::shells(c)?,
                shell::latest_application_sequence(c)?,
            ))
        })
        .map_err(|d| d.reason())?;
    let threads = threads.map_err(|d| d.reason())?;
    let projects = projects.ok_or("project_not_reproducible")?;
    let v = json!({
        "schemaVersion": shell::SCHEMA_VERSION,
        "snapshotSequence": sequence,
        "projects": projects,
        "threads": threads,
    });
    // The seam writes the Exit with serde: serve only what it writes as `JSON.stringify` does.
    if serde_json::to_vec(&v).ok() != Some(crate::effect_json::to_vec(&v)) {
        return Err("number_format");
    }
    Ok(v)
}

/// Two successful Exits at different `snapshotSequence`s are `sequence_skew` (a write landed
/// between Node's read and Rust's), not a mismatch; anything else is compared with `COMPARE`.
fn shadow_diff(node: &str, rust: &str) -> (&'static str, &'static str, String) {
    let seq = |t: &str| {
        let v: Value = serde_json::from_str(t).ok()?;
        (v["_tag"] == "Success").then(|| v["value"]["snapshotSequence"].as_i64())?
    };
    if let (Some(a), Some(b)) = (seq(node), seq(rust))
        && a != b
    {
        let path = "$.value.snapshotSequence".to_owned();
        return ("sequence_skew", "snapshotSequence", path);
    }
    match diff_body(&COMPARE, node.as_bytes(), rust.as_bytes()) {
        Some((ENRICHMENT, path)) => ("mismatch", ENRICHMENT, path),
        Some((_, path)) => ("mismatch", "exit", path),
        None => ("mismatch", "exit", "$".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::read::tests::fixture;
    use crate::shell::fixture::{Fx, T0, at, thread_payload};
    use crate::shell::tests::INDEXES;

    const PROJECT: &str = "INSERT INTO projection_projects (project_id, title, workspace_root, \
        default_model_selection_json, default_thread_env_mode, auto_pull, favicon_path, \
        project_icon_json, scripts_json, created_at, updated_at, deleted_at) VALUES \
        ('project-1', 'P', '/w', '{\"instanceId\":\"codex\",\"model\":\"m\"}', 'local', 1, \
        'f.png', '{\"kind\":\"emoji\",\"emoji\":\"x\"}', '[]', 'c', 'u', NULL), \
        ('gone', 'G', '/g', NULL, NULL, 0, NULL, NULL, '[]', 'b', 'u', 'd');";

    fn run(sql: &str, payload: Value) -> Result<String, &'static str> {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), &format!("{INDEXES}{PROJECT}{sql}"));
        snapshot(&db, &payload).map(|v| String::from_utf8(crate::effect_json::to_vec(&v)).unwrap())
    }

    fn ids(body: &str) -> Vec<String> {
        let v: Value = serde_json::from_str(body).unwrap();
        v["threads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["id"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn no_archived_threads_gives_projects_and_the_sequence() {
        let mut fx = Fx::default();
        fx.thread("active", 1, json!({})).event(7, "project", 1);
        let body = run(&fx.0, json!({})).unwrap();
        assert_eq!(
            body,
            concat!(
                r#"{"schemaVersion":2,"snapshotSequence":7,"projects":[{"id":"project-1","title":"P","#,
                r#""workspaceRoot":"/w","repositoryIdentity":null,"defaultModelSelection":{"instanceId":"codex","model":"m"},"#,
                r#""defaultThreadEnvMode":"local","autoPull":true,"faviconPath":"f.png","#,
                r#""projectIcon":{"kind":"emoji","emoji":"x"},"scripts":[],"createdAt":"c","updatedAt":"u"}],"#,
                r#""threads":[]}"#
            )
        );
        // Excess payload keys are ignored, as `Schema.Struct({})` does.
        assert_eq!(run(&fx.0, json!({"x": 1})).unwrap(), body);
    }

    #[test]
    fn only_archived_threads_in_nodes_order() {
        let mut fx = Fx::default();
        fx.thread("active", 1, json!({}))
            .thread("b", 3, json!({"archivedAt": at(3)}))
            .thread("a", 2, json!({"archivedAt": at(2)}))
            .thread("gone", 4, json!({"archivedAt": T0, "deletedAt": T0}));
        let body = run(&fx.0, json!({})).unwrap();
        assert_eq!(ids(&body), ["a", "b"]);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["snapshotSequence"], 0);
        assert_eq!(v["threads"][0]["archivedAt"], at(2));
    }

    #[test]
    fn legacy_threads_serve_or_decline_like_the_builder() {
        // A migrated v1 thread: Node's shell read never imports, so it is read like the others.
        let mut fx = Fx::default();
        fx.thread(
            "v1",
            1,
            json!({"archivedAt": T0, "historyOrigin": "v1_import"}),
        );
        assert_eq!(ids(&run(&fx.0, json!({})).unwrap()), ["v1"]);
        // A legacy single linked PR is not ported: the whole snapshot declines.
        let mut p = thread_payload(
            "pr",
            json!({"archivedAt": T0, "linkedPullRequest": {"projectId": "p", "repository": "o/r",
                "number": 1, "url": "https://github.com/o/r/pull/1"}}),
        );
        p.as_object_mut().unwrap().remove("pullRequests");
        fx.thread_raw("pr", &p);
        assert_eq!(run(&fx.0, json!({})), Err("not_ported"));
    }

    #[test]
    fn unordered_rows_decline() {
        let rows = |archived: Value| {
            let mut fx = Fx::default();
            fx.thread("t", 1, json!({"archivedAt": archived}))
                .run("t", 1, "completed", json!({}))
                .item(
                    "t",
                    "a",
                    Some(1),
                    "command_execution",
                    "running",
                    json!({"input": "x"}),
                )
                .item(
                    "t",
                    "b",
                    Some(1),
                    "command_execution",
                    "running",
                    json!({"input": "y"}),
                );
            fx.0
        };
        assert_eq!(run(&rows(T0.into()), json!({})), Err("not_ported"));
        // The same rows on an active thread do not concern the archived snapshot.
        assert_eq!(
            ids(&run(&rows(Value::Null), json!({})).unwrap()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn declines_payloads_rows_and_drift() {
        for p in [json!(null), json!([]), json!("x"), json!(1)] {
            assert_eq!(run("", p), Err("payload"));
        }
        let bad = "UPDATE projection_projects SET title = ' P' WHERE project_id = 'project-1';";
        assert_eq!(run(bad, json!({})), Err("project_not_reproducible"));
        let mut fx = Fx::default();
        fx.thread("d", 1, json!({"archivedAt": T0, "runtimeMode": "turbo"}));
        assert_eq!(run(&fx.0, json!({})), Err("payload_drift"));
    }

    #[test]
    fn snapshot_leaves_the_db_file_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut fx = Fx::default();
        fx.thread("a", 1, json!({"archivedAt": T0}))
            .event(3, "project", 1);
        let db = fixture(dir.path(), &format!("{INDEXES}{PROJECT}{}", fx.0));
        let files = || {
            let mut v: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| {
                    let p = e.unwrap().path();
                    (p.clone(), std::fs::read(&p).unwrap())
                })
                .collect();
            v.sort();
            v
        };
        let before = files();
        for _ in 0..3 {
            assert!(snapshot(&db, &json!({})).is_ok());
        }
        assert!(files() == before, "a snapshot changed the DB files");
    }

    #[test]
    fn shadow_classifies_skew_enrichment_and_mismatches() {
        let exit = |seq: i64, identity: Value, title: &str| {
            json!({"_tag": "Success", "value": {"schemaVersion": 2, "snapshotSequence": seq,
                "projects": [{"id": "p", "title": title, "repositoryIdentity": identity}],
                "threads": []}})
            .to_string()
        };
        let rust = exit(5, Value::Null, "P");
        assert_eq!(
            shadow_diff(&exit(6, Value::Null, "Q"), &rust),
            (
                "sequence_skew",
                "snapshotSequence",
                "$.value.snapshotSequence".into()
            )
        );
        assert_eq!(
            shadow_diff(&exit(5, json!({"name": "r"}), "P"), &rust),
            (
                "mismatch",
                ENRICHMENT,
                "$.value.projects[0].repositoryIdentity".into()
            )
        );
        // Enrichment never hides another difference.
        assert_eq!(
            shadow_diff(&exit(5, json!({"name": "r"}), "Q"), &rust),
            ("mismatch", "exit", "$.value.projects[0].title".into())
        );
        // Node failed: a mismatch, never a skew.
        let fail = json!({"_tag": "Failure", "cause": []}).to_string();
        assert_eq!(shadow_diff(&fail, &rust).0, "mismatch");
    }
}
