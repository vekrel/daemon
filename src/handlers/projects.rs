//! `GET /api/projects`, byte-compatible with the engine's `ProjectService.snapshot`
//! (`project/http.ts:38-51`, `project/ProjectService.ts:156-181`, `:550-563`).
//!
//! Rows come from `ProjectStoreV2.list()`: `projection_projects` where `deleted_at IS NULL`, in
//! `created_at, project_id` order (`orchestration-v2/ProjectStore.ts:105-135`, `:198-202`). Each is
//! decoded with `ProjectDbRow` and encoded with `Project` (`contracts/project.ts:151-166`), so keys
//! come out in schema order. Enrichment is the cold cache's answer: `repositoryIdentity: null` and
//! the row's `faviconPath` (Node fills both in on its own streams). Rust serves only rows whose
//! decode → encode round trip it reproduces exactly; any other row declines the whole request.
use super::{HandlerCtx, auth_session::AuthSession, pairing_links::caller};
use crate::{
    db::read::StateDb,
    http_auth, http_errors,
    http_seam::{Compare, RouteHandler},
    js_string::{trim, units},
};
use axum::{
    body::Bytes,
    http::{Method, Response, StatusCode, request::Parts},
};
use futures_util::{FutureExt, future::BoxFuture};
use serde_json::{Map, Value, json};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub const KEY: &str = "GET /api/projects";

pub struct Projects {
    pub auth: Arc<AuthSession>,
    pub db: Arc<StateDb>,
}

fn declined(why: &str) -> Option<Response<Bytes>> {
    tracing::info!(route = KEY, why, outcome = "declined", "rust projects");
    None
}

impl RouteHandler for Projects {
    fn method_path(&self) -> (Method, &'static str) {
        (Method::GET, "/api/projects")
    }

    fn compare(&self) -> Compare {
        Compare {
            times: &["$.updatedAt"],
            headers: &["content-type", "vary", "access-control-allow-origin"],
            enrich: &[
                "$.projects[*].repositoryIdentity",
                "$.projects[*].faviconPath",
            ],
            ..Compare::DEFAULT
        }
    }

    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        async move {
            let p = match caller(&self.auth, req).await? {
                Ok(p) => p,
                Err(r) => return Some(r),
            };
            if let Some(r) = http_auth::require_scope(&p, "orchestration:read") {
                return Some(r);
            }
            let db = self.db.clone();
            let read = tokio::task::spawn_blocking(move || db.read(rows))
                .await
                .ok()?;
            let rows = match read {
                Ok(rows) => rows,
                Err(d) => return declined(d.reason()),
            };
            let Some(projects) = rows.iter().map(project).collect::<Option<Vec<_>>>() else {
                return declined("row_not_reproducible");
            };
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
            Some(snapshot(projects, now.as_millis() as i64))
        }
        .boxed()
    }
}

/// `ProjectSnapshot` at `now_ms` (`DateTime.formatIso(DateTime.now)`).
fn snapshot(projects: Vec<Value>, now_ms: i64) -> Response<Bytes> {
    let updated_at = super::auth_session::iso_millis(now_ms);
    http_errors::json(
        StatusCode::OK,
        &json!({ "projects": projects, "updatedAt": updated_at }),
    )
}

/// One `projection_projects` row as SQLite holds it.
#[derive(Debug)]
struct Row {
    id: String,
    title: String,
    workspace_root: String,
    model: Option<String>,
    env_mode: Option<String>,
    auto_pull: i64,
    favicon: Option<String>,
    icon: Option<String>,
    scripts: String,
    created_at: String,
    updated_at: String,
    deleted_at: Option<String>,
}

/// `selectRows` with `includeDeleted: false`. A NULL or non-text value where Node's schema wants
/// a string fails the typed read: a decline, as it is Node's 500.
fn rows(c: &rusqlite::Connection) -> rusqlite::Result<Vec<Row>> {
    let mut q = c.prepare(
        "SELECT project_id, title, workspace_root, default_model_selection_json, \
         default_thread_env_mode, auto_pull, favicon_path, project_icon_json, scripts_json, \
         created_at, updated_at, deleted_at FROM projection_projects \
         WHERE deleted_at IS NULL ORDER BY created_at ASC, project_id ASC",
    )?;
    q.query_map([], |r| {
        Ok(Row {
            id: r.get(0)?,
            title: r.get(1)?,
            workspace_root: r.get(2)?,
            model: r.get(3)?,
            env_mode: r.get(4)?,
            auto_pull: r.get(5)?,
            favicon: r.get(6)?,
            icon: r.get(7)?,
            scripts: r.get(8)?,
            created_at: r.get(9)?,
            updated_at: r.get(10)?,
            deleted_at: r.get(11)?,
        })
    })?
    .collect()
}

/// `toProject(row, null)` encoded with `Project`; `None` where Rust cannot match Node's bytes.
fn project(r: &Row) -> Option<Value> {
    let text = |s: &str| trimmed(s).then(|| Value::from(s));
    // A NULL column is `null`; a value must convert.
    let nullable = |v: Option<&str>, f: fn(&str) -> Option<Value>| v.map_or(Some(Value::Null), f);
    Some(json!({
        "id": text(&r.id)?,
        "title": text(&r.title)?,
        "workspaceRoot": text(&r.workspace_root)?,
        "repositoryIdentity": null,
        "faviconPath": nullable(r.favicon.as_deref(), |s| trimmed(s).then(|| s.into()))?,
        "projectIcon": nullable(r.icon.as_deref(), icon)?,
        "defaultModelSelection": nullable(r.model.as_deref(), model)?,
        "defaultThreadEnvMode": match r.env_mode.as_deref() {
            None => Value::Null,
            Some(m @ ("local" | "worktree")) => m.into(),
            Some(_) => return None,
        },
        // `BooleanFromBit`.
        "autoPull": match r.auto_pull {
            0 => false,
            1 => true,
            _ => return None,
        },
        "scripts": scripts(&r.scripts)?,
        // `IsoDateTime` is a plain string: passed through.
        "createdAt": r.created_at,
        "updatedAt": r.updated_at,
        "deletedAt": r.deleted_at,
    }))
}

/// `ProjectStoreV2.listShells()` (`toShell` of each `list()` row, `ProjectStore.ts:56-71`) encoded
/// with `OrchestrationProjectShell` (`contracts/orchestrationProject.ts:8-22`): the `Project`
/// fields in shell order, without `deletedAt`, `repositoryIdentity` the cold `null`. `Ok(None)`:
/// a row Rust cannot reproduce (decline).
pub fn shells(c: &rusqlite::Connection) -> rusqlite::Result<Option<Vec<Value>>> {
    const KEYS: [&str; 12] = [
        "id",
        "title",
        "workspaceRoot",
        "repositoryIdentity",
        "defaultModelSelection",
        "defaultThreadEnvMode",
        "autoPull",
        "faviconPath",
        "projectIcon",
        "scripts",
        "createdAt",
        "updatedAt",
    ];
    Ok(rows(c)?
        .iter()
        .map(|r| {
            let mut p = project(r)?;
            Some(Value::Object(
                KEYS.iter().map(|&k| (k.into(), p[k].take())).collect(),
            ))
        })
        .collect())
}

/// `TrimmedNonEmptyString` that its decode and encode leave unchanged. Untrimmed text, which
/// Effect would trim, declines rather than being trimmed here.
fn trimmed(s: &str) -> bool {
    let u = units(s);
    !u.is_empty() && trim(&u).len() == u.len()
}

/// A JSON object whose keys are all in `allowed`; unknown keys (which Effect drops) decline.
fn object<'a>(v: &'a Value, allowed: &[&str]) -> Option<&'a Map<String, Value>> {
    let o = v.as_object()?;
    o.keys().all(|k| allowed.contains(&k.as_str())).then_some(o)
}

fn text_at(o: &Map<String, Value>, k: &str) -> Option<Value> {
    let s = o.get(k)?.as_str()?;
    trimmed(s).then(|| s.into())
}

fn bool_at(o: &Map<String, Value>, k: &str) -> Option<Value> {
    o.get(k)?.as_bool().map(Value::from)
}

/// `Schema.fromJsonString(ModelSelection)` decoded, then `ModelSelection` encoded:
/// `{instanceId, model, options?}`. Only the canonical form: no legacy `provider`, no legacy
/// options object.
fn model(json: &str) -> Option<Value> {
    let v = crate::effect_json::parse(json)?;
    let o = object(&v, &["instanceId", "model", "options"])?;
    let id = o.get("instanceId")?.as_str()?;
    // `ProviderInstanceId`: /^[a-zA-Z][a-zA-Z0-9_-]*$/, at most 64 chars.
    let slug = id.len() <= 64
        && id.starts_with(|c: char| c.is_ascii_alphabetic())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !slug {
        return None;
    }
    let mut out = Map::new();
    out.insert("instanceId".into(), id.into());
    out.insert("model".into(), text_at(o, "model")?);
    if let Some(opts) = o.get("options") {
        let list = opts
            .as_array()?
            .iter()
            .map(|s| {
                let s = object(s, &["id", "value"])?;
                let value = match s.get("value")? {
                    Value::Bool(b) => Value::Bool(*b),
                    _ => text_at(s, "value")?,
                };
                Some(json!({ "id": text_at(s, "id")?, "value": value }))
            })
            .collect::<Option<Vec<_>>>()?;
        out.insert("options".into(), list.into());
    }
    Some(out.into())
}

const COLORS: [&str; 18] = [
    "gray", "red", "orange", "amber", "yellow", "lime", "green", "emerald", "teal", "cyan", "sky",
    "blue", "indigo", "violet", "purple", "fuchsia", "pink", "rose",
];

/// `StoredProjectIcon` decoded, then `ReceivedProjectIcon` encoded.
fn icon(json: &str) -> Option<Value> {
    let v = crate::effect_json::parse(json)?;
    let color = |o: &Map<String, Value>| {
        let c = o.get("color")?.as_str()?;
        COLORS.contains(&c).then(|| Value::from(c))
    };
    match v.get("kind")?.as_str()? {
        "lucide" => {
            // Legacy `monogramText` / `monogram` (decoded into a monogram) decline.
            let o = object(&v, &["kind", "name", "color"])?;
            let name = o.get("name")?.as_str()?;
            // /^[a-z0-9]+(?:-[a-z0-9]+)*$/, at most 64.
            let ok = name.len() <= 64
                && name.split('-').all(|p| {
                    !p.is_empty() && p.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9'))
                });
            ok.then_some(())?;
            Some(json!({ "kind": "lucide", "name": name, "color": color(o)? }))
        }
        "emoji" => {
            let o = object(&v, &["kind", "emoji"])?;
            let e = o.get("emoji")?.as_str()?;
            (trimmed(e) && units(e).len() <= 32).then(|| json!({ "kind": "emoji", "emoji": e }))
        }
        "monogram" => {
            let o = object(&v, &["kind", "text", "color"])?;
            let t = o.get("text")?.as_str()?;
            // shortcut: the pattern is /^[\p{L}\p{N}][\p{L}\p{N}\p{M}‌‍]*$/u; only ASCII
            // alphanumerics are checked here and anything else declines. Port it if real rows need it.
            let ok = !t.is_empty() && t.len() <= 32 && t.bytes().all(|b| b.is_ascii_alphanumeric());
            ok.then_some(())?;
            Some(json!({ "kind": "monogram", "text": t, "color": color(o)? }))
        }
        _ => None,
    }
}

const ICONS: [&str; 6] = ["play", "test", "lint", "configure", "build", "debug"];

/// `Schema.fromJsonString(Schema.Array(ProjectScript))`, re-encoded in schema order.
fn scripts(json: &str) -> Option<Value> {
    const KEYS: [&str; 9] = [
        "id",
        "name",
        "command",
        "icon",
        "runOnWorktreeCreate",
        "runOnSettle",
        "async",
        "previewUrl",
        "autoOpenPreview",
    ];
    let v = crate::effect_json::parse(json)?;
    let list = v
        .as_array()?
        .iter()
        .map(|s| {
            let o = object(s, &KEYS)?;
            let mut out = Map::new();
            for k in ["id", "name", "command"] {
                out.insert(k.into(), text_at(o, k)?);
            }
            let icon = o.get("icon")?.as_str()?;
            out.insert("icon".into(), ICONS.contains(&icon).then(|| icon.into())?);
            out.insert(
                "runOnWorktreeCreate".into(),
                bool_at(o, "runOnWorktreeCreate")?,
            );
            for k in ["runOnSettle", "async", "previewUrl", "autoOpenPreview"] {
                if o.contains_key(k) {
                    let v = if k == "previewUrl" {
                        text_at(o, k)?
                    } else {
                        bool_at(o, k)?
                    };
                    out.insert(k.into(), v);
                }
            }
            Some(Value::Object(out))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(list.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::read::tests::fixture;

    const COLS: &str = "project_id, title, workspace_root, default_model_selection_json, \
        default_thread_env_mode, auto_pull, favicon_path, project_icon_json, scripts_json, \
        created_at, updated_at, deleted_at";

    fn body(db: &StateDb) -> Option<String> {
        let rows = db.read(rows).ok()?;
        let projects = rows.iter().map(project).collect::<Option<Vec<_>>>()?;
        let r = snapshot(projects, 1_893_456_000_123);
        Some(String::from_utf8(r.body().to_vec()).unwrap())
    }

    fn with(rows: &str) -> (tempfile::TempDir, StateDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(
            dir.path(),
            &format!("INSERT INTO projection_projects ({COLS}) VALUES {rows};"),
        );
        (dir, db)
    }

    /// Expected bytes: Node's `GET /api/projects` for the same rows (`live_differential`
    /// `projects_shadow_matches_node` seeds these rows and compares), `updatedAt` pinned.
    const GOLDEN: &str = include_str!("../../tests/golden/projects.json");

    const GOLDEN_ROWS: &str = include_str!("../../tests/golden/projects_rows.sql");

    #[test]
    fn golden_rows_match_node_in_order_without_deleted_rows() {
        let (_d, db) = with(GOLDEN_ROWS);
        assert_eq!(body(&db).as_deref(), Some(GOLDEN.trim_end()));
    }

    #[test]
    fn empty_table() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), "");
        assert_eq!(
            body(&db).as_deref(),
            Some(r#"{"projects":[],"updatedAt":"2030-01-01T00:00:00.123Z"}"#)
        );
    }

    #[test]
    fn rows_node_reshapes_or_rejects_decline() {
        let row = |model: &str, mode: &str, pull: &str, fav: &str, icon: &str, scripts: &str| {
            format!(
                "('p', 'T', '/w', {model}, {mode}, {pull}, {fav}, {icon}, {scripts}, 'c', 'u', NULL)"
            )
        };
        let ok = row("NULL", "NULL", "0", "NULL", "NULL", "'[]'");
        assert!(body(&with(&ok).1).is_some(), "baseline serves");
        let cases = [
            // Effect trims or rejects these.
            "('p', ' T', '/w', NULL, NULL, 0, NULL, NULL, '[]', 'c', 'u', NULL)".to_owned(),
            "('p', '', '/w', NULL, NULL, 0, NULL, NULL, '[]', 'c', 'u', NULL)".to_owned(),
            "('p', 'T', '/w ', NULL, NULL, 0, NULL, NULL, '[]', 'c', 'u', NULL)".to_owned(),
            "('p', 'T', NULL, NULL, NULL, 0, NULL, NULL, '[]', 'c', 'u', NULL)".to_owned(),
            row("NULL", "NULL", "0", "'\u{a0}x.png'", "NULL", "'[]'"),
            row("NULL", "NULL", "0", "''", "NULL", "'[]'"),
            // Legacy model selection, bad slug, legacy options object, extra key.
            row(
                r#"'{"provider":"codex","model":"m"}'"#,
                "NULL",
                "0",
                "NULL",
                "NULL",
                "'[]'",
            ),
            row(
                r#"'{"instanceId":"1x","model":"m"}'"#,
                "NULL",
                "0",
                "NULL",
                "NULL",
                "'[]'",
            ),
            row(
                r#"'{"instanceId":"x","model":"m","options":{"fast":true}}'"#,
                "NULL",
                "0",
                "NULL",
                "NULL",
                "'[]'",
            ),
            row(
                r#"'{"instanceId":"x","model":"m","x":1}'"#,
                "NULL",
                "0",
                "NULL",
                "NULL",
                "'[]'",
            ),
            row("'not json'", "NULL", "0", "NULL", "NULL", "'[]'"),
            // Env mode, bit.
            row("NULL", "'cloud'", "0", "NULL", "NULL", "'[]'"),
            row("NULL", "NULL", "2", "NULL", "NULL", "'[]'"),
            row("NULL", "NULL", "NULL", "NULL", "NULL", "'[]'"),
            // Icons: legacy monogram, bad name, bad color, long emoji, non-ASCII monogram, unknown kind.
            row(
                "NULL",
                "NULL",
                "0",
                "NULL",
                r#"'{"kind":"lucide","name":"a","color":"red","monogramText":"A"}'"#,
                "'[]'",
            ),
            row(
                "NULL",
                "NULL",
                "0",
                "NULL",
                r#"'{"kind":"lucide","name":"A-b","color":"red"}'"#,
                "'[]'",
            ),
            row(
                "NULL",
                "NULL",
                "0",
                "NULL",
                r#"'{"kind":"lucide","name":"a--b","color":"red"}'"#,
                "'[]'",
            ),
            row(
                "NULL",
                "NULL",
                "0",
                "NULL",
                r#"'{"kind":"lucide","name":"a","color":"black"}'"#,
                "'[]'",
            ),
            row(
                "NULL",
                "NULL",
                "0",
                "NULL",
                &format!(r#"'{{"kind":"emoji","emoji":"{}"}}'"#, "🦀".repeat(17)),
                "'[]'",
            ),
            row(
                "NULL",
                "NULL",
                "0",
                "NULL",
                r#"'{"kind":"monogram","text":"Ü","color":"red"}'"#,
                "'[]'",
            ),
            row("NULL", "NULL", "0", "NULL", r#"'{"kind":"image"}'"#, "'[]'"),
            // Scripts: NULL, not an array, missing key, bad icon, extra key, untrimmed, null optional.
            row("NULL", "NULL", "0", "NULL", "NULL", "NULL"),
            row("NULL", "NULL", "0", "NULL", "NULL", "'{}'"),
            row(
                "NULL",
                "NULL",
                "0",
                "NULL",
                "NULL",
                r#"'[{"id":"a","name":"n","command":"c","icon":"play"}]'"#,
            ),
            row(
                "NULL",
                "NULL",
                "0",
                "NULL",
                "NULL",
                r#"'[{"id":"a","name":"n","command":"c","icon":"run","runOnWorktreeCreate":true}]'"#,
            ),
            row(
                "NULL",
                "NULL",
                "0",
                "NULL",
                "NULL",
                r#"'[{"id":"a","name":"n","command":"c","icon":"play","runOnWorktreeCreate":true,"x":1}]'"#,
            ),
            row(
                "NULL",
                "NULL",
                "0",
                "NULL",
                "NULL",
                r#"'[{"id":"a ","name":"n","command":"c","icon":"play","runOnWorktreeCreate":true}]'"#,
            ),
            row(
                "NULL",
                "NULL",
                "0",
                "NULL",
                "NULL",
                r#"'[{"id":"a","name":"n","command":"c","icon":"play","runOnWorktreeCreate":true,"async":null}]'"#,
            ),
        ];
        for c in cases {
            assert_eq!(body(&with(&c).1), None, "{c}");
        }
    }

    #[test]
    fn order_is_created_at_then_project_id() {
        let (_d, db) = with(
            "('b', 'B', '/b', NULL, NULL, 0, NULL, NULL, '[]', '2', 'u', NULL),
             ('a', 'A', '/a', NULL, NULL, 0, NULL, NULL, '[]', '2', 'u', NULL),
             ('c', 'C', '/c', NULL, NULL, 0, NULL, NULL, '[]', '1', 'u', NULL)",
        );
        let v: Value = serde_json::from_str(&body(&db).unwrap()).unwrap();
        let ids: Vec<_> = v["projects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["c", "a", "b"]);
    }
}
