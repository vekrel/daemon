//! `orchestration.getTurnItem` (`orchestration:read`): `ThreadManagementService.getTurnItem`
//! (`ensureProjectionTranscript`, then `ProjectionStore.ts:5196-5206`, then
//! `projectTurnItemForDetail`, `WireProjection.ts:179-207`).
//!
//! Node decodes the row's `payload_json` with `OrchestrationV2TurnItemJson` and encodes it with
//! `OrchestrationV2TurnItem`. For a row that is already in the canonical encoded form (keys in
//! schema order, no unknown keys, canonical dates and strings, safe integers) that round trip is
//! the identity, so Rust checks the row against a port of the schema and sends it as stored.
//! Everything else declines (Node answers), logged with a reason:
//! - `legacy_thread`: the thread came from v1 (an `orchestration_v2_legacy_imports` or v1
//!   `projection_threads` row). Node's first read of such a thread imports its transcript (a
//!   write), so Rust never answers for one, imported or not. Decided before the item is read.
//! - `payload`: a payload Node's schema rejects or rewrites (untrimmed ids, unknown keys).
//! - `type_not_ported`: `notification`, `user_message`, `user_input_request`, `file_change`,
//!   `handoff`, `dynamic_tool` (transforms, or `projectTurnItemForDetail` rewrites them).
//! - `not_canonical`: a row the round trip would change, or that Node fails to decode.
//! - `truncated`: a `command_execution` / `subagent` text `projectTurnItemForDetail` would cut.
//! - `schema_unknown` / `db_busy` / `db_error`: `db::read`.
use crate::{
    db::read::{Decline, StateDb},
    handlers::HandlerCtx,
    rpc_seam::UnaryHandler,
};
use futures_util::{FutureExt, future::BoxFuture};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Map, Value, json};
use std::sync::{Arc, OnceLock};

pub const TAG: &str = "orchestration.getTurnItem";

#[derive(Default)]
pub struct TurnItem {
    /// Opened on the first request, from `ctx.state_dir` (keeps the gate's cached verdict).
    db: OnceLock<Arc<StateDb>>,
}

impl UnaryHandler for TurnItem {
    fn default_mode(&self) -> crate::config::Mode {
        crate::config::Mode::Serve
    }
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
            let r = tokio::task::spawn_blocking(move || get_turn_item(&db, &payload)).await;
            match r.ok()? {
                Ok(v) => Some(Ok(v)),
                Err(reason) => {
                    tracing::info!(tag = TAG, reason, "turn item declined");
                    None
                }
            }
        }
        .boxed()
    }
}

/// The Exit Success value, or the decline reason.
pub fn get_turn_item(db: &StateDb, payload: &Value) -> Result<Value, &'static str> {
    let (thread_id, item_id) = decode(payload).ok_or("payload")?;
    let row = db
        .read(|c| {
            if legacy_thread(c, thread_id)? {
                return Ok(Err("legacy_thread"));
            }
            let payload_json: Option<String> = c
                .query_row(
                    "SELECT payload_json FROM orchestration_v2_projection_turn_items \
                     WHERE turn_item_id = ?1 AND thread_id = ?2",
                    [item_id, thread_id],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(Ok(payload_json))
        })
        .map_err(Decline::reason)??;
    let Some(text) = row else {
        return Ok(json!({ "item": null }));
    };
    let mut item = crate::effect_json::parse(&text).ok_or("not_canonical")?;
    project(&mut item)?;
    Ok(json!({ "item": item }))
}

/// `OrchestrationV2GetTurnItemInput` as Effect decodes it, where the decoded value is the input:
/// `threadId` / `itemId` already trimmed and non-blank, `revision` a string (Node ignores it).
fn decode(p: &Value) -> Option<(&str, &str)> {
    let m = p.as_object()?;
    if !m
        .keys()
        .all(|k| matches!(k.as_str(), "threadId" | "itemId" | "revision"))
    {
        return None;
    }
    let id = |k| m.get(k)?.as_str().filter(|s| tne(s));
    if m.get("revision").is_some_and(|r| !r.is_string()) {
        return None;
    }
    Some((id("threadId")?, id("itemId")?))
}

/// A v1 thread: Node's `ensureTranscript` would import it on first read (`transcript_imported_at
/// IS NULL`, `LegacyV1ThreadImporter.ts:684-753`). Imported ones are declined too: Rust does not
/// need to know whether Node's import already ran.
fn legacy_thread(c: &Connection, thread_id: &str) -> rusqlite::Result<bool> {
    let imported: bool = c.query_row(
        "SELECT EXISTS (SELECT 1 FROM orchestration_v2_legacy_imports WHERE thread_id = ?1)",
        [thread_id],
        |r| r.get(0),
    )?;
    if imported {
        return Ok(true);
    }
    // v1's own table: a thread whose shell import has not run yet. Absent once v1 is gone.
    let v1: bool = c.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'projection_threads')",
        [],
        |r| r.get(0),
    )?;
    Ok(v1
        && c.query_row(
            "SELECT EXISTS (SELECT 1 FROM projection_threads WHERE thread_id = ?1)",
            [thread_id],
            |r| r.get(0),
        )?)
}

/// `projectTurnItemForDetail` for the ported types: the identity, as long as the item is
/// canonical and no text is over `MAX_ON_DEMAND_BYTES`, except that the optional text it
/// reassigns (`output`, `progress`) is sent as `null` when absent (the RPC encodes `undefined`
/// so), in its schema position.
fn project(item: &mut Value) -> Result<(), &'static str> {
    let m = item.as_object_mut().ok_or("not_canonical")?;
    let ty = m.get("type").and_then(Value::as_str).unwrap_or_default();
    let fields = fields_for(ty).ok_or("type_not_ported")?;
    if !obj(m, &fields) {
        return Err("not_canonical");
    }
    // `truncateDetail` leaves a string alone when its UTF-8 length is within the limit (its
    // UTF-16 length is never larger).
    let cut: &[&str] = match ty {
        "command_execution" => &["input", "output"],
        "subagent" => &["prompt", "progress", "result"],
        _ => &[],
    };
    let long = cut.iter().any(|k| {
        m.get(*k)
            .and_then(Value::as_str)
            .is_some_and(|s| s.len() > MAX_ON_DEMAND_BYTES)
    });
    if long {
        return Err("truncated");
    }
    let (after, key) = match ty {
        "command_execution" => ("input", "output"),
        "subagent" => ("prompt", "progress"),
        _ => return Ok(()),
    };
    if !m.contains_key(key) {
        let at = m.keys().position(|k| k == after).expect("required field") + 1;
        m.shift_insert(at, key.to_owned(), Value::Null);
    }
    Ok(())
}

const MAX_ON_DEMAND_BYTES: usize = 256 * 1024;

/// One schema node, as far as the canonical check needs it.
enum T {
    /// `Schema.String`.
    Str,
    /// `TrimmedNonEmptyString` (and the entity ids built on it), with its extra checks.
    Tne(Check),
    Bool,
    /// `Schema.Int` (a safe integer) at or above the bound.
    Int(i64),
    /// `Schema.DateTimeUtc`: encoded as `toISOString`.
    Date,
    Lit(&'static [&'static str]),
    Null(&'static T),
    Arr(&'static T),
    /// `[]` only: the element schema is not ported (`attachments`).
    EmptyArr,
    Obj(&'static [F]),
    /// Members told apart by a literal (`type` or `_tag`): the first that fits.
    Union(&'static [&'static [F]]),
}

enum Check {
    None,
    /// `isMaxLength` (UTF-16 units).
    Max(usize),
    /// `providerInstance.ts` `slugSchema`: at most 64, `/^[a-zA-Z][a-zA-Z0-9_-]*$/`.
    Slug,
    /// `ToolActivityNativeAppReference` `appId`: at most 512, `/^[A-Za-z0-9._-]+$/u`.
    AppId,
}

/// A struct field: name, `Schema.optional`, schema.
struct F(&'static str, bool, T);

const TNE: T = T::Tne(Check::None);
const SLUG: T = T::Tne(Check::Slug);
const URL: T = T::Tne(Check::Max(4096));
const POS: T = T::Int(1);
const NON_NEG: T = T::Int(0);
const SAFE: i64 = (1 << 53) - 1;

const NATIVE_APP: T = T::Union(&[
    &[
        F("_tag", false, T::Lit(&["app-id"])),
        F("appId", false, T::Tne(Check::AppId)),
    ],
    &[
        F("_tag", false, T::Lit(&["display-name"])),
        F("displayName", false, T::Tne(Check::Max(160))),
    ],
]);

/// `ToolActivityIcon` (`providerRuntime.ts:409`).
const ICON: T = T::Union(&[
    &[
        F("_tag", false, T::Lit(&["website"])),
        F("pageUrl", false, URL),
        F("faviconUrl", true, URL),
        F("faviconUrlDark", true, URL),
    ],
    &[
        F("_tag", false, T::Lit(&["native-app"])),
        F("app", false, NATIVE_APP),
    ],
    &[
        F("_tag", false, T::Lit(&["themed-logo"])),
        F("logoUrl", false, URL),
        F("logoUrlDark", true, URL),
    ],
]);

/// `OrchestrationV2TurnItemBaseFields` (`orchestrationV2.ts`), the Json variant's dates included.
const BASE: &[F] = &[
    F("toolNonExecutionKind", true, T::Str),
    F("toolSurface", true, T::Lit(&["browser", "computer"])),
    F("toolIcon", true, ICON),
    F(
        "toolSource",
        true,
        T::Obj(&[
            F("key", false, T::Tne(Check::Max(512))),
            F("name", false, T::Tne(Check::Max(160))),
            F(
                "kind",
                false,
                T::Lit(&["browser", "computer", "integration"]),
            ),
            F("icon", true, ICON),
        ]),
    ),
    F("id", false, TNE),
    F("threadId", false, TNE),
    F("runId", false, T::Null(&TNE)),
    F("nodeId", false, T::Null(&TNE)),
    F("providerThreadId", false, T::Null(&TNE)),
    F("providerTurnId", false, T::Null(&TNE)),
    F(
        "nativeItemRef",
        false,
        T::Null(&T::Obj(&[
            F("driver", false, SLUG),
            F("nativeId", false, T::Null(&TNE)),
            F("strength", false, T::Lit(&["strong", "weak", "none"])),
            F("fingerprint", true, TNE),
            F("ordinal", true, NON_NEG),
        ])),
    ),
    F("parentItemId", false, T::Null(&TNE)),
    F("ordinal", false, NON_NEG),
    F(
        "status",
        false,
        T::Lit(&[
            "idle",
            "pending",
            "running",
            "waiting",
            "completed",
            "failed",
            "cancelled",
            "interrupted",
        ]),
    ),
    F("title", false, T::Null(&T::Str)),
    F("startedAt", false, T::Null(&T::Date)),
    F("completedAt", false, T::Null(&T::Date)),
    F("updatedAt", false, T::Date),
];

const MESSAGE: &[F] = &[F("message", false, T::Str)];

/// The fields after `type` of each ported `OrchestrationV2TurnItemJson` member.
fn specific(ty: &str) -> Option<&'static [F]> {
    Some(match ty {
        "assistant_message" => &[
            F("messageId", false, TNE),
            F("text", false, T::Str),
            F("attachments", true, T::EmptyArr),
            F("streaming", false, T::Bool),
        ],
        "reasoning" => &[F("text", false, T::Str), F("streaming", false, T::Bool)],
        "proposed_plan" => &[
            F("planId", false, TNE),
            F("markdown", false, T::Str),
            F("streaming", false, T::Bool),
        ],
        "todo_list" => &[
            F("planId", false, TNE),
            F(
                "steps",
                false,
                T::Arr(&T::Obj(&[
                    F("id", false, TNE),
                    F("text", false, TNE),
                    F(
                        "status",
                        false,
                        T::Lit(&["pending", "running", "completed"]),
                    ),
                    F("durationAnchorAt", true, T::Str),
                    F("durationMs", true, NON_NEG),
                ])),
            ),
            F("explanation", true, T::Str),
        ],
        "command_execution" => &[
            F("input", false, T::Str),
            F("output", true, T::Str),
            F("outputOmitted", true, T::Bool),
            F("outputIndicatesFailure", true, T::Bool),
            F("exitCode", true, T::Int(-SAFE)),
        ],
        "file_search" => &[
            F("pattern", true, T::Str),
            F(
                "results",
                true,
                T::Arr(&T::Obj(&[
                    F("fileName", false, TNE),
                    F("line", true, POS),
                    F("column", true, POS),
                    F("preview", true, T::Str),
                ])),
            ),
        ],
        "web_search" => &[
            F("patterns", true, T::Arr(&T::Str)),
            F(
                "results",
                true,
                T::Arr(&T::Obj(&[
                    F("title", true, T::Str),
                    F("url", true, TNE),
                    F("snippet", true, T::Str),
                ])),
            ),
        ],
        "approval_request" => &[
            F("requestId", false, TNE),
            F(
                "requestKind",
                false,
                T::Lit(&[
                    "command",
                    "file-read",
                    "file-change",
                    "mcp-elicitation",
                    "permission",
                ]),
            ),
            F("prompt", true, T::Str),
            F("reason", true, T::Str),
            F(
                "fullAccessOverride",
                true,
                T::Lit(&["ask_rule", "provider_check"]),
            ),
            F("appName", true, T::Str),
            F(
                "options",
                true,
                T::Arr(&T::Obj(&[
                    F(
                        "decision",
                        false,
                        T::Lit(&[
                            "accept",
                            "acceptForSession",
                            "acceptAlways",
                            "decline",
                            "cancel",
                        ]),
                    ),
                    F("label", false, TNE),
                    F("warning", true, TNE),
                ])),
            ),
        ],
        "checkpoint" => &[
            F("checkpointId", false, TNE),
            F("scopeId", false, TNE),
            F(
                "files",
                false,
                T::Arr(&T::Obj(&[
                    F("path", false, TNE),
                    F("kind", false, TNE),
                    F("additions", false, NON_NEG),
                    F("deletions", false, NON_NEG),
                ])),
            ),
        ],
        "run_interrupt_request" | "run_interrupt_result" | "system_notice" => MESSAGE,
        "error" => &[
            F(
                "failure",
                false,
                T::Obj(&[
                    F(
                        "class",
                        false,
                        T::Lit(&[
                            "usage_limit",
                            "provider_error",
                            "transport_error",
                            "permission_error",
                            "validation_error",
                            "unknown",
                        ]),
                    ),
                    F("message", false, T::Tne(Check::Max(4096))),
                    F("code", false, T::Null(&T::Tne(Check::Max(128)))),
                    F("retryable", false, T::Null(&T::Bool)),
                    F("resetAt", true, T::Null(&T::Str)),
                ]),
            ),
            F(
                "retry",
                true,
                T::Obj(&[
                    F("attempt", false, POS),
                    F("maxAttempts", false, T::Null(&POS)),
                    F("retryDelayMs", false, T::Null(&NON_NEG)),
                ]),
            ),
        ],
        "compaction" => &[
            F("driver", false, T::Null(&SLUG)),
            F("summary", true, T::Str),
            F("beforeTokenCount", true, NON_NEG),
            F("afterTokenCount", true, NON_NEG),
        ],
        "fork" => &[
            F(
                "source",
                false,
                T::Union(&[
                    &[
                        F("type", false, T::Lit(&["run"])),
                        F("threadId", false, TNE),
                        F("runId", false, TNE),
                    ],
                    &[F("type", false, T::Lit(&["node"])), F("nodeId", false, TNE)],
                    &[
                        F("type", false, T::Lit(&["provider_thread"])),
                        F("providerThreadId", false, TNE),
                        F("providerTurnId", true, TNE),
                    ],
                ]),
            ),
            F("targetThreadId", false, TNE),
            F("providerThreadId", true, TNE),
        ],
        "thread_created" => &[
            F("targetThreadId", false, TNE),
            F("targetRunId", false, T::Null(&TNE)),
            F("targetProviderInstanceId", false, SLUG),
            F("targetModel", false, TNE),
        ],
        // `OrchestrationV2SecretRequestFields` (it carries `type` itself, in the same place).
        "secret_request" => &[
            F("label", false, TNE),
            F("reason", false, T::Str),
            F("placeholder", true, T::Str),
            F(
                "secretStatus",
                false,
                T::Lit(&["pending", "saved", "declined", "cancelled"]),
            ),
        ],
        "subagent" => &[
            F("subagentId", false, TNE),
            F("origin", false, T::Lit(&["provider_native", "app_owned"])),
            F("driver", false, SLUG),
            F("providerInstanceId", false, SLUG),
            F("childThreadId", false, T::Null(&TNE)),
            F("prompt", false, T::Str),
            F("progress", true, T::Str),
            F("result", false, T::Null(&T::Str)),
        ],
        _ => return None,
    })
}

/// Base fields, `type`, then the member's own fields. A member field named like a base field
/// replaces it in place (object spread: `fork`'s optional `providerThreadId`).
fn fields_for(ty: &str) -> Option<Vec<&'static F>> {
    static TYPE: [F; 1] = [F("type", false, T::Str)];
    let mut fields: Vec<&F> = BASE.iter().chain(&TYPE).collect();
    for f in specific(ty)? {
        match fields.iter().position(|b| b.0 == f.0) {
            Some(i) => fields[i] = f,
            None => fields.push(f),
        }
    }
    Some(fields)
}

/// `m` is exactly the encoded form of a struct with `fields`: keys in field order, every
/// required field present, nothing else.
fn obj(m: &Map<String, Value>, fields: &[&F]) -> bool {
    let mut at = 0;
    for (k, v) in m {
        let Some(i) = fields[at..].iter().position(|f| f.0 == k) else {
            return false; // unknown, or out of order
        };
        if fields[at..at + i].iter().any(|f| !f.1) || !check(&fields[at + i].2, v) {
            return false;
        }
        at += i + 1;
    }
    fields[at..].iter().all(|f| f.1)
}

fn check(t: &T, v: &Value) -> bool {
    match t {
        T::Str => v.is_string(),
        T::Tne(c) => v.as_str().is_some_and(|s| tne(s) && checked(c, s)),
        T::Bool => v.is_boolean(),
        T::Int(min) => v.as_i64().is_some_and(|n| n >= *min && n <= SAFE),
        T::Date => v
            .as_str()
            .is_some_and(|s| crate::effect_json::date(s).is_some()),
        T::Lit(l) => v.as_str().is_some_and(|s| l.contains(&s)),
        T::Null(t) => v.is_null() || check(t, v),
        T::Arr(t) => v.as_array().is_some_and(|a| a.iter().all(|e| check(t, e))),
        T::EmptyArr => v.as_array().is_some_and(Vec::is_empty),
        T::Obj(f) => v
            .as_object()
            .is_some_and(|m| obj(m, &f.iter().collect::<Vec<_>>())),
        T::Union(members) => v.as_object().is_some_and(|m| {
            members
                .iter()
                .any(|f| obj(m, &f.iter().collect::<Vec<_>>()))
        }),
    }
}

/// Trimmed (`String.prototype.trim`) and non-empty: `TrimmedNonEmptyString` decodes it to itself.
fn tne(s: &str) -> bool {
    !s.is_empty() && s.trim_matches(crate::machine::is_js_space) == s
}

fn checked(c: &Check, s: &str) -> bool {
    let len = || s.encode_utf16().count();
    let b = s.as_bytes();
    match c {
        Check::None => true,
        Check::Max(n) => len() <= *n,
        Check::Slug => {
            len() <= 64
                && b[0].is_ascii_alphabetic()
                && b.iter()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
        }
        Check::AppId => {
            len() <= 512
                && b.iter()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::read::tests::fixture;

    const ITEMS: &str = include_str!("../../tests/fixtures/turn_items.json");

    /// The fixture items as (served, reason, payload_json text).
    fn items() -> Vec<(bool, String, String)> {
        let v: Vec<Value> = serde_json::from_str(ITEMS).unwrap();
        v.iter()
            .map(|e| {
                let reason = e["reason"].as_str().unwrap_or_default().to_owned();
                (e["served"] == true, reason, e["item"].to_string())
            })
            .collect()
    }

    /// What Node sends for fixture item `i`: its `sent` form, else the item as stored.
    fn sent(i: usize) -> String {
        let v: Vec<Value> = serde_json::from_str(ITEMS).unwrap();
        let e = &v[i];
        e.get("sent").unwrap_or(&e["item"]).to_string()
    }

    fn insert_sql(thread: &str, id: &str, payload: &str) -> String {
        let q = |s: &str| s.replace('\'', "''");
        format!(
            "INSERT INTO orchestration_v2_projection_turn_items VALUES \
             ('{}', '{}', NULL, NULL, NULL, NULL, NULL, 0, 't', 's', 'u', '{}');\n",
            q(id),
            q(thread),
            q(payload)
        )
    }

    fn db_with(dir: &std::path::Path, extra: &str) -> StateDb {
        let mut sql = String::new();
        for (_, _, p) in items() {
            let v: Value = serde_json::from_str(&p).unwrap();
            sql += &insert_sql("thread-a", v["id"].as_str().unwrap(), &p);
        }
        fixture(dir, &(sql + extra))
    }

    fn req(thread: &str, item: &str) -> Value {
        json!({"threadId": thread, "itemId": item})
    }

    #[test]
    fn found_items_are_sent_as_stored() {
        let dir = tempfile::tempdir().unwrap();
        let db = db_with(dir.path(), "");
        for (i, (served, reason, p)) in items().into_iter().enumerate() {
            let v: Value = serde_json::from_str(&p).unwrap();
            let r = get_turn_item(&db, &req("thread-a", v["id"].as_str().unwrap()));
            if served {
                let got = serde_json::to_string(&r.expect(&p)).unwrap();
                assert_eq!(got, format!(r#"{{"item":{}}}"#, sent(i)));
            } else {
                assert_eq!(r, Err(reason.as_str()), "{p}");
            }
        }
    }

    #[test]
    fn a_missing_item_is_item_null() {
        let dir = tempfile::tempdir().unwrap();
        let db = db_with(dir.path(), "");
        for p in [
            req("thread-a", "nope"),
            req("thread-other", "ti-reasoning"),
            json!({"threadId": "thread-a", "itemId": "nope", "revision": "r1"}),
        ] {
            let r = get_turn_item(&db, &p).unwrap();
            assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"item":null}"#);
        }
        // `revision` is decoded and ignored.
        let a = get_turn_item(&db, &req("thread-a", "ti-cmd"));
        let b = get_turn_item(
            &db,
            &json!({"threadId": "thread-a", "itemId": "ti-cmd", "revision": "x"}),
        );
        assert!(a.is_ok());
        assert_eq!(a, b);
    }

    #[test]
    fn legacy_threads_decline_before_the_item_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let item = items()[0].2.replace("thread-a", "thread-legacy");
        let mut sql = insert_sql("thread-legacy", "ti-reasoning", &item);
        sql += &insert_sql(
            "thread-done",
            "ti-reasoning-2",
            &item.replace("thread-legacy", "thread-done"),
        );
        sql += "INSERT INTO orchestration_v2_legacy_imports VALUES
                  ('thread-legacy', 't', 't', NULL, 0, NULL),
                  ('thread-done', 't', 't', 't', 3, NULL);
                CREATE TABLE projection_threads (thread_id TEXT PRIMARY KEY);
                INSERT INTO projection_threads VALUES ('thread-v1');";
        let db = db_with(dir.path(), &sql);
        let file = dir.path().join("statev2.sqlite");
        let before = std::fs::read(&file).unwrap();
        for (t, i) in [
            ("thread-legacy", "ti-reasoning"),
            ("thread-done", "ti-reasoning-2"),
            ("thread-legacy", "missing"),
            ("thread-v1", "missing"),
        ] {
            assert_eq!(get_turn_item(&db, &req(t, i)), Err("legacy_thread"), "{t}");
        }
        assert!(get_turn_item(&db, &req("thread-a", "ti-reasoning")).is_ok());
        assert_eq!(std::fs::read(&file).unwrap(), before, "DB unchanged");
    }

    #[test]
    fn malformed_payloads_decline() {
        let dir = tempfile::tempdir().unwrap();
        let db = db_with(dir.path(), "");
        for p in [
            json!(null),
            json!([]),
            json!({"threadId": "thread-a"}),
            json!({"itemId": "ti-cmd"}),
            json!({"threadId": 1, "itemId": "ti-cmd"}),
            json!({"threadId": "thread-a", "itemId": ""}),
            json!({"threadId": " thread-a", "itemId": "ti-cmd"}),
            json!({"threadId": "thread-a", "itemId": "ti-cmd\u{a0}"}),
            json!({"threadId": "thread-a", "itemId": "ti-cmd", "revision": 1}),
            json!({"threadId": "thread-a", "itemId": "ti-cmd", "other": 1}),
        ] {
            assert_eq!(get_turn_item(&db, &p), Err("payload"), "{p}");
        }
    }

    #[test]
    fn rows_node_would_change_or_reject_decline() {
        let dir = tempfile::tempdir().unwrap();
        let base: Value = serde_json::from_str(&items()[5].2).unwrap(); // ti-cmd
        let with = |k: &str, v: Value| {
            let mut m = base.clone();
            m[k] = v;
            m.to_string()
        };
        let big = "x".repeat(MAX_ON_DEMAND_BYTES);
        let cases = [
            ("bad-json", "{\"id\":".to_owned(), "not_canonical"),
            ("lone", r#"{"text":"\ud800"}"#.to_owned(), "not_canonical"),
            ("array", "[]".to_owned(), "not_canonical"),
            ("no-type", r#"{"id":"x"}"#.to_owned(), "type_not_ported"),
            (
                "future",
                with("type", json!("future_thing")),
                "type_not_ported",
            ),
            ("neg", with("ordinal", json!(-1)), "not_canonical"),
            (
                "unsafe",
                with("ordinal", json!(9007199254740992u64)),
                "not_canonical",
            ),
            ("status", with("status", json!("done")), "not_canonical"),
            (
                "missing",
                {
                    let mut m = base.clone();
                    m.as_object_mut().unwrap().shift_remove("input");
                    m.to_string()
                },
                "not_canonical",
            ),
            (
                "long-out",
                with("output", json!(format!("{big}y"))),
                "truncated",
            ),
            (
                "long-in",
                with("input", json!(format!("é{big}"))),
                "truncated",
            ),
            ("at-limit", with("output", json!(big)), ""),
        ];
        let mut sql = String::new();
        for (id, p, _) in &cases {
            sql += &insert_sql("thread-x", id, p);
        }
        let db = fixture(dir.path(), &sql);
        for (id, p, want) in cases {
            let r = get_turn_item(&db, &req("thread-x", id));
            match want {
                "" => assert_eq!(
                    serde_json::to_string(&r.unwrap()).unwrap(),
                    format!(r#"{{"item":{p}}}"#)
                ),
                w => assert_eq!(r, Err(w), "{id}"),
            }
        }
    }

    #[test]
    fn string_checks_follow_the_schema() {
        assert!(tne("a b") && !tne(" a") && !tne("a\u{feff}") && !tne(""));
        assert!(checked(&Check::Slug, "codex-2_x") && !checked(&Check::Slug, "2codex"));
        assert!(!checked(&Check::Slug, &"a".repeat(65)) && checked(&Check::Slug, &"a".repeat(64)));
        assert!(checked(&Check::AppId, "com.x-y_z") && !checked(&Check::AppId, "a/b"));
        // UTF-16 units: one astral char is 2.
        assert!(checked(&Check::Max(2), "🎉") && !checked(&Check::Max(1), "🎉"));
    }
}
