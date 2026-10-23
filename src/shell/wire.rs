//! Effect Schema decoding of the JSON columns the shell reads, ported schema by schema from
//! `packages/contracts/src` (Engine 2aa67bc). `decode` gives the value as Effect would encode it
//! again: keys in schema order, excess keys dropped, `TrimmedString`s trimmed, decoding defaults
//! filled, `DateTimeUtc` in `toISOString` form. A value Effect would reject is `Err` with its path,
//! and the caller declines (Node's decode fails the whole snapshot with a 500).
use crate::js_string;
use serde_json::{Map, Value};

/// Where a payload stops decoding as Effect decodes it (a JSON path; names, never values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift(pub String);

type R = Result<Value, Drift>;

/// One schema node.
#[derive(Clone, Copy)]
pub enum S {
    /// `Schema.String`.
    Str,
    /// `TrimmedNonEmptyString` (and every `makeEntityId` id), with `isMaxLength` in UTF-16 units.
    NonBlank(Option<usize>),
    /// `ProviderInstanceId` / `ProviderDriverKind`: a non-blank trimmed slug, `^[a-zA-Z][a-zA-Z0-9_-]*$`, 64 max.
    Slug,
    Bool,
    /// `Schema.Int` (a safe integer) at least the bound.
    Int(i64),
    /// `Schema.Number` checked `isFinite`.
    Finite,
    /// `Schema.DateTimeUtc` / `DateTimeUtcFromString`.
    /// shortcut: only the canonical `toISOString` form decodes; other forms `DateTime.make` accepts drift (decline). Port its parser if real rows hold them.
    Date,
    Lit(&'static [&'static str]),
    /// `Schema.Literal(true)` / `Schema.Literal(2)`.
    Exact(&'static str),
    /// `Schema.Unknown`, also `Schema.Record(Schema.String, Schema.Unknown)` as `Obj`.
    Unknown,
    Obj,
    Null(&'static S),
    Arr(&'static S),
    Struct(&'static [F]),
    /// Members tried in order; the first that decodes wins (members here are disjoint by tag).
    Union(&'static [S]),
    Custom(fn(&Value, &str) -> R),
}

/// How a struct key decodes when absent.
#[derive(Clone, Copy)]
pub enum K {
    Req,
    /// `Schema.optional` / `optionalKey`: absent stays absent.
    Opt,
    /// `withDecodingDefault`: absent decodes to this value.
    Default(fn() -> Value),
}

#[derive(Clone, Copy)]
pub struct F(pub &'static str, pub K, pub S);

fn drift(path: &str) -> Drift {
    Drift(path.to_owned())
}

/// `s.trim()` (ECMAScript whitespace).
fn js_trim(s: &str) -> String {
    let u = js_string::units(s);
    String::from_utf16(js_string::trim(&u)).expect("trimming whitespace keeps pairs whole")
}

fn safe_int(v: &Value) -> Option<i64> {
    const MAX: f64 = 9_007_199_254_740_991.0;
    match v {
        Value::Number(n) => match n.as_i64() {
            Some(i) => (i.unsigned_abs() <= MAX as u64).then_some(i),
            None => n
                .as_f64()
                .filter(|f| f.fract() == 0.0 && f.abs() <= MAX)
                .map(|f| f as i64),
        },
        _ => None,
    }
}

fn is_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphabetic()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
}

/// Decodes `v` with schema `s`; `path` names it in a `Drift`.
pub fn decode(s: &S, v: &Value, path: &str) -> R {
    match *s {
        S::Str => v.is_string().then(|| v.clone()).ok_or_else(|| drift(path)),
        S::NonBlank(max) => {
            let t = js_trim(v.as_str().ok_or_else(|| drift(path))?);
            let len = t.encode_utf16().count();
            (len > 0 && max.is_none_or(|m| len <= m))
                .then_some(Value::String(t))
                .ok_or_else(|| drift(path))
        }
        S::Slug => {
            let t = js_trim(v.as_str().ok_or_else(|| drift(path))?);
            is_slug(&t)
                .then_some(Value::String(t))
                .ok_or_else(|| drift(path))
        }
        S::Bool => v.is_boolean().then(|| v.clone()).ok_or_else(|| drift(path)),
        S::Int(min) => match safe_int(v) {
            Some(i) if i >= min => Ok(v.clone()),
            _ => Err(drift(path)),
        },
        S::Finite => match v.as_f64() {
            Some(f) if f.is_finite() => Ok(v.clone()),
            _ => Err(drift(path)),
        },
        S::Date => v
            .as_str()
            .and_then(crate::effect_json::date)
            .map(|d| Value::String(d.to_owned()))
            .ok_or_else(|| drift(path)),
        S::Lit(set) => match v.as_str() {
            Some(x) if set.contains(&x) => Ok(v.clone()),
            _ => Err(drift(path)),
        },
        S::Exact(lit) => (serde_json::from_str::<Value>(lit).ok().as_ref() == Some(v))
            .then(|| v.clone())
            .ok_or_else(|| drift(path)),
        S::Unknown => Ok(v.clone()),
        S::Obj => v.is_object().then(|| v.clone()).ok_or_else(|| drift(path)),
        S::Null(inner) => match v {
            Value::Null => Ok(Value::Null),
            _ => decode(inner, v, path),
        },
        S::Arr(item) => {
            let a = v.as_array().ok_or_else(|| drift(path))?;
            a.iter()
                .enumerate()
                .map(|(i, x)| decode(item, x, &format!("{path}[{i}]")))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        S::Struct(fields) => decode_struct(fields, v, path).map(Value::Object),
        S::Union(members) => members
            .iter()
            .find_map(|m| decode(m, v, path).ok())
            .ok_or_else(|| drift(path)),
        S::Custom(f) => f(v, path),
    }
}

fn decode_struct(fields: &[F], v: &Value, path: &str) -> Result<Map<String, Value>, Drift> {
    let o = v.as_object().ok_or_else(|| drift(path))?;
    let mut out = Map::new();
    for F(key, kind, s) in fields {
        let p = format!("{path}.{key}");
        match (o.get(*key), kind) {
            (Some(x), _) => {
                out.insert((*key).to_owned(), decode(s, x, &p)?);
            }
            (None, K::Req) => return Err(drift(&p)),
            (None, K::Opt) => {}
            (None, K::Default(d)) => {
                out.insert((*key).to_owned(), d());
            }
        }
    }
    Ok(out)
}

fn null() -> Value {
    Value::Null
}
fn empty() -> Value {
    Value::Array(vec![])
}

pub const ID: S = S::NonBlank(None);
const NULL_ID: S = S::Null(&ID);
const NON_BLANK: S = S::NonBlank(None);
const NULL_NON_BLANK: S = S::Null(&NON_BLANK);
const DATE: S = S::Date;
const NULL_DATE: S = S::Null(&DATE);
const NULL_STR: S = S::Null(&S::Str);
const INT0: S = S::Int(0);
const INT1: S = S::Int(1);

// --- contracts/modelSelection.ts, contracts/model.ts ---

const OPTION_SELECTION: S = S::Struct(&[
    F("id", K::Req, NON_BLANK),
    F("value", K::Req, S::Union(&[NON_BLANK, S::Bool])),
]);
const OPTION_SELECTIONS_ARRAY: S = S::Arr(&OPTION_SELECTION);

/// `ProviderOptionSelections`: the canonical array, or a legacy object coerced to one
/// (`coerceLegacyOptionsObjectToArray`, keys in JS property order).
fn option_selections(v: &Value, path: &str) -> R {
    if v.is_array() {
        return decode(&OPTION_SELECTIONS_ARRAY, v, path);
    }
    let o = v.as_object().ok_or_else(|| drift(path))?;
    let mut entries = Vec::new();
    for (raw_key, raw_value) in o {
        let id = js_trim(raw_key);
        if id.is_empty() {
            continue;
        }
        match raw_value {
            Value::String(s) => {
                let t = js_trim(s);
                if !t.is_empty() {
                    entries.push(serde_json::json!({"id": id, "value": t}));
                }
            }
            Value::Bool(b) => entries.push(serde_json::json!({"id": id, "value": b})),
            _ => {}
        }
    }
    decode(&OPTION_SELECTIONS_ARRAY, &Value::Array(entries), path)
}

/// `ModelSelection`: `ModelSelectionSource` (legacy `provider` names the instance) decoded to
/// `ModelSelectionWire {instanceId, model, options?}`.
fn model_selection(v: &Value, path: &str) -> R {
    let o = v.as_object().ok_or_else(|| drift(path))?;
    let model = o
        .get("model")
        .ok_or_else(|| drift(&format!("{path}.model")))?;
    let instance = match (o.get("instanceId"), o.get("provider")) {
        (Some(i), _) => i,
        (None, Some(p)) if p.is_string() => p,
        _ => return Err(drift(&format!("{path}.instanceId"))),
    };
    let mut out = Map::new();
    out.insert(
        "instanceId".into(),
        decode(&S::Slug, instance, &format!("{path}.instanceId"))?,
    );
    out.insert(
        "model".into(),
        decode(&NON_BLANK, model, &format!("{path}.model"))?,
    );
    if let Some(opts) = o.get("options") {
        out.insert(
            "options".into(),
            option_selections(opts, &format!("{path}.options"))?,
        );
    }
    Ok(Value::Object(out))
}
pub const MODEL_SELECTION: S = S::Custom(model_selection);

// --- contracts/threadPullRequest.ts, contracts/pullRequest.ts ---

const PR_STATE: S = S::Lit(&["open", "closed", "merged"]);
const LINKED_PR: S = S::Struct(&[
    F("projectId", K::Req, ID),
    F("repository", K::Req, NON_BLANK),
    F("number", K::Req, INT1),
    F("url", K::Req, NON_BLANK),
]);
const ACTOR: S = S::Struct(&[
    F("isBot", K::Opt, S::Bool),
    F("login", K::Req, NON_BLANK),
    F("name", K::Req, NULL_STR),
    F("avatarUrl", K::Req, NULL_STR),
]);
const PR_SNAPSHOT: S = S::Struct(&[
    F("state", K::Req, PR_STATE),
    F("title", K::Req, NON_BLANK),
    F("headBranch", K::Req, NON_BLANK),
    F("baseBranch", K::Req, NON_BLANK),
    F("isDraft", K::Req, S::Bool),
    F("updatedAt", K::Req, NULL_STR),
    F("syncedAt", K::Req, S::Str),
    F("closedAt", K::Opt, NULL_STR),
    F("mergedAt", K::Opt, NULL_STR),
    F("author", K::Opt, S::Null(&ACTOR)),
    F("additions", K::Opt, INT0),
    F("deletions", K::Opt, INT0),
    F("changedFiles", K::Opt, INT0),
    F(
        "reviewDecision",
        K::Opt,
        S::Null(&S::Lit(&[
            "approved",
            "changes-requested",
            "review-required",
        ])),
    ),
    F(
        "checksState",
        K::Opt,
        S::Null(&S::Lit(&["passing", "failing", "pending"])),
    ),
    F(
        "mergeability",
        K::Opt,
        S::Lit(&["mergeable", "conflicting", "unknown"]),
    ),
]);
const PR_STACK: S = S::Struct(&[
    F("kind", K::Req, S::Lit(&["native"])),
    F("id", K::Req, NON_BLANK),
    F("number", K::Req, INT1),
    F("url", K::Req, NON_BLANK),
    F("base", K::Req, NON_BLANK),
    F(
        "layers",
        K::Req,
        S::Arr(&S::Struct(&[
            F("number", K::Req, INT1),
            F("headBranch", K::Req, NON_BLANK),
            F("state", K::Req, PR_STATE),
        ])),
    ),
]);
const PR_WATCH: S = S::Struct(&[
    F("startedAt", K::Req, S::Str),
    F("headSha", K::Req, NULL_NON_BLANK),
    F("failedChecks", K::Req, S::Arr(&NON_BLANK)),
    F("passed", K::Req, S::Bool),
    F("passedChecks", K::Default(empty), S::Arr(&NON_BLANK)),
    F("remarksThrough", K::Req, S::Str),
    F("remarkIds", K::Req, S::Arr(&NON_BLANK)),
    F("conflicting", K::Req, S::Bool),
    F("wakes", K::Req, INT0),
]);
const PR_LINK: S = S::Struct(&[
    F("host", K::Req, NON_BLANK),
    F("repository", K::Req, NON_BLANK),
    F("number", K::Req, INT1),
    F("url", K::Req, NON_BLANK),
    F("repositoryWebUrl", K::Opt, NON_BLANK),
    F(
        "source",
        K::Req,
        S::Lit(&["manual", "created", "agent", "stack", "stack-dismissed"]),
    ),
    F("linkedAt", K::Req, S::Str),
    F("snapshot", K::Req, S::Null(&PR_SNAPSHOT)),
    F("stack", K::Req, S::Null(&PR_STACK)),
    F("watch", K::Opt, PR_WATCH),
    F("endedWatch", K::Opt, PR_WATCH),
]);

// --- contracts/orchestrationV2.ts ---

const ACTOR_KIND: S = S::Lit(&["user", "agent", "system"]);
const CREATION_SOURCE: S = S::Lit(&["web", "mobile", "mcp", "provider", "server"]);
const LINEAGE: S = S::Struct(&[
    F("parentThreadId", K::Req, NULL_ID),
    F(
        "relationshipToParent",
        K::Req,
        S::Null(&S::Lit(&["fork", "subagent"])),
    ),
    F("rootThreadId", K::Req, ID),
]);
const FORKED_FROM: S = S::Union(&[
    S::Struct(&[
        F("type", K::Req, S::Lit(&["run"])),
        F("threadId", K::Req, ID),
        F("runId", K::Req, ID),
    ]),
    S::Struct(&[
        F("type", K::Req, S::Lit(&["node"])),
        F("nodeId", K::Req, ID),
    ]),
    S::Struct(&[
        F("type", K::Req, S::Lit(&["provider_thread"])),
        F("providerThreadId", K::Req, ID),
        F("providerTurnId", K::Opt, ID),
    ]),
]);
const LIMIT_RECOVERY: S = S::Struct(&[
    F("requestId", K::Opt, ID),
    F("runId", K::Req, ID),
    F("resetAt", K::Req, S::Str),
    F("autoResume", K::Req, S::Bool),
    F("snooze", K::Opt, S::Bool),
]);

/// `OrchestrationV2AppThreadJson` (`:1948-1975` over `OrchestrationV2AppThread`, `:373-436`).
pub const APP_THREAD_JSON: S = S::Struct(&[
    F("createdBy", K::Req, ACTOR_KIND),
    F("creationSource", K::Req, CREATION_SOURCE),
    F("id", K::Req, ID),
    F("projectId", K::Req, ID),
    F("title", K::Req, NON_BLANK),
    F("providerInstanceId", K::Req, S::Slug),
    F("modelSelection", K::Req, MODEL_SELECTION),
    F(
        "runtimeMode",
        K::Req,
        S::Lit(&[
            "approval-required",
            "auto-accept-edits",
            "auto",
            "full-access",
        ]),
    ),
    F("interactionMode", K::Req, S::Lit(&["default", "plan"])),
    F("branch", K::Req, NULL_NON_BLANK),
    F("worktreePath", K::Req, NULL_NON_BLANK),
    F("linkedPullRequest", K::Opt, S::Null(&LINKED_PR)),
    F("pullRequests", K::Opt, S::Arr(&PR_LINK)),
    F("branchPullRequest", K::Opt, S::Null(&LINKED_PR)),
    F("activeProviderThreadId", K::Req, NULL_ID),
    F("historyOrigin", K::Opt, S::Lit(&["native", "v1_import"])),
    F("lineage", K::Req, LINEAGE),
    F("forkedFrom", K::Req, S::Null(&FORKED_FROM)),
    F("createdAt", K::Req, DATE),
    F("updatedAt", K::Req, DATE),
    F("archivedAt", K::Req, NULL_DATE),
    F(
        "settledOverride",
        K::Default(null),
        S::Null(&S::Lit(&["settled", "active"])),
    ),
    F("settledAt", K::Default(null), NULL_DATE),
    F("unsettledAt", K::Opt, NULL_DATE),
    F("snoozedUntil", K::Opt, NULL_DATE),
    F("snoozedAt", K::Opt, NULL_DATE),
    F("lastSnoozeWakeAt", K::Opt, NULL_DATE),
    F("limitRecovery", K::Opt, S::Null(&LIMIT_RECOVERY)),
    F("pinnedAt", K::Opt, NULL_DATE),
    F("autoSettleDisabledAt", K::Opt, NULL_DATE),
    F("pinOrderKey", K::Opt, NULL_NON_BLANK),
    F("activeOrderKey", K::Opt, NULL_NON_BLANK),
    F("lastVisitedAt", K::Default(null), NULL_DATE),
    F(
        "titleRegeneration",
        K::Opt,
        S::Null(&S::Struct(&[
            F("requestId", K::Req, ID),
            F("startedAt", K::Req, DATE),
        ])),
    ),
    F("rollbackRequestId", K::Opt, ID),
    F(
        "rollbackFailure",
        K::Opt,
        S::Null(&S::Struct(&[
            F("requestId", K::Req, ID),
            F("message", K::Req, NON_BLANK),
        ])),
    ),
    F("deletedAt", K::Req, NULL_DATE),
]);

const KNOWN_TASK_KINDS: [&str; 4] = ["subagent", "command", "monitor", "background_task"];

const TASK_SUBAGENT: S = S::Struct(&[
    F("taskId", K::Req, NON_BLANK),
    F("description", K::Opt, NON_BLANK),
    F("parentTaskId", K::Opt, NON_BLANK),
    F("kind", K::Req, S::Lit(&["subagent"])),
    F("providerInstanceId", K::Opt, S::Slug),
    F("childThreadId", K::Opt, ID),
]);
const TASK_COMMAND: S = S::Struct(&[
    F("taskId", K::Req, NON_BLANK),
    F("description", K::Opt, NON_BLANK),
    F("parentTaskId", K::Opt, NON_BLANK),
    F("kind", K::Req, S::Lit(&["command"])),
]);
const TASK_MONITOR: S = S::Struct(&[
    F("taskId", K::Req, NON_BLANK),
    F("description", K::Opt, NON_BLANK),
    F("parentTaskId", K::Opt, NON_BLANK),
    F("kind", K::Req, S::Lit(&["monitor"])),
]);
const TASK_BACKGROUND: S = S::Struct(&[
    F("taskId", K::Req, NON_BLANK),
    F("description", K::Opt, NON_BLANK),
    F("parentTaskId", K::Opt, NON_BLANK),
    F("kind", K::Req, S::Lit(&["background_task"])),
]);

/// `OrchestrationV2PendingBackgroundTask` (`kindUnionWithFallback`, `:790-848`): an unknown or
/// absent `kind` decodes to a `background_task` with the shared fields.
fn pending_background_task(v: &Value, path: &str) -> R {
    for m in [TASK_SUBAGENT, TASK_COMMAND, TASK_MONITOR, TASK_BACKGROUND] {
        if let Ok(x) = decode(&m, v, path) {
            return Ok(x);
        }
    }
    const FALLBACK: S = S::Struct(&[
        F("taskId", K::Req, NON_BLANK),
        F("description", K::Opt, NON_BLANK),
        F("parentTaskId", K::Opt, NON_BLANK),
        F("kind", K::Opt, S::Str),
    ]);
    let mut o = match decode(&FALLBACK, v, path)? {
        Value::Object(o) => o,
        _ => unreachable!("a struct decodes to an object"),
    };
    if let Some(k) = o.remove("kind")
        && KNOWN_TASK_KINDS.contains(&k.as_str().unwrap_or_default())
    {
        return Err(drift(&format!("{path}.kind")));
    }
    o.insert("kind".into(), "background_task".into());
    Ok(Value::Object(o))
}
pub const PENDING_BACKGROUND_TASK: S = S::Custom(pending_background_task);

/// Encoding a derived task through the shell schema: the union member its `kind` names, keys in
/// that member's order (`derivePendingBackgroundWork` builds them in spread order).
pub fn encode_pending_background_task(task: &Map<String, Value>) -> Result<Value, Drift> {
    let member = match task.get("kind").and_then(Value::as_str) {
        Some("subagent") => TASK_SUBAGENT,
        Some("command") => TASK_COMMAND,
        Some("monitor") => TASK_MONITOR,
        Some("background_task") => TASK_BACKGROUND,
        _ => return Err(drift("pendingBackgroundTasks.kind")),
    };
    decode(
        &member,
        &Value::Object(task.clone()),
        "pendingBackgroundTasks",
    )
}

pub const GOAL: S = S::Struct(&[
    F("objective", K::Req, NON_BLANK),
    F(
        "status",
        K::Req,
        S::Lit(&[
            "active",
            "paused",
            "blocked",
            "usage_limited",
            "budget_limited",
            "complete",
        ]),
    ),
    F("tokensUsed", K::Opt, INT0),
    F("tokenBudget", K::Opt, S::Null(&INT0)),
    F("timeUsedSeconds", K::Opt, INT0),
    F("checks", K::Opt, INT0),
    F("lastCheck", K::Opt, S::Str),
]);

const PROVIDER_REF: S = S::Struct(&[
    F("driver", K::Req, S::Slug),
    F("nativeId", K::Req, NULL_NON_BLANK),
    F("strength", K::Req, S::Lit(&["strong", "weak", "none"])),
    F("fingerprint", K::Opt, NON_BLANK),
    F("ordinal", K::Opt, INT0),
]);

/// `ThreadTokenUsageSnapshot` (`providerRuntime.ts:260-283`).
const TOKEN_USAGE: S = S::Struct(&[
    F("usedTokens", K::Req, INT0),
    F("totalProcessedTokens", K::Opt, INT0),
    F("maxTokens", K::Opt, INT1),
    F("inputTokens", K::Opt, INT0),
    F("cachedInputTokens", K::Opt, INT0),
    F("outputTokens", K::Opt, INT0),
    F("reasoningOutputTokens", K::Opt, INT0),
    F("lastUsedTokens", K::Opt, INT0),
    F("lastInputTokens", K::Opt, INT0),
    F("lastCachedInputTokens", K::Opt, INT0),
    F("lastOutputTokens", K::Opt, INT0),
    F("lastReasoningOutputTokens", K::Opt, INT0),
    F("toolUses", K::Opt, INT0),
    F("durationMs", K::Opt, INT0),
    F("compactsAutomatically", K::Opt, S::Bool),
    F("autoCompactThreshold", K::Opt, INT1),
    F(
        "cost",
        K::Opt,
        S::Struct(&[
            F("amount", K::Req, S::Finite),
            F("currency", K::Req, S::NonBlank(Some(32))),
        ]),
    ),
]);

/// `OrchestrationV2ProviderThreadJson` (`:878-912`, `:2029-2035`).
pub const PROVIDER_THREAD_JSON: S = S::Struct(&[
    F("id", K::Req, ID),
    F("driver", K::Req, S::Slug),
    F("providerInstanceId", K::Req, S::Slug),
    F("providerSessionId", K::Req, NULL_ID),
    F("appThreadId", K::Req, NULL_ID),
    F("ownerNodeId", K::Req, NULL_ID),
    F("nativeThreadRef", K::Req, S::Null(&PROVIDER_REF)),
    F("nativeConversationHeadRef", K::Req, S::Null(&PROVIDER_REF)),
    F(
        "status",
        K::Req,
        S::Lit(&[
            "not_loaded",
            "idle",
            "active",
            "archived",
            "closed",
            "error",
        ]),
    ),
    F("firstRunOrdinal", K::Req, S::Null(&INT1)),
    F("lastRunOrdinal", K::Req, S::Null(&INT1)),
    F("handoffIds", K::Req, S::Arr(&ID)),
    F(
        "forkedFrom",
        K::Req,
        S::Null(&S::Struct(&[
            F("providerThreadId", K::Req, ID),
            F("providerTurnId", K::Opt, ID),
            F("checkpointId", K::Opt, ID),
        ])),
    ),
    F(
        "pendingBackgroundTasks",
        K::Default(empty),
        S::Arr(&PENDING_BACKGROUND_TASK),
    ),
    F("contextUsage", K::Default(null), S::Null(&TOKEN_USAGE)),
    F(
        "nativeMetadata",
        K::Default(null),
        S::Null(&S::Struct(&[
            F("modelSelection", K::Opt, MODEL_SELECTION),
            F("title", K::Opt, NULL_NON_BLANK),
            F("updatedAt", K::Opt, NULL_NON_BLANK),
            F("itemIdentityVersion", K::Opt, S::Exact("2")),
            F("forkHeadMessageId", K::Opt, NON_BLANK),
        ])),
    ),
    F("goal", K::Default(null), S::Null(&GOAL)),
    F("createdAt", K::Req, DATE),
    F("updatedAt", K::Req, DATE),
]);

/// `OrchestrationV2RuntimeRequestJson` (`:1012-1035`, `:2064-2070`).
pub const RUNTIME_REQUEST_JSON: S = S::Struct(&[
    F("id", K::Req, ID),
    F("nodeId", K::Req, ID),
    F("providerTurnId", K::Req, NULL_ID),
    F("nativeRequestRef", K::Req, S::Null(&PROVIDER_REF)),
    F(
        "kind",
        K::Req,
        S::Lit(&[
            "command",
            "file-read",
            "file-change",
            "mcp-elicitation",
            "permission",
            "dynamic_tool_call",
            "user_input",
            "auth_refresh",
        ]),
    ),
    F(
        "status",
        K::Req,
        S::Lit(&["pending", "resolved", "expired", "cancelled"]),
    ),
    F(
        "responseCapability",
        K::Req,
        S::Union(&[
            S::Struct(&[
                F("type", K::Req, S::Lit(&["live"])),
                F("providerSessionId", K::Req, ID),
            ]),
            S::Struct(&[F("type", K::Req, S::Lit(&["message"]))]),
            S::Struct(&[
                F("type", K::Req, S::Lit(&["not_resumable"])),
                F("reason", K::Req, S::Str),
            ]),
        ]),
    ),
    F("createdAt", K::Req, DATE),
    F("resolvedAt", K::Req, NULL_DATE),
    F(
        "decision",
        K::Opt,
        S::Lit(&[
            "accept",
            "acceptForSession",
            "acceptAlways",
            "decline",
            "cancel",
        ]),
    ),
    F("answers", K::Opt, S::Obj),
]);

/// The base fields of every `OrchestrationV2TurnItemJson` member (`:2095-2100`, `:1305-1325`).
/// shortcut: `toolIcon` and `toolSource` are checked as present-or-absent only (the shell never reads them); port `ToolActivityIcon`/`ToolActivitySource` if a mismatch shows.
const TURN_ITEM_BASE: [F; 18] = [
    F("toolNonExecutionKind", K::Opt, S::Str),
    F("toolSurface", K::Opt, S::Lit(&["browser", "computer"])),
    F("toolIcon", K::Opt, S::Obj),
    F("toolSource", K::Opt, S::Obj),
    F("id", K::Req, ID),
    F("threadId", K::Req, ID),
    F("runId", K::Req, NULL_ID),
    F("nodeId", K::Req, NULL_ID),
    F("providerThreadId", K::Req, NULL_ID),
    F("providerTurnId", K::Req, NULL_ID),
    F("nativeItemRef", K::Req, S::Null(&PROVIDER_REF)),
    F("parentItemId", K::Req, NULL_ID),
    F("ordinal", K::Req, INT0),
    F(
        "status",
        K::Req,
        S::Lit(&[
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
    F("title", K::Req, NULL_STR),
    F("startedAt", K::Req, NULL_DATE),
    F("completedAt", K::Req, NULL_DATE),
    F("updatedAt", K::Req, DATE),
];

const FAILURE: S = S::Struct(&[
    F(
        "class",
        K::Req,
        S::Lit(&[
            "usage_limit",
            "provider_error",
            "transport_error",
            "permission_error",
            "validation_error",
            "unknown",
        ]),
    ),
    F("message", K::Req, S::NonBlank(Some(4096))),
    F("code", K::Req, S::Null(&S::NonBlank(Some(128)))),
    F("retryable", K::Req, S::Null(&S::Bool)),
    F("resetAt", K::Opt, NULL_STR),
]);

/// Member fields of the turn-item types the shell reads (the pending-work, failure and secret
/// queries select only these types).
fn turn_item_member(kind: &str) -> Option<&'static [F]> {
    Some(match kind {
        "file_change" => &[
            F("fileName", K::Req, NON_BLANK),
            F("additions", K::Opt, INT0),
            F("deletions", K::Opt, INT0),
            F("diffStr", K::Opt, S::Str),
            F("oldStr", K::Opt, S::Str),
            F("newStr", K::Opt, S::Str),
            F(
                "changes",
                K::Opt,
                S::Arr(&S::Struct(&[
                    F("operation", K::Req, NON_BLANK),
                    F("path", K::Req, NON_BLANK),
                    F("oldPath", K::Opt, NON_BLANK),
                    F("fileType", K::Opt, NON_BLANK),
                    F("mimeType", K::Opt, NON_BLANK),
                ])),
            ),
        ],
        "command_execution" => &[
            F("input", K::Req, S::Str),
            F("output", K::Opt, S::Str),
            F("outputOmitted", K::Opt, S::Bool),
            F("outputIndicatesFailure", K::Opt, S::Bool),
            F("exitCode", K::Opt, S::Int(i64::MIN)),
        ],
        "file_search" => &[
            F("pattern", K::Opt, S::Str),
            F(
                "results",
                K::Opt,
                S::Arr(&S::Struct(&[
                    F("fileName", K::Req, NON_BLANK),
                    F("line", K::Opt, INT1),
                    F("column", K::Opt, INT1),
                    F("preview", K::Opt, S::Str),
                ])),
            ),
        ],
        "web_search" => &[
            F("patterns", K::Opt, S::Arr(&S::Str)),
            F(
                "results",
                K::Opt,
                S::Arr(&S::Struct(&[
                    F("title", K::Opt, S::Str),
                    F("url", K::Opt, NON_BLANK),
                    F("snippet", K::Opt, S::Str),
                ])),
            ),
        ],
        "error" => &[
            F("failure", K::Req, FAILURE),
            F(
                "retry",
                K::Opt,
                S::Struct(&[
                    F("attempt", K::Req, INT1),
                    F("maxAttempts", K::Req, S::Null(&INT1)),
                    F("retryDelayMs", K::Req, S::Null(&INT0)),
                ]),
            ),
        ],
        "compaction" => &[
            F("driver", K::Req, S::Null(&S::Slug)),
            F("summary", K::Opt, S::Str),
            F("beforeTokenCount", K::Opt, INT0),
            F("afterTokenCount", K::Opt, INT0),
        ],
        "secret_request" => &[
            F("label", K::Req, NON_BLANK),
            F("reason", K::Req, S::Str),
            F("placeholder", K::Opt, S::Str),
            F(
                "secretStatus",
                K::Req,
                S::Lit(&["pending", "saved", "declined", "cancelled"]),
            ),
        ],
        "subagent" => &[
            F("subagentId", K::Req, ID),
            F("origin", K::Req, S::Lit(&["provider_native", "app_owned"])),
            F("driver", K::Req, S::Slug),
            F("providerInstanceId", K::Req, S::Slug),
            F("childThreadId", K::Req, NULL_ID),
            F("prompt", K::Req, S::Str),
            F("progress", K::Opt, S::Str),
            F("result", K::Req, NULL_STR),
        ],
        "dynamic_tool" => &[
            F("toolName", K::Req, NULL_NON_BLANK),
            F("viewedImagePath", K::Opt, NON_BLANK),
            F("input", K::Req, S::Unknown),
            F("output", K::Opt, S::Unknown),
            F("outputOmitted", K::Opt, S::Bool),
        ],
        _ => return None,
    })
}

/// A turn item the shell can decode: `Ok(None)` for a `type` not ported (the caller declines).
pub fn decode_turn_item(v: &Value, path: &str) -> Result<Option<Value>, Drift> {
    let Some(kind) = v.get("type").and_then(Value::as_str) else {
        return Err(drift(&format!("{path}.type")));
    };
    let Some(member) = turn_item_member(kind) else {
        return Ok(None);
    };
    let mut out = decode_struct(&TURN_ITEM_BASE, v, path)?;
    out.insert("type".into(), kind.into());
    out.extend(decode_struct(member, v, path)?);
    Ok(Some(Value::Object(out)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn de(s: &S, v: Value) -> R {
        decode(s, &v, "$")
    }
    fn text(v: &Value) -> String {
        String::from_utf8(crate::effect_json::to_vec(v)).unwrap()
    }

    #[test]
    fn trimmed_strings_trim_with_js_whitespace_and_reject_blank() {
        assert_eq!(de(&ID, json!("\u{feff} a \u{a0}")), Ok(json!("a")));
        assert_eq!(de(&ID, json!(" \u{2028} ")), Err(Drift("$".into())));
        // U+0085 is not JS whitespace: kept.
        assert_eq!(de(&ID, json!("a\u{85}")), Ok(json!("a\u{85}")));
        assert_eq!(de(&S::NonBlank(Some(2)), json!(" 😀 ")), Ok(json!("😀")));
        assert!(
            de(&S::NonBlank(Some(1)), json!("😀")).is_err(),
            "2 UTF-16 units"
        );
        assert_eq!(de(&S::Slug, json!(" codex_2-x ")), Ok(json!("codex_2-x")));
        for bad in ["2codex", "co dex", "", "codex!"] {
            assert!(de(&S::Slug, json!(bad)).is_err(), "{bad}");
        }
        assert!(de(&S::Slug, json!("a".repeat(65))).is_err());
    }

    #[test]
    fn numbers_dates_literals() {
        assert_eq!(de(&INT0, json!(3)), Ok(json!(3)));
        assert_eq!(de(&INT0, json!(3.0)), Ok(json!(3.0)));
        assert!(de(&INT0, json!(-1)).is_err());
        assert!(de(&INT1, json!(0)).is_err());
        assert!(de(&INT0, json!(1.5)).is_err());
        assert!(de(&INT0, json!(9007199254740992u64)).is_err(), "not safe");
        assert!(de(&INT0, json!("1")).is_err());
        assert_eq!(
            de(&DATE, json!("2026-10-23T08:00:00.000Z")),
            Ok(json!("2026-10-23T08:00:00.000Z"))
        );
        assert!(de(&DATE, json!("2026-10-23T08:00:00Z")).is_err());
        assert!(de(&S::Lit(&["a"]), json!("b")).is_err());
        assert_eq!(de(&S::Exact("2"), json!(2)), Ok(json!(2)));
        assert!(de(&S::Exact("2"), json!(3)).is_err());
        assert!(de(&S::Finite, json!(1.5)).is_ok());
    }

    #[test]
    fn structs_reorder_drop_excess_fill_defaults_and_name_the_path() {
        const T: S = S::Struct(&[
            F("a", K::Req, S::Str),
            F("b", K::Opt, S::Bool),
            F("c", K::Default(null), NULL_STR),
            F("d", K::Opt, S::Arr(&ID)),
        ]);
        let v = de(&T, json!({"x": 1, "d": [" i "], "a": "s"})).unwrap();
        assert_eq!(text(&v), r#"{"a":"s","c":null,"d":["i"]}"#);
        assert_eq!(de(&T, json!({"b": true})), Err(Drift("$.a".into())));
        assert_eq!(
            de(&T, json!({"a": "s", "d": ["ok", " "]})),
            Err(Drift("$.d[1]".into()))
        );
        assert!(de(&T, json!([])).is_err());
        assert!(de(&T, json!(null)).is_err());
    }

    #[test]
    fn model_selection_takes_legacy_provider_and_options_objects() {
        let ms = |v: Value| de(&MODEL_SELECTION, v).map(|v| text(&v));
        assert_eq!(
            ms(json!({"model": " m ", "extra": 1, "instanceId": "codex"})),
            Ok(r#"{"instanceId":"codex","model":"m"}"#.into())
        );
        assert_eq!(
            ms(json!({"provider": "claudeAgent", "model": "m"})),
            Ok(r#"{"instanceId":"claudeAgent","model":"m"}"#.into())
        );
        // instanceId wins over provider; a non-string provider names nothing.
        assert_eq!(
            ms(json!({"provider": "x", "instanceId": "y", "model": "m"})),
            Ok(r#"{"instanceId":"y","model":"m"}"#.into())
        );
        assert!(ms(json!({"provider": 1, "model": "m"})).is_err());
        assert!(ms(json!({"instanceId": "y"})).is_err(), "model is required");
        assert_eq!(
            ms(json!({"instanceId": "y", "model": "m",
                "options": [{"id": " effort ", "value": " high "}, {"value": true, "id": "fast"}]})),
            Ok(r#"{"instanceId":"y","model":"m","options":[{"id":"effort","value":"high"},{"id":"fast","value":true}]}"#.into())
        );
        // Legacy object: JS property order (index keys first), blanks and other types dropped.
        let legacy: Value = crate::effect_json::parse(
            r#"{"instanceId":"y","model":"m","options":{"b":" x ","2":true," ":"z","n":1,"e":"  "}}"#,
        )
        .unwrap();
        assert_eq!(
            ms(legacy),
            Ok(r#"{"instanceId":"y","model":"m","options":[{"id":"2","value":true},{"id":"b","value":"x"}]}"#.into())
        );
        assert!(
            ms(json!({"instanceId": "y", "model": "m", "options": [{"id": "a", "value": 1}]}))
                .is_err()
        );
        assert!(ms(json!({"instanceId": "y", "model": "m", "options": null})).is_err());
    }

    #[test]
    fn app_thread_defaults_and_unions() {
        let base = json!({
            "createdBy": "user", "creationSource": "web", "id": "t", "projectId": "p",
            "title": " T ", "providerInstanceId": "codex",
            "modelSelection": {"instanceId": "codex", "model": "m"},
            "runtimeMode": "full-access", "interactionMode": "default",
            "branch": null, "worktreePath": null, "activeProviderThreadId": null,
            "lineage": {"rootThreadId": "t", "parentThreadId": null, "relationshipToParent": null},
            "forkedFrom": {"runId": "r", "type": "run", "threadId": "s", "nodeId": "n"},
            "createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-01T00:00:00.000Z",
            "archivedAt": null, "deletedAt": null, "unknownKey": 1
        });
        let t = de(&APP_THREAD_JSON, base.clone()).unwrap();
        assert_eq!(t["title"], "T");
        assert_eq!(
            text(&t["forkedFrom"]),
            r#"{"type":"run","threadId":"s","runId":"r"}"#
        );
        assert_eq!(
            text(&t["lineage"]),
            r#"{"parentThreadId":null,"relationshipToParent":null,"rootThreadId":"t"}"#
        );
        for k in ["settledOverride", "settledAt", "lastVisitedAt"] {
            assert_eq!(t[k], Value::Null, "{k} defaults to null");
        }
        for k in ["unsettledAt", "pullRequests", "historyOrigin", "unknownKey"] {
            assert!(t.get(k).is_none(), "{k} stays absent");
        }
        let mut b = base.clone();
        b["forkedFrom"] = json!({"type": "provider_thread", "providerThreadId": "pt"});
        assert_eq!(
            text(&de(&APP_THREAD_JSON, b).unwrap()["forkedFrom"]),
            r#"{"type":"provider_thread","providerThreadId":"pt"}"#
        );
        let mut b = base.clone();
        b["forkedFrom"] = json!({"type": "other"});
        assert_eq!(de(&APP_THREAD_JSON, b), Err(Drift("$.forkedFrom".into())));
        let mut b = base;
        b["pullRequests"] = json!([{"host": "github.com", "repository": "o/r", "number": 1,
            "url": "u", "source": "manual", "linkedAt": "x", "snapshot": null, "stack": null,
            "watch": {"startedAt": "s", "headSha": null, "failedChecks": [], "passed": false,
                "remarksThrough": "r", "remarkIds": [], "conflicting": false, "wakes": 0}}]);
        let t = de(&APP_THREAD_JSON, b).unwrap();
        assert_eq!(t["pullRequests"][0]["watch"]["passedChecks"], json!([]));
    }

    #[test]
    fn pending_background_tasks_fall_back_to_background_task() {
        let t = |v: Value| de(&PENDING_BACKGROUND_TASK, v).map(|v| text(&v));
        assert_eq!(
            t(json!({"kind": "subagent", "taskId": " a ", "childThreadId": "c", "x": 1})),
            Ok(r#"{"taskId":"a","kind":"subagent","childThreadId":"c"}"#.into())
        );
        assert_eq!(
            t(json!({"kind": "future", "taskId": "a", "description": "d", "childThreadId": "c"})),
            Ok(r#"{"taskId":"a","description":"d","kind":"background_task"}"#.into())
        );
        assert_eq!(
            t(json!({"taskId": "a"})),
            Ok(r#"{"taskId":"a","kind":"background_task"}"#.into())
        );
        // A known kind must decode in full.
        assert!(t(json!({"kind": "subagent", "taskId": "a", "childThreadId": " "})).is_err());
        assert!(t(json!({"kind": 1, "taskId": "a"})).is_err());
        let mut m = Map::new();
        m.insert("kind".into(), "command".into());
        m.insert("description".into(), "d".into());
        m.insert("taskId".into(), "a".into());
        assert_eq!(
            text(&encode_pending_background_task(&m).unwrap()),
            r#"{"taskId":"a","description":"d","kind":"command"}"#
        );
    }

    #[test]
    fn turn_items_decode_ported_types_only() {
        let item = json!({
            "type": "command_execution", "id": " i ", "threadId": "t", "runId": "r",
            "nodeId": null, "providerThreadId": null, "providerTurnId": null,
            "nativeItemRef": {"driver": "codex", "nativeId": " n ", "strength": "strong"},
            "parentItemId": null, "ordinal": 0, "status": "running", "title": null,
            "startedAt": null, "completedAt": null, "updatedAt": "2026-01-01T00:00:00.000Z",
            "input": " ls "
        });
        let d = decode_turn_item(&item, "$").unwrap().unwrap();
        assert_eq!(d["id"], "i");
        assert_eq!(d["input"], " ls ", "Schema.String keeps spaces");
        assert_eq!(d["nativeItemRef"]["nativeId"], "n");
        let mut other = item.clone();
        other["type"] = "user_message".into();
        assert_eq!(decode_turn_item(&other, "$"), Ok(None));
        let mut bad = item;
        bad.as_object_mut().unwrap().remove("input");
        assert_eq!(decode_turn_item(&bad, "$"), Err(Drift("$.input".into())));
        assert!(decode_turn_item(&json!({}), "$").is_err());
    }
}
