//! The shell's TypeScript, ported function by function (Engine 2aa67bc): `ProjectionStore.ts`
//! (`shellStatusFromStoredRunStatus`, `itemCountThroughRun`, `shellForkSourceIds`,
//! `visibleItemCountForShell`, `shellFromState`, `pendingRuntimeRequestSummary`,
//! `secretRequestAsPendingInput`, `providerInstanceHistoryForShell`, `activeProviderGoalForShell`,
//! `runMapsByThreadId`, `pendingBackgroundDataByThreadId`, `shellThreadStateFromRow`) and the shared
//! helpers it calls (`orchestrationV2PendingBackgroundWork.ts`, `orchestrationV2ThreadError.ts`,
//! `threadPullRequests.ts#threadPullRequestsOf`). Values are the decoded JSON (`wire::decode`).
use super::{
    Decline,
    sql::{
        ProviderThreadRow, ShellPendingTurnItemRow, ShellRunItemCountRow, ShellRunRow,
        ShellThreadRow,
    },
    wire,
};
use crate::js_string;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

type Obj = Map<String, Value>;

/// `ShellThreadState`.
#[derive(Debug, Clone, PartialEq)]
pub struct ShellThreadState {
    pub thread: Obj,
    pub latest_run_id: Option<String>,
    pub latest_run_status: String,
    pub latest_run_requested_at: Option<String>,
    pub latest_run_started_at: Option<String>,
    pub latest_run_completed_at: Option<String>,
    pub latest_run_stop_requested: bool,
    pub active_run_id: Option<String>,
    pub blocked_on_thread_wait: bool,
    pub activity_run_status: Option<String>,
    pub activity_run_started_at: Option<String>,
    pub error: ErrorSummary,
    pub pending_runtime_request: Value,
    pub latest_user_message_at: Option<String>,
    pub latest_user_authored_message_at: Option<String>,
    pub has_actionable_proposed_plan: bool,
    pub pending_background_tasks: Vec<Obj>,
    pub provider_instance_history: Vec<Value>,
    pub goal: Value,
    pub item_count: i64,
    pub runless_item_count: i64,
    pub updated_at: Value,
    pub run_ordinal_by_id: HashMap<String, i64>,
    pub item_count_by_run_id: Vec<(String, i64)>,
}

impl ShellThreadState {
    pub fn id(&self) -> &str {
        self.thread["id"].as_str().expect("decoded id")
    }
}

fn s(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

fn opt_str(v: Option<String>) -> Value {
    v.map_or(Value::Null, Value::String)
}

pub fn shell_status_from_stored_run_status(status: Option<&str>) -> &str {
    match status {
        None => "idle",
        Some(
            s @ ("preparing" | "queued" | "starting" | "running" | "waiting" | "completed"
            | "interrupted" | "failed" | "cancelled" | "rolled_back"),
        ) => s,
        Some(_) => "failed",
    }
}

pub fn item_count_through_run(state: &ShellThreadState, run_id: &str) -> i64 {
    let Some(&run_ordinal) = state.run_ordinal_by_id.get(run_id) else {
        return 0;
    };
    let mut count = if s(state.thread.get("historyOrigin")) == Some("v1_import") {
        state.runless_item_count
    } else {
        0
    };
    for (id, item_count) in &state.item_count_by_run_id {
        if let Some(&o) = state.run_ordinal_by_id.get(id)
            && o <= run_ordinal
        {
            count += item_count;
        }
    }
    count
}

/// `shellForkSourceIds`: distinct run-fork sources in row order.
pub fn shell_fork_source_ids<'a>(
    rows: impl IntoIterator<Item = &'a ShellThreadRow>,
) -> Vec<String> {
    let mut seen = HashSet::new();
    rows.into_iter()
        .filter_map(|r| r.forked_from_run_source_thread_id.clone())
        .filter(|id| seen.insert(id.clone()))
        .collect()
}

/// `forkedFrom` when it is `{type: "run"}`: (threadId, runId).
fn run_fork(thread: &Obj) -> Option<(&str, &str)> {
    let f = thread.get("forkedFrom")?.as_object()?;
    (s(f.get("type")) == Some("run"))
        .then(|| Some((s(f.get("threadId"))?, s(f.get("runId"))?)))
        .flatten()
}

pub fn visible_item_count_for_shell(
    thread_id: &str,
    states: &HashMap<String, ShellThreadState>,
    seen: Option<&HashSet<String>>,
) -> i64 {
    let Some(state) = states.get(thread_id) else {
        return 0;
    };
    let Some((source_id, run_id)) = run_fork(&state.thread) else {
        return state.item_count;
    };
    let empty = HashSet::new();
    let seen = seen.unwrap_or(&empty);
    if seen.contains(state.id()) {
        return state.item_count;
    }
    let Some(source) = states.get(source_id) else {
        return state.item_count;
    };
    let inherited_prefix = if run_fork(&source.thread).is_some() {
        let mut next = seen.clone();
        next.insert(state.id().to_owned());
        visible_item_count_for_shell(source.id(), states, Some(&next)) - source.item_count
    } else {
        0
    };
    inherited_prefix + item_count_through_run(source, run_id) + 1 + state.item_count
}

/// `threadErrorSummary`'s result.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorSummary {
    pub usage_limit_reset_at: Value,
    pub last_error: Value,
    pub last_error_class: Value,
    pub last_error_code: Value,
}

pub fn thread_error_summary(failure: Option<&Value>, session_error: Option<&str>) -> ErrorSummary {
    let message = failure.and_then(|f| s(f.get("message")));
    let current = match session_error {
        Some(e) if Some(e) != message => None,
        _ => failure,
    };
    let field = |k: &str| {
        current
            .and_then(|f| f.get(k))
            .cloned()
            .unwrap_or(Value::Null)
    };
    ErrorSummary {
        usage_limit_reset_at: if current.and_then(|f| s(f.get("class"))) == Some("usage_limit") {
            field("resetAt")
        } else {
            Value::Null
        },
        last_error: opt_str(session_error.or(message).map(str::to_owned)),
        last_error_class: field("class"),
        last_error_code: field("code"),
    }
}

/// `pendingRuntimeRequestSummary`, encoded as `OrchestrationV2PendingRuntimeRequestSummary`.
pub fn pending_runtime_request_summary(request: &Value) -> Value {
    serde_json::json!({
        "id": request["id"],
        "kind": request["kind"],
        "createdAt": request["createdAt"],
        "blocking": request["responseCapability"]["type"] != "message",
    })
}

pub fn secret_request_as_pending_input(item: &Value) -> Option<Value> {
    if item["type"] != "secret_request" || item["nodeId"].is_null() {
        return None;
    }
    let created = if item["startedAt"].is_null() {
        &item["updatedAt"]
    } else {
        &item["startedAt"]
    };
    Some(serde_json::json!({
        "id": item["id"],
        "kind": "user_input",
        "createdAt": created,
        "blocking": true,
    }))
}

pub fn provider_instance_history_for_shell(
    thread_id: &str,
    provider_threads: &[Value],
) -> Vec<Value> {
    let mut list: Vec<&Value> = provider_threads
        .iter()
        .filter(|t| s(t.get("appThreadId")) == Some(thread_id) && t["ownerNodeId"].is_null())
        .collect();
    // Canonical `toISOString` text orders as its epoch milliseconds do.
    list.sort_by(|l, r| {
        let key = |t: &&Value| t["createdAt"].as_str().unwrap_or_default().to_owned();
        key(l).cmp(&key(r)).then_with(|| {
            crate::handlers::browse::locale_compare(
                l["id"].as_str().unwrap_or_default(),
                r["id"].as_str().unwrap_or_default(),
            )
        })
    });
    let mut history: Vec<Value> = Vec::new();
    for t in list {
        if !history.contains(&t["providerInstanceId"]) {
            history.push(t["providerInstanceId"].clone());
        }
    }
    history
}

pub fn active_provider_goal_for_shell(provider_threads: &[Value], active: &Value) -> Value {
    provider_threads
        .iter()
        .find(|t| &t["id"] == active)
        .map(|t| t["goal"].clone())
        .unwrap_or(Value::Null)
}

/// `threadPullRequestsOf`. A legacy single `linkedPullRequest` needs the change-request URL
/// parser (`legacyThreadPullRequestKey`), which is not ported: decline.
pub fn thread_pull_requests_of(thread: &Obj) -> Result<Value, &'static str> {
    if let Some(p) = thread.get("pullRequests") {
        return Ok(p.clone());
    }
    match thread.get("linkedPullRequest") {
        None | Some(Value::Null) => Ok(Value::Array(vec![])),
        Some(_) => Err("legacy_linked_pull_request"),
    }
}

// --- orchestrationV2PendingBackgroundWork.ts ---

const BACKGROUND_TURN_ITEM_TYPES: [&str; 3] = ["command_execution", "dynamic_tool", "subagent"];
const EXECUTION_TURN_ITEM_TYPES: [&str; 7] = [
    "command_execution",
    "dynamic_tool",
    "subagent",
    "file_change",
    "file_search",
    "web_search",
    "compaction",
];
const SETTLED_FOR_BACKGROUND_WAIT_RUN_STATUSES: [&str; 5] =
    ["cancelled", "completed", "failed", "interrupted", "waiting"];

fn is_work_active(status: &Value) -> bool {
    matches!(status.as_str(), Some("pending" | "running" | "waiting"))
}

fn js_trim(s: &str) -> String {
    String::from_utf16(js_string::trim(&js_string::units(s))).expect("whole pairs")
}

/// `deriveBlockedOnThreadWait`. Resolving a dynamic tool's MCP name (`resolveT3McpToolId`) is not
/// ported: reaching it declines.
pub fn derive_blocked_on_thread_wait(
    active_run_id: Option<&str>,
    turn_items: &[Value],
) -> Result<bool, &'static str> {
    let Some(active) = active_run_id else {
        return Ok(false);
    };
    for item in turn_items {
        let kind = item["type"].as_str().unwrap_or_default();
        if s(item.get("runId")) != Some(active)
            || !EXECUTION_TURN_ITEM_TYPES.contains(&kind)
            || !matches!(item["status"].as_str(), Some("running" | "waiting"))
            || (kind == "subagent" && item["origin"] == "app_owned")
        {
            continue;
        }
        if kind != "dynamic_tool" {
            return Ok(false);
        }
        return Err("t3_mcp_tool_name");
    }
    Ok(false)
}

fn description_from_turn_item(item: &Value) -> Option<String> {
    if let Some(t) = item["title"].as_str() {
        let t = js_trim(t);
        if !t.is_empty() {
            return Some(t);
        }
    }
    let kind = item["type"].as_str();
    if kind == Some("command_execution")
        && let Some(i) = item["input"].as_str()
    {
        let c = js_trim(i);
        return (!c.is_empty()).then_some(c);
    }
    if kind == Some("dynamic_tool")
        && let Some(n) = item["toolName"].as_str()
    {
        let n = js_trim(n);
        if !n.is_empty() {
            return Some(n);
        }
    }
    if kind == Some("subagent")
        && let Some(p) = item["prompt"].as_str()
    {
        let p = js_trim(p);
        return (!p.is_empty()).then_some(p);
    }
    None
}

fn pending_task_from_turn_item(task_id: &str, item: &Value) -> Obj {
    let mut t = Obj::new();
    t.insert("taskId".into(), task_id.into());
    if let Some(d) = description_from_turn_item(item) {
        t.insert("description".into(), d.into());
    }
    match item["type"].as_str() {
        Some("subagent") => {
            t.insert("kind".into(), "subagent".into());
            if let Some(p) = item.get("owningProviderInstanceId") {
                t.insert("providerInstanceId".into(), p.clone());
            }
            if !item["childThreadId"].is_null() {
                t.insert("childThreadId".into(), item["childThreadId"].clone());
            }
        }
        Some("command_execution") => {
            t.insert("kind".into(), "command".into());
        }
        _ => {
            t.insert("kind".into(), "background_task".into());
        }
    }
    t
}

fn native_task_id_from_turn_item(item: &Value) -> String {
    match item["nativeItemRef"]["nativeId"].as_str() {
        Some(n) if !n.is_empty() => n.to_owned(),
        _ => item["id"].as_str().unwrap_or_default().to_owned(),
    }
}

/// `pendingBackgroundTurnItems` without `runs` (the SQL already left out rolled-back runs).
fn pending_background_turn_items(turn_items: &[Value]) -> impl Iterator<Item = &Value> {
    turn_items.iter().filter(|item| {
        let kind = item["type"].as_str().unwrap_or_default();
        let persistent = item["input"]
            .as_object()
            .is_some_and(|i| i.get("persistent") == Some(&Value::Bool(true)));
        BACKGROUND_TURN_ITEM_TYPES.contains(&kind)
            && is_work_active(&item["status"])
            && !(kind == "dynamic_tool" && persistent)
    })
}

/// `pullRequestWatchTasks`. Its key (`threadPullRequestKeyOf`) needs the change-request URL
/// parser, which is not ported: a watched link declines.
fn pull_request_watch_tasks(pull_requests: Option<&Value>) -> Result<Vec<Obj>, &'static str> {
    let watched = pull_requests
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|l| l.get("watch").is_some() && l["source"] != "stack-dismissed");
    if watched {
        Err("pull_request_watch")
    } else {
        Ok(vec![])
    }
}

/// The run `derivePendingBackgroundWork` gets from the shell: `{id, ordinal: 0, status}`.
pub struct LatestRun<'a> {
    pub status: &'a str,
}

/// `derivePendingBackgroundWork` as the shell calls it (`hasActiveRun` given, no `runs`).
pub fn derive_pending_background_work(
    latest_run: Option<LatestRun>,
    provider_threads: &[Value],
    turn_items: &[Value],
    active_provider_thread_id: &Value,
    has_active_run: bool,
    pull_requests: Option<&Value>,
) -> Result<Vec<Obj>, &'static str> {
    if has_active_run {
        return Ok(vec![]);
    }
    let Some(latest) = latest_run else {
        return pull_request_watch_tasks(pull_requests);
    };
    if !SETTLED_FOR_BACKGROUND_WAIT_RUN_STATUSES.contains(&latest.status) {
        return Ok(vec![]);
    }
    let mut by_task_id = Obj::new();
    let threads = provider_threads
        .iter()
        .filter(|t| active_provider_thread_id.is_null() || &t["id"] == active_provider_thread_id);
    for pt in threads {
        for task in pt["pendingBackgroundTasks"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let id = task["taskId"].as_str().unwrap_or_default();
            if id.is_empty() || by_task_id.contains_key(id) {
                continue;
            }
            let mut named = task.as_object().cloned().unwrap_or_default();
            let raw = named.remove("description");
            if task["kind"] == "subagent" {
                named.insert(
                    "providerInstanceId".into(),
                    pt["providerInstanceId"].clone(),
                );
            }
            if let Some(d) = raw.as_ref().and_then(Value::as_str).map(js_trim)
                && !d.is_empty()
            {
                named.insert("description".into(), d.into());
            }
            by_task_id.insert(id.to_owned(), Value::Object(named));
        }
    }
    for item in pending_background_turn_items(turn_items) {
        let task_id = native_task_id_from_turn_item(item);
        if by_task_id.contains_key(&task_id) {
            continue;
        }
        let t = pending_task_from_turn_item(&task_id, item);
        by_task_id.insert(task_id, Value::Object(t));
    }
    pull_request_watch_tasks(pull_requests)?;
    Ok(by_task_id
        .into_iter()
        .map(|(_, v)| match v {
            Value::Object(o) => o,
            _ => unreachable!(),
        })
        .collect())
}

// --- ProjectionStore.ts: maps and per-row state ---

pub type RunMaps = (
    HashMap<String, HashMap<String, i64>>,
    HashMap<String, Vec<(String, i64)>>,
);

pub fn run_maps_by_thread_id(runs: &[ShellRunRow], counts: &[ShellRunItemCountRow]) -> RunMaps {
    let mut ordinals: HashMap<String, HashMap<String, i64>> = HashMap::new();
    for r in runs {
        ordinals
            .entry(r.thread_id.clone())
            .or_default()
            .insert(r.run_id.clone(), r.ordinal);
    }
    let mut items: HashMap<String, Vec<(String, i64)>> = HashMap::new();
    for r in counts {
        let e = items.entry(r.thread_id.clone()).or_default();
        match e.iter_mut().find(|(id, _)| id == &r.run_id) {
            Some(x) => x.1 = r.item_count,
            None => e.push((r.run_id.clone(), r.item_count)),
        }
    }
    (ordinals, items)
}

fn parse(text: &str, thread_id: &str, what: &str) -> Result<Value, Decline> {
    crate::effect_json::parse(text).ok_or_else(|| Decline::PayloadDrift {
        thread_id: thread_id.to_owned(),
        path: what.to_owned(),
    })
}

fn decode(schema: &wire::S, text: &str, thread_id: &str, what: &str) -> Result<Value, Decline> {
    let v = parse(text, thread_id, what)?;
    wire::decode(schema, &v, "$").map_err(|d| Decline::PayloadDrift {
        thread_id: thread_id.to_owned(),
        path: format!("{what}{}", &d.0[1..]),
    })
}

fn decode_turn_item(text: &str, thread_id: &str, what: &str) -> Result<Value, Decline> {
    let v = parse(text, thread_id, what)?;
    match wire::decode_turn_item(&v, "$") {
        Ok(Some(item)) => Ok(item),
        Ok(None) => Err(Decline::ItemKindNotPorted {
            thread_id: thread_id.to_owned(),
            kind: v["type"].as_str().unwrap_or_default().to_owned(),
        }),
        Err(d) => Err(Decline::PayloadDrift {
            thread_id: thread_id.to_owned(),
            path: format!("{what}{}", &d.0[1..]),
        }),
    }
}

/// `DateTime.makeUnsafe(text)` re-encoded.
fn date(text: Option<&String>, thread_id: &str, what: &str) -> Result<Option<String>, Decline> {
    text.map(|t| {
        crate::effect_json::date(t)
            .map(str::to_owned)
            .ok_or_else(|| Decline::PayloadDrift {
                thread_id: thread_id.to_owned(),
                path: what.to_owned(),
            })
    })
    .transpose()
}

pub struct PendingBackgroundData {
    pub provider_threads_by_thread_id: HashMap<String, Vec<Value>>,
    pub pending_turn_items_by_thread_id: HashMap<String, Vec<Value>>,
}

pub fn pending_background_data_by_thread_id(
    provider_thread_rows: &[ProviderThreadRow],
    pending_turn_item_rows: &[ShellPendingTurnItemRow],
) -> Result<PendingBackgroundData, Decline> {
    let mut providers: HashMap<String, Vec<Value>> = HashMap::new();
    for row in provider_thread_rows {
        let pt = decode(
            &wire::PROVIDER_THREAD_JSON,
            &row.payload_json,
            &row.thread_id,
            "providerThread",
        )?;
        let thread_id = if !row.thread_id.is_empty() {
            row.thread_id.clone()
        } else {
            match pt["appThreadId"].as_str() {
                Some(t) => t.to_owned(),
                None => continue,
            }
        };
        providers.entry(thread_id).or_default().push(pt);
    }
    let mut items: HashMap<String, Vec<Value>> = HashMap::new();
    for row in pending_turn_item_rows {
        let mut item = decode_turn_item(&row.payload_json, &row.thread_id, "pendingTurnItem")?;
        if let Some(p) = &row.owning_provider_instance_id {
            item.as_object_mut()
                .expect("object")
                .insert("owningProviderInstanceId".into(), p.clone().into());
        }
        items.entry(row.thread_id.clone()).or_default().push(item);
    }
    Ok(PendingBackgroundData {
        provider_threads_by_thread_id: providers,
        pending_turn_items_by_thread_id: items,
    })
}

pub fn shell_thread_state_from_row(
    row: &ShellThreadRow,
    maps: &RunMaps,
    data: &PendingBackgroundData,
) -> Result<ShellThreadState, Decline> {
    let tid = row.thread_id.as_str();
    let thread = match decode(&wire::APP_THREAD_JSON, &row.payload_json, tid, "thread")? {
        Value::Object(o) => o,
        _ => unreachable!("a struct decodes to an object"),
    };
    let not_ported = |what: &'static str| Decline::NotPorted {
        thread_id: tid.to_owned(),
        what,
    };
    let mut pending_runtime_request = match &row.pending_request_payload_json {
        Some(p) => pending_runtime_request_summary(&decode(
            &wire::RUNTIME_REQUEST_JSON,
            p,
            tid,
            "pendingRequest",
        )?),
        None => Value::Null,
    };
    if (pending_runtime_request.is_null() || pending_runtime_request["blocking"] == false)
        && let Some(p) = &row.pending_secret_request_payload_json
    {
        let item = decode_turn_item(p, tid, "pendingSecretRequest")?;
        if let Some(v) = secret_request_as_pending_input(&item) {
            pending_runtime_request = v;
        }
    }
    let mut terminal_failure = row
        .terminal_failure_payload_json
        .as_ref()
        .map(|p| decode_turn_item(p, tid, "terminalFailure"))
        .transpose()?;
    let mut latest_run_id = row.latest_run_id.clone();
    let mut latest_run_status =
        shell_status_from_stored_run_status(row.latest_run_status.as_deref()).to_owned();
    let mut latest_run_requested_at = date(
        row.latest_run_requested_at.as_ref(),
        tid,
        "latestRunRequestedAt",
    )?;
    let mut latest_run_started_at = date(
        row.latest_run_started_at.as_ref(),
        tid,
        "latestRunStartedAt",
    )?;
    let mut latest_run_completed_at = date(
        row.latest_run_completed_at.as_ref(),
        tid,
        "latestRunCompletedAt",
    )?;
    let mut latest_run_stop_requested = row.latest_run_stop_requested == 1;
    if let (Some(blocking_run_id), Some(p)) =
        (&row.blocking_run_id, &row.blocking_failure_payload_json)
    {
        // `Effect.orElseSucceed(() => null)`: a payload that does not decode is no failure.
        let blocking_failure = decode_turn_item(p, tid, "blockingFailure").ok();
        let failure = blocking_failure
            .as_ref()
            .filter(|f| f["type"] == "error")
            .map(|f| &f["failure"]);
        let blocks_queue = thread_error_summary(failure, row.last_error.as_deref())
            .last_error_class
            == "usage_limit";
        if blocks_queue && blocking_failure.is_some() {
            terminal_failure = blocking_failure;
            latest_run_id = Some(blocking_run_id.clone());
            latest_run_stop_requested = row.blocking_run_stop_requested == 1;
            latest_run_status = "failed".into();
            latest_run_requested_at = date(
                row.blocking_run_requested_at.as_ref(),
                tid,
                "blockingRunRequestedAt",
            )?;
            latest_run_started_at = date(
                row.blocking_run_started_at.as_ref(),
                tid,
                "blockingRunStartedAt",
            )?;
            latest_run_completed_at = date(
                row.blocking_run_completed_at.as_ref(),
                tid,
                "blockingRunCompletedAt",
            )?;
        }
    }
    let id = thread["id"].as_str().expect("decoded id");
    let none = Vec::new();
    let provider_threads = data.provider_threads_by_thread_id.get(id).unwrap_or(&none);
    let turn_items = data
        .pending_turn_items_by_thread_id
        .get(id)
        .unwrap_or(&none);
    let pending_background_tasks = derive_pending_background_work(
        (latest_run_id.is_some() && latest_run_status != "idle").then_some(LatestRun {
            status: &latest_run_status,
        }),
        provider_threads,
        turn_items,
        &thread["activeProviderThreadId"],
        row.active_run_id.is_some(),
        thread.get("pullRequests"),
    )
    .map_err(not_ported)?;
    let blocked_on_thread_wait = derive_blocked_on_thread_wait(
        row.active_run_id
            .as_deref()
            .filter(|_| row.active_run_status.as_deref() == Some("running")),
        turn_items,
    )
    .map_err(not_ported)?;
    let failure = terminal_failure
        .as_ref()
        .filter(|f| f["type"] == "error")
        .map(|f| &f["failure"]);
    Ok(ShellThreadState {
        latest_run_id,
        latest_run_status,
        latest_run_requested_at,
        latest_run_started_at,
        latest_run_completed_at,
        latest_run_stop_requested,
        active_run_id: row.active_run_id.clone(),
        blocked_on_thread_wait,
        activity_run_started_at: date(
            row.activity_run_started_at.as_ref(),
            tid,
            "activityRunStartedAt",
        )?,
        activity_run_status: row
            .activity_run_status
            .clone()
            .filter(|s| matches!(s.as_str(), "preparing" | "starting" | "running" | "waiting")),
        error: thread_error_summary(failure, row.last_error.as_deref()),
        pending_runtime_request,
        latest_user_message_at: date(
            row.latest_user_message_at.as_ref(),
            tid,
            "latestUserMessageAt",
        )?,
        latest_user_authored_message_at: date(
            row.latest_user_authored_message_at.as_ref(),
            tid,
            "latestUserAuthoredMessageAt",
        )?,
        has_actionable_proposed_plan: row.has_actionable_proposed_plan == 1,
        pending_background_tasks,
        provider_instance_history: provider_instance_history_for_shell(id, provider_threads),
        goal: active_provider_goal_for_shell(provider_threads, &thread["activeProviderThreadId"]),
        item_count: row.item_count,
        runless_item_count: row.runless_item_count,
        updated_at: thread["updatedAt"].clone(),
        run_ordinal_by_id: maps.0.get(tid).cloned().unwrap_or_default(),
        item_count_by_run_id: maps.1.get(tid).cloned().unwrap_or_default(),
        thread,
    })
}

/// `shellFromState`, encoded with `OrchestrationV2ThreadShell` (`contracts/orchestrationV2.ts:1809-1885`):
/// keys in that schema's order, which is not the object literal's.
pub fn shell_from_state(
    state: &ShellThreadState,
    visible_item_count: i64,
) -> Result<Value, Decline> {
    let t = &state.thread;
    let tid = state.id();
    let get = |k: &str| t.get(k).cloned().unwrap_or(Value::Null);
    let or_null = get;
    let mut o = Obj::new();
    let mut put = |k: &str, v: Value| {
        o.insert(k.to_owned(), v);
    };
    for k in [
        "createdBy",
        "creationSource",
        "id",
        "projectId",
        "title",
        "providerInstanceId",
        "modelSelection",
        "runtimeMode",
        "interactionMode",
        "branch",
        "worktreePath",
    ] {
        put(k, get(k));
    }
    if let Some(v) = t.get("linkedPullRequest") {
        put("linkedPullRequest", v.clone());
    }
    put(
        "pullRequests",
        thread_pull_requests_of(t).map_err(|what| Decline::NotPorted {
            thread_id: tid.to_owned(),
            what,
        })?,
    );
    if let Some(v) = t.get("branchPullRequest") {
        put("branchPullRequest", v.clone());
    }
    put("lineage", get("lineage"));
    put("forkedFrom", get("forkedFrom"));
    put("activeProviderThreadId", get("activeProviderThreadId"));
    if let Some(v) = t.get("historyOrigin") {
        put("historyOrigin", v.clone());
    }
    put("latestRunId", opt_str(state.latest_run_id.clone()));
    put(
        "latestRunRequestedAt",
        opt_str(state.latest_run_requested_at.clone()),
    );
    put(
        "latestRunStartedAt",
        opt_str(state.latest_run_started_at.clone()),
    );
    put(
        "latestRunCompletedAt",
        opt_str(state.latest_run_completed_at.clone()),
    );
    put(
        "latestRunStopRequested",
        state.latest_run_stop_requested.into(),
    );
    put("activeRunId", opt_str(state.active_run_id.clone()));
    put(
        "activityRunStartedAt",
        opt_str(state.activity_run_started_at.clone()),
    );
    put(
        "activityRunStatus",
        opt_str(state.activity_run_status.clone()),
    );
    put("blockedOnThreadWait", state.blocked_on_thread_wait.into());
    put("status", state.latest_run_status.clone().into());
    put("lastError", state.error.last_error.clone());
    put("lastErrorClass", state.error.last_error_class.clone());
    put("lastErrorCode", state.error.last_error_code.clone());
    put(
        "usageLimitResetAt",
        state.error.usage_limit_reset_at.clone(),
    );
    put(
        "pendingRuntimeRequest",
        state.pending_runtime_request.clone(),
    );
    put("latestVisibleMessage", Value::Null);
    put(
        "latestUserMessageAt",
        opt_str(state.latest_user_message_at.clone()),
    );
    put(
        "latestUserAuthoredMessageAt",
        opt_str(state.latest_user_authored_message_at.clone()),
    );
    put(
        "hasActionableProposedPlan",
        state.has_actionable_proposed_plan.into(),
    );
    let tasks = state
        .pending_background_tasks
        .iter()
        .map(wire::encode_pending_background_task)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|d| Decline::PayloadDrift {
            thread_id: tid.to_owned(),
            path: d.0,
        })?;
    put("pendingBackgroundTasks", Value::Array(tasks));
    put(
        "providerInstanceHistory",
        Value::Array(state.provider_instance_history.clone()),
    );
    put("goal", state.goal.clone());
    put("itemCount", state.item_count.into());
    put("visibleItemCount", visible_item_count.into());
    put("createdAt", get("createdAt"));
    put("updatedAt", state.updated_at.clone());
    put("archivedAt", get("archivedAt"));
    put("settledOverride", get("settledOverride"));
    put("settledAt", get("settledAt"));
    for k in [
        "unsettledAt",
        "snoozedUntil",
        "snoozedAt",
        "limitRecovery",
        "pinnedAt",
        "autoSettleDisabledAt",
        "pinOrderKey",
    ] {
        put(k, or_null(k));
    }
    if let Some(v) = t.get("activeOrderKey") {
        put("activeOrderKey", v.clone());
    }
    put("lastVisitedAt", get("lastVisitedAt"));
    put("titleRegeneration", or_null("titleRegeneration"));
    put("deletedAt", get("deletedAt"));
    Ok(Value::Object(o))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn run_status_maps_unknown_to_failed() {
        assert_eq!(shell_status_from_stored_run_status(None), "idle");
        assert_eq!(
            shell_status_from_stored_run_status(Some("waiting")),
            "waiting"
        );
        assert_eq!(
            shell_status_from_stored_run_status(Some("rolled_back")),
            "rolled_back"
        );
        assert_eq!(shell_status_from_stored_run_status(Some("weird")), "failed");
    }

    #[test]
    fn error_summary_prefers_the_session_error() {
        let f = json!({"class": "usage_limit", "message": "m", "code": "c", "resetAt": "r"});
        let e = thread_error_summary(Some(&f), None);
        assert_eq!(
            (
                e.usage_limit_reset_at,
                e.last_error,
                e.last_error_class,
                e.last_error_code
            ),
            (json!("r"), json!("m"), json!("usage_limit"), json!("c"))
        );
        // The same message: still the failure's class.
        assert_eq!(
            thread_error_summary(Some(&f), Some("m")).last_error_class,
            json!("usage_limit")
        );
        // Another session error: the failure is stale.
        let e = thread_error_summary(Some(&f), Some("other"));
        assert_eq!(
            (
                e.usage_limit_reset_at,
                e.last_error,
                e.last_error_class,
                e.last_error_code
            ),
            (Value::Null, json!("other"), Value::Null, Value::Null)
        );
        let e = thread_error_summary(None, Some("s"));
        assert_eq!(
            (e.last_error, e.last_error_class),
            (json!("s"), Value::Null)
        );
        let e = thread_error_summary(None, None);
        assert_eq!(e.last_error, Value::Null);
        let p = json!({"class": "provider_error", "message": "m", "code": null});
        let e = thread_error_summary(Some(&p), None);
        assert_eq!(
            (e.usage_limit_reset_at, e.last_error_code),
            (Value::Null, Value::Null)
        );
        // A usage limit without resetAt.
        let u = json!({"class": "usage_limit", "message": "m", "code": null});
        assert_eq!(
            thread_error_summary(Some(&u), None).usage_limit_reset_at,
            Value::Null
        );
    }

    #[test]
    fn runtime_request_and_secret_summaries() {
        let r = json!({"id": "q", "kind": "permission", "createdAt": "c", "responseCapability": {"type": "message"}});
        assert_eq!(
            pending_runtime_request_summary(&r).to_string(),
            r#"{"id":"q","kind":"permission","createdAt":"c","blocking":false}"#
        );
        let mut live = r.clone();
        live["responseCapability"] = json!({"type": "live", "providerSessionId": "s"});
        assert_eq!(pending_runtime_request_summary(&live)["blocking"], true);
        let secret = json!({"type": "secret_request", "id": "i", "nodeId": "n", "startedAt": null, "updatedAt": "u"});
        assert_eq!(
            secret_request_as_pending_input(&secret)
                .unwrap()
                .to_string(),
            r#"{"id":"i","kind":"user_input","createdAt":"u","blocking":true}"#
        );
        let mut started = secret.clone();
        started["startedAt"] = "s".into();
        assert_eq!(
            secret_request_as_pending_input(&started).unwrap()["createdAt"],
            "s"
        );
        let mut no_node = secret.clone();
        no_node["nodeId"] = Value::Null;
        assert_eq!(secret_request_as_pending_input(&no_node), None);
        assert_eq!(
            secret_request_as_pending_input(&json!({"type": "error", "nodeId": "n"})),
            None
        );
    }

    #[test]
    fn provider_history_sorts_by_created_then_id_and_dedups() {
        let pt = |id: &str, inst: &str, at: &str, app: &str, owner: Value| json!({"id": id, "providerInstanceId": inst, "createdAt": at, "appThreadId": app, "ownerNodeId": owner, "goal": {"objective": id}});
        let list = [
            pt("b", "codex", "2026-01-02T00:00:00.000Z", "t", Value::Null),
            pt("a", "claude", "2026-01-02T00:00:00.000Z", "t", Value::Null),
            pt("c", "codex", "2026-01-01T00:00:00.000Z", "t", Value::Null),
            pt("d", "other", "2026-01-01T00:00:00.000Z", "t", json!("node")),
            pt("e", "gemini", "2026-01-01T00:00:00.000Z", "u", Value::Null),
        ];
        assert_eq!(
            provider_instance_history_for_shell("t", &list),
            vec![json!("codex"), json!("claude")]
        );
        assert_eq!(
            active_provider_goal_for_shell(&list, &json!("d")),
            json!({"objective": "d"})
        );
        assert_eq!(
            active_provider_goal_for_shell(&list, &Value::Null),
            Value::Null
        );
        assert_eq!(
            active_provider_goal_for_shell(&list, &json!("zz")),
            Value::Null
        );
    }

    #[test]
    fn pull_requests_of_a_thread() {
        let t = |v: Value| thread_pull_requests_of(v.as_object().unwrap());
        assert_eq!(t(json!({"pullRequests": [1]})), Ok(json!([1])));
        assert_eq!(
            t(json!({"pullRequests": [], "linkedPullRequest": {"x": 1}})),
            Ok(json!([]))
        );
        assert_eq!(t(json!({})), Ok(json!([])));
        assert_eq!(t(json!({"linkedPullRequest": null})), Ok(json!([])));
        assert_eq!(
            t(json!({"linkedPullRequest": {"x": 1}})),
            Err("legacy_linked_pull_request")
        );
    }

    fn item(kind: &str, status: &str, extra: Value) -> Value {
        let mut v = json!({"type": kind, "status": status, "id": format!("{kind}-{status}"), "runId": "r",
            "title": null, "nativeItemRef": null, "input": null, "childThreadId": null});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    }
    fn tasks(r: Result<Vec<Obj>, &'static str>) -> String {
        Value::Array(r.unwrap().into_iter().map(Value::Object).collect()).to_string()
    }
    const SETTLED: Option<LatestRun> = Some(LatestRun {
        status: "completed",
    });

    #[test]
    fn pending_work_gates_on_the_active_and_latest_run() {
        let items = [item(
            "command_execution",
            "running",
            json!({"input": " sleep 9 "}),
        )];
        let d = |latest, active| {
            derive_pending_background_work(latest, &[], &items, &Value::Null, active, None)
        };
        assert_eq!(tasks(d(SETTLED, true)), "[]", "an active run holds nothing");
        assert_eq!(
            tasks(d(Some(LatestRun { status: "running" }), false)),
            "[]",
            "unsettled"
        );
        assert_eq!(
            tasks(d(
                Some(LatestRun {
                    status: "rolled_back"
                }),
                false
            )),
            "[]"
        );
        assert_eq!(tasks(d(None, false)), "[]", "no run: only PR watches");
        assert_eq!(
            tasks(d(Some(LatestRun { status: "waiting" }), false)),
            r#"[{"taskId":"command_execution-running","description":"sleep 9","kind":"command"}]"#
        );
        let watched = json!([{"watch": {}, "source": "manual"}]);
        let dismissed = json!([{"watch": {}, "source": "stack-dismissed"}, {"source": "manual"}]);
        let w = |latest, prs| {
            derive_pending_background_work(latest, &[], &[], &Value::Null, false, Some(prs))
        };
        assert_eq!(w(None, &watched), Err("pull_request_watch"));
        assert_eq!(w(SETTLED, &watched), Err("pull_request_watch"));
        assert_eq!(tasks(w(None, &dismissed)), "[]");
    }

    #[test]
    fn pending_work_from_provider_threads_then_items() {
        let pts = [
            json!({"id": "p1", "providerInstanceId": "codex", "pendingBackgroundTasks": [
                {"taskId": "t1", "kind": "subagent", "description": "  d  ", "providerInstanceId": "stale"},
                {"taskId": "t2", "kind": "monitor", "description": " "},
            ]}),
            json!({"id": "p2", "providerInstanceId": "claude", "pendingBackgroundTasks": [
                {"taskId": "t1", "kind": "command"}, {"taskId": "t3", "kind": "command"},
            ]}),
        ];
        let items = [
            item(
                "subagent",
                "waiting",
                json!({"id": "s", "prompt": " go ", "owningProviderInstanceId": "codex", "childThreadId": "c"}),
            ),
            item(
                "dynamic_tool",
                "pending",
                json!({"id": "dt", "toolName": " tool ", "nativeItemRef": {"nativeId": "t3"}}),
            ),
            item(
                "dynamic_tool",
                "running",
                json!({"id": "persist", "input": {"persistent": true}}),
            ),
            item("command_execution", "completed", json!({})),
            item("file_change", "running", json!({})),
            item(
                "command_execution",
                "running",
                json!({"id": "c2", "title": " T ", "input": "x", "nativeItemRef": {"nativeId": ""}}),
            ),
            item(
                "command_execution",
                "running",
                json!({"id": "c3", "input": "  "}),
            ),
        ];
        let all = derive_pending_background_work(SETTLED, &pts, &items, &Value::Null, false, None);
        assert_eq!(
            tasks(all),
            concat!(
                r#"[{"taskId":"t1","kind":"subagent","providerInstanceId":"codex","description":"d"},"#,
                r#"{"taskId":"t2","kind":"monitor"},{"taskId":"t3","kind":"command"},"#,
                r#"{"taskId":"s","description":"go","kind":"subagent","providerInstanceId":"codex","childThreadId":"c"},"#,
                r#"{"taskId":"c2","description":"T","kind":"command"},{"taskId":"c3","kind":"command"}]"#
            )
        );
        // The active provider thread only.
        let one = derive_pending_background_work(SETTLED, &pts, &[], &json!("p2"), false, None);
        assert_eq!(
            tasks(one),
            r#"[{"taskId":"t1","kind":"command"},{"taskId":"t3","kind":"command"}]"#
        );
        // A dynamic tool's description is its trimmed name.
        let dt = [item(
            "dynamic_tool",
            "running",
            json!({"id": "x", "toolName": " n "}),
        )];
        let r = derive_pending_background_work(SETTLED, &[], &dt, &Value::Null, false, None);
        assert_eq!(
            tasks(r),
            r#"[{"taskId":"x","description":"n","kind":"background_task"}]"#
        );
    }

    #[test]
    fn blocked_on_thread_wait_only_for_running_runs() {
        let items = [item("command_execution", "running", json!({}))];
        assert_eq!(derive_blocked_on_thread_wait(None, &items), Ok(false));
        assert_eq!(
            derive_blocked_on_thread_wait(Some("r"), &items),
            Ok(false),
            "other work runs"
        );
        assert_eq!(derive_blocked_on_thread_wait(Some("r"), &[]), Ok(false));
        let skipped = [
            item("command_execution", "running", json!({"runId": "other"})),
            item("assistant_message", "running", json!({})),
            item("command_execution", "pending", json!({})),
            item("subagent", "running", json!({"origin": "app_owned"})),
        ];
        assert_eq!(
            derive_blocked_on_thread_wait(Some("r"), &skipped),
            Ok(false)
        );
        let tool = [item(
            "dynamic_tool",
            "waiting",
            json!({"toolName": "t3_thread_wait"}),
        )];
        assert_eq!(
            derive_blocked_on_thread_wait(Some("r"), &tool),
            Err("t3_mcp_tool_name")
        );
    }

    fn state(id: &str, items: i64, forked: Value) -> ShellThreadState {
        ShellThreadState {
            thread: json!({"id": id, "forkedFrom": forked})
                .as_object()
                .unwrap()
                .clone(),
            latest_run_id: None,
            latest_run_status: "idle".into(),
            latest_run_requested_at: None,
            latest_run_started_at: None,
            latest_run_completed_at: None,
            latest_run_stop_requested: false,
            active_run_id: None,
            blocked_on_thread_wait: false,
            activity_run_status: None,
            activity_run_started_at: None,
            error: thread_error_summary(None, None),
            pending_runtime_request: Value::Null,
            latest_user_message_at: None,
            latest_user_authored_message_at: None,
            has_actionable_proposed_plan: false,
            pending_background_tasks: vec![],
            provider_instance_history: vec![],
            goal: Value::Null,
            item_count: items,
            runless_item_count: 0,
            updated_at: Value::Null,
            run_ordinal_by_id: HashMap::new(),
            item_count_by_run_id: vec![],
        }
    }
    fn fork(thread: &str, run: &str) -> Value {
        json!({"type": "run", "threadId": thread, "runId": run})
    }

    #[test]
    fn item_count_through_run_counts_runs_up_to_the_ordinal() {
        let mut s = state("s", 10, Value::Null);
        s.run_ordinal_by_id = HashMap::from([("r1".into(), 1), ("r2".into(), 2), ("r3".into(), 3)]);
        s.item_count_by_run_id = vec![
            ("r1".into(), 4),
            ("r2".into(), 3),
            ("r3".into(), 2),
            ("gone".into(), 9),
        ];
        s.runless_item_count = 5;
        assert_eq!(item_count_through_run(&s, "r2"), 7);
        assert_eq!(item_count_through_run(&s, "missing"), 0);
        s.thread.insert("historyOrigin".into(), "v1_import".into());
        assert_eq!(
            item_count_through_run(&s, "r2"),
            12,
            "imported history counts runless items"
        );
    }

    #[test]
    fn visible_item_count_walks_run_forks() {
        let mut root = state("root", 10, Value::Null);
        root.run_ordinal_by_id = HashMap::from([("r1".into(), 1), ("r2".into(), 2)]);
        root.item_count_by_run_id = vec![("r1".into(), 3), ("r2".into(), 4)];
        let mut mid = state("mid", 5, fork("root", "r1"));
        mid.run_ordinal_by_id = HashMap::from([("m1".into(), 1)]);
        mid.item_count_by_run_id = vec![("m1".into(), 2)];
        let leaf = state("leaf", 1, fork("mid", "m1"));
        let node = state("node", 6, json!({"type": "node", "nodeId": "n"}));
        let orphan = state("orphan", 2, fork("nowhere", "x"));
        let states: HashMap<String, ShellThreadState> = [root, mid, leaf, node, orphan]
            .into_iter()
            .map(|s| (s.id().to_owned(), s))
            .collect();
        let v = |id| visible_item_count_for_shell(id, &states, None);
        assert_eq!(v("root"), 10);
        assert_eq!(v("node"), 6);
        assert_eq!(v("orphan"), 2);
        assert_eq!(v("missing"), 0);
        assert_eq!(v("mid"), 3 + 1 + 5);
        // leaf: mid's visible prefix beyond mid's own items (3 + 1), mid through m1 (2), the fork marker, leaf.
        assert_eq!(v("leaf"), (9 - 5) + 2 + 1 + 1);
        // A fork cycle stops at the thread already seen.
        let a = state("a", 1, fork("b", "x"));
        let b = state("b", 2, fork("a", "y"));
        let cyc: HashMap<_, _> = [a, b].into_iter().map(|s| (s.id().to_owned(), s)).collect();
        // b seen from a: (a again: its own 1) - 1 + 0 + 1 + 2 = 3; a: (3 - 2) + 0 + 1 + 1.
        assert_eq!(visible_item_count_for_shell("a", &cyc, None), 3);
    }

    #[test]
    fn run_maps_group_by_thread() {
        let runs = [
            ShellRunRow {
                thread_id: "t".into(),
                run_id: "r1".into(),
                ordinal: 1,
            },
            ShellRunRow {
                thread_id: "u".into(),
                run_id: "r2".into(),
                ordinal: 1,
            },
        ];
        let counts = [ShellRunItemCountRow {
            thread_id: "t".into(),
            run_id: "r1".into(),
            item_count: 7,
        }];
        let (o, c) = run_maps_by_thread_id(&runs, &counts);
        assert_eq!(o["t"]["r1"], 1);
        assert_eq!(o["u"]["r2"], 1);
        assert_eq!(c["t"], vec![("r1".to_owned(), 7)]);
        assert!(!c.contains_key("u"));
    }
}
