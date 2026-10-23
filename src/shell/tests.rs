//! `build_threads` over synthetic state DBs: one case per branch of the shell's TypeScript. The
//! expected values follow the engine's code by hand; the live test checks the same fixtures against
//! Node (`tests/live_differential.rs`, `shell_builder_matches_node_on_fixtures`).
use super::fixture::{Fx, T0, at, thread_payload};
use super::*;
use crate::db::read::{StateDb, tests::fixture};
use serde_json::json;
use std::collections::HashSet;

pub(crate) const INDEXES: &str = "
CREATE INDEX idx_orchestration_events_application_high_water
    ON orchestration_events(sequence)
    WHERE aggregate_kind = 'project'
      OR (application_event_version = 2 AND aggregate_kind = 'thread');
CREATE INDEX orchestration_v2_projection_turn_items_thread_run_idx
    ON orchestration_v2_projection_turn_items(thread_id, run_id);
";

fn db(fx: &Fx) -> (tempfile::TempDir, StateDb) {
    let dir = tempfile::tempdir().unwrap();
    let db = fixture(dir.path(), &format!("{INDEXES}{}", fx.0));
    (dir, db)
}

fn build(fx: &Fx, location: Location) -> Result<Vec<Value>, Decline> {
    let (_dir, db) = db(fx);
    db.read(|c| Ok(build_threads(c, location)))
        .map_err(Decline::Read)?
}

fn one(fx: &Fx) -> Value {
    let mut v = build(fx, Location::Active).unwrap();
    assert_eq!(v.len(), 1, "{v:?}");
    v.remove(0)
}

fn by_id(v: &[Value], id: &str) -> Value {
    v.iter().find(|t| t["id"] == id).cloned().unwrap()
}

fn text(v: &Value) -> String {
    String::from_utf8(crate::effect_json::to_vec(v)).unwrap()
}

#[test]
fn a_thread_without_runs_has_every_key_in_schema_order() {
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}));
    let want = concat!(
        r#"{"createdBy":"user","creationSource":"web","id":"t","projectId":"project-1","title":"Thread t","#,
        r#""providerInstanceId":"codex","modelSelection":{"instanceId":"codex","model":"gpt-5"},"#,
        r#""runtimeMode":"full-access","interactionMode":"default","branch":null,"worktreePath":null,"#,
        r#""pullRequests":[],"lineage":{"parentThreadId":null,"relationshipToParent":null,"rootThreadId":"t"},"#,
        r#""forkedFrom":null,"activeProviderThreadId":null,"latestRunId":null,"latestRunRequestedAt":null,"#,
        r#""latestRunStartedAt":null,"latestRunCompletedAt":null,"latestRunStopRequested":false,"activeRunId":null,"#,
        r#""activityRunStartedAt":null,"activityRunStatus":null,"blockedOnThreadWait":false,"status":"idle","#,
        r#""lastError":null,"lastErrorClass":null,"lastErrorCode":null,"usageLimitResetAt":null,"#,
        r#""pendingRuntimeRequest":null,"latestVisibleMessage":null,"latestUserMessageAt":null,"#,
        r#""latestUserAuthoredMessageAt":null,"hasActionableProposedPlan":false,"pendingBackgroundTasks":[],"#,
        r#""providerInstanceHistory":[],"goal":null,"itemCount":0,"visibleItemCount":0,"#,
        r#""createdAt":"2026-01-01T00:00:00.000Z","updatedAt":"2026-01-01T00:01:00.000Z","archivedAt":null,"#,
        r#""settledOverride":null,"settledAt":null,"unsettledAt":null,"snoozedUntil":null,"snoozedAt":null,"#,
        r#""limitRecovery":null,"pinnedAt":null,"autoSettleDisabledAt":null,"pinOrderKey":null,"#,
        r#""lastVisitedAt":null,"titleRegeneration":null,"deletedAt":null}"#
    );
    assert_eq!(text(&one(&fx)), want);
    assert_eq!(
        one(&fx).as_object().unwrap().len(),
        54,
        "58 fields less the 4 optional ones"
    );
}

#[test]
fn optional_thread_keys_appear_where_the_payload_has_them() {
    let mut fx = Fx::default();
    fx.thread(
        "t",
        1,
        json!({"linkedPullRequest": null, "branchPullRequest": {"projectId": "p", "repository": "o/r", "number": 2, "url": "u"},
            "historyOrigin": "native", "activeOrderKey": "a0", "pinOrderKey": "k", "unsettledAt": T0,
            "limitRecovery": {"runId": "r", "resetAt": "x", "autoResume": true}, "lastSnoozeWakeAt": T0,
            "titleRegeneration": {"startedAt": T0, "requestId": "c"}}),
    );
    let t = one(&fx);
    let keys: Vec<&str> = t.as_object().unwrap().keys().map(String::as_str).collect();
    let pos = |k: &str| {
        keys.iter()
            .position(|x| *x == k)
            .unwrap_or_else(|| panic!("{k}"))
    };
    assert!(
        pos("worktreePath") < pos("linkedPullRequest")
            && pos("linkedPullRequest") < pos("pullRequests")
    );
    assert!(
        pos("pullRequests") < pos("branchPullRequest") && pos("branchPullRequest") < pos("lineage")
    );
    assert!(
        pos("activeProviderThreadId") < pos("historyOrigin")
            && pos("historyOrigin") < pos("latestRunId")
    );
    assert!(
        pos("pinOrderKey") < pos("activeOrderKey") && pos("activeOrderKey") < pos("lastVisitedAt")
    );
    assert!(!keys.contains(&"lastSnoozeWakeAt"), "not a shell field");
    assert_eq!(
        text(&t["titleRegeneration"]),
        r#"{"requestId":"c","startedAt":"2026-01-01T00:00:00.000Z"}"#
    );
    assert_eq!(
        text(&t["limitRecovery"]),
        r#"{"runId":"r","resetAt":"x","autoResume":true}"#
    );
    assert_eq!(keys.len(), 58);
}

#[test]
fn each_stored_run_status_is_the_thread_status() {
    for status in [
        "preparing",
        "queued",
        "starting",
        "running",
        "waiting",
        "completed",
        "interrupted",
        "failed",
        "cancelled",
        "rolled_back",
    ] {
        let mut fx = Fx::default();
        fx.thread("t", 1, json!({})).run("t", 1, status, json!({}));
        let t = one(&fx);
        assert_eq!(t["status"], status);
        assert_eq!(t["latestRunId"], "t:run:1");
        assert_eq!(t["latestRunRequestedAt"], at(1));
        assert_eq!(t["latestRunStartedAt"], at(1));
        let interruptible = matches!(status, "preparing" | "starting" | "running");
        assert_eq!(t["activeRunId"].is_string(), interruptible, "{status}");
        let activity = interruptible || status == "waiting";
        assert_eq!(
            t["activityRunStatus"].as_str(),
            activity.then_some(status),
            "{status}"
        );
        assert_eq!(t["activityRunStartedAt"].is_string(), activity, "{status}");
    }
}

#[test]
fn a_held_queue_is_not_the_presented_run_and_activity_prefers_work_started() {
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "waiting", json!({"workStartedAt": at(9)}))
        .run("t", 2, "queued", json!({"queueHeld": true}));
    let t = one(&fx);
    assert_eq!(
        (t["latestRunId"].as_str(), t["status"].as_str()),
        (Some("t:run:1"), Some("waiting"))
    );
    assert_eq!(t["activityRunStartedAt"], at(9));
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "completed", json!({}))
        .run(
            "t",
            2,
            "queued",
            json!({"queueHeld": false, "startedAt": null}),
        );
    let t = one(&fx);
    assert_eq!(
        (t["latestRunId"].as_str(), t["latestRunStartedAt"].clone()),
        (Some("t:run:2"), Value::Null)
    );
}

#[test]
fn stop_requests_counts_and_messages() {
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "completed", json!({}))
        .run("t", 2, "rolled_back", json!({}))
        .run("t", 3, "interrupted", json!({}))
        .item(
            "t",
            "i1",
            Some(1),
            "assistant_message",
            "completed",
            json!({}),
        )
        .item(
            "t",
            "i2",
            Some(2),
            "assistant_message",
            "completed",
            json!({}),
        )
        .item(
            "t",
            "i3",
            Some(3),
            "run_interrupt_request",
            "completed",
            json!({}),
        )
        .item("t", "i4", None, "user_message", "completed", json!({}))
        .message("t", "m1", "user", "user", 5)
        .message("t", "m2", "user", "agent", 6)
        .message("t", "m3", "assistant", "agent", 7)
        .plan("t", "proposed_plan", "completed");
    let t = one(&fx);
    assert_eq!(t["latestRunStopRequested"], true);
    assert_eq!(
        t["itemCount"], 3,
        "rolled-back run's items left out, runless kept"
    );
    assert_eq!(t["visibleItemCount"], 3);
    assert_eq!(t["latestUserMessageAt"], at(6));
    assert_eq!(t["latestUserAuthoredMessageAt"], at(5));
    assert_eq!(t["hasActionableProposedPlan"], false);
    fx.plan("t", "proposed_plan", "active");
    assert_eq!(one(&fx)["hasActionableProposedPlan"], true);
}

fn failure(class: &str, message: &str) -> Value {
    json!({"failure": {"class": class, "message": message, "code": "E1", "retryable": false, "resetAt": "2026-02-01T00:00:00.000Z"}})
}

#[test]
fn a_failed_run_reports_its_root_failure_and_the_session_error() {
    let mut fx = Fx::default();
    let mut err = failure("provider_error", " boom ");
    err["nodeId"] = "t:run:1:root".into();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "failed", json!({}))
        .item("t", "e1", Some(1), "error", "failed", err.clone());
    let t = one(&fx);
    assert_eq!(
        (
            t["lastError"].clone(),
            t["lastErrorClass"].clone(),
            t["lastErrorCode"].clone(),
            t["usageLimitResetAt"].clone()
        ),
        (
            json!("boom"),
            json!("provider_error"),
            json!("E1"),
            Value::Null
        )
    );
    // A newer session error on the thread's instance replaces the stale failure.
    fx.session_error("t", "codex", "session down");
    let t = one(&fx);
    assert_eq!(
        (t["lastError"].clone(), t["lastErrorClass"].clone()),
        (json!("session down"), Value::Null)
    );
    // A failure item off the root node is not the run's failure.
    let mut fx = Fx::default();
    err["nodeId"] = "elsewhere".into();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "failed", json!({}))
        .item("t", "e1", Some(1), "error", "failed", err);
    assert_eq!(one(&fx)["lastError"], Value::Null);
}

#[test]
fn a_usage_limited_run_is_presented_over_later_queued_runs() {
    let mut err = failure("usage_limit", "limit");
    err["nodeId"] = "t:run:1:root".into();
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "failed", json!({"completedAt": at(3)}))
        .item("t", "e1", Some(1), "error", "failed", err)
        .item(
            "t",
            "stop",
            Some(1),
            "run_interrupt_request",
            "completed",
            json!({}),
        )
        .run("t", 2, "queued", json!({}));
    let t = one(&fx);
    assert_eq!(
        (t["latestRunId"].as_str(), t["status"].as_str()),
        (Some("t:run:1"), Some("failed"))
    );
    assert_eq!(t["latestRunStopRequested"], true);
    assert_eq!(t["latestRunCompletedAt"], at(3));
    assert_eq!(t["usageLimitResetAt"], "2026-02-01T00:00:00.000Z");
    assert_eq!(t["lastErrorClass"], "usage_limit");
    // Another class does not hold the queue: the queued run is presented.
    let mut err = failure("provider_error", "x");
    err["nodeId"] = "t:run:1:root".into();
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "failed", json!({"completedAt": at(3)}))
        .item("t", "e1", Some(1), "error", "failed", err)
        .run("t", 2, "queued", json!({}));
    let t = one(&fx);
    assert_eq!(
        (t["latestRunId"].as_str(), t["status"].as_str()),
        (Some("t:run:2"), Some("queued"))
    );
    assert_eq!(t["lastErrorClass"], Value::Null);
}

#[test]
fn pending_runtime_requests_and_secrets() {
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .request("t", "q-old", "resolved", json!({"type": "message"}))
        .request(
            "t",
            "q1",
            "pending",
            json!({"type": "live", "providerSessionId": "s"}),
        );
    assert_eq!(
        text(&one(&fx)["pendingRuntimeRequest"]),
        r#"{"id":"q1","kind":"permission","createdAt":"2026-01-01T00:40:00.000Z","blocking":true}"#
    );
    // A non-blocking question gives way to a waiting secret request on a live run.
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .request("t", "q1", "pending", json!({"type": "message"}))
        .run("t", 1, "running", json!({}))
        .item(
            "t",
            "sec",
            Some(1),
            "secret_request",
            "waiting",
            json!({"nodeId": "n", "label": "API key", "reason": "r", "secretStatus": "pending", "startedAt": at(2)}),
        );
    assert_eq!(
        text(&one(&fx)["pendingRuntimeRequest"]),
        r#"{"id":"sec","kind":"user_input","createdAt":"2026-01-01T00:02:00.000Z","blocking":true}"#
    );
}

#[test]
fn pending_background_work_on_a_settled_run() {
    let sub = json!({"subagentId": "n", "origin": "provider_native", "driver": "codex",
        "providerInstanceId": "codex", "childThreadId": "child", "prompt": " look ", "result": null,
        "providerThreadId": "pt1"});
    let base = |fx: &mut Fx| {
        fx.thread("t", 1, json!({"activeProviderThreadId": "pt1"}))
            .run("t", 1, "completed", json!({}))
            .provider_thread("t", "pt1", "codex", json!({"pendingBackgroundTasks": [{"taskId": "bg", "kind": "subagent", "description": " d "}],
                "goal": {"objective": " ship ", "status": "active"}}))
            .provider_thread("t", "pt0", "claudeAgent", json!({"createdAt": "2025-12-31T00:00:00.000Z",
                "pendingBackgroundTasks": [{"taskId": "other", "kind": "command"}]}))
            .item("t", "done", Some(1), "command_execution", "completed", json!({"input": "x"}));
    };
    let mut fx = Fx::default();
    base(&mut fx);
    fx.item(
        "t",
        "cmd",
        Some(1),
        "command_execution",
        "running",
        json!({"input": " sleep 5 "}),
    );
    let t = one(&fx);
    // Only the active provider thread's tasks, then the one pending item.
    assert_eq!(
        text(&t["pendingBackgroundTasks"]),
        concat!(
            r#"[{"taskId":"bg","description":"d","kind":"subagent","providerInstanceId":"codex"},"#,
            r#"{"taskId":"cmd","description":"sleep 5","kind":"command"}]"#
        )
    );
    assert_eq!(
        text(&t["providerInstanceHistory"]),
        r#"["claudeAgent","codex"]"#
    );
    assert_eq!(
        text(&t["goal"]),
        r#"{"objective":"ship","status":"active"}"#
    );
    let mut fx = Fx::default();
    base(&mut fx);
    fx.item("t", "sub", Some(1), "subagent", "waiting", sub.clone());
    assert_eq!(
        text(&one(&fx)["pendingBackgroundTasks"]),
        concat!(
            r#"[{"taskId":"bg","description":"d","kind":"subagent","providerInstanceId":"codex"},"#,
            r#"{"taskId":"sub","description":"look","kind":"subagent","providerInstanceId":"codex","childThreadId":"child"}]"#
        )
    );
    // Two qualifying items: their order is SQLite's plan. Decline.
    fx.item(
        "t",
        "cmd",
        Some(1),
        "command_execution",
        "running",
        json!({"input": "x"}),
    );
    let unordered = Decline::NotPorted {
        thread_id: "t".into(),
        what: "unordered_rows",
    };
    assert_eq!(build(&fx, Location::Active), Err(unordered.clone()));
    // While a run is active, nothing is pending (the gate comes first).
    fx.run("t", 2, "running", json!({}));
    assert_eq!(one(&fx)["pendingBackgroundTasks"], json!([]));
    // No active provider thread: both rows with tasks contribute. Decline.
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "completed", json!({}))
        .provider_thread(
            "t",
            "pt1",
            "codex",
            json!({"pendingBackgroundTasks": [{"taskId": "a", "kind": "command"}]}),
        )
        .provider_thread(
            "t",
            "pt2",
            "codex",
            json!({"pendingBackgroundTasks": [{"taskId": "b", "kind": "command"}]}),
        );
    assert_eq!(build(&fx, Location::Active), Err(unordered));
}

#[test]
fn a_running_run_reads_execution_items_for_the_thread_wait() {
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "running", json!({}))
        .item(
            "t",
            "fc",
            Some(1),
            "file_change",
            "running",
            json!({"fileName": "a.rs"}),
        );
    assert_eq!(
        one(&fx)["blockedOnThreadWait"],
        false,
        "a file change is not a wait"
    );
    let mut only_tool = Fx::default();
    only_tool
        .thread("t", 1, json!({}))
        .run("t", 1, "running", json!({}))
        .item(
            "t",
            "dt",
            Some(1),
            "dynamic_tool",
            "running",
            json!({"toolName": "t3_thread_wait", "input": {}}),
        );
    assert_eq!(
        build(&only_tool, Location::Active),
        Err(Decline::NotPorted {
            thread_id: "t".into(),
            what: "t3_mcp_tool_name"
        })
    );
}

#[test]
fn run_forks_count_the_inherited_prefix_through_a_chain() {
    let mut fx = Fx::default();
    fx.thread("root", 1, json!({"archivedAt": T0}))
        .run("root", 1, "completed", json!({}))
        .run("root", 2, "completed", json!({}))
        .item(
            "root",
            "r1a",
            Some(1),
            "assistant_message",
            "completed",
            json!({}),
        )
        .item(
            "root",
            "r1b",
            Some(1),
            "assistant_message",
            "completed",
            json!({}),
        )
        .item(
            "root",
            "r2a",
            Some(2),
            "assistant_message",
            "completed",
            json!({}),
        )
        .thread(
            "mid",
            2,
            json!({"forkedFrom": {"type": "run", "threadId": "root", "runId": "root:run:1"}}),
        )
        .run("mid", 1, "completed", json!({}))
        .item(
            "mid",
            "m1",
            Some(1),
            "assistant_message",
            "completed",
            json!({}),
        )
        .thread(
            "leaf",
            3,
            json!({"forkedFrom": {"type": "run", "threadId": "mid", "runId": "mid:run:1"}}),
        )
        .item("leaf", "l1", None, "user_message", "completed", json!({}));
    let active = build(&fx, Location::Active).unwrap();
    assert_eq!(
        active.iter().map(|t| t["id"].clone()).collect::<Vec<_>>(),
        vec![json!("mid"), json!("leaf")]
    );
    assert_eq!(by_id(&active, "mid")["visibleItemCount"], 2 + 1 + 1);
    // leaf: mid's prefix (2 + 1), mid through its run 1 (1), the fork marker (1), leaf's own (1).
    assert_eq!(by_id(&active, "leaf")["visibleItemCount"], 3 + 1 + 1 + 1);
    let archived = build(&fx, Location::Archive).unwrap();
    assert_eq!(archived.len(), 1);
    assert_eq!(archived[0]["id"], "root");
    assert_eq!(archived[0]["visibleItemCount"], 3);
    // An archived source of an archived source is still walked to.
    let mut fx = Fx::default();
    fx.thread("root", 1, json!({"archivedAt": T0}))
        .run("root", 1, "completed", json!({}))
        .item("root", "r1a", Some(1), "assistant_message", "completed", json!({}))
        .item("root", "r1b", Some(1), "assistant_message", "completed", json!({}))
        .thread("mid", 2, json!({"archivedAt": T0, "forkedFrom": {"type": "run", "threadId": "root", "runId": "root:run:1"}}))
        .run("mid", 1, "completed", json!({}))
        .item("mid", "m1", Some(1), "assistant_message", "completed", json!({}))
        .thread("leaf", 3, json!({"forkedFrom": {"type": "run", "threadId": "mid", "runId": "mid:run:1"}}))
        .item("leaf", "l1", None, "user_message", "completed", json!({}));
    assert_eq!(one(&fx)["visibleItemCount"], 3 + 1 + 1 + 1);
}

#[test]
fn only_the_location_s_threads_are_targets() {
    let mut fx = Fx::default();
    fx.thread("a", 1, json!({}))
        .thread("z", 2, json!({"archivedAt": T0}));
    let (_d, sdb) = db(&fx);
    let targets = |l| {
        sdb.read(|c| read_shell_snapshot_rows(c, l).map(|r| r.target_thread_ids))
            .unwrap()
    };
    assert_eq!(targets(Location::Active), HashSet::from(["a".to_owned()]));
    assert_eq!(targets(Location::Archive), HashSet::from(["z".to_owned()]));
}

#[test]
fn deleted_threads_are_left_out_even_as_fork_sources() {
    let mut fx = Fx::default();
    fx.thread("gone", 1, json!({"deletedAt": T0}))
        .thread(
            "t",
            2,
            json!({"forkedFrom": {"type": "run", "threadId": "gone", "runId": "gone:run:1"}}),
        )
        .item("t", "i", None, "user_message", "completed", json!({}));
    let t = one(&fx);
    assert_eq!(t["id"], "t");
    assert_eq!(t["visibleItemCount"], 1, "source missing: own items only");
}

#[test]
fn threads_come_in_updated_at_then_id_order() {
    let mut fx = Fx::default();
    fx.thread("b", 2, json!({}))
        .thread("a", 2, json!({}))
        .thread("c", 1, json!({}));
    let ids: Vec<Value> = build(&fx, Location::Active)
        .unwrap()
        .into_iter()
        .map(|t| t["id"].clone())
        .collect();
    assert_eq!(ids, vec![json!("c"), json!("a"), json!("b")]);
    assert_eq!(build(&Fx::default(), Location::Active), Ok(vec![]));
}

#[test]
fn legacy_rows_decode_or_decline() {
    let mut fx = Fx::default();
    fx.thread(
        "t",
        1,
        json!({"modelSelection": {"provider": "codex", "model": " m ", "options": {"effort": "high"}},
            "settledOverride": null, "title": "  padded  "}),
    );
    let t = one(&fx);
    assert_eq!(
        text(&t["modelSelection"]),
        r#"{"instanceId":"codex","model":"m","options":[{"id":"effort","value":"high"}]}"#
    );
    assert_eq!(t["title"], "padded");
    // A payload written before `settledAt`/`lastVisitedAt` existed decodes them to null.
    let mut p = thread_payload("old", json!({}));
    for k in ["settledOverride", "settledAt", "lastVisitedAt"] {
        p.as_object_mut().unwrap().remove(k);
    }
    let mut fx = Fx::default();
    fx.thread_raw("old", &p);
    let t = one(&fx);
    assert_eq!(
        (
            t["settledOverride"].clone(),
            t["settledAt"].clone(),
            t["lastVisitedAt"].clone()
        ),
        (Value::Null, Value::Null, Value::Null)
    );
    // A single legacy linked PR without `pullRequests` needs the URL parser: decline.
    let mut p = thread_payload(
        "pr",
        json!({"linkedPullRequest": {"projectId": "p", "repository": "o/r", "number": 1, "url": "https://github.com/o/r/pull/1"}}),
    );
    p.as_object_mut().unwrap().remove("pullRequests");
    let mut fx = Fx::default();
    fx.thread_raw("pr", &p);
    assert_eq!(
        build(&fx, Location::Active),
        Err(Decline::NotPorted {
            thread_id: "pr".into(),
            what: "legacy_linked_pull_request"
        })
    );
}

#[test]
fn drift_and_unknown_kinds_decline_with_their_reason() {
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({"runtimeMode": "turbo"}));
    let e = build(&fx, Location::Active).unwrap_err();
    assert_eq!(
        e,
        Decline::PayloadDrift {
            thread_id: "t".into(),
            path: "thread.runtimeMode".into()
        }
    );
    assert_eq!(e.reason(), "payload_drift");
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({"createdAt": "2026-01-01T00:00:00Z"}));
    let e = build(&fx, Location::Active).unwrap_err();
    assert_eq!(
        e,
        Decline::DecodeLimit {
            thread_id: "t".into(),
            path: "thread.createdAt".into()
        }
    );
    assert_eq!(e.reason(), "decode_limit");
    // A fork source that does not decode fails the snapshot, as in Node.
    let mut fx = Fx::default();
    fx.thread("src", 1, json!({"archivedAt": T0, "title": " "}))
        .thread(
            "t",
            2,
            json!({"forkedFrom": {"type": "run", "threadId": "src", "runId": "r"}}),
        );
    assert!(
        matches!(build(&fx, Location::Active), Err(Decline::PayloadDrift { thread_id, .. }) if thread_id == "src")
    );
    // The terminal failure query only selects `error` rows; a payload of another type is not ported.
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "failed", json!({}))
        .item(
            "t",
            "e",
            Some(1),
            "error",
            "failed",
            json!({"type": "notification", "nodeId": "t:run:1:root"}),
        );
    let e = build(&fx, Location::Active).unwrap_err();
    assert_eq!(
        e,
        Decline::ItemKindNotPorted {
            thread_id: "t".into(),
            kind: "notification".into()
        }
    );
    assert_eq!(e.reason(), "item_kind_not_ported");
    // A PR watch task needs the PR key normaliser.
    let mut fx = Fx::default();
    fx.thread(
        "t",
        1,
        json!({"pullRequests": [{"host": "github.com", "repository": "o/r", "number": 1, "url": "u",
        "source": "manual", "linkedAt": "x", "snapshot": null, "stack": null,
        "watch": {"startedAt": "s", "headSha": null, "failedChecks": [], "passed": false,
            "remarksThrough": "r", "remarkIds": [], "conflicting": false, "wakes": 0}}]}),
    );
    assert_eq!(
        build(&fx, Location::Active).unwrap_err(),
        Decline::NotPorted {
            thread_id: "t".into(),
            what: "pull_request_watch"
        }
    );
}

#[test]
fn latest_application_sequence_counts_project_and_v2_thread_events() {
    let (_d, sdb) = db(&Fx::default());
    assert_eq!(sdb.read(latest_application_sequence), Ok(0));
    let mut fx = Fx::default();
    fx.event(3, "project", 1)
        .event(5, "thread", 2)
        .event(9, "thread", 1);
    let (_d, sdb) = db(&fx);
    assert_eq!(sdb.read(latest_application_sequence), Ok(5));
    fx.event(11, "project", 1);
    let (_d, sdb) = db(&fx);
    assert_eq!(sdb.read(latest_application_sequence), Ok(11));
}

#[test]
fn the_live_scenarios_all_build() {
    let fx = super::fixture::scenarios();
    let active = build(&fx, Location::Active).unwrap();
    let archived = build(&fx, Location::Archive).unwrap();
    assert_eq!((active.len(), archived.len()), (34, 4));
    assert!(
        active
            .iter()
            .all(|t| t["id"].as_str().unwrap().starts_with("fx-"))
    );
    let bg = by_id(&active, "fx-bg");
    assert_eq!(
        text(&bg["pendingBackgroundTasks"]),
        concat!(
            r#"[{"taskId":"fx-bg-task","description":"d","kind":"subagent","providerInstanceId":"codex"},"#,
            r#"{"taskId":"fx-bg-future","description":"f","kind":"background_task"},"#,
            r#"{"taskId":"fx-bg-cmd","description":"sleep 5","kind":"command"}]"#
        )
    );
    assert_eq!(
        text(&by_id(&active, "fx-bg-tool")["pendingBackgroundTasks"]),
        r#"[{"taskId":"fx-bg-tool-a","description":"T","kind":"background_task"}]"#
    );
    assert_eq!(
        text(&by_id(&active, "fx-bg-sub")["pendingBackgroundTasks"]),
        r#"[{"taskId":"native-sub","description":"look","kind":"subagent","providerInstanceId":"codex","childThreadId":"child"}]"#
    );
    assert_eq!(
        by_id(&active, "fx-limit-icon")["latestRunId"],
        "fx-limit-icon:run:1"
    );
    assert_eq!(
        by_id(&active, "fx-limit-bad-icon")["latestRunId"],
        "fx-limit-bad-icon:run:2"
    );
    // A v1-import source counts its runless items in the inherited prefix.
    assert_eq!(by_id(&active, "fx-mid")["visibleItemCount"], 1 + 2 + 1 + 1);
    assert_eq!(by_id(&active, "fx-leaf")["visibleItemCount"], 4 + 1 + 1 + 1);
    assert_eq!(
        by_id(&active, "fx-deep-leaf")["visibleItemCount"],
        3 + 1 + 1 + 1
    );
}

/// A failed blocking run whose error item carries `extra`, behind a queued run.
fn limited(extra: Value) -> Fx {
    let mut err = json!({"nodeId": "t:run:1:root", "failure": {"class": "usage_limit", "message": "limit",
        "code": null, "retryable": false}});
    for (k, x) in extra.as_object().unwrap() {
        err[k] = x.clone();
    }
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "failed", json!({"completedAt": at(3)}))
        .item("t", "e1", Some(1), "error", "failed", err)
        .run("t", 2, "queued", json!({}));
    fx
}

#[test]
fn the_blocking_failure_swallows_only_what_effect_rejects() {
    let icons = [
        json!({"_tag": "website", "pageUrl": " https://x "}),
        json!({"_tag": "native-app", "app": {"_tag": "app-id", "appId": "com.app_1-x"}}),
        json!({"_tag": "native-app", "app": {"_tag": "display-name", "displayName": "Mail"}}),
        json!({"_tag": "themed-logo", "logoUrl": "l", "logoUrlDark": "d"}),
    ];
    for icon in icons {
        let t = one(&limited(json!({"toolIcon": icon,
            "toolSource": {"key": "k", "name": "n", "kind": "browser", "icon": icon}})));
        assert_eq!(
            t["latestRunId"], "t:run:1",
            "a valid icon decodes: the limit holds the queue"
        );
    }
    let rejected = [
        json!({"toolIcon": {"_tag": "website"}}),
        json!({"toolIcon": {"_tag": "planet", "pageUrl": "p"}}),
        json!({"toolIcon": {"pageUrl": "p"}}),
        json!({"toolIcon": {"_tag": "native-app", "app": {"_tag": "app-id", "appId": "has space"}}}),
        json!({"toolIcon": {"_tag": "native-app", "app": {"_tag": "display-name", "displayName": "x".repeat(161)}}}),
        json!({"toolIcon": {"_tag": "website", "pageUrl": "x".repeat(4097)}}),
        json!({"toolSource": {"key": "k", "name": "n", "kind": "tool"}}),
        json!({"toolSource": {"key": " ", "name": "n", "kind": "browser"}}),
        json!({"toolSource": {"key": "k", "name": "n", "kind": "browser", "icon": {"_tag": "themed-logo"}}}),
    ];
    for bad in &rejected {
        // Node's decode fails, `orElseSucceed` gives null: the queued run is presented.
        let t = one(&limited(bad.clone()));
        assert_eq!(t["latestRunId"], "t:run:2", "{bad}");
        assert_eq!(t["lastErrorClass"], Value::Null, "{bad}");
    }
    // The same payload as the presented run's terminal failure: Node's snapshot fails (500).
    let mut err = failure("provider_error", "x");
    err["nodeId"] = "t:run:1:root".into();
    err["toolIcon"] = json!({"_tag": "website"});
    let mut fx = Fx::default();
    fx.thread("t", 1, json!({}))
        .run("t", 1, "failed", json!({}))
        .item("t", "e1", Some(1), "error", "failed", err);
    assert_eq!(
        build(&fx, Location::Active),
        Err(Decline::PayloadDrift {
            thread_id: "t".into(),
            path: "terminalFailure.toolIcon".into()
        })
    );
    // What Rust cannot judge is never null: a non-canonical date, an unported type.
    assert_eq!(
        build(
            &limited(json!({"updatedAt": "2026-01-01T00:00:00Z"})),
            Location::Active
        ),
        Err(Decline::DecodeLimit {
            thread_id: "t".into(),
            path: "blockingFailure.updatedAt".into()
        })
    );
    assert_eq!(
        build(&limited(json!({"type": "notification"})), Location::Active),
        Err(Decline::ItemKindNotPorted {
            thread_id: "t".into(),
            kind: "notification".into()
        })
    );
}
