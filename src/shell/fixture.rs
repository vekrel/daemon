//! Synthetic projection rows for shell tests (unit tests here, live goldens against Node in
//! `tests/live_differential.rs`): the columns and payloads the engine's projectors write, with
//! every NOT NULL column filled so the same SQL loads into a real engine DB.
use serde_json::{Value, json};

pub const T0: &str = "2026-01-01T00:00:00.000Z";

pub fn at(minute: u32) -> String {
    format!("2026-01-01T00:{minute:02}:00.000Z")
}

/// A thread payload as the engine writes it, with `extra` merged over the defaults.
pub fn thread_payload(id: &str, extra: Value) -> Value {
    let mut v = json!({
        "createdBy": "user", "creationSource": "web", "id": id, "projectId": "project-1",
        "title": format!("Thread {id}"), "providerInstanceId": "codex",
        "modelSelection": {"instanceId": "codex", "model": "gpt-5"},
        "runtimeMode": "full-access", "interactionMode": "default", "branch": null,
        "worktreePath": null, "pullRequests": [], "activeProviderThreadId": null,
        "lineage": {"parentThreadId": null, "relationshipToParent": null, "rootThreadId": id},
        "forkedFrom": null, "createdAt": T0, "updatedAt": T0, "archivedAt": null,
        "settledOverride": null, "settledAt": null, "snoozedUntil": null, "snoozedAt": null,
        "lastVisitedAt": null, "titleRegeneration": null, "deletedAt": null
    });
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

/// Rows the fixture SQL inserts; `sql()` renders them.
#[derive(Default)]
pub struct Fx(pub String);

pub fn q(v: &Value) -> String {
    match v {
        Value::Null => "NULL".into(),
        Value::String(s) => format!("'{}'", s.replace('\'', "''")),
        other => format!("'{}'", other.to_string().replace('\'', "''")),
    }
}

impl Fx {
    pub fn thread(&mut self, id: &str, updated: u32, extra: Value) -> &mut Self {
        let mut p = thread_payload(id, extra);
        if p["updatedAt"] == T0 {
            p["updatedAt"] = at(updated).into();
        }
        self.thread_raw(id, &p)
    }

    /// The thread row for payload `p` as the engine's projector writes it.
    pub fn thread_raw(&mut self, id: &str, p: &Value) -> &mut Self {
        let s = |k: &str| p.get(k).cloned().unwrap_or(Value::Null);
        self.0 += &format!(
            "INSERT INTO orchestration_v2_projection_threads (thread_id, project_id, title, default_provider, runtime_mode, interaction_mode, created_at, updated_at, archived_at, deleted_at, payload_json, provider_instance_id) VALUES ({}, 'project-1', 't', 'codex', 'full-access', 'default', {}, {}, {}, {}, {}, {});\n",
            q(&id.into()),
            q(&s("createdAt")),
            q(&s("updatedAt")),
            q(&s("archivedAt")),
            q(&s("deletedAt")),
            q(p),
            q(&s("providerInstanceId")),
        );
        self
    }

    pub fn run(&mut self, thread: &str, ordinal: i64, status: &str, extra: Value) -> &mut Self {
        let id = format!("{thread}:run:{ordinal}");
        let mut p = json!({"id": id, "threadId": thread, "ordinal": ordinal, "status": status,
            "rootNodeId": format!("{id}:root"), "requestedAt": at(ordinal as u32),
            "startedAt": at(ordinal as u32), "completedAt": null});
        for (k, x) in extra.as_object().unwrap() {
            p[k] = x.clone();
        }
        self.0 += &format!(
            "INSERT INTO orchestration_v2_projection_runs (run_id, thread_id, ordinal, provider, status, requested_at, completed_at, payload_json, provider_instance_id) VALUES ({}, {}, {ordinal}, 'codex', {}, {}, {}, {}, 'codex');\n",
            q(&id.into()),
            q(&thread.into()),
            q(&status.into()),
            q(&p["requestedAt"]),
            q(&p["completedAt"]),
            q(&p),
        );
        self
    }

    /// A turn item; `run` is the run ordinal (`None`: runless); `extra` holds the member fields.
    pub fn item(
        &mut self,
        thread: &str,
        id: &str,
        run: Option<i64>,
        kind: &str,
        status: &str,
        extra: Value,
    ) -> &mut Self {
        let run_id = run.map(|o| format!("{thread}:run:{o}"));
        let mut p = json!({"type": kind, "id": id, "threadId": thread, "runId": run_id,
            "nodeId": null, "providerThreadId": null, "providerTurnId": null,
            "nativeItemRef": null, "parentItemId": null, "ordinal": 0, "status": status,
            "title": null, "startedAt": null, "completedAt": null, "updatedAt": at(30)});
        for (k, x) in extra.as_object().unwrap() {
            p[k] = x.clone();
        }
        self.0 += &format!(
            "INSERT INTO orchestration_v2_projection_turn_items (turn_item_id, thread_id, run_id, node_id, provider_thread_id, ordinal, type, status, updated_at, payload_json) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {});\n",
            q(&id.into()),
            q(&thread.into()),
            q(&p["runId"]),
            q(&p["nodeId"]),
            q(&p["providerThreadId"]),
            p["ordinal"],
            q(&kind.into()),
            q(&status.into()),
            q(&p["updatedAt"]),
            q(&p),
        );
        self
    }

    pub fn request(
        &mut self,
        thread: &str,
        id: &str,
        status: &str,
        capability: Value,
    ) -> &mut Self {
        let p = json!({"id": id, "nodeId": "node-1", "providerTurnId": null, "nativeRequestRef": null,
            "kind": "permission", "status": status, "responseCapability": capability,
            "createdAt": at(40), "resolvedAt": null});
        self.0 += &format!(
            "INSERT INTO orchestration_v2_projection_runtime_requests (runtime_request_id, thread_id, node_id, kind, status, created_at, payload_json) VALUES ({}, {}, 'node-1', 'permission', {}, {}, {});\n",
            q(&id.into()),
            q(&thread.into()),
            q(&status.into()),
            q(&p["createdAt"]),
            q(&p),
        );
        self
    }

    pub fn message(
        &mut self,
        thread: &str,
        id: &str,
        role: &str,
        created_by: &str,
        minute: u32,
    ) -> &mut Self {
        let p = json!({"createdBy": created_by});
        self.0 += &format!(
            "INSERT INTO orchestration_v2_projection_messages (message_id, thread_id, role, streaming, created_at, updated_at, payload_json) VALUES ({}, {}, {}, 0, {}, {}, {});\n",
            q(&id.into()),
            q(&thread.into()),
            q(&role.into()),
            q(&at(minute).into()),
            q(&at(minute).into()),
            q(&p),
        );
        self
    }

    pub fn plan(&mut self, thread: &str, kind: &str, status: &str) -> &mut Self {
        self.0 += &format!(
            "INSERT INTO orchestration_v2_projection_plans (plan_id, thread_id, node_id, kind, status, payload_json) VALUES ('{thread}:plan:{kind}:{status}', {}, 'n', {}, {}, '{{}}');\n",
            q(&thread.into()),
            q(&kind.into()),
            q(&status.into()),
        );
        self
    }

    pub fn provider_thread(
        &mut self,
        thread: &str,
        id: &str,
        instance: &str,
        extra: Value,
    ) -> &mut Self {
        let mut p = json!({"id": id, "driver": "codex", "providerInstanceId": instance,
            "providerSessionId": null, "appThreadId": thread, "ownerNodeId": null,
            "nativeThreadRef": null, "nativeConversationHeadRef": null, "status": "idle",
            "firstRunOrdinal": null, "lastRunOrdinal": null, "handoffIds": [], "forkedFrom": null,
            "createdAt": T0, "updatedAt": T0});
        for (k, x) in extra.as_object().unwrap() {
            p[k] = x.clone();
        }
        self.0 += &format!(
            "INSERT INTO orchestration_v2_projection_provider_threads (provider_thread_id, thread_id, provider, status, updated_at, provider_instance_id, payload_json) VALUES ({}, {}, 'codex', 'idle', '{T0}', {}, {});\n",
            q(&id.into()),
            q(&thread.into()),
            q(&instance.into()),
            q(&p),
        );
        self
    }

    pub fn session_error(&mut self, thread: &str, instance: &str, error: &str) -> &mut Self {
        let id = format!("{thread}:session:{instance}");
        self.0 += &format!(
            "INSERT INTO orchestration_v2_projection_provider_sessions (provider_session_id, thread_id, provider, status, updated_at, payload_json, provider_instance_id) VALUES ({}, {}, 'codex', 'error', {}, {}, {});
             INSERT INTO orchestration_v2_projection_provider_session_bindings (provider_session_id, thread_id) VALUES ({}, {});\n",
            q(&id.clone().into()),
            q(&thread.into()),
            q(&T0.into()),
            q(&json!({"lastError": error})),
            q(&instance.into()),
            q(&id.into()),
            q(&thread.into()),
        );
        self
    }

    pub fn event(&mut self, sequence: i64, kind: &str, version: i64) -> &mut Self {
        self.0 += &format!(
            "INSERT INTO orchestration_events (sequence, event_id, aggregate_kind, stream_id, stream_version, event_type, occurred_at, payload_json, metadata_json, application_event_version) VALUES ({sequence}, 'e{sequence}', '{kind}', 's', 0, 'x', '{T0}', '{{}}', '{{}}', {version});\n"
        );
        self
    }
}

fn failure(class: &str, message: &str, node: &str) -> Value {
    json!({"nodeId": node, "failure": {"class": class, "message": message, "code": "E1",
        "retryable": false, "resetAt": "2026-02-01T00:00:00.000Z"}})
}

/// One thread per branch the shell's TypeScript takes, ids prefixed `fx-`; every one decodes
/// (the decline cases are separate, since one decline fails the whole snapshot).
pub fn scenarios() -> Fx {
    let mut fx = Fx::default();
    fx.thread("fx-empty", 1, json!({}));
    fx.thread(
        "fx-optional",
        2,
        json!({"linkedPullRequest": null, "branchPullRequest": {"projectId": "p", "repository": "o/r", "number": 2, "url": "u"},
            "historyOrigin": "native", "activeOrderKey": "a0", "pinOrderKey": "k", "unsettledAt": T0,
            "pinnedAt": T0, "autoSettleDisabledAt": T0, "settledOverride": "active",
            "limitRecovery": {"runId": "r", "resetAt": "x", "autoResume": true}, "lastSnoozeWakeAt": T0,
            "titleRegeneration": {"startedAt": T0, "requestId": "c"},
            "pullRequests": [{"host": "github.com", "repository": "o/r", "number": 3, "url": "https://github.com/o/r/pull/3",
                "source": "stack-dismissed", "linkedAt": "x", "snapshot": {"state": "open", "title": " t ", "headBranch": "h",
                "baseBranch": "b", "isDraft": false, "updatedAt": null, "syncedAt": "s"}, "stack": null,
                "watch": {"startedAt": "s", "headSha": null, "failedChecks": [], "passed": false,
                    "remarksThrough": "r", "remarkIds": [], "conflicting": false, "wakes": 0}}]}),
    );
    for (i, status) in [
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
    ]
    .iter()
    .enumerate()
    {
        let id = format!("fx-status-{status}");
        fx.thread(&id, 3 + i as u32, json!({}))
            .run(&id, 1, status, json!({}));
    }
    fx.thread("fx-held", 14, json!({}))
        .run("fx-held", 1, "waiting", json!({"workStartedAt": at(9)}))
        .run("fx-held", 2, "queued", json!({"queueHeld": true}));
    fx.thread("fx-queued", 15, json!({}))
        .run("fx-queued", 1, "completed", json!({}))
        .run(
            "fx-queued",
            2,
            "queued",
            json!({"queueHeld": false, "startedAt": null}),
        );
    fx.thread("fx-counts", 16, json!({}))
        .run("fx-counts", 1, "completed", json!({}))
        .run("fx-counts", 2, "rolled_back", json!({}))
        .run("fx-counts", 3, "interrupted", json!({}))
        .item(
            "fx-counts",
            "fx-counts-i1",
            Some(1),
            "assistant_message",
            "completed",
            json!({}),
        )
        .item(
            "fx-counts",
            "fx-counts-i2",
            Some(2),
            "assistant_message",
            "completed",
            json!({}),
        )
        .item(
            "fx-counts",
            "fx-counts-i3",
            Some(3),
            "run_interrupt_request",
            "completed",
            json!({}),
        )
        .item(
            "fx-counts",
            "fx-counts-i4",
            None,
            "user_message",
            "completed",
            json!({}),
        )
        .message("fx-counts", "fx-counts-m1", "user", "user", 5)
        .message("fx-counts", "fx-counts-m2", "user", "agent", 6)
        .message("fx-counts", "fx-counts-m3", "assistant", "agent", 7)
        .plan("fx-counts", "proposed_plan", "active");
    fx.thread("fx-failed", 17, json!({}))
        .run("fx-failed", 1, "failed", json!({"completedAt": at(2)}))
        .item(
            "fx-failed",
            "fx-failed-e",
            Some(1),
            "error",
            "failed",
            failure("provider_error", " boom ", "fx-failed:run:1:root"),
        );
    fx.thread("fx-session", 18, json!({}))
        .run("fx-session", 1, "failed", json!({"completedAt": at(2)}))
        .item(
            "fx-session",
            "fx-session-e",
            Some(1),
            "error",
            "failed",
            failure("provider_error", "boom", "fx-session:run:1:root"),
        )
        .session_error("fx-session", "codex", "session down");
    fx.thread("fx-limit", 19, json!({}))
        .run("fx-limit", 1, "failed", json!({"completedAt": at(3)}))
        .item(
            "fx-limit",
            "fx-limit-e",
            Some(1),
            "error",
            "failed",
            failure("usage_limit", "limit", "fx-limit:run:1:root"),
        )
        .item(
            "fx-limit",
            "fx-limit-stop",
            Some(1),
            "run_interrupt_request",
            "completed",
            json!({}),
        )
        .run("fx-limit", 2, "queued", json!({}));
    fx.thread("fx-limit-other", 20, json!({}))
        .run("fx-limit-other", 1, "failed", json!({"completedAt": at(3)}))
        .item(
            "fx-limit-other",
            "fx-limit-other-e",
            Some(1),
            "error",
            "failed",
            failure("provider_error", "x", "fx-limit-other:run:1:root"),
        )
        .run("fx-limit-other", 2, "queued", json!({}));
    fx.thread("fx-request", 21, json!({}))
        .request(
            "fx-request",
            "fx-request-old",
            "resolved",
            json!({"type": "message"}),
        )
        .request(
            "fx-request",
            "fx-request-q",
            "pending",
            json!({"type": "live", "providerSessionId": "s"}),
        );
    fx.thread("fx-secret", 22, json!({}))
        .request("fx-secret", "fx-secret-q", "pending", json!({"type": "message"}))
        .run("fx-secret", 1, "running", json!({}))
        .item("fx-secret", "fx-secret-s", Some(1), "secret_request", "waiting",
            json!({"nodeId": "n", "label": "API key", "reason": "r", "secretStatus": "pending", "startedAt": at(2)}));
    // One contributing provider thread and one qualifying item per thread: with more, the order
    // is SQLite's plan and Rust declines (`unordered_rows`).
    fx.thread("fx-bg", 23, json!({"activeProviderThreadId": "fx-bg-pt1"}))
        .run("fx-bg", 1, "completed", json!({}))
        .provider_thread(
            "fx-bg",
            "fx-bg-pt1",
            "codex",
            json!({"pendingBackgroundTasks": [
            {"taskId": "fx-bg-task", "kind": "subagent", "description": " d "},
            {"taskId": "fx-bg-future", "kind": "future", "description": "f"}],
            "goal": {"objective": " ship ", "status": "active", "tokensUsed": 3}}),
        )
        .provider_thread(
            "fx-bg",
            "fx-bg-pt0",
            "claudeAgent",
            json!({"createdAt": "2025-12-31T00:00:00.000Z",
            "pendingBackgroundTasks": [{"taskId": "fx-bg-inactive", "kind": "command"}]}),
        )
        .item(
            "fx-bg",
            "fx-bg-cmd",
            Some(1),
            "command_execution",
            "running",
            json!({"input": " sleep 5 "}),
        )
        .item(
            "fx-bg",
            "fx-bg-done",
            Some(1),
            "command_execution",
            "completed",
            json!({"input": "x"}),
        )
        .item(
            "fx-bg",
            "fx-bg-persist",
            Some(1),
            "dynamic_tool",
            "running",
            json!({"toolName": "watch", "input": {"persistent": true}}),
        );
    fx.thread("fx-bg-tool", 37, json!({}))
        .run("fx-bg-tool", 1, "completed", json!({}))
        .item(
            "fx-bg-tool",
            "fx-bg-tool-a",
            Some(1),
            "dynamic_tool",
            "pending",
            json!({"toolName": " tool ", "input": {}, "title": " T "}),
        );
    fx.thread("fx-bg-sub", 38, json!({}))
        .run("fx-bg-sub", 1, "interrupted", json!({}))
        .item("fx-bg-sub", "fx-bg-sub-a", Some(1), "subagent", "waiting", json!({"subagentId": "n", "origin": "provider_native",
            "driver": "codex", "providerInstanceId": "codex", "childThreadId": "child", "prompt": " look ", "result": null,
            "providerThreadId": "fx-bg-pt1", "nativeItemRef": {"driver": "codex", "nativeId": "native-sub", "strength": "strong"}}));
    // A usage-limited blocking run whose error item has a valid icon (it holds the queue) and one
    // Effect rejects (`orElseSucceed`: null, the queued run is presented).
    for (id, icon) in [
        (
            "fx-limit-icon",
            json!({"_tag": "native-app", "app": {"_tag": "app-id", "appId": "com.app"}}),
        ),
        (
            "fx-limit-bad-icon",
            json!({"_tag": "native-app", "app": {"_tag": "app-id", "appId": "bad id"}}),
        ),
    ] {
        let mut err = failure("usage_limit", "limit", &format!("{id}:run:1:root"));
        err["toolIcon"] = icon;
        err["toolSource"] = json!({"key": "k", "name": "n", "kind": "integration"});
        fx.thread(id, 39, json!({}))
            .run(id, 1, "failed", json!({"completedAt": at(3)}))
            .item(id, &format!("{id}-e"), Some(1), "error", "failed", err)
            .run(id, 2, "queued", json!({}));
    }
    fx.thread("fx-running", 24, json!({}))
        .run("fx-running", 1, "running", json!({}))
        .item(
            "fx-running",
            "fx-running-fc",
            Some(1),
            "file_change",
            "running",
            json!({"fileName": "a.rs"}),
        )
        .item(
            "fx-running",
            "fx-running-cmd",
            Some(1),
            "command_execution",
            "running",
            json!({"input": "make"}),
        );
    fx.thread(
        "fx-root",
        25,
        json!({"archivedAt": T0, "historyOrigin": "v1_import"}),
    )
    .run("fx-root", 1, "completed", json!({}))
    .run("fx-root", 2, "completed", json!({}))
    .item(
        "fx-root",
        "fx-root-a",
        Some(1),
        "assistant_message",
        "completed",
        json!({}),
    )
    .item(
        "fx-root",
        "fx-root-b",
        Some(1),
        "assistant_message",
        "completed",
        json!({}),
    )
    .item(
        "fx-root",
        "fx-root-c",
        Some(2),
        "assistant_message",
        "completed",
        json!({}),
    )
    .item(
        "fx-root",
        "fx-root-d",
        None,
        "user_message",
        "completed",
        json!({}),
    );
    fx.thread(
        "fx-mid",
        26,
        json!({"forkedFrom": {"type": "run", "threadId": "fx-root", "runId": "fx-root:run:1"}}),
    )
    .run("fx-mid", 1, "completed", json!({}))
    .item(
        "fx-mid",
        "fx-mid-a",
        Some(1),
        "assistant_message",
        "completed",
        json!({}),
    );
    fx.thread(
        "fx-leaf",
        27,
        json!({"forkedFrom": {"type": "run", "threadId": "fx-mid", "runId": "fx-mid:run:1"}}),
    )
    .item(
        "fx-leaf",
        "fx-leaf-a",
        None,
        "user_message",
        "completed",
        json!({}),
    );
    fx.thread("fx-deep-root", 34, json!({"archivedAt": T0}))
        .run("fx-deep-root", 1, "completed", json!({}))
        .item(
            "fx-deep-root",
            "fx-deep-root-a",
            Some(1),
            "assistant_message",
            "completed",
            json!({}),
        )
        .item(
            "fx-deep-root",
            "fx-deep-root-b",
            Some(1),
            "assistant_message",
            "completed",
            json!({}),
        );
    fx.thread(
        "fx-deep-mid",
        35,
        json!({"archivedAt": T0,
        "forkedFrom": {"type": "run", "threadId": "fx-deep-root", "runId": "fx-deep-root:run:1"}}),
    )
    .run("fx-deep-mid", 1, "completed", json!({}))
    .item(
        "fx-deep-mid",
        "fx-deep-mid-a",
        Some(1),
        "assistant_message",
        "completed",
        json!({}),
    );
    fx.thread("fx-deep-leaf", 36, json!({"forkedFrom": {"type": "run", "threadId": "fx-deep-mid", "runId": "fx-deep-mid:run:1"}}))
        .item("fx-deep-leaf", "fx-deep-leaf-a", None, "user_message", "completed", json!({}));
    fx.thread("fx-gone", 28, json!({"deletedAt": T0}));
    fx.thread(
        "fx-orphan",
        29,
        json!({"forkedFrom": {"type": "run", "threadId": "fx-gone", "runId": "fx-gone:run:1"}}),
    )
    .item(
        "fx-orphan",
        "fx-orphan-a",
        None,
        "user_message",
        "completed",
        json!({}),
    );
    fx.thread("fx-node-fork", 30, json!({"forkedFrom": {"type": "node", "nodeId": "n"},
        "lineage": {"parentThreadId": "fx-empty", "relationshipToParent": "subagent", "rootThreadId": "fx-empty"},
        "createdBy": "agent", "creationSource": "provider"}));
    fx.thread("fx-legacy", 31, json!({"modelSelection": {"provider": "codex", "model": " m ", "options": {"effort": "high", "2": true}},
        "title": "  padded  "}));
    let mut old = thread_payload("fx-old", json!({"updatedAt": at(32)}));
    for k in [
        "settledOverride",
        "settledAt",
        "lastVisitedAt",
        "snoozedUntil",
        "snoozedAt",
        "titleRegeneration",
    ] {
        old.as_object_mut().expect("object").remove(k);
    }
    fx.thread_raw("fx-old", &old);
    fx.thread(
        "fx-archived",
        33,
        json!({"archivedAt": at(33), "settledAt": at(33), "lastVisitedAt": at(34)}),
    );
    fx
}
