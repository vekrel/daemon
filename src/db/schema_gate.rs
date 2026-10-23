//! The schema gate: Rust's reads were checked against migration 67 of the engine. Unless the DB
//! holds exactly these migrations and these columns, every read declines (`schema_unknown`).
//! Constants dumped from a fresh engine DB (Engine 2aa67bc).
use rusqlite::Connection;

/// `effect_sql_migrations.name` for ids 1..=67, in id order.
pub const MIGRATIONS: [&str; 67] = [
    "OrchestrationEvents",
    "OrchestrationCommandReceipts",
    "CheckpointDiffBlobs",
    "ProviderSessionRuntime",
    "Projections",
    "ProjectionThreadSessionRuntimeModeColumns",
    "ProjectionThreadMessageAttachments",
    "ProjectionThreadActivitySequence",
    "ProviderSessionRuntimeMode",
    "ProjectionThreadsRuntimeMode",
    "OrchestrationThreadCreatedRuntimeMode",
    "ProjectionThreadsInteractionMode",
    "ProjectionThreadProposedPlans",
    "ProjectionThreadProposedPlanImplementation",
    "ProjectionTurnsSourceProposedPlan",
    "CanonicalizeModelSelections",
    "ProjectionThreadsArchivedAt",
    "ProjectionThreadsArchivedAtIndex",
    "ProjectionSnapshotLookupIndexes",
    "AuthAccessManagement",
    "AuthSessionClientMetadata",
    "AuthSessionLastConnectedAt",
    "ProjectionThreadShellSummary",
    "BackfillProjectionThreadShellSummary",
    "CleanupInvalidProjectionPendingApprovals",
    "CanonicalizeModelSelectionOptions",
    "ProviderSessionRuntimeInstanceId",
    "ProjectionThreadSessionInstanceId",
    "ProjectionThreadDetailOrderingIndexes",
    "ProjectionThreadShellArchiveIndexes",
    "AuthAuthorizationScopes",
    "AuthPairingProofKeyThumbprint",
    "ProjectionThreadsSettled",
    "ProjectionThreadsSnoozed",
    "ProjectionThreadTitleRegeneration",
    "ProjectionThreadsPinned",
    "ProjectionTurnsKeysetIndex",
    "ProjectionThreadsPinOrderKey",
    "ProjectionProjectsDefaultThreadEnvMode",
    "ProjectionProjectFaviconPath",
    "AuthSessionClientConnection",
    "ProjectionThreadLinkedPullRequest",
    "ProjectionThreadsUnsettledAt",
    "ClearAutomaticProjectModelDefaults",
    "ProjectionProjectsAutoPull",
    "RepairAutomaticSettlementTimestamps",
    "ProjectionProjectIcon",
    "ProjectionThreadBranchPullRequest",
    "ProjectionThreadsActiveOrderKey",
    "ProjectionThreadPullRequests",
    "ProjectionThreadMessageContext",
    "ProjectionThreadTitleState",
    "PullRequestFilesViewed",
    "ProjectionThreadsAutoSettleDisabledAt",
    "OrchestrationV2",
    "RemoveRedundantProjectionIndexes",
    "ScheduledTaskWebhooks",
    "WebhookRelayDeliveries",
    "McpAppModelContext",
    "ThreadSnapshotWindowIndexes",
    "PullRequestReviewGuides",
    "ThreadFailureLookupIndex",
    "DropUnusedV1Projections",
    "CanonicalizeThreadPullRequestLinks",
    "CodexUsageNativeTurnIndex",
    "RepairClientSettlementTimestamps",
    "WebhookDedupe",
];

/// Every table this plan reads: `name TYPE` per column in `cid` order (`PRAGMA table_info`).
pub const TABLES: [(&str, &str); 12] = [
    (
        "orchestration_events",
        "sequence INTEGER, event_id TEXT, aggregate_kind TEXT, stream_id TEXT, stream_version INTEGER, event_type TEXT, occurred_at TEXT, command_id TEXT, causation_event_id TEXT, correlation_id TEXT, actor_kind TEXT, payload_json TEXT, metadata_json TEXT, application_event_version INTEGER",
    ),
    (
        "orchestration_v2_legacy_imports",
        "thread_id TEXT, source_updated_at TEXT, shell_imported_at TEXT, transcript_imported_at TEXT, imported_message_count INTEGER, last_error TEXT",
    ),
    (
        "orchestration_v2_projection_messages",
        "message_id TEXT, thread_id TEXT, run_id TEXT, node_id TEXT, role TEXT, streaming INTEGER, created_at TEXT, updated_at TEXT, payload_json TEXT",
    ),
    (
        "orchestration_v2_projection_plans",
        "plan_id TEXT, thread_id TEXT, run_id TEXT, node_id TEXT, kind TEXT, status TEXT, payload_json TEXT",
    ),
    (
        "orchestration_v2_projection_provider_session_bindings",
        "provider_session_id TEXT, thread_id TEXT",
    ),
    (
        "orchestration_v2_projection_provider_sessions",
        "provider_session_id TEXT, thread_id TEXT, provider TEXT, status TEXT, model TEXT, updated_at TEXT, payload_json TEXT, driver TEXT, provider_instance_id TEXT",
    ),
    (
        "orchestration_v2_projection_provider_threads",
        "provider_thread_id TEXT, thread_id TEXT, owner_node_id TEXT, provider TEXT, provider_session_id TEXT, status TEXT, first_run_ordinal INTEGER, last_run_ordinal INTEGER, updated_at TEXT, payload_json TEXT, driver TEXT, provider_instance_id TEXT",
    ),
    (
        "orchestration_v2_projection_runs",
        "run_id TEXT, thread_id TEXT, ordinal INTEGER, provider TEXT, provider_thread_id TEXT, status TEXT, requested_at TEXT, completed_at TEXT, payload_json TEXT, provider_instance_id TEXT",
    ),
    (
        "orchestration_v2_projection_runtime_requests",
        "runtime_request_id TEXT, thread_id TEXT, node_id TEXT, provider_turn_id TEXT, kind TEXT, status TEXT, created_at TEXT, resolved_at TEXT, payload_json TEXT",
    ),
    (
        "orchestration_v2_projection_threads",
        "thread_id TEXT, project_id TEXT, title TEXT, default_provider TEXT, runtime_mode TEXT, interaction_mode TEXT, active_provider_thread_id TEXT, created_at TEXT, updated_at TEXT, archived_at TEXT, deleted_at TEXT, payload_json TEXT, provider_instance_id TEXT",
    ),
    (
        "orchestration_v2_projection_turn_items",
        "turn_item_id TEXT, thread_id TEXT, run_id TEXT, node_id TEXT, provider_thread_id TEXT, provider_turn_id TEXT, parent_item_id TEXT, ordinal INTEGER, type TEXT, status TEXT, updated_at TEXT, payload_json TEXT",
    ),
    (
        "projection_projects",
        "project_id TEXT, title TEXT, workspace_root TEXT, scripts_json TEXT, created_at TEXT, updated_at TEXT, deleted_at TEXT, default_model_selection_json TEXT, default_thread_env_mode TEXT, favicon_path TEXT, auto_pull INTEGER, project_icon_json TEXT",
    ),
];

/// `None` when the DB matches; otherwise the first difference (names only, never row data).
pub fn check(c: &Connection) -> rusqlite::Result<Option<String>> {
    let mut q =
        c.prepare("SELECT migration_id, name FROM effect_sql_migrations ORDER BY migration_id")?;
    let rows: Vec<(i64, String)> = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let want = MIGRATIONS
        .iter()
        .enumerate()
        .map(|(i, n)| (i as i64 + 1, *n));
    if rows.len() != MIGRATIONS.len() || !rows.iter().map(|(i, n)| (*i, n.as_str())).eq(want) {
        let last = rows.last().map(|(i, n)| format!("{i} {n}"));
        return Ok(Some(format!(
            "migrations: {} rows, last {last:?}",
            rows.len()
        )));
    }
    let mut q = c.prepare("SELECT name, type FROM pragma_table_info(?1) ORDER BY cid")?;
    for (table, want) in TABLES {
        let cols: Vec<String> = q
            .query_map([table], |r| {
                Ok(format!(
                    "{} {}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?
                ))
            })?
            .collect::<Result<_, _>>()?;
        if cols.join(", ") != want {
            return Ok(Some(format!("columns of {table}")));
        }
    }
    Ok(None)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// DDL for a DB the gate accepts.
    pub(crate) fn schema_sql() -> String {
        let mut s = String::from(
            "CREATE TABLE effect_sql_migrations (migration_id INTEGER PRIMARY KEY NOT NULL, \
             created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, name TEXT NOT NULL);\n",
        );
        for (i, n) in MIGRATIONS.iter().enumerate() {
            s += &format!(
                "INSERT INTO effect_sql_migrations (migration_id, name) VALUES ({}, '{n}');\n",
                i + 1
            );
        }
        for (t, cols) in TABLES {
            s += &format!("CREATE TABLE {t} ({cols});\n");
        }
        s
    }

    fn db(extra: &str) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(&schema_sql()).unwrap();
        c.execute_batch(extra).unwrap();
        c
    }

    #[test]
    fn accepts_the_known_schema_only() {
        assert_eq!(check(&db("")).unwrap(), None);
        // Extra tables and indexes are not read: still accepted.
        assert_eq!(
            check(&db(
                "CREATE TABLE other (a); CREATE INDEX i ON projection_projects (title);"
            ))
            .unwrap(),
            None
        );
        let trips = |extra: &str| check(&db(extra)).unwrap().expect(extra);
        assert_eq!(
            trips("INSERT INTO effect_sql_migrations (migration_id, name) VALUES (68, 'Future')"),
            r#"migrations: 68 rows, last Some("68 Future")"#
        );
        trips("UPDATE effect_sql_migrations SET name = 'Renamed' WHERE migration_id = 40");
        trips("DELETE FROM effect_sql_migrations WHERE migration_id = 67");
        assert_eq!(
            trips("ALTER TABLE orchestration_v2_projection_runs DROP COLUMN provider_instance_id"),
            "columns of orchestration_v2_projection_runs"
        );
        trips("ALTER TABLE projection_projects ADD COLUMN later TEXT");
        trips("DROP TABLE orchestration_v2_legacy_imports");
        let typed = TABLES[0].1.replacen("sequence INTEGER", "sequence TEXT", 1);
        trips(&format!(
            "DROP TABLE orchestration_events; CREATE TABLE orchestration_events ({typed});"
        ));
    }
}
