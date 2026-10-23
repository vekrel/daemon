//! The shell's SQL, copied from `orchestration-v2/ProjectionStore.ts` (Engine 2aa67bc) and
//! `persistence/OrchestrationEventStore.ts`. Effect's `${value}` is a `?` parameter and
//! `sql.in(ids)` is `(?, ?, …)`; nothing else is changed.
use rusqlite::{Connection, Row, params_from_iter};

/// `selectShellThreadRows` (`ProjectionStore.ts:5634-5835`), up to its dynamic `WHERE` tail.
pub const SHELL_THREAD_ROWS: &str = r#"
            SELECT
              t.thread_id,
              t.payload_json,
              CASE
                WHEN json_extract(t.payload_json, '$.forkedFrom.type') = 'run'
                  THEN json_extract(t.payload_json, '$.forkedFrom.threadId')
                ELSE NULL
              END AS forked_from_run_source_thread_id,
              presented.run_id AS latest_run_id,
              presented.status AS latest_run_status,
              presented.requested_at AS latest_run_requested_at,
              json_extract(presented.payload_json, '$.startedAt') AS latest_run_started_at,
              presented.completed_at AS latest_run_completed_at,
              EXISTS (
                SELECT 1 FROM orchestration_v2_projection_turn_items stop_request
                WHERE stop_request.thread_id = t.thread_id AND stop_request.run_id = presented.run_id
                  AND stop_request.type = 'run_interrupt_request'
              ) AS latest_run_stop_requested,
              active.run_id AS active_run_id,
              active.status AS active_run_status,
              (
                SELECT r.status
                FROM orchestration_v2_projection_runs r
                WHERE r.thread_id = t.thread_id
                  AND r.status IN ('preparing', 'starting', 'running', 'waiting')
                ORDER BY r.ordinal DESC, r.run_id DESC
                LIMIT 1
              ) AS activity_run_status,
              (
                -- Mirrors orchestrationV2RunWorkStartedAt.
                SELECT COALESCE(
                  json_extract(r.payload_json, '$.workStartedAt'),
                  json_extract(r.payload_json, '$.startedAt'),
                  r.requested_at
                )
                FROM orchestration_v2_projection_runs r
                WHERE r.thread_id = t.thread_id
                  AND r.status IN ('preparing', 'starting', 'running', 'waiting')
                ORDER BY r.ordinal DESC, r.run_id DESC
                LIMIT 1
              ) AS activity_run_started_at,
              (
                SELECT json_extract(session.payload_json, '$.lastError')
                -- Keep bindings outermost: one provider instance can hold every session.
                FROM orchestration_v2_projection_provider_session_bindings binding
                CROSS JOIN orchestration_v2_projection_provider_sessions session
                  ON session.provider_session_id = binding.provider_session_id
                WHERE binding.thread_id = t.thread_id
                  AND session.provider_instance_id = t.provider_instance_id
                ORDER BY session.updated_at DESC, session.provider_session_id DESC
                LIMIT 1
              ) AS last_error,
              (
                SELECT item.payload_json
                FROM orchestration_v2_projection_turn_items item
                INNER JOIN orchestration_v2_projection_runs r ON r.run_id = item.run_id
                WHERE r.run_id = presented.run_id
                  AND r.status = 'failed'
                  AND item.thread_id = t.thread_id
                  AND item.type = 'error' AND item.status = 'failed'
                  AND item.node_id IS json_extract(r.payload_json, '$.rootNodeId')
                ORDER BY item.updated_at DESC, item.ordinal DESC, item.turn_item_id DESC
                LIMIT 1
              ) AS terminal_failure_payload_json,
              blocked.run_id AS blocking_run_id,
              blocked.requested_at AS blocking_run_requested_at,
              json_extract(blocked.payload_json, '$.startedAt') AS blocking_run_started_at,
              blocked.completed_at AS blocking_run_completed_at,
              EXISTS (
                SELECT 1 FROM orchestration_v2_projection_turn_items stop_request
                WHERE stop_request.thread_id = t.thread_id AND stop_request.run_id = blocked.run_id
                  AND stop_request.type = 'run_interrupt_request'
              ) AS blocking_run_stop_requested,
              (
                SELECT item.payload_json
                FROM orchestration_v2_projection_turn_items item
                WHERE item.thread_id = t.thread_id
                  AND item.run_id = blocked.run_id
                  AND item.type = 'error' AND item.status = 'failed'
                  AND item.node_id IS json_extract(blocked.payload_json, '$.rootNodeId')
                ORDER BY item.updated_at DESC, item.ordinal DESC, item.turn_item_id DESC
                LIMIT 1
              ) AS blocking_failure_payload_json,
              (
                SELECT request.payload_json
                FROM orchestration_v2_projection_runtime_requests request
                WHERE request.thread_id = t.thread_id
                  AND request.status = 'pending'
                ORDER BY request.created_at DESC, request.runtime_request_id DESC
                LIMIT 1
              ) AS pending_request_payload_json,
              (
                SELECT secret.payload_json
                -- Keep runs outermost so completed history is never scanned for a pending secret.
                FROM orchestration_v2_projection_runs r
                CROSS JOIN orchestration_v2_projection_turn_items secret
                  INDEXED BY orchestration_v2_projection_turn_items_thread_run_idx
                WHERE r.thread_id = t.thread_id
                  AND r.status IN ('preparing', 'starting', 'running', 'waiting')
                  AND secret.thread_id = t.thread_id AND secret.run_id = r.run_id
                  AND secret.type = 'secret_request' AND secret.status = 'waiting'
                ORDER BY secret.updated_at DESC, secret.turn_item_id DESC
                LIMIT 1
              ) AS pending_secret_request_payload_json,
              (
                SELECT message.updated_at
                FROM orchestration_v2_projection_messages message
                WHERE message.thread_id = t.thread_id
                  AND message.role = 'user'
                ORDER BY message.updated_at DESC, message.message_id DESC
                LIMIT 1
              ) AS latest_user_message_at,
              (
                SELECT message.updated_at
                FROM orchestration_v2_projection_messages message
                WHERE message.thread_id = t.thread_id
                  AND message.role = 'user'
                  AND json_extract(message.payload_json, '$.createdBy') = 'user'
                ORDER BY message.updated_at DESC, message.message_id DESC
                LIMIT 1
              ) AS latest_user_authored_message_at,
              EXISTS (
                SELECT 1
                FROM orchestration_v2_projection_plans plan
                WHERE plan.thread_id = t.thread_id
                  AND plan.kind = 'proposed_plan'
                  AND plan.status = 'active'
              ) AS has_actionable_proposed_plan,
              -- Count per run on the covering (thread_id, run_id) index, then
              -- look up each run once, instead of one run lookup per item.
              (
                SELECT COALESCE(SUM(per_run.item_count), 0)
                FROM (
                  SELECT i.run_id, COUNT(*) AS item_count
                  FROM orchestration_v2_projection_turn_items i
                  WHERE i.thread_id = t.thread_id
                  GROUP BY i.run_id
                ) per_run
                LEFT JOIN orchestration_v2_projection_runs r
                  ON r.run_id = per_run.run_id
                WHERE per_run.run_id IS NULL OR r.status <> 'rolled_back'
              ) AS item_count,
              (
                SELECT COUNT(*)
                FROM orchestration_v2_projection_turn_items i
                WHERE i.thread_id = t.thread_id
                  AND i.run_id IS NULL
              ) AS runless_item_count
            FROM orchestration_v2_projection_threads t
            LEFT JOIN orchestration_v2_projection_runs active ON active.run_id = (
              SELECT r.run_id
              FROM orchestration_v2_projection_runs r
              WHERE r.thread_id = t.thread_id
                AND r.status IN ('preparing', 'starting', 'running')
              ORDER BY r.ordinal DESC, r.run_id DESC
              LIMIT 1
            )
            -- The newest run not waiting in a held queue, matching latestUnheldRun.
            LEFT JOIN orchestration_v2_projection_runs presented ON presented.run_id = (
              SELECT candidate.run_id
              FROM orchestration_v2_projection_runs candidate
              WHERE candidate.thread_id = t.thread_id
                AND NOT (
                  candidate.status = 'queued'
                  AND json_extract(candidate.payload_json, '$.queueHeld') IS 1
                )
              ORDER BY candidate.ordinal DESC, candidate.run_id DESC
              LIMIT 1
            )
            LEFT JOIN orchestration_v2_projection_runs blocked ON blocked.run_id = (
              SELECT candidate.run_id
              FROM orchestration_v2_projection_runs candidate
              WHERE candidate.thread_id = t.thread_id
                AND candidate.status <> 'queued'
                AND NOT (
                  candidate.status = 'cancelled'
                  AND json_extract(candidate.payload_json, '$.startedAt') IS NULL
                )
              -- latestExecutedRun: the run that ended last (runRanAfter).
              ORDER BY candidate.completed_at IS NULL DESC, candidate.completed_at DESC,
                candidate.ordinal DESC, candidate.run_id DESC
              LIMIT 1
            ) AND blocked.status = 'failed'
            WHERE t.deleted_at IS NULL"#;
/// The `threadId` fragment.
pub const AND_THREAD_ID: &str = " AND t.thread_id = ?";
/// The `location` fragments.
pub const AND_ACTIVE: &str = " AND json_extract(t.payload_json, '$.archivedAt') IS NULL";
pub const AND_ARCHIVE: &str = " AND json_extract(t.payload_json, '$.archivedAt') IS NOT NULL";
pub const ORDER_SHELL_THREADS: &str =
    "\n            ORDER BY t.updated_at ASC, t.thread_id ASC\n          ";

/// `selectShellRunRows(threadIds)` (`:5837-5848`).
pub const SHELL_RUN_ROWS: &str = "
            SELECT thread_id, run_id, ordinal
            FROM orchestration_v2_projection_runs
            WHERE thread_id IN ";
/// `selectShellRunItemCounts(threadIds)` (`:5850-5865`).
pub const SHELL_RUN_ITEM_COUNTS: &str = "
            SELECT thread_id, run_id, COUNT(*) AS item_count
            FROM orchestration_v2_projection_turn_items
            WHERE run_id IS NOT NULL
              AND thread_id IN ";
pub const GROUP_BY_THREAD_RUN: &str = "
            GROUP BY thread_id, run_id
          ";
/// `selectShellProviderThreadRows(threadIds)` (`:5867-5878`).
pub const SHELL_PROVIDER_THREAD_ROWS: &str = "
            SELECT thread_id, payload_json
            FROM orchestration_v2_projection_provider_threads
            WHERE thread_id IN ";
/// `selectShellPendingTurnItemRows(threadIds, activeRunIds)` (`:5880-5907`): the head, then
/// `AND i.thread_id IN (…)`, then the `UNION ALL` arm when there are running runs.
pub const SHELL_PENDING_TURN_ITEMS: &str = "
      SELECT i.thread_id, i.payload_json, p.provider_instance_id AS owning_provider_instance_id
      FROM orchestration_v2_projection_turn_items i
      LEFT JOIN orchestration_v2_projection_provider_threads p
        ON p.provider_thread_id = i.provider_thread_id
      LEFT JOIN orchestration_v2_projection_runs r
        ON r.run_id = i.run_id
      WHERE i.type IN ('command_execution', 'dynamic_tool', 'subagent')
        AND i.status NOT IN ('completed', 'interrupted', 'failed', 'cancelled')
        AND (i.run_id IS NULL OR r.status <> 'rolled_back')
        AND i.thread_id IN ";
pub const SHELL_PENDING_TURN_ITEMS_RUNNING: &str = "
        -- Preserve the pending-item partial index; read other work only from running runs.
        UNION ALL
        SELECT i.thread_id, i.payload_json, NULL AS owning_provider_instance_id
        FROM orchestration_v2_projection_turn_items i
        WHERE i.run_id IN ";
pub const SHELL_PENDING_TURN_ITEMS_RUNNING_TAIL: &str = "
          AND i.type IN ('file_change', 'file_search', 'web_search', 'compaction')
          AND i.status IN ('running', 'waiting')
      ";

/// `latestApplicationSequence` (`OrchestrationEventStore.ts:667-677`).
pub const LATEST_APPLICATION_SEQUENCE: &str = "
    SELECT MAX(sequence) AS sequence
    FROM orchestration_events INDEXED BY idx_orchestration_events_application_high_water
    WHERE aggregate_kind = 'project'
      OR (application_event_version = 2 AND aggregate_kind = 'thread')
  ";

/// `sql.in(ids)`.
fn sql_in(n: usize) -> String {
    format!("({})", vec!["?"; n].join(", "))
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShellThreadRow {
    pub thread_id: String,
    pub payload_json: String,
    pub forked_from_run_source_thread_id: Option<String>,
    pub latest_run_id: Option<String>,
    pub latest_run_status: Option<String>,
    pub latest_run_requested_at: Option<String>,
    pub latest_run_started_at: Option<String>,
    pub latest_run_completed_at: Option<String>,
    pub latest_run_stop_requested: i64,
    pub active_run_id: Option<String>,
    pub active_run_status: Option<String>,
    pub activity_run_status: Option<String>,
    pub activity_run_started_at: Option<String>,
    pub last_error: Option<String>,
    pub terminal_failure_payload_json: Option<String>,
    pub blocking_run_id: Option<String>,
    pub blocking_run_requested_at: Option<String>,
    pub blocking_run_started_at: Option<String>,
    pub blocking_run_completed_at: Option<String>,
    pub blocking_run_stop_requested: i64,
    pub blocking_failure_payload_json: Option<String>,
    pub pending_request_payload_json: Option<String>,
    pub pending_secret_request_payload_json: Option<String>,
    pub latest_user_message_at: Option<String>,
    pub latest_user_authored_message_at: Option<String>,
    pub has_actionable_proposed_plan: i64,
    pub item_count: i64,
    pub runless_item_count: i64,
}

impl ShellThreadRow {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(ShellThreadRow {
            thread_id: r.get("thread_id")?,
            payload_json: r.get("payload_json")?,
            forked_from_run_source_thread_id: r.get("forked_from_run_source_thread_id")?,
            latest_run_id: r.get("latest_run_id")?,
            latest_run_status: r.get("latest_run_status")?,
            latest_run_requested_at: r.get("latest_run_requested_at")?,
            latest_run_started_at: r.get("latest_run_started_at")?,
            latest_run_completed_at: r.get("latest_run_completed_at")?,
            latest_run_stop_requested: r.get("latest_run_stop_requested")?,
            active_run_id: r.get("active_run_id")?,
            active_run_status: r.get("active_run_status")?,
            activity_run_status: r.get("activity_run_status")?,
            activity_run_started_at: r.get("activity_run_started_at")?,
            last_error: r.get("last_error")?,
            terminal_failure_payload_json: r.get("terminal_failure_payload_json")?,
            blocking_run_id: r.get("blocking_run_id")?,
            blocking_run_requested_at: r.get("blocking_run_requested_at")?,
            blocking_run_started_at: r.get("blocking_run_started_at")?,
            blocking_run_completed_at: r.get("blocking_run_completed_at")?,
            blocking_run_stop_requested: r.get("blocking_run_stop_requested")?,
            blocking_failure_payload_json: r.get("blocking_failure_payload_json")?,
            pending_request_payload_json: r.get("pending_request_payload_json")?,
            pending_secret_request_payload_json: r.get("pending_secret_request_payload_json")?,
            latest_user_message_at: r.get("latest_user_message_at")?,
            latest_user_authored_message_at: r.get("latest_user_authored_message_at")?,
            has_actionable_proposed_plan: r.get("has_actionable_proposed_plan")?,
            item_count: r.get("item_count")?,
            runless_item_count: r.get("runless_item_count")?,
        })
    }
}

/// Which archive state the shell asks for (`ShellSnapshotOptions.location`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    Active,
    Archive,
}

/// `selectShellThreadRows(threadId, { location })`. The shell never passes `projectId` or
/// `unsettledOnly`, so those fragments are not ported.
pub fn select_shell_thread_rows(
    c: &Connection,
    thread_id: Option<&str>,
    location: Option<Location>,
) -> rusqlite::Result<Vec<ShellThreadRow>> {
    let mut q = String::from(SHELL_THREAD_ROWS);
    if thread_id.is_some() {
        q += AND_THREAD_ID;
    }
    match location {
        Some(Location::Active) => q += AND_ACTIVE,
        Some(Location::Archive) => q += AND_ARCHIVE,
        None => {}
    }
    q += ORDER_SHELL_THREADS;
    let mut st = c.prepare(&q)?;
    st.query_map(params_from_iter(thread_id), ShellThreadRow::from_row)?
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShellRunRow {
    pub thread_id: String,
    pub run_id: String,
    pub ordinal: i64,
}

pub fn select_shell_run_rows(c: &Connection, ids: &[String]) -> rusqlite::Result<Vec<ShellRunRow>> {
    let q = format!("{SHELL_RUN_ROWS}{}\n          ", sql_in(ids.len()));
    c.prepare(&q)?
        .query_map(params_from_iter(ids), |r| {
            Ok(ShellRunRow {
                thread_id: r.get(0)?,
                run_id: r.get(1)?,
                ordinal: r.get(2)?,
            })
        })?
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShellRunItemCountRow {
    pub thread_id: String,
    pub run_id: String,
    pub item_count: i64,
}

pub fn select_shell_run_item_counts(
    c: &Connection,
    ids: &[String],
) -> rusqlite::Result<Vec<ShellRunItemCountRow>> {
    let q = format!(
        "{SHELL_RUN_ITEM_COUNTS}{}{GROUP_BY_THREAD_RUN}",
        sql_in(ids.len())
    );
    c.prepare(&q)?
        .query_map(params_from_iter(ids), |r| {
            Ok(ShellRunItemCountRow {
                thread_id: r.get(0)?,
                run_id: r.get(1)?,
                item_count: r.get(2)?,
            })
        })?
        .collect()
}

/// `PayloadRow & { thread_id }`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderThreadRow {
    pub thread_id: String,
    pub payload_json: String,
}

pub fn select_shell_provider_thread_rows(
    c: &Connection,
    ids: &[String],
) -> rusqlite::Result<Vec<ProviderThreadRow>> {
    let q = format!(
        "{SHELL_PROVIDER_THREAD_ROWS}{}\n          ",
        sql_in(ids.len())
    );
    c.prepare(&q)?
        .query_map(params_from_iter(ids), |r| {
            Ok(ProviderThreadRow {
                thread_id: r.get(0)?,
                payload_json: r.get(1)?,
            })
        })?
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShellPendingTurnItemRow {
    pub thread_id: String,
    pub payload_json: String,
    pub owning_provider_instance_id: Option<String>,
}

pub fn select_shell_pending_turn_item_rows(
    c: &Connection,
    ids: &[String],
    active_run_ids: &[String],
) -> rusqlite::Result<Vec<ShellPendingTurnItemRow>> {
    let mut q = format!("{SHELL_PENDING_TURN_ITEMS}{}\n      ", sql_in(ids.len()));
    if !active_run_ids.is_empty() {
        q += SHELL_PENDING_TURN_ITEMS_RUNNING;
        q += &sql_in(active_run_ids.len());
        q += SHELL_PENDING_TURN_ITEMS_RUNNING_TAIL;
    }
    c.prepare(&q)?
        .query_map(params_from_iter(ids.iter().chain(active_run_ids)), |r| {
            Ok(ShellPendingTurnItemRow {
                thread_id: r.get(0)?,
                payload_json: r.get(1)?,
                owning_provider_instance_id: r.get(2)?,
            })
        })?
        .collect()
}

/// `latestApplicationSequence`: `MAX(sequence)` or 0.
pub fn latest_application_sequence(c: &Connection) -> rusqlite::Result<i64> {
    c.query_row(LATEST_APPLICATION_SEQUENCE, [], |r| {
        r.get::<_, Option<i64>>(0)
    })
    .map(|s| s.unwrap_or(0))
}
