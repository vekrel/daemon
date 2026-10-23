//! The shell thread builder: `ProjectionStore.readShellSnapshot` (`readShellSnapshotRows` then
//! `decodeShellSnapshot`, `orchestration-v2/ProjectionStore.ts:6291-6408`, Engine 2aa67bc) as
//! the shell routes call it, inside the caller's read transaction. Each thread is the JSON value
//! Node's `OrchestrationV2ThreadShell` encoding gives, keys in schema order.
//!
//! Node's shell read never imports a legacy v1 transcript (no `ensureLegacyTranscript` on this
//! path: `ThreadManagementService.readShellSnapshot` is `Orchestrator.readShellSnapshot`), so a
//! migrated thread is read like any other; legacy row shapes the decoders normalise (a
//! `modelSelection.provider`, an options object) are ported, the rest decline.
#[cfg(any(test, feature = "replay"))]
pub mod fixture;
pub mod sql;
pub mod state;
pub mod wire;

pub use sql::{Location, latest_application_sequence};

/// `ORCHESTRATION_V2_PROJECTION_SCHEMA_VERSION` (`ProjectionStore.ts:593`): the snapshots'
/// `schemaVersion`.
pub const SCHEMA_VERSION: i64 = 2;

use crate::db::read;
use rusqlite::Connection;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Why Rust cannot give Node's answer. Every variant is a decline: Node answers (with its 200, or
/// with the 500 its own decode fails into).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decline {
    /// The read itself (busy, SQL error, schema gate).
    Read(read::Decline),
    /// A payload Effect rejects (schema drift): Node's snapshot fails there. `path` names the
    /// field, never its value.
    PayloadDrift { thread_id: String, path: String },
    /// A value the port cannot judge (a non-canonical date, JSON text serde does not parse):
    /// Effect may accept it.
    DecodeLimit { thread_id: String, path: String },
    /// A turn item of a type the shell decoder does not port.
    ItemKindNotPorted { thread_id: String, kind: String },
    /// A branch of the TypeScript not ported (a legacy single linked PR, a PR watch task, an MCP
    /// tool name, rows whose order SQL leaves open).
    NotPorted {
        thread_id: String,
        what: &'static str,
    },
}

impl Decline {
    pub fn reason(&self) -> &'static str {
        match self {
            Decline::Read(r) => r.reason(),
            Decline::PayloadDrift { .. } => "payload_drift",
            Decline::DecodeLimit { .. } => "decode_limit",
            Decline::ItemKindNotPorted { .. } => "item_kind_not_ported",
            Decline::NotPorted { .. } => "not_ported",
        }
    }
}

impl From<rusqlite::Error> for Decline {
    fn from(e: rusqlite::Error) -> Self {
        Decline::Read(e.into())
    }
}

/// `readShellSnapshotRows`' result.
pub struct ShellSnapshotRows {
    pub target_thread_ids: HashSet<String>,
    pub thread_rows: Vec<sql::ShellThreadRow>,
    pub run_rows: Vec<sql::ShellRunRow>,
    pub item_count_rows: Vec<sql::ShellRunItemCountRow>,
    pub provider_thread_rows: Vec<sql::ProviderThreadRow>,
    pub pending_turn_item_rows: Vec<sql::ShellPendingTurnItemRow>,
}

/// `readShellSnapshotRows({ location })`. Its `MAX(sequence)` over thread events is not read: the
/// shell routes take `latestApplicationSequence` instead (`ShellStream.loadShellSnapshotParts`).
pub fn read_shell_snapshot_rows(
    c: &Connection,
    location: Location,
) -> rusqlite::Result<ShellSnapshotRows> {
    let target = sql::select_shell_thread_rows(c, None, Some(location))?;
    let target_thread_ids: HashSet<String> = target.iter().map(|r| r.thread_id.clone()).collect();
    let mut order: Vec<String> = Vec::new();
    let mut rows_by_thread_id: HashMap<String, sql::ShellThreadRow> = HashMap::new();
    for row in target {
        if !rows_by_thread_id.contains_key(&row.thread_id) {
            order.push(row.thread_id.clone());
        }
        rows_by_thread_id.insert(row.thread_id.clone(), row);
    }
    let mut pending: Vec<String> = order
        .iter()
        .filter_map(|id| {
            rows_by_thread_id[id]
                .forked_from_run_source_thread_id
                .clone()
        })
        .collect();
    while let Some(source_id) = pending.pop() {
        if rows_by_thread_id.contains_key(&source_id) {
            continue;
        }
        let Some(source) = sql::select_shell_thread_rows(c, Some(&source_id), None)?
            .into_iter()
            .next()
        else {
            continue;
        };
        if let Some(next) = &source.forked_from_run_source_thread_id {
            pending.push(next.clone());
        }
        order.push(source_id.clone());
        rows_by_thread_id.insert(source_id, source);
    }
    let thread_rows: Vec<sql::ShellThreadRow> = order
        .iter()
        .map(|id| rows_by_thread_id.remove(id).expect("ordered id"))
        .collect();
    let fork_source_ids = state::shell_fork_source_ids(&thread_rows);
    let running: Vec<String> = thread_rows
        .iter()
        .filter(|r| r.active_run_id.is_some() && r.active_run_status.as_deref() == Some("running"))
        .filter_map(|r| r.active_run_id.clone())
        .collect();
    let some = |ids: &[String]| !ids.is_empty();
    Ok(ShellSnapshotRows {
        target_thread_ids,
        run_rows: match some(&fork_source_ids) {
            true => sql::select_shell_run_rows(c, &fork_source_ids)?,
            false => vec![],
        },
        item_count_rows: match some(&fork_source_ids) {
            true => sql::select_shell_run_item_counts(c, &fork_source_ids)?,
            false => vec![],
        },
        provider_thread_rows: match some(&order) {
            true => sql::select_shell_provider_thread_rows(c, &order)?,
            false => vec![],
        },
        pending_turn_item_rows: match some(&order) {
            true => sql::select_shell_pending_turn_item_rows(c, &order, &running)?,
            false => vec![],
        },
        thread_rows,
    })
}

/// `decodeShellSnapshot`: (`threads`, `archivedThreads`).
pub fn decode_shell_snapshot(
    rows: &ShellSnapshotRows,
) -> Result<(Vec<Value>, Vec<Value>), Decline> {
    let maps = state::run_maps_by_thread_id(&rows.run_rows, &rows.item_count_rows);
    let data = state::pending_background_data_by_thread_id(
        &rows.provider_thread_rows,
        &rows.pending_turn_item_rows,
    )?;
    let states = rows
        .thread_rows
        .iter()
        .map(|row| state::shell_thread_state_from_row(row, &maps, &data))
        .collect::<Result<Vec<_>, _>>()?;
    let states_by_thread_id: HashMap<String, state::ShellThreadState> = states
        .iter()
        .map(|s| (s.id().to_owned(), s.clone()))
        .collect();
    let mut threads = Vec::new();
    let mut archived = Vec::new();
    for s in states
        .iter()
        .filter(|s| rows.target_thread_ids.contains(s.id()))
    {
        let visible = state::visible_item_count_for_shell(s.id(), &states_by_thread_id, None);
        let shell = state::shell_from_state(s, visible)?;
        match shell["archivedAt"].is_null() {
            true => threads.push(shell),
            false => archived.push(shell),
        }
    }
    Ok((threads, archived))
}

/// The thread shells of `location`, in Node's order, read in the caller's transaction.
pub fn build_threads(c: &Connection, location: Location) -> Result<Vec<Value>, Decline> {
    let rows = read_shell_snapshot_rows(c, location)?;
    let (threads, archived) = decode_shell_snapshot(&rows)?;
    Ok(match location {
        Location::Active => threads,
        Location::Archive => archived,
    })
}

#[cfg(test)]
pub(crate) mod tests;
