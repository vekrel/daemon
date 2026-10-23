//! Read-only access to the engine's state DB for handlers that answer from projections: one
//! read-only connection and one read transaction per request, behind the schema gate. Every
//! failure is a decline (Node answers); Rust never writes this DB.
use super::schema_gate;
use rusqlite::{Connection, ErrorCode, OpenFlags};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

/// Why a read declined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decline {
    /// The DB is not the schema Rust was checked against (`schema_gate`).
    SchemaUnknown,
    /// A writer held the DB past the busy timeout.
    Busy,
    /// Any other SQLite error (missing file, bad row, SQL error).
    Sql,
}

impl Decline {
    pub fn reason(self) -> &'static str {
        match self {
            Decline::SchemaUnknown => "schema_unknown",
            Decline::Busy => "db_busy",
            Decline::Sql => "db_error",
        }
    }
}

impl From<rusqlite::Error> for Decline {
    fn from(e: rusqlite::Error) -> Self {
        let busy = matches!(
            e.sqlite_error_code(),
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        );
        tracing::info!(error = %e, "state db read declined");
        if busy { Decline::Busy } else { Decline::Sql }
    }
}

const BUSY_TIMEOUT: Duration = Duration::from_millis(100);

/// What the gate's verdict depends on: `PRAGMA schema_version` and the migration rows (a
/// data-only migration does not move `schema_version`).
type GateKey = (i64, i64, Option<i64>);

/// `<state_dir>/statev2.sqlite` with the gate's verdict cached per `GateKey`.
#[derive(Debug)]
pub struct StateDb {
    path: PathBuf,
    gate: Mutex<Option<(GateKey, bool)>>,
    /// One idle connection kept between reads: opening one costs 40-60 ms under load (6B Task 7).
    /// A concurrent read opens its own; a connection whose read failed is dropped.
    idle: Mutex<Option<Connection>>,
}

impl StateDb {
    pub fn new(state_dir: &Path) -> Self {
        StateDb {
            path: state_dir.join("statev2.sqlite"),
            gate: Mutex::new(None),
            idle: Mutex::new(None),
        }
    }

    /// Runs `f` inside one read transaction (one consistent WAL snapshot). Blocking: call from
    /// `spawn_blocking`. The gate runs on the first read and again whenever its `GateKey` moves.
    pub fn read<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, Decline> {
        let idle = self.idle.lock().expect("idle lock").take();
        let mut c = match idle {
            Some(c) => c,
            None => open(&self.path)?,
        };
        let out = Self::read_on(&self.gate, &mut c, f);
        if out.is_ok() {
            *self.idle.lock().expect("idle lock") = Some(c);
        }
        out
    }

    fn read_on<T>(
        gate: &Mutex<Option<(GateKey, bool)>>,
        c: &mut Connection,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, Decline> {
        let tx = c.transaction()?;
        // The first read starts the snapshot, so the gate and `f` see the same schema.
        let version: i64 = tx.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
        let (n, max) = tx.query_row(
            "SELECT count(*), max(migration_id) FROM effect_sql_migrations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let key = (version, n, max);
        let cached = *gate.lock().expect("gate lock");
        let ok = match cached {
            Some((k, ok)) if k == key => ok,
            _ => {
                let ok = match schema_gate::check(&tx)? {
                    None => true,
                    Some(why) => {
                        tracing::warn!(why, "state db schema unknown: Rust declines its reads");
                        false
                    }
                };
                *gate.lock().expect("gate lock") = Some((key, ok));
                ok
            }
        };
        if !ok {
            return Err(Decline::SchemaUnknown);
        }
        Ok(f(&tx)?)
        // `tx` drops here: a rollback, which for a read transaction only ends the snapshot.
    }
}

/// `SQLITE_OPEN_READ_ONLY`, `query_only`, 100 ms busy timeout.
fn open(path: &Path) -> rusqlite::Result<Connection> {
    let c = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    c.busy_timeout(BUSY_TIMEOUT)?;
    c.execute_batch("PRAGMA query_only = 1")?;
    Ok(c)
}

/// The engine would import a migrated v1 thread's transcript (a write) on its next read of it:
/// its `orchestration_v2_legacy_imports` row has `transcript_imported_at IS NULL`
/// (`LegacyV1ThreadImporter.ts:684-700`). Handlers decline such threads.
pub fn needs_legacy_import(c: &Connection, thread_id: &str) -> rusqlite::Result<bool> {
    let pending = c.query_row(
        "SELECT transcript_imported_at IS NULL FROM orchestration_v2_legacy_imports \
         WHERE thread_id = ?1 LIMIT 1",
        [thread_id],
        |r| r.get::<_, bool>(0),
    );
    match pending {
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        r => r,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A state DB with exactly the schema the gate expects, plus `extra` SQL.
    pub(crate) fn fixture(dir: &Path, extra: &str) -> StateDb {
        let c = Connection::open(dir.join("statev2.sqlite")).unwrap();
        c.execute_batch(&schema_gate::tests::schema_sql()).unwrap();
        c.execute_batch(extra).unwrap();
        StateDb::new(dir)
    }

    fn count(db: &StateDb) -> Result<i64, Decline> {
        db.read(|c| c.query_row("SELECT count(*) FROM projection_projects", [], |r| r.get(0)))
    }

    #[test]
    fn reads_inside_one_read_only_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), "");
        assert_eq!(count(&db), Ok(0));
        let r = db.read(|c| {
            let q: i64 = c.query_row("PRAGMA query_only", [], |r| r.get(0))?;
            let auto = c.is_autocommit();
            let w = c.execute("CREATE TABLE x (a)", []).is_err();
            Ok((q, auto, w))
        });
        assert_eq!(
            r,
            Ok((1, false, true)),
            "query_only, inside BEGIN, writes refused"
        );
        assert_eq!(db.read(|c| c.execute("SELECT nope", [])), Err(Decline::Sql));
        let missing = StateDb::new(&dir.path().join("nowhere"));
        assert_eq!(count(&missing), Err(Decline::Sql));
    }

    #[test]
    fn reads_reuse_one_idle_connection() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), "");
        // A per-connection setting survives only on the same connection.
        db.read(|c| c.execute_batch("PRAGMA cache_size = -1234"))
            .unwrap();
        let size = db.read(|c| c.query_row("PRAGMA cache_size", [], |r| r.get::<_, i64>(0)));
        assert_eq!(size, Ok(-1234));
        // A failed read drops its connection.
        assert_eq!(db.read(|c| c.execute("SELECT nope", [])), Err(Decline::Sql));
        let size = db.read(|c| c.query_row("PRAGMA cache_size", [], |r| r.get::<_, i64>(0)));
        assert_ne!(size, Ok(-1234));
    }

    #[test]
    fn a_held_write_lock_is_busy_after_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), "");
        // Rollback journal: a writer's EXCLUSIVE lock blocks readers (WAL readers never block).
        let w = Connection::open(dir.path().join("statev2.sqlite")).unwrap();
        w.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let t = std::time::Instant::now();
        assert_eq!(count(&db), Err(Decline::Busy));
        assert!(t.elapsed() >= BUSY_TIMEOUT, "{:?}", t.elapsed());
        w.execute_batch("ROLLBACK").unwrap();
        assert_eq!(count(&db), Ok(0));
    }

    #[test]
    fn gate_rechecks_when_migrations_or_the_schema_move() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), "");
        assert_eq!(count(&db), Ok(0));
        let w = Connection::open(dir.path().join("statev2.sqlite")).unwrap();
        // A data-only migration 68: schema_version stays, the migration rows move.
        w.execute_batch(
            "INSERT INTO effect_sql_migrations (migration_id, name) VALUES (68, 'Future')",
        )
        .unwrap();
        assert_eq!(count(&db), Err(Decline::SchemaUnknown));
        w.execute_batch("DELETE FROM effect_sql_migrations WHERE migration_id = 68")
            .unwrap();
        assert_eq!(count(&db), Ok(0));
        // A column dropped behind a cached verdict: schema_version moves.
        w.execute_batch("ALTER TABLE projection_projects DROP COLUMN project_icon_json")
            .unwrap();
        assert_eq!(count(&db), Err(Decline::SchemaUnknown));
    }

    #[test]
    fn legacy_import_pending_only_for_a_null_transcript() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(
            dir.path(),
            "INSERT INTO orchestration_v2_legacy_imports
               (thread_id, source_updated_at, shell_imported_at, transcript_imported_at, imported_message_count)
             VALUES ('pending', 't', 't', NULL, 0), ('done', 't', 't', 't', 3);",
        );
        let r = db.read(|c| {
            Ok([
                needs_legacy_import(c, "pending")?,
                needs_legacy_import(c, "done")?,
                needs_legacy_import(c, "v2-native")?,
            ])
        });
        assert_eq!(r, Ok([true, false, false]));
    }
}
