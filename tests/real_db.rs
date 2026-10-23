//! The `VEKREL_REAL_DB` harness: skips cleanly when unset, leaves no copy behind and never touches
//! the original; with the owner's DB set, the copy passes the schema gate.
use std::{path::Path, process::Command};
use vekrel::db::read::StateDb;

mod support {
    pub mod real_db;
}
use support::real_db::{copy_from, real_db};

#[test]
fn skips_cleanly_when_unset() {
    assert!(copy_from(None).is_none());
}

/// Runs only inside `copy_is_deleted_at_exit_and_the_original_is_untouched`'s child process.
#[test]
fn child_reads_the_copy() {
    if std::env::var_os("VEKREL_REAL_DB_CHILD").is_none() {
        return;
    }
    let path = real_db().expect("VEKREL_REAL_DB set");
    assert_eq!(real_db(), Some(path), "copied once per binary");
    let c = rusqlite::Connection::open(path).unwrap();
    let n: i64 = c
        .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 3);
    println!("COPY={}", path.display());
}

/// (name, size, mtime) of every file in `dir`.
fn listing(dir: &Path) -> Vec<(String, u64, std::time::SystemTime)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let m = e.metadata().unwrap();
            (
                e.file_name().into_string().unwrap(),
                m.len(),
                m.modified().unwrap(),
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
fn copy_is_deleted_at_exit_and_the_original_is_untouched() {
    let src = tempfile::tempdir().unwrap();
    let db = src.path().join("statev2.sqlite");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(
        "PRAGMA journal_mode = WAL; CREATE TABLE t (a); INSERT INTO t VALUES (1), (2), (3);",
    )
    .unwrap();
    drop(c);
    let before = listing(src.path());
    // The child's temp dir is private, so "nothing left" is exact.
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_reads_the_copy", "--nocapture"])
        .env("VEKREL_REAL_DB", &db)
        .env("VEKREL_REAL_DB_CHILD", "1")
        .env("TMPDIR", tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let copy = stdout
        .lines()
        .find_map(|l| l.strip_prefix("COPY="))
        .expect("child printed the copy path");
    assert!(copy.starts_with(&*tmp.path().to_string_lossy()), "{copy}");
    assert!(!Path::new(copy).exists());
    assert_eq!(
        std::fs::read_dir(tmp.path()).unwrap().count(),
        0,
        "temp dir empty after exit"
    );
    // The main file is untouched. A read-only open of a WAL DB that nobody has open creates
    // SQLite's empty `-wal` / `-shm` sidecars (with the owner's T3 Code running they exist already).
    let after = listing(src.path());
    assert_eq!(after[0], before[0], "original: same size and mtime");
    let rest: Vec<_> = after[1..]
        .iter()
        .map(|(n, len, _)| (n.as_str(), *len))
        .collect();
    assert!(
        rest.iter().all(|(n, len)| *n == "statev2.sqlite-shm" || (*n == "statev2.sqlite-wal" && *len == 0)),
        "{rest:?}"
    );
}

#[test]
fn owner_db_copy_passes_the_schema_gate() {
    let Some(path) = real_db() else {
        return;
    };
    let db = StateDb::new(path.parent().unwrap());
    let r = db.read(|c| {
        let threads: i64 = c.query_row(
            "SELECT count(*) FROM orchestration_v2_projection_threads",
            [],
            |r| r.get(0),
        )?;
        let projects: i64 =
            c.query_row("SELECT count(*) FROM projection_projects", [], |r| r.get(0))?;
        Ok((threads, projects))
    });
    let (threads, projects) = r.expect("gate passes and reads succeed");
    println!("owner DB copy: {threads} threads, {projects} projects");
    assert!(threads > 0);
}

/// SHA-256 of `path` (streamed: the copy is about 2 GB).
fn digest(path: &Path) -> Option<Vec<u8>> {
    use sha2::Digest;
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let (mut h, mut buf) = (sha2::Sha256::new(), vec![0; 1 << 20]);
    loop {
        match f.read(&mut buf).unwrap() {
            0 => return Some(h.finalize().to_vec()),
            n => h.update(&buf[..n]),
        }
    }
}

/// SHA-256 per table of every row in rowid order (`WITHOUT ROWID` tables in key order), each
/// value tagged with its SQLite type: equal dumps mean equal logical content, whatever the pages.
fn logical_dump(c: &rusqlite::Connection) -> Vec<(String, Vec<u8>)> {
    use rusqlite::types::ValueRef;
    use sha2::Digest;
    let tables: Vec<(String, bool)> = c
        .prepare("SELECT name, sql LIKE '%WITHOUT ROWID%' FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    tables
        .into_iter()
        .map(|(t, no_rowid)| {
            let order = if no_rowid { "" } else { " ORDER BY rowid" };
            let mut q = c.prepare(&format!("SELECT * FROM \"{t}\"{order}")).unwrap();
            let n = q.column_count();
            let mut h = sha2::Sha256::new();
            let mut rows = q.query([]).unwrap();
            while let Some(r) = rows.next().unwrap() {
                for i in 0..n {
                    match r.get_ref(i).unwrap() {
                        ValueRef::Null => h.update(b"n"),
                        ValueRef::Integer(v) => {
                            h.update([b"i".as_slice(), &v.to_le_bytes()].concat())
                        }
                        ValueRef::Real(v) => h.update([b"r".as_slice(), &v.to_le_bytes()].concat()),
                        ValueRef::Text(v) | ValueRef::Blob(v) => {
                            h.update((v.len() as u64).to_le_bytes());
                            h.update(v);
                        }
                    }
                }
                h.update(b"\n");
            }
            (t, h.finalize().to_vec())
        })
        .collect()
}

/// Every turn item of the owner's DB through Rust's `getTurnItem`, and thread searches built from
/// its titles through `searchThreads` (what serve answers): every legacy thread's item declines
/// before its row is read, and the copy (and its WAL) is byte-identical and has the same logical
/// dump afterwards.
#[test]
fn owner_db_turn_items_decline_legacy_threads_and_write_nothing() {
    use vekrel::handlers::{thread_search::search, turn_item::get_turn_item};
    let Some(path) = real_db() else {
        return;
    };
    let files = ["", "-wal"].map(|s| path.with_file_name(format!("statev2.sqlite{s}")));
    // Opened first: a read-only open creates the empty `-wal` / `-shm` sidecars.
    let c = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    c.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .unwrap();
    let before: Vec<_> = files.iter().map(|f| digest(f)).collect();
    let dump_before = logical_dump(&c);
    let titles: Vec<String> = c
        .prepare(
            "SELECT title FROM orchestration_v2_projection_threads ORDER BY thread_id LIMIT 200",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let rows: Vec<(String, String, bool)> = c
        .prepare(
            "SELECT thread_id, turn_item_id, thread_id IN \
             (SELECT thread_id FROM orchestration_v2_legacy_imports) \
             FROM orchestration_v2_projection_turn_items",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    drop(c);
    let db = StateDb::new(path.parent().unwrap());
    let mut outcomes = std::collections::BTreeMap::<&str, usize>::new();
    let (mut legacy, mut legacy_declined) = (0, 0);
    for (t, i, is_legacy) in &rows {
        let r = get_turn_item(&db, &serde_json::json!({"threadId": t, "itemId": i}));
        let o = match &r {
            Ok(v) => {
                assert!(!v["item"].is_null(), "{i}: listed row read as missing");
                "served"
            }
            Err(why) => why,
        };
        *outcomes.entry(o).or_default() += 1;
        if *is_legacy {
            legacy += 1;
            legacy_declined += usize::from(o == "legacy_thread");
        }
    }
    println!(
        "owner DB getTurnItem over {} items: {outcomes:?}",
        rows.len()
    );
    assert_eq!(
        legacy_declined, legacy,
        "every legacy thread's item declined"
    );
    assert_eq!(outcomes.get("legacy_thread").copied().unwrap_or(0), legacy);
    assert!(outcomes.get("served").copied().unwrap_or(0) > 0);
    let mut hits = 0;
    for t in &titles {
        let q: String = t.chars().take(12).collect();
        if let Some(v) = search(&db, &serde_json::json!({"query": q})) {
            hits += usize::from(!v["matches"].as_array().is_none_or(Vec::is_empty));
        }
    }
    println!(
        "owner DB searchThreads: {} queries, {hits} with hits",
        titles.len()
    );
    assert!(hits > 0);
    drop(db);
    let after: Vec<_> = files.iter().map(|f| digest(f)).collect();
    assert_eq!(before, after, "the copy is byte-identical after the run");
    let c = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    assert_eq!(
        dump_before,
        logical_dump(&c),
        "the copy's logical dump is unchanged"
    );
}
