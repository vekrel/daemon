//! `VEKREL_REAL_DB`: a local-only copy of the owner's `statev2.sqlite` (about 2 GB, private
//! conversation text) for tests. Unset: tests skip. Set: the file is copied once per test binary
//! with SQLite's backup API from a read-only connection (the owner's T3 Code may be writing it;
//! never `cp` a live WAL file) into a temp dir that is deleted when the process exits. The
//! original is never opened writable; nothing built from the copy is written to the repo. If no
//! process has the original open, SQLite's read-only open leaves empty `-wal` / `-shm` sidecars
//! next to it (harmless; the main file is unchanged). A run killed before its cleanup (Ctrl-C,
//! SIGKILL) leaves its dirs behind; each copy first deletes those of dead processes (`sweep_stale`).
#![allow(dead_code)]
use rusqlite::{Connection, OpenFlags, backup};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

/// The copy (`<tmp>/statev2.sqlite`), or `None` with the reason printed when the variable is unset.
pub fn real_db() -> Option<&'static Path> {
    static COPY: OnceLock<Option<PathBuf>> = OnceLock::new();
    COPY.get_or_init(|| {
        let (dir, path) = copy_from(std::env::var_os("VEKREL_REAL_DB"))?;
        *DIR.lock().unwrap() = Some(dir);
        // Statics are never dropped: delete the copy at exit (the harness exits via `exit`).
        unsafe { libc::atexit(remove_copy) };
        Some(path)
    })
    .as_deref()
}

static DIR: Mutex<Option<tempfile::TempDir>> = Mutex::new(None);

extern "C" fn remove_copy() {
    if let Ok(mut d) = DIR.lock() {
        drop(d.take());
    }
}

/// Copies `src` into a new temp dir; `None` (printed) when `src` is `None`. Panics on a copy
/// error: a set variable that cannot be read is a broken setup, not a skip.
pub fn copy_from(src: Option<OsString>) -> Option<(tempfile::TempDir, PathBuf)> {
    let Some(src) = src else {
        eprintln!("VEKREL_REAL_DB unset: skipping the owner-DB test");
        return None;
    };
    let from = Connection::open_with_flags(
        &src,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap_or_else(|e| panic!("VEKREL_REAL_DB {src:?}: {e}"));
    sweep_stale(&std::env::temp_dir());
    let dir = tempfile::Builder::new()
        .prefix(&pid_prefix("vekrel-real-db-"))
        .tempdir()
        .unwrap();
    let path = dir.path().join("statev2.sqlite");
    let mut to = Connection::open(&path).unwrap();
    {
        let b = backup::Backup::new(&from, &mut to).unwrap();
        // All pages in one step, so the copy is one consistent snapshot; retry while a writer
        // holds the lock.
        loop {
            match b.step(-1).unwrap() {
                backup::StepResult::Done => break,
                _ => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    }
    Some((dir, path))
}

/// `<name><pid>-`: a temp-dir prefix `sweep_stale` can trace back to this process.
pub fn pid_prefix(name: &str) -> String {
    format!("{name}{}-", std::process::id())
}

/// Deletes the dirs in `tmp` left by dead test processes: `vekrel-real-db-<pid>-*` and
/// `vekrel-shell-golden-<pid>-*` (owner data) and `vekrel-live-<tag>-<pid>` (engine homes, which
/// may hold a moved copy).
pub fn sweep_stale(tmp: &Path) {
    for e in std::fs::read_dir(tmp).into_iter().flatten().flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let pid = match ["vekrel-real-db-", "vekrel-shell-golden-"]
            .iter()
            .find_map(|p| name.strip_prefix(p))
        {
            Some(rest) => rest.split('-').next(),
            None if name.starts_with("vekrel-live-") => name.rsplit('-').next(),
            None => None,
        };
        let Some(pid) = pid.and_then(|p| p.parse::<i32>().ok()) else {
            continue;
        };
        if !alive(pid) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

fn alive(pid: i32) -> bool {
    // EPERM: it exists, owned by someone else.
    (unsafe { libc::kill(pid, 0) } == 0)
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[test]
fn sweep_stale_deletes_only_dirs_of_dead_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let dead = child.id();
    child.wait().unwrap();
    let me = std::process::id();
    let names = [
        format!("vekrel-real-db-{dead}-abc"),
        format!("vekrel-shell-golden-{dead}-abc"),
        format!("vekrel-live-shell-owner-{dead}"),
        format!("vekrel-real-db-{me}-abc"),
        format!("vekrel-live-shell-owner-{me}"),
        "vekrel-real-db-XyZ123".into(),
        format!("other-{dead}"),
    ];
    for n in &names {
        std::fs::create_dir(tmp.path().join(n)).unwrap();
        std::fs::write(tmp.path().join(n).join("statev2.sqlite"), "x").unwrap();
    }
    sweep_stale(tmp.path());
    let left: Vec<bool> = names.iter().map(|n| tmp.path().join(n).exists()).collect();
    assert_eq!(left, [false, false, false, true, true, true, true]);
}
