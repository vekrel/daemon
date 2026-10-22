//! `--record`: appends every proxied WS text frame to an NDJSON file, off the forwarding path.
use crate::proxy_ws::{Dir, FrameTap};
use serde::Serialize;
use std::{
    fs::{self, File},
    hash::{BuildHasher, RandomState},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_tungstenite::tungstenite::Message;

/// Frames queued for the writer before new ones are dropped (and counted).
const QUEUE: usize = 4096;

pub struct Recorder {
    path: PathBuf,
    tx: SyncSender<Item>,
    writer: Mutex<Option<thread::JoinHandle<()>>>,
    dropped: AtomicU64,
    skipped: AtomicU64,
}

/// A frame to write, or `None`: flush and stop.
type Item = Option<(u64, u64, Dir, String)>;

#[derive(Serialize)]
struct Line<'a> {
    t: u64,
    conn: u64,
    dir: &'a str,
    frame: &'a str,
}

impl Recorder {
    /// Opens `<dir>/<YYYYMMDDTHHMMSSZ>-<8 hex>.ndjson` and starts its writer thread.
    pub fn create(dir: &Path) -> io::Result<Self> {
        // Recordings hold session tokens and cookies: owner-only, like the engine's secrets.
        let mut db = fs::DirBuilder::new();
        db.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            db.mode(0o700).create(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(not(unix))]
        db.create(dir)?;
        let secs = now_ms() / 1000;
        let rand = RandomState::new().hash_one(secs) as u32;
        let path = dir.join(format!("{}-{rand:08x}.ndjson", iso_basic(secs)));
        let mut opts = File::options();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let file = opts.open(&path)?;
        let (tx, rx) = sync_channel(QUEUE);
        let writer = thread::Builder::new()
            .name("vekrel-recorder".into())
            .spawn(move || write_loop(rx, BufWriter::new(file)))?;
        tracing::info!("recording ws frames to {}", path.display());
        Ok(Self {
            path,
            tx,
            writer: Mutex::new(Some(writer)),
            dropped: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Frames lost because the writer fell `QUEUE` frames behind.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Writes out what is queued and stops the writer, waiting at most `limit`.
    /// Frames tapped afterwards are counted as dropped.
    pub fn close(&self, limit: Duration) {
        let end = Instant::now() + limit;
        // The stop marker queues behind pending frames; retry while the queue is full.
        while let Err(TrySendError::Full(_)) = self.tx.try_send(None) {
            if Instant::now() >= end {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let Some(w) = self.writer.lock().unwrap().take() else {
            return;
        };
        while !w.is_finished() && Instant::now() < end {
            thread::sleep(Duration::from_millis(5));
        }
        if w.is_finished() {
            let _ = w.join();
        } else {
            tracing::warn!("recorder did not flush within {limit:?}");
        }
    }

    /// Non-text frames (binary, ping, pong, close) seen and not recorded.
    pub fn skipped(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
    }
}

impl FrameTap for Recorder {
    fn on_frame(&self, conn: u64, dir: Dir, frame: &Message) {
        // Effect RPC is text-only; other frames are counted, not recorded.
        let Message::Text(text) = frame else {
            self.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match self
            .tx
            .try_send(Some((now_ms(), conn, dir, text.as_str().to_owned())))
        {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() {
                    tracing::warn!("recorder queue full, {n} frames dropped so far");
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn write_loop(rx: Receiver<Item>, mut out: BufWriter<File>) {
    let write = |out: &mut BufWriter<File>, (t, conn, dir, frame): (u64, u64, Dir, String)| {
        let dir = match dir {
            Dir::C2s => "c2s",
            Dir::S2c => "s2c",
        };
        serde_json::to_writer(
            &mut *out,
            &Line {
                t,
                conn,
                dir,
                frame: &frame,
            },
        )?;
        out.write_all(b"\n")
    };
    while let Ok(Some(item)) = rx.recv() {
        // Drain what is queued, then flush once, so the file is current whenever the queue is idle.
        let mut stop = false;
        let res = write(&mut out, item)
            .and_then(|()| {
                rx.try_iter()
                    .map_while(|i| {
                        stop = i.is_none();
                        i
                    })
                    .try_for_each(|i| write(&mut out, i))
            })
            .and_then(|()| out.flush());
        if let Err(e) = res {
            tracing::error!("recorder write failed, recording stopped: {e}");
            return;
        }
        if stop {
            return;
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// ISO 8601 basic format, UTC (no colons, so the name is valid on every filesystem).
fn iso_basic(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil_from_days.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let (h, mi, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

#[cfg(test)]
mod tests {
    #[test]
    fn iso_basic() {
        assert_eq!(super::iso_basic(0), "19700101T000000Z");
        assert_eq!(super::iso_basic(1_792_670_645), "20261022T120405Z");
        assert_eq!(super::iso_basic(951_782_400), "20000229T000000Z");
    }

    #[cfg(unix)]
    #[test]
    fn recording_file_and_dir_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("vekrel-perm-{}", std::process::id()));
        let dir = root.join("recordings");
        // Pre-existing, too-open dir must be tightened.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rec = super::Recorder::create(&dir).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(rec.path()), 0o600);
        let _ = std::fs::remove_dir_all(&root);
    }
}
