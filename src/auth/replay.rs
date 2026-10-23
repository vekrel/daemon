//! DPoP replay markers, shared with the engine: the same file name, content and atomic
//! `open(wx)` + `link()` publish as `ServerSecretStore.create` (`verifyRequestDpopProof`), so a
//! proof either process consumed is a replay for the other.
use super::{dpop::Proof, dpop::b64_sha256};
use std::{
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

/// `secrets/dpop-proof-<b64url(sha256("<thumbprint>:<jti>"))>.bin`.
pub fn marker_path(secrets: &Path, thumbprint: &str, jti: &str) -> PathBuf {
    secrets.join(format!(
        "dpop-proof-{}.bin",
        b64_sha256(&format!("{thumbprint}:{jti}"))
    ))
}

/// The marker body Node writes (`consumedAt` is `toISOString()`).
pub fn content(p: &Proof, now_ms: i64) -> String {
    format!(
        "thumbprint={}\njti={}\niat={}\nconsumedAt={}",
        p.thumbprint,
        p.jti,
        p.iat,
        crate::handlers::auth_session::iso_millis(now_ms)
    )
}

#[derive(Debug, PartialEq)]
pub enum Created {
    /// Rust consumed the proof: it must answer the request itself.
    Yes(PathBuf),
    /// The marker already exists (`AlreadyExists` → `dpopFailureReason: "replay"`).
    Replay,
    /// Nothing was published (Node would 500): Node answers.
    Failed,
}

/// `ServerSecretStore.create`: write a `0600` temp file with `O_EXCL`, sync, then `link()` it to
/// the final name, which fails if any process published that marker first. The temp file always goes.
pub fn create(secrets: &Path, p: &Proof, now_ms: i64) -> Created {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let path = marker_path(secrets, &p.thumbprint, &p.jti);
    let tmp = path.with_extension(format!(
        "bin.{}-{}-{}.tmp",
        std::process::id(),
        now_ms,
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        f.write_all(content(p, now_ms).as_bytes())?;
        f.sync_all()?;
        std::fs::hard_link(&tmp, &path)
    })();
    let _ = std::fs::remove_file(&tmp);
    match written {
        Ok(()) => Created::Yes(path),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Created::Replay,
        Err(e) => {
            tracing::warn!("dpop replay marker not written: {}", e.kind());
            Created::Failed
        }
    }
}

/// Shadow: was this proof consumed before `arrived` (so Node, handling the same request, will
/// call it a replay)? A marker Node publishes while handling this very request is newer.
/// `None`: the directory cannot be read.
// shortcut: assumes sub-second mtimes (APFS, ext4); on a 1 s filesystem Node's own marker can
// look older and shadow logs a false replay. Upgrade: snapshot existence before forwarding.
pub fn seen_before(secrets: &Path, p: &Proof, arrived: SystemTime) -> Option<bool> {
    match std::fs::metadata(marker_path(secrets, &p.thumbprint, &p.jti)) {
        Ok(m) => Some(m.modified().ok()? < arrived),
        Err(e) if e.kind() == ErrorKind::NotFound => Some(false),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn proof() -> Proof {
        Proof {
            thumbprint: "thumb".into(),
            jti: "proof-1".into(),
            iat: 100,
        }
    }

    /// `ServerSecretStore.create` as the engine does it, in a test: `open(tmp, "wx", 0o600)`,
    /// write, `link(tmp, final)`, remove tmp. `Err(AlreadyExists)` is Node's replay.
    fn node_create(secrets: &Path, name: &str, body: &str) -> std::io::Result<()> {
        let path = secrets.join(format!("{name}.bin"));
        let tmp = secrets.join(format!("{name}.bin.node-uuid.tmp"));
        std::fs::write(&tmp, body)?;
        let r = std::fs::hard_link(&tmp, &path);
        std::fs::remove_file(&tmp)?;
        r
    }

    fn names(d: &Path) -> Vec<String> {
        let mut v: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn creates_nodes_marker_once_then_replay() {
        let d = tempfile::tempdir().unwrap();
        let Created::Yes(path) = create(d.path(), &proof(), 1_893_456_000_123) else {
            panic!("not created")
        };
        let name = format!("dpop-proof-{}.bin", b64_sha256("thumb:proof-1"));
        assert_eq!(
            names(d.path()),
            std::slice::from_ref(&name),
            "temp file removed"
        );
        assert_eq!(path, d.path().join(&name));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "thumbprint=thumb\njti=proof-1\niat=100\nconsumedAt=2030-01-01T00:00:00.123Z"
        );
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(
                &std::fs::metadata(&path).unwrap().permissions()
            ) & 0o777,
            0o600
        );
        assert_eq!(create(d.path(), &proof(), 0), Created::Replay);
        assert_eq!(names(d.path()), [name]);
        // No secrets directory: nothing published, Node answers.
        assert_eq!(create(&d.path().join("nope"), &proof(), 0), Created::Failed);
    }

    #[test]
    fn replay_is_seen_across_processes() {
        let d = tempfile::tempdir().unwrap();
        let name = format!("dpop-proof-{}", b64_sha256("thumb:proof-1"));
        // A marker the engine wrote blocks Rust, in serve (create) and shadow (seen_before).
        let later = SystemTime::now() + Duration::from_secs(5);
        node_create(d.path(), &name, "from node").unwrap();
        assert_eq!(seen_before(d.path(), &proof(), later), Some(true));
        assert_eq!(create(d.path(), &proof(), 0), Created::Replay);
        // A marker Rust wrote blocks the engine.
        let other = Proof {
            jti: "proof-2".into(),
            ..proof()
        };
        assert!(matches!(create(d.path(), &other, 0), Created::Yes(_)));
        let name2 = format!("dpop-proof-{}", b64_sha256("thumb:proof-2"));
        let e = node_create(d.path(), &name2, "x").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::AlreadyExists);
        // The engine's pruner matches `dpop-proof-*.bin` only: every file left is one.
        assert!(
            names(d.path())
                .iter()
                .all(|n| n.starts_with("dpop-proof-") && n.ends_with(".bin"))
        );
    }

    #[test]
    fn shadow_ignores_markers_newer_than_the_request() {
        let d = tempfile::tempdir().unwrap();
        let arrived = SystemTime::now() - Duration::from_secs(5);
        assert_eq!(seen_before(d.path(), &proof(), arrived), Some(false));
        // Node consumed the proof while handling this same request: not a replay.
        assert!(matches!(create(d.path(), &proof(), 0), Created::Yes(_)));
        assert_eq!(seen_before(d.path(), &proof(), arrived), Some(false));
    }
}
