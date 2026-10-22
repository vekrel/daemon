//! Every frame of a real (or synthetic) boot session must parse; replay must compare it.
use std::path::Path;
use vekrel::{
    replay::{Line, compare},
    rpc_wire::{ClientMsg, Envelope, parse_frame},
};

fn load(path: &Path) -> Vec<Line> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Parses every frame; returns the number of connections, counting a c2s Request with id 0 as
/// a new one (recordings made before the `conn` field have no other marker).
fn check(lines: &[Line]) -> usize {
    let failures: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| parse_frame(&l.frame).err().map(|e| (i + 1, e)))
        .collect();
    assert!(failures.is_empty(), "{failures:?}");
    assert!(compare(lines, lines).matches);
    lines
        .iter()
        .flat_map(|l| parse_frame(&l.frame).unwrap())
        .filter(|e| matches!(e, Envelope::Client(ClientMsg::Request { id, .. }) if id == 0))
        .count()
}

#[test]
fn synthetic_boot_parses() {
    let lines = load(Path::new("tests/fixtures/synthetic-boot.ndjson"));
    assert_eq!(check(&lines), 1);
}

#[test]
fn real_boot_session_parses_and_splits_into_two_connections() {
    let Some(dir) = std::env::var_os("VEKREL_FIXTURES_DIR") else {
        eprintln!("VEKREL_FIXTURES_DIR unset: skipping the real boot-session fixture");
        return;
    };
    let lines = load(&Path::new(&dir).join("2026-10-22-boot-session.ndjson"));
    assert_eq!(lines.len(), 179);
    assert_eq!(check(&lines), 2);
}
