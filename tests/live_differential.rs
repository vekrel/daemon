//! Differential test against the real engine: `GET /api/auth/session` through the daemon in
//! shadow mode must log a `match` for every request and no `mismatch`.
//!
//! Ignored unless `VEKREL_LIVE_ENGINE` is the engine's `apps/server/dist/bin.mjs`:
//! `VEKREL_LIVE_ENGINE=/path/to/bin.mjs cargo test --test live_differential -- --ignored --nocapture`
//! Uses a temp `VEKREL_HOME` and free ports; pairs with curl; never contacts an AI provider.
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Stops the daemon (which stops the engine) and deletes the temp home, even on panic.
struct Daemon {
    child: Child,
    home: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn log(home: &Path) -> String {
    std::fs::read_to_string(home.join("serve.log")).unwrap_or_default()
}

/// `curl -s [-H h]... url` → (status, body).
fn curl(args: &[&str]) -> (u16, String) {
    let out = Command::new("curl")
        .args(["-s", "-w", "\n%{http_code}"])
        .args(args)
        .output()
        .expect("curl");
    let s = String::from_utf8(out.stdout).unwrap();
    let (body, code) = s.rsplit_once('\n').unwrap();
    (code.parse().unwrap_or(0), body.to_owned())
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn auth_session_shadow_matches_node() {
    let Ok(bin) = std::env::var("VEKREL_LIVE_ENGINE") else {
        eprintln!("VEKREL_LIVE_ENGINE unset; skipping");
        return;
    };
    let (public, engine) = (free_port(), free_port());
    let home = std::env::temp_dir().join(format!("vekrel-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let cfg = home.join("vekrel.toml");
    std::fs::write(
        &cfg,
        format!(
            "[server]\nport = {public}\n[engine]\ncommand = \"node\"\nargs = [{bin:?}]\nport = {engine}\n\
             [rust.handlers]\n\"GET /api/auth/session\" = \"shadow\"\n"
        ),
    )
    .unwrap();
    let out = std::fs::File::create(home.join("serve.log")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_vekrel"))
        .args(["serve", "--config"])
        .arg(&cfg)
        .env("VEKREL_HOME", &home)
        .env("NO_COLOR", "1")
        .stdout(out.try_clone().unwrap())
        .stderr(out)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let d = Daemon {
        child,
        home: home.clone(),
    };
    let base = format!("http://127.0.0.1:{public}");
    let url = format!("{base}/api/auth/session");

    // Ready once the engine answers through the proxy and has printed its pairing token.
    let deadline = Instant::now() + Duration::from_secs(90);
    let token = loop {
        assert!(
            Instant::now() < deadline,
            "engine not ready:\n{}",
            log(&home)
        );
        let l = log(&home);
        let tok = l.split("#token=").nth(1).map(|t| {
            t.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || "-_".contains(*c))
                .collect::<String>()
        });
        if let (Some(t), (200, _)) = (tok, curl(&[&format!("{base}/.well-known/vekrel/machine")])) {
            break t;
        }
        std::thread::sleep(Duration::from_millis(500));
    };

    // Pair: the engine sets its session cookie; keep the token.
    let jar = home.join("jar");
    let (code, _) = curl(&[
        "-c",
        jar.to_str().unwrap(),
        "-X",
        "POST",
        "-H",
        "content-type: application/json",
        "-d",
        &format!(r#"{{"credential":"{token}"}}"#),
        &format!("{base}/api/auth/browser-session"),
    ]);
    assert_eq!(code, 200, "pairing failed");
    let jar_text = std::fs::read_to_string(&jar).unwrap();
    let (name, session) = jar_text
        .lines()
        .filter_map(|l| {
            let f: Vec<_> = l.split('\t').collect();
            (f.len() == 7 && f[5].starts_with("t3_session"))
                .then(|| (f[5].to_owned(), f[6].to_owned()))
        })
        .next()
        .expect("session cookie");
    let cookie = format!("cookie: {name}={session}");
    let (enc, sig) = session.split_once('.').unwrap();
    // Tampered: a changed middle signature character, and a payload with a different signature.
    let mid = sig.len() / 2;
    let flip = if &sig[mid..=mid] == "A" { "B" } else { "A" };
    let bad_sig = format!(
        "cookie: {name}={enc}.{}{flip}{}",
        &sig[..mid],
        &sig[mid + 1..]
    );
    let bad_payload = format!("cookie: {name}=x{enc}.{sig}");

    let mut cases: Vec<(&str, Vec<String>, bool)> = vec![
        ("no cookie", vec![], false),
        ("valid cookie", vec![cookie.clone()], true),
        ("tampered signature", vec![bad_sig], false),
        ("tampered payload", vec![bad_payload], false),
        (
            "valid bearer",
            vec![format!("authorization: Bearer {session}")],
            true,
        ),
        (
            "cookie from foreign origin",
            vec![cookie.clone(), "origin: http://evil.test".into()],
            false,
        ),
        (
            "cookie via proxy origin",
            vec![cookie.clone(), format!("origin: http://127.0.0.1:{public}")],
            true,
        ),
    ];
    let run = |cases: &mut Vec<(&str, Vec<String>, bool)>| {
        for (what, headers, authed) in cases.drain(..) {
            let mut args: Vec<String> = headers
                .iter()
                .flat_map(|h| ["-H".into(), h.clone()])
                .collect();
            args.push(url.clone());
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let (code, body) = curl(&args);
            assert_eq!(code, 200, "{what}");
            let want = format!(r#"{{"authenticated":{authed},"#);
            assert!(body.starts_with(&want), "{what}: authenticated != {authed}");
            println!("{what}: 200, authenticated={authed}");
        }
    };
    run(&mut cases);

    // Row-only changes: Node ignores the row's expires_at, honours revoked_at.
    let db = rusqlite::Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
    db.busy_timeout(Duration::from_secs(5)).unwrap();
    db.execute(
        "UPDATE auth_sessions SET expires_at = '2000-01-01T00:00:00.000Z'",
        [],
    )
    .unwrap();
    cases.push(("expired row", vec![cookie.clone()], true));
    run(&mut cases);
    db.execute(
        "UPDATE auth_sessions SET revoked_at = '2026-01-01T00:00:00.000Z'",
        [],
    )
    .unwrap();
    cases.push(("revoked row", vec![cookie], false));
    run(&mut cases);

    std::thread::sleep(Duration::from_millis(300));
    let l = log(&home);
    let shadow: Vec<&str> = l.lines().filter(|l| l.contains("rust shadow")).collect();
    let mismatches = shadow.iter().filter(|l| l.contains("mismatch")).count();
    let matches = shadow.iter().filter(|l| l.contains("\"match\"")).count();
    println!("shadow log: {matches} match, {mismatches} mismatch");
    for s in &shadow {
        if s.contains("mismatch") {
            println!("{s}");
        }
    }
    assert_eq!(mismatches, 0);
    assert_eq!(matches, 9, "every request compared");
    drop(d);
    assert!(!home.exists());
}
