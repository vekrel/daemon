//! Differential tests against the real engine: `GET /api/auth/session`,
//! `GET /.well-known/vekrel/machine` and the `projects.readFile` / `filesystem.browse` RPCs
//! through the daemon in shadow mode must log a `match` for every request Rust answers and no
//! `mismatch`.
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

/// Starts the daemon over the real engine with every handler in shadow mode and waits until the
/// engine answers and has printed its pairing token. `None` when `VEKREL_LIVE_ENGINE` is unset.
fn start(tag: &str) -> Option<(Daemon, String, PathBuf, String)> {
    start_with(tag, |_, _| {})
}

/// Handlers that default to `serve` (plan 5's and plan 6B's proven reads); these tests start them
/// in `shadow` unless `prep` says otherwise.
const PLAN5_KEYS: [&str; 13] = [
    "orchestration.searchThreads",
    "orchestration.getTurnItem",
    "POST /api/auth/websocket-ticket",
    "GET /ws dpop",
    "subscribeAuthAccess",
    "POST /api/auth/pairing-token",
    "GET /api/auth/pairing-links",
    "POST /api/auth/pairing-links/revoke",
    "POST /api/auth/browser-session",
    "POST /oauth/token",
    "GET /api/auth/clients",
    "POST /api/auth/clients/revoke",
    "POST /api/auth/clients/revoke-others",
];

/// `start`, letting `prep` lay out files in the temp home and adjust the daemon command.
fn start_with(
    tag: &str,
    prep: impl FnOnce(&Path, &mut Command),
) -> Option<(Daemon, String, PathBuf, String)> {
    let Ok(bin) = std::env::var("VEKREL_LIVE_ENGINE") else {
        eprintln!("VEKREL_LIVE_ENGINE unset; skipping");
        return None;
    };
    let (public, engine) = (free_port(), free_port());
    let home = std::env::temp_dir().join(format!("vekrel-live-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let cfg = home.join("vekrel.toml");
    std::fs::write(
        &cfg,
        format!(
            "[server]\nport = {public}\n[engine]\ncommand = \"node\"\nargs = [{bin:?}]\nport = {engine}\n\
             [rust.handlers]\n{}\"GET /api/auth/session\" = \"shadow\"\n\
             \"GET /.well-known/vekrel/machine\" = \"shadow\"\n\
             \"projects.readFile\" = \"shadow\"\n\"filesystem.browse\" = \"shadow\"\n",
            PLAN5_KEYS.map(|k| format!("\"{k}\" = \"shadow\"\n")).concat()
        ),
    )
    .unwrap();
    let out = std::fs::File::create(home.join("serve.log")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vekrel"));
    prep(&home, &mut cmd);
    // A key `prep` adds overrides the plan 5 shadow line, which comes first (TOML rejects duplicate
    // keys), so the last line for a key wins.
    let t = std::fs::read_to_string(&cfg).unwrap();
    let mut seen = std::collections::HashSet::new();
    let mut lines: Vec<&str> = t
        .lines()
        .rev()
        .filter(|l| !l.starts_with('"') || seen.insert(l.split(" = ").next().unwrap()))
        .collect();
    lines.reverse();
    std::fs::write(&cfg, lines.join("\n") + "\n").unwrap();
    let child = cmd
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
        // /healthz is the daemon's own route, so readiness polls add no shadow log lines.
        let (_, health) = curl(&[&format!("{base}/healthz")]);
        if let (Some(t), true) = (tok, health.contains(r#""engine":"up""#)) {
            break t;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    Some((d, base, home, token))
}

/// Shadow log lines for `route` where Rust declined (Node answered alone).
fn declined(home: &Path, route: &str) -> usize {
    let tag = format!("tag=\"{route}\"");
    log(home)
        .lines()
        .filter(|l| l.contains(&tag) && l.contains("outcome=\"declined\""))
        .count()
}

/// (matches, mismatches, declines + load skips) for `route` once at least `n` outcomes are logged,
/// or after 60 s. Each comparison is logged after Node's answer reached the client, so a loaded
/// machine logs late; a decline is Rust not answering (e.g. the machine descriptor still loading
/// after startup); a load skip is a comparison the shadow limiter dropped (`shadow_timeout` after
/// 10 s, or `shadow_skipped_busy`), logged with `handler=` instead of `route=`.
fn shadow_counts_at_least(home: &Path, route: &str, n: usize) -> (usize, usize, usize) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let handler = format!("handler=\"{route}\"");
    loop {
        let (m, mm) = shadow_counts(home, route);
        let route_tag = format!("route=\"{route}\"");
        let skips = log(home)
            .lines()
            .filter(|l| {
                (l.contains(&handler)
                    && (l.contains("shadow_timeout") || l.contains("shadow_skipped_busy")))
                    || (l.contains(&route_tag) && l.contains("outcome=\"declined\""))
            })
            .count();
        if m + mm + skips >= n || Instant::now() > deadline {
            return (m, mm, skips);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// (matches, mismatches) among the shadow log lines for `route`, declines excluded; prints
/// mismatching lines.
fn shadow_counts(home: &Path, route: &str) -> (usize, usize) {
    std::thread::sleep(Duration::from_millis(300));
    let l = log(home);
    let tags = [format!("route=\"{route}\""), format!("tag=\"{route}\"")];
    let shadow: Vec<&str> = l
        .lines()
        .filter(|l| l.contains("rust shadow") && tags.iter().any(|t| l.contains(t)))
        .filter(|l| !l.contains("outcome=\"declined\""))
        .collect();
    let mismatches = shadow.iter().filter(|l| !l.contains("\"match\"")).count();
    for s in shadow.iter().filter(|l| !l.contains("\"match\"")) {
        println!("{s}");
    }
    (shadow.len() - mismatches, mismatches)
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn machine_descriptor_shadow_matches_node() {
    let Some((d, base, home, _)) = start("machine") else {
        return;
    };
    let url = format!("{base}/.well-known/vekrel/machine");
    let get = |n: usize| {
        for _ in 0..n {
            let (code, body) = curl(&[&url]);
            assert_eq!(code, 200);
            assert!(body.starts_with(r#"{"machineId":""#), "{body}");
        }
    };
    get(9);
    // Node's headers, which serve mode copies (besides length and date).
    let (_, raw) = curl(&["-D", "-", "-o", "/dev/null", &url]);
    let raw = raw.to_ascii_lowercase();
    for h in [
        "content-type: application/json",
        "vary: accept-encoding",
        "access-control-allow-origin: *",
    ] {
        assert!(raw.contains(h), "{h} missing:\n{raw}");
    }
    // agentActivityPublishing is read per request: turn it on with a relay that never resolves.
    let secrets = home.join("userdata/secrets");
    for (n, v) in [
        ("cloud-publish-agent-activity", "true"),
        ("cloud-relay-url", "wss://relay.invalid"),
        ("cloud-relay-machine-credential", "test-credential"),
    ] {
        std::fs::write(secrets.join(format!("{n}.bin")), v).unwrap();
    }
    let (_, body) = curl(&[&url]);
    assert!(body.contains(r#""agentActivityPublishing":true"#), "{body}");
    get(9);
    let (matches, mismatches, skips) =
        shadow_counts_at_least(&home, "GET /.well-known/vekrel/machine", 20);
    println!(
        "machine shadow log: {matches} match, {mismatches} mismatch, {skips} declined/skipped"
    );
    assert_eq!(mismatches, 0);
    // Under load Rust may still be loading the descriptor (declined) or the limiter may drop a
    // comparison; both are logged, so every request has exactly one outcome.
    assert_eq!(matches + skips, 20, "every request has a logged outcome");
    assert!(matches >= 10, "most requests compared");
    drop(d);
    assert!(!home.exists());
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn auth_session_shadow_matches_node() {
    let Some((d, base, home, token)) = start("auth") else {
        return;
    };
    let url = format!("{base}/api/auth/session");

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
            (f.len() == 7 && f[5].starts_with("vekrel_session"))
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
            vec![cookie.clone(), format!("origin: {base}")],
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

    let (matches, mismatches) = shadow_counts(&home, "GET /api/auth/session");
    println!("shadow log: {matches} match, {mismatches} mismatch");
    assert_eq!(mismatches, 0);
    assert_eq!(matches, 9, "every request compared");
    drop(d);
    assert!(!home.exists());
}

/// Pairs with the printed token; returns the `cookie:` header value for the session.
fn pair(base: &str, home: &Path, token: &str) -> String {
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
    std::fs::read_to_string(&jar)
        .unwrap()
        .lines()
        .filter_map(|l| {
            let f: Vec<_> = l.split('\t').collect();
            (f.len() == 7 && f[5].starts_with("vekrel_session"))
                .then(|| format!("{}={}", f[5], f[6]))
        })
        .next()
        .expect("session cookie")
}

const CHROME: &str = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn read_file_shadow_matches_node() {
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

    // The engine runs in <home>/ws (its cwd) with HOME=<home>/fakehome.
    let Some((d, base, home, token)) = start_with("readfile", |home, cmd| {
        let w = |rel: &str, bytes: &[u8]| std::fs::write(home.join(rel), bytes).unwrap();
        for dir in ["ws/sub", "out", "fakehome"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        w("ws/small.txt", b"hello\n");
        w(r"ws/a\b", b"one file\n");
        w("out/secret.txt", b"top secret\n");
        w("fakehome/x.txt", b"home file\n");
        w("ws/nul.bin", b"a\0b");
        w("ws/bom.txt", b"\xef\xbb\xbfhi");
        w(
            "ws/invalid.txt",
            b"ok\xff\xfe\x80 \xc3\x28 \xe2\x82 \xf0\x9f\x98 end",
        );
        let mib = 1024 * 1024;
        let mut big = vec![b'a'; mib - 1];
        big.extend("é".as_bytes());
        big.extend(vec![b'b'; mib]);
        w("ws/big.txt", &big);
        let mut big4 = vec![b'a'; mib - 2];
        big4.extend("😀".as_bytes());
        big4.extend(vec![b'z'; 100]);
        w("ws/big4.txt", &big4);
        w("ws/exact.txt", &vec![b'c'; mib]);
        #[cfg(unix)]
        for (to, at) in [
            ("../out/secret.txt", "link"),
            ("nowhere", "dangling"),
            ("../out", "outdir"),
        ] {
            std::os::unix::fs::symlink(to, home.join("ws").join(at)).unwrap();
        }
        cmd.current_dir(home.join("ws"))
            .env("HOME", home.join("fakehome"));
    }) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let ws = home.join("ws").to_string_lossy().into_owned();
    let out = home.join("out").to_string_lossy().into_owned();
    let p = |rel: &str| json!({"cwd": ws, "relativePath": rel});
    let allow = |rel: &str| json!({"cwd": ws, "relativePath": rel, "allowMissing": true});
    let cases: Vec<(&str, Value)> = vec![
        ("t3.json allowMissing", allow("t3.json")),
        ("small", p("small.txt")),
        (
            "padded",
            json!({"cwd": format!(" {ws} "), "relativePath": "  ./sub/../small.txt  "}),
        ),
        ("2 MiB, split 2-byte char", p("big.txt")),
        ("split 4-byte char", p("big4.txt")),
        ("exactly 1 MiB", p("exact.txt")),
        ("bom", p("bom.txt")),
        ("invalid utf-8", p("invalid.txt")),
        ("nul byte", p("nul.bin")),
        ("../outside", p("../out/secret.txt")),
        (".", p(".")),
        ("symlink escape", p("link")),
        ("missing through escaping dir", allow("outdir/nope")),
        ("absolute outside", p(&format!("{out}/secret.txt"))),
        (
            "absolute missing allowMissing",
            allow(&format!("{out}/nope")),
        ),
        ("absolute missing", p(&format!("{out}/nope"))),
        ("~/x", p("~/x.txt")),
        ("missing", p("t3.json")),
        ("deep missing allowMissing", allow("a/b/c.txt")),
        ("dangling allowMissing", allow("dangling")),
        ("ENOTDIR allowMissing", allow("small.txt/x")),
        ("directory", p("sub")),
        (
            "cwd missing",
            json!({"cwd": format!("{ws}-nope"), "relativePath": "x.txt"}),
        ),
        (
            "cwd relative",
            json!({"cwd": ".", "relativePath": "small.txt"}),
        ),
        ("network path", p("//host/x")),
        (r"..\x", p(r"..\x")),
        (r"a\b", p(r"a\b")),
        // Node answers these with a Die or an errno-less TypeError: Rust declines.
        ("NUL in path", p("a\u{0}b")),
        ("blank path", p("  ")),
    ];
    let port = base.rsplit(':').next().unwrap().to_owned();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let exits = rt.block_on(async {
        let mut req = format!("ws://127.0.0.1:{port}/ws?orchestrationProtocol=2")
            .into_client_request()
            .unwrap();
        req.headers_mut().insert("cookie", cookie.parse().unwrap());
        let (mut c, _) = tokio_tungstenite::connect_async(req).await.expect("ws");
        for (i, (_, payload)) in cases.iter().enumerate() {
            let m = json!({"_tag":"Request","id":1000 + i,"tag":"projects.readFile","payload":payload,"headers":[]});
            c.send(Message::text(m.to_string())).await.unwrap();
        }
        let mut exits = std::collections::BTreeMap::new();
        while exits.len() < cases.len() {
            let msg = tokio::time::timeout(Duration::from_secs(20), c.next()).await;
            let Ok(Some(Ok(Message::Text(t)))) = msg else {
                panic!("no frame: {msg:?}")
            };
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            for m in v.as_array().cloned().unwrap_or(vec![v]) {
                if m["_tag"] == "Exit" && m["requestId"].as_u64().is_some_and(|i| i >= 1000) {
                    exits.insert(m["requestId"].as_u64().unwrap() - 1000, m["exit"].clone());
                }
            }
        }
        exits
    });
    for (i, (what, _)) in cases.iter().enumerate() {
        let e = &exits[&(i as u64)];
        let outcome = match e["_tag"].as_str() {
            Some("Success") => "Success".to_owned(),
            _ => format!("Failure {}", e["cause"][0]["error"]["failure"]),
        };
        println!("{what}: {outcome}");
    }
    assert_eq!(exits[&0]["value"]["exists"], false);
    let (matches, mismatches) = shadow_counts(&home, "projects.readFile");
    println!("raw client: {matches} match, {mismatches} mismatch");
    assert_eq!(mismatches, 0);
    let declines = declined(&home, "projects.readFile");
    println!("raw client: {declines} declined");
    assert_eq!(declines, 2);
    assert_eq!(matches, cases.len() - 2, "every other request compared");

    // A browser boot asks for `t3.json` on its own; pair it with a second token.
    if !Path::new(CHROME).exists() {
        println!("Chrome missing; skipped the browser boot");
    } else {
        let (code, body) = curl(&[
            "-X",
            "POST",
            "-H",
            &format!("cookie: {cookie}"),
            "-H",
            "content-type: application/json",
            "-d",
            "{}",
            &format!("{base}/api/auth/pairing-token"),
        ]);
        assert_eq!(code, 200, "{body}");
        let cred: Value = serde_json::from_str(&body).unwrap();
        let cred = cred["credential"].as_str().unwrap();
        let profile = home.join("chrome");
        let mut chrome = Command::new(CHROME)
            .args(["--headless=new", "--disable-gpu", "--no-first-run"])
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg("--remote-debugging-port=0")
            .arg(format!("{base}/pair#token={cred}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(45);
        while shadow_counts(&home, "projects.readFile").0
            + shadow_counts(&home, "projects.readFile").1
            <= cases.len() - 2
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(500));
        }
        let _ = chrome.kill();
        let _ = chrome.wait();
        let (m, mm) = shadow_counts(&home, "projects.readFile");
        println!("after browser boot: {m} match, {mm} mismatch");
        assert_eq!(mm, 0);
        assert!(
            m > cases.len() - 2,
            "the browser boot sent projects.readFile"
        );
    }
    drop(d);
    assert!(!home.exists());
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn browse_shadow_matches_node() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

    // The engine's `os.homedir()` is this temp dir, filled with the add-project flow's tricky names.
    let Some((d, base, home, token)) = start_with("browse", |h, cmd| {
        std::fs::create_dir_all(h.join("home")).unwrap();
        cmd.env("HOME", h.join("home"));
    }) else {
        return;
    };
    let tree = home.join("home").canonicalize().unwrap();
    for n in [
        "Alpha",
        "beta",
        "Ébauche",
        "école",
        "10-ten",
        "2-two",
        "_under",
        "-dash",
        ".dot",
        ".Hidden",
        "🎉 party",
        "naïve",
        "Zeta",
        "ünïcödé",
        "Ωmega",
        "Жук",
        "İstanbul",
        "ΟΔΟΣ",
        "Straße",
        "a b",
        "locked",
        "han",
        "Alpha/inner",
    ] {
        std::fs::create_dir_all(tree.join(n)).unwrap();
    }
    std::fs::create_dir(tree.join("han/不")).unwrap();
    std::fs::write(tree.join("file.txt"), "").unwrap();
    std::os::unix::fs::symlink(tree.join("beta"), tree.join("link-dir")).unwrap();
    // Unlocked on drop (before the home is deleted), even on panic.
    struct Locked(PathBuf);
    impl Drop for Locked {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }
    use std::os::unix::fs::PermissionsExt;
    let locked = Locked(tree.join("locked"));
    std::fs::set_permissions(&locked.0, std::fs::Permissions::from_mode(0o000)).unwrap();

    let t = tree.to_str().unwrap();
    let mut answered: Vec<serde_json::Value> = [
        "~",
        "~/",
        " ~/ ",
        "~/a",
        "~/A",
        "~/É",
        "~/é",
        "~/.",
        "~/.h",
        "~/1",
        "~/🎉",
        "~/z",
        "~/Ж",
        "~/i",
        "~/İ",
        "~/ΟΔ",
        "~/οδοσ",
        "~/straß",
        "~/a ",
        "/",
        "/U",
    ]
    .iter()
    .map(|p| serde_json::json!({"partialPath": p}))
    .collect();
    for p in ["/", "/na", "/locked/", "/Alpha/"] {
        answered.push(serde_json::json!({"partialPath": format!("{t}{p}")}));
    }
    answered.push(serde_json::json!({"partialPath": "./", "cwd": t}));
    answered.push(serde_json::json!({"partialPath": "../", "cwd": format!("{t}/Alpha")}));
    // Node answers these alone: errors, a Han name, a path relative to Node's cwd.
    let declined: Vec<serde_json::Value> = [
        format!("{t}/missing/"),
        format!("{t}/han/"),
        format!("{t}/file.txt/"),
        "C:\\Users".into(),
        "./x".into(),
        "relative".into(),
    ]
    .into_iter()
    .map(|p| serde_json::json!({"partialPath": p}))
    .collect();

    let cookie = pair(&base, &home, &token);
    let ws = base.replace("http://", "ws://") + "/ws?orchestrationProtocol=2";
    let rt = tokio::runtime::Runtime::new().unwrap();
    let replies = rt.block_on(async {
        let mut req = ws.into_client_request().unwrap();
        let h = req.headers_mut();
        h.insert("cookie", cookie.parse().unwrap());
        h.insert("origin", base.parse().unwrap());
        let (mut c, _) = tokio_tungstenite::connect_async(req).await.expect("ws");
        let all: Vec<_> = answered.iter().chain(&declined).collect();
        let mut replies = Vec::new();
        for (id, payload) in all.iter().enumerate() {
            let r = serde_json::json!({"_tag":"Request","id":id,"tag":"filesystem.browse",
                "payload":payload,"traceId":"0123456789abcdef0123456789abcdef",
                "spanId":"0123456789abcdef","sampled":true,"headers":[]});
            c.send(Message::text(r.to_string())).await.unwrap();
            loop {
                let m = tokio::time::timeout(Duration::from_secs(10), c.next())
                    .await
                    .expect("reply")
                    .unwrap()
                    .unwrap();
                let Message::Text(t) = m else { continue };
                let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
                if v["_tag"] == "Exit" && v["requestId"] == id {
                    replies.push(v["exit"]["_tag"].as_str().unwrap().to_owned());
                    break;
                }
            }
        }
        replies
    });
    // Every request got Node's answer; the answered ones succeed.
    assert_eq!(replies.len(), answered.len() + declined.len());
    assert!(
        replies[..answered.len()].iter().all(|r| r == "Success"),
        "{replies:?}"
    );

    std::thread::sleep(Duration::from_millis(300));
    let l = log(&home);
    let lines: Vec<&str> = l
        .lines()
        .filter(|l| {
            (l.contains("rust shadow") || l.contains("rust handler declined"))
                && l.contains("tag=\"filesystem.browse\"")
        })
        .collect();
    let count = |o: &str| {
        lines
            .iter()
            .filter(|l| l.contains(&format!("outcome=\"{o}\"")))
            .count()
    };
    let (matches, mismatches, declines) = (count("match"), count("mismatch"), count("declined"));
    for m in lines.iter().filter(|l| l.contains("mismatch")) {
        println!("{m}");
    }
    println!(
        "browse shadow log: {matches} match, {mismatches} mismatch, {declines} declined (of {} requests)",
        replies.len()
    );
    assert_eq!(mismatches, 0);
    assert_eq!(matches, answered.len(), "every answerable request compared");
    assert_eq!(declines, declined.len());
    drop(locked);
    drop(d);
    assert!(!home.exists());
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn unsupported_engine_flag_defers_served_rpcs_to_node() {
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

    // `--host` is a flag Rust cannot reproduce, so it verifies no WS session; readFile in serve.
    let Some((d, base, home, token)) = start_with("unsupported", |home, cmd| {
        let cfg = home.join("vekrel.toml");
        let t = std::fs::read_to_string(&cfg).unwrap();
        let t = t
            .replacen("bin.mjs\"]", "bin.mjs\", \"--host\", \"127.0.0.1\"]", 1)
            .replace(
                "\"projects.readFile\" = \"shadow\"",
                "\"projects.readFile\" = \"serve\"",
            );
        assert!(t.contains("--host") && t.contains("= \"serve\""), "{t}");
        std::fs::write(&cfg, t).unwrap();
        std::fs::create_dir_all(home.join("ws")).unwrap();
        std::fs::write(home.join("ws/small.txt"), b"hello\n").unwrap();
        cmd.current_dir(home.join("ws"));
    }) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let port = base.rsplit(':').next().unwrap().to_owned();
    let ws = home.join("ws").to_string_lossy().into_owned();
    let exit = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mut req = format!("ws://127.0.0.1:{port}/ws?orchestrationProtocol=2")
            .into_client_request()
            .unwrap();
        req.headers_mut().insert("cookie", cookie.parse().unwrap());
        let (mut c, _) = tokio_tungstenite::connect_async(req).await.expect("ws");
        let m = json!({"_tag":"Request","id":7,"tag":"projects.readFile",
            "payload":{"cwd": ws, "relativePath": "small.txt"},"headers":[]});
        c.send(Message::text(m.to_string())).await.unwrap();
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(20), c.next()).await;
            let Ok(Some(Ok(Message::Text(t)))) = msg else {
                panic!("no frame: {msg:?}")
            };
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            if let Some(m) = v
                .as_array()
                .cloned()
                .unwrap_or(vec![v])
                .into_iter()
                .find(|m| m["_tag"] == "Exit" && m["requestId"] == 7)
            {
                break m["exit"].clone();
            }
        }
    });
    println!("readFile with --host: {exit}");
    assert_eq!(exit["_tag"], "Success", "Node answered, not a Rust denial");
    let l = log(&home);
    assert!(l.contains("deferred_unverifiable_credential"), "{l}");
    drop(d);
    assert!(!home.exists());
}

/// `wsTicket` upgrades: Rust's verdict log must match Node's 101/401, and a readFile on a ticket
/// socket is served by Rust (`projects.readFile` in serve; not deferred).
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn ws_ticket_verdicts_match_node() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use futures_util::{SinkExt, StreamExt};
    use hmac::{Hmac, KeyInit, Mac};
    use serde_json::{Value, json};
    use tokio_tungstenite::tungstenite::{Error as WsError, Message};

    let Some((d, base, home, token)) = start_with("wsticket", |home, cmd| {
        let cfg = home.join("vekrel.toml");
        let t = std::fs::read_to_string(&cfg).unwrap().replace(
            "\"projects.readFile\" = \"shadow\"",
            "\"projects.readFile\" = \"serve\"",
        );
        std::fs::write(&cfg, t).unwrap();
        std::fs::create_dir_all(home.join("ws")).unwrap();
        std::fs::write(home.join("ws/small.txt"), b"hello\n").unwrap();
        cmd.current_dir(home.join("ws"));
    }) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let (code, body) = curl(&[
        "-X",
        "POST",
        "-H",
        &format!("cookie: {cookie}"),
        &format!("{base}/api/auth/websocket-ticket"),
    ]);
    assert_eq!(code, 200, "{body}");
    let issued: Value = serde_json::from_str(&body).unwrap();
    let ticket = issued["ticket"].as_str().unwrap().to_owned();

    // Tampered: a different payload under Node's signature.
    let (enc, sig) = ticket.split_once('.').unwrap();
    let mut claims: Value = serde_json::from_slice(&B64.decode(enc).unwrap()).unwrap();
    claims["exp"] = json!(claims["exp"].as_i64().unwrap() + 1);
    let tampered = format!("{}.{sig}", B64.encode(claims.to_string()));
    // Expired: Node exposes no TTL hook, so mint one Node-style with the engine's own key.
    let key = std::fs::read(home.join("userdata/secrets/server-signing-key.bin")).unwrap();
    let past = claims["iat"].as_i64().unwrap() - 600_000;
    let json = format!(
        r#"{{"v":1,"kind":"websocket","sid":{},"iat":{past},"exp":{}}}"#,
        claims["sid"],
        past + 300_000
    );
    let enc = B64.encode(json);
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
    mac.update(enc.as_bytes());
    let expired = format!("{enc}.{}", B64.encode(mac.finalize().into_bytes()));

    let port = base.rsplit(':').next().unwrap().to_owned();
    let ws = home.join("ws").to_string_lossy().into_owned();
    let url = |t: &str| format!("ws://127.0.0.1:{port}/ws?wsTicket={t}&orchestrationProtocol=2");
    let exit = tokio::runtime::Runtime::new().unwrap().block_on(async {
        for (what, t) in [("tampered", &tampered), ("expired", &expired)] {
            match tokio_tungstenite::connect_async(url(t)).await {
                Err(WsError::Http(r)) => assert_eq!(r.status(), 401, "{what}"),
                other => panic!("{what}: {:?}", other.map(|_| ())),
            }
        }
        let (mut c, res) = tokio_tungstenite::connect_async(url(&ticket))
            .await
            .expect("valid ticket upgrades");
        assert_eq!(res.status(), 101);
        let m = json!({"_tag":"Request","id":7,"tag":"projects.readFile",
            "payload":{"cwd": ws, "relativePath": "small.txt"},"headers":[]});
        c.send(Message::text(m.to_string())).await.unwrap();
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(20), c.next()).await;
            let Ok(Some(Ok(Message::Text(t)))) = msg else {
                panic!("no frame: {msg:?}")
            };
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            if let Some(m) = v
                .as_array()
                .cloned()
                .unwrap_or(vec![v])
                .into_iter()
                .find(|m| m["_tag"] == "Exit" && m["requestId"] == 7)
            {
                break m["exit"].clone();
            }
        }
    });
    println!("readFile on a ticket socket: {exit}");
    assert_eq!(exit["_tag"], "Success");
    std::thread::sleep(Duration::from_millis(300));
    let l = log(&home);
    let verdicts: Vec<&str> = l
        .lines()
        .filter(|l| l.contains("ws ticket verdict"))
        .collect();
    for v in &verdicts {
        println!("{v}");
    }
    let has = |s: &str| verdicts.iter().filter(|l| l.contains(s)).count();
    assert_eq!(verdicts.len(), 3, "{verdicts:?}");
    assert_eq!(has("outcome=\"match\""), 3, "{verdicts:?}");
    assert_eq!(has("rust=\"verified\" node=101"), 1);
    assert_eq!(has("rust=\"bad_signature\" node=401"), 1);
    assert_eq!(has("rust=\"ticket_expired\" node=401"), 1);
    assert!(!l.contains("deferred_unverifiable_credential"), "{l}");
    drop(d);
    assert!(!home.exists());
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn ws_ticket_issue_shadow_matches_and_node_accepts_rust_tickets() {
    const ROUTE: &str = "POST /api/auth/websocket-ticket";
    let with_mode = |mode: &'static str| {
        move |home: &Path, _: &mut Command| {
            let cfg = home.join("vekrel.toml");
            let t = std::fs::read_to_string(&cfg).unwrap();
            std::fs::write(&cfg, format!("{t}\"{ROUTE}\" = \"{mode}\"\n")).unwrap();
        }
    };
    let ticket_req = |base: &str, cookie: Option<&str>| {
        let c = cookie.map(|c| format!("cookie: {c}"));
        let mut a = vec!["-D", "-", "-X", "POST"];
        if let Some(c) = &c {
            a.extend(["-H", c.as_str()]);
        }
        let url = format!("{base}/api/auth/websocket-ticket");
        a.push(&url);
        let (code, out) = curl(&a);
        let (head, body) = out.split_once("\r\n\r\n").unwrap();
        (code, head.to_ascii_lowercase(), body.to_owned())
    };

    // Shadow: Node answers, Rust issues its own ticket alongside; no mismatches.
    let Some((d, base, home, token)) = start_with("wsissue-shadow", with_mode("shadow")) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let (code, _, body) = ticket_req(&base, None);
    assert_eq!(code, 401, "{body}");
    for _ in 0..3 {
        let (code, head, body) = ticket_req(&base, Some(&cookie));
        assert_eq!(code, 200, "{body}");
        assert!(!head.contains("x-vekrel-served-by"), "{head}");
    }
    let (matches, mismatches) = shadow_counts(&home, ROUTE);
    println!("shadow: {matches} match, {mismatches} mismatch");
    assert_eq!((matches, mismatches), (4, 0));
    drop(d);
    assert!(!home.exists());

    // Serve: Rust's ticket opens Node's own `/ws` (engine port, bypassing Rust).
    let Some((d, base, home, token)) = start_with("wsissue-serve", with_mode("serve")) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let (code, head, body) = ticket_req(&base, Some(&cookie));
    assert_eq!(code, 200, "{body}");
    assert!(head.contains("x-vekrel-served-by: rust"), "{head}");
    assert!(head.contains("cache-control: no-store") && head.contains("pragma: no-cache"));
    let ticket = serde_json::from_str::<serde_json::Value>(&body).unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    let cfg = std::fs::read_to_string(home.join("vekrel.toml")).unwrap();
    let engine = cfg
        .split("[engine]")
        .nth(1)
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("port = ")))
        .unwrap()
        .to_owned();
    let url = format!("ws://127.0.0.1:{engine}/ws?wsTicket={ticket}&orchestrationProtocol=2");
    let status = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(tokio_tungstenite::connect_async(url))
        .expect("Node accepts Rust's ticket")
        .1
        .status();
    println!("Node /ws with Rust ticket: {status}");
    assert_eq!(status, 101);
    drop(d);
    assert!(!home.exists());
}

/// An ES256 DPoP proof (`dsaEncoding: "ieee-p1363"`), with `ath` when `token` is given.
fn dpop_proof(key: &p256::ecdsa::SigningKey, htm: &str, htu: &str, token: Option<&str>) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use p256::ecdsa::{Signature, signature::Signer};
    use sha2::Digest;
    static JTI: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let p = key.verifying_key().to_sec1_point(false);
    let b = p.as_bytes();
    let (x, y) = (B64.encode(&b[1..33]), B64.encode(&b[33..65]));
    let h = format!(
        r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}}}"#
    );
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let jti = format!(
        "live-{}",
        JTI.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let ath = token.map_or(String::new(), |t| {
        format!(
            r#","ath":"{}""#,
            B64.encode(sha2::Sha256::digest(t.as_bytes()))
        )
    });
    let pl = format!(r#"{{"htm":"{htm}","htu":"{htu}","jti":"{jti}","iat":{iat}{ath}}}"#);
    let hp = format!("{}.{}", B64.encode(h), B64.encode(pl));
    let sig: Signature = key.sign(hp.as_bytes());
    format!("{hp}.{}", B64.encode(sig.to_bytes()))
}

/// A native client pairs through `/oauth/token` with a DPoP key (Node answers), then uses the
/// DPoP token through Rust: `GET /api/auth/session` in shadow, `/ws` with DPoP in serve.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn dpop_native_client_through_rust() {
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use tokio_tungstenite::tungstenite::{Error as WsError, Message, client::IntoClientRequest};

    let Some((d, base, home, pairing)) = start_with("dpop", |home, cmd| {
        let cfg = home.join("vekrel.toml");
        let t = std::fs::read_to_string(&cfg).unwrap().replace(
            "\"projects.readFile\" = \"shadow\"",
            "\"projects.readFile\" = \"serve\"\n\"GET /ws dpop\" = \"serve\"",
        );
        std::fs::write(&cfg, t).unwrap();
        std::fs::create_dir_all(home.join("ws")).unwrap();
        std::fs::write(home.join("ws/small.txt"), b"hello\n").unwrap();
        cmd.current_dir(home.join("ws"));
    }) else {
        return;
    };
    let cfg = std::fs::read_to_string(home.join("vekrel.toml")).unwrap();
    let engine = cfg
        .split("[engine]")
        .nth(1)
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("port = ")))
        .unwrap()
        .to_owned();
    let port = base.rsplit(':').next().unwrap().to_owned();
    let internal = format!("http://127.0.0.1:{engine}");
    let key = p256::ecdsa::SigningKey::from_slice(&[11; 32]).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let http = reqwest::Client::new();
    let markers = || {
        std::fs::read_dir(home.join("userdata/secrets"))
            .unwrap()
            .filter(|e| {
                let n = e.as_ref().unwrap().file_name();
                n.to_str().unwrap().starts_with("dpop-proof-")
            })
            .count()
    };

    // 1. Pairing with a proof for the URL the client used: Node (behind the proxy) rejects it.
    let exchange = |htu: String| {
        let form = [
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", pairing.as_str()),
            (
                "subject_token_type",
                "urn:t3:params:oauth:token-type:machine-bootstrap",
            ),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("client_label", "live dpop"),
        ];
        let req = http
            .post(format!("{base}/oauth/token"))
            .header("dpop", dpop_proof(&key, "POST", &htu, None))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(form)
                    .finish(),
            );
        rt.block_on(async {
            let r = req.send().await.unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        })
    };
    let (s, body) = exchange(format!("{base}/oauth/token"));
    println!("oauth/token, proof for the public URL: {s} {body}");
    assert_eq!(s, 401, "{body}");
    assert!(
        body.contains(r#""dpopFailureReason":"request_mismatch""#),
        "{body}"
    );
    // ... and accepts one for the engine's internal URL.
    let (s, body) = exchange(format!("{internal}/oauth/token"));
    println!("oauth/token, proof for the internal URL: {s} {body}");
    assert_eq!(s, 200, "{body}");
    let issued: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(issued["token_type"], "DPoP");
    let token = issued["access_token"].as_str().unwrap().to_owned();
    let before = markers();

    // 2. Shadow `GET /api/auth/session`: (proof URL, Node's answer).
    let session = |htu: String| {
        let req = http
            .get(format!("{base}/api/auth/session"))
            .header("authorization", format!("DPoP {token}"))
            .header("dpop", dpop_proof(&key, "GET", &htu, Some(&token)));
        rt.block_on(async {
            let r = req.send().await.unwrap();
            let v: Value = r.json().await.unwrap();
            v["authenticated"].as_bool().unwrap()
        })
    };
    let public_ok = session(format!("{base}/api/auth/session"));
    let internal_ok = session(format!("{internal}/api/auth/session"));
    println!(
        "session (shadow): Node says public-URL proof={public_ok}, internal-URL proof={internal_ok}"
    );
    assert!(!public_ok && internal_ok);
    std::thread::sleep(Duration::from_millis(500));
    let l = log(&home);
    let shadow: Vec<&str> = l
        .lines()
        .filter(|l| l.contains("rust shadow") && l.contains("GET /api/auth/session"))
        .collect();
    for s in &shadow {
        println!("{s}");
    }
    assert_eq!(shadow.len(), 2, "{shadow:?}");
    assert!(shadow[0].contains("outcome=\"node_htu_host_mismatch\""));
    assert!(shadow[1].contains("outcome=\"mismatch\""));
    assert_eq!(
        markers(),
        before + 1,
        "only Node's own consumed proof; shadow writes none"
    );

    // 3. `/ws` with DPoP (serve): Rust consumes the public-URL proof and opens Node's socket with
    //    a ticket; `projects.readFile` is answered by Rust. The same proof again is a replay.
    let ws = home.join("ws").to_string_lossy().into_owned();
    let proof = dpop_proof(
        &key,
        "GET",
        &format!("http://127.0.0.1:{port}/ws"),
        Some(&token),
    );
    let upgrade = || {
        let mut req = format!("ws://127.0.0.1:{port}/ws?orchestrationProtocol=2")
            .into_client_request()
            .unwrap();
        req.headers_mut()
            .insert("authorization", format!("DPoP {token}").parse().unwrap());
        req.headers_mut().insert("dpop", proof.parse().unwrap());
        req
    };
    let exit = rt.block_on(async {
        let (mut c, res) = tokio_tungstenite::connect_async(upgrade())
            .await
            .expect("DPoP upgrade");
        assert_eq!(res.status(), 101);
        let m = json!({"_tag":"Request","id":7,"tag":"projects.readFile",
            "payload":{"cwd": ws, "relativePath": "small.txt"},"headers":[]});
        c.send(Message::text(m.to_string())).await.unwrap();
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(20), c.next()).await;
            let Ok(Some(Ok(Message::Text(t)))) = msg else {
                panic!("no frame: {msg:?}")
            };
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            if let Some(m) = v
                .as_array()
                .cloned()
                .unwrap_or(vec![v])
                .into_iter()
                .find(|m| m["_tag"] == "Exit" && m["requestId"] == 7)
            {
                break m["exit"].clone();
            }
        }
    });
    println!("readFile on a DPoP socket: {exit}");
    assert_eq!(exit["_tag"], "Success");
    let replay = rt.block_on(tokio_tungstenite::connect_async(upgrade()));
    match replay {
        Err(WsError::Http(r)) => {
            let body =
                String::from_utf8_lossy(r.body().as_deref().unwrap_or_default()).into_owned();
            println!("replayed DPoP upgrade: {} {body}", r.status());
            assert_eq!(r.status(), 401);
        }
        other => panic!("replay: {:?}", other.map(|_| ())),
    }
    std::thread::sleep(Duration::from_millis(300));
    let l = log(&home);
    let verdicts: Vec<&str> = l
        .lines()
        .filter(|l| l.contains("ws dpop verdict"))
        .collect();
    for v in &verdicts {
        println!("{v}");
    }
    assert_eq!(verdicts.len(), 2, "{verdicts:?}");
    assert!(verdicts[0].contains("rust=\"verified\" node=101 outcome=\"match\""));
    assert!(verdicts[1].contains("rust=\"replay\" node=401 outcome=\"match\""));
    assert!(!l.contains("deferred_unverifiable_credential"), "{l}");
    drop(d);
    assert!(!home.exists());
}

// ---- subscribeAuthAccess ----

/// `applyAuthAccessStreamEvent` from Vekrel-Web `packages/client-runtime/src/state/auth.ts`:
/// a snapshot replaces, upserts replace by key (appending), removes filter by key.
fn apply_auth_event(state: &mut serde_json::Value, e: &serde_json::Value) {
    let upsert = |list: &mut serde_json::Value, key: &str, v: &serde_json::Value| {
        let a = list.as_array_mut().unwrap();
        a.retain(|x| x[key] != v[key]);
        a.push(v.clone());
    };
    let p = &e["payload"];
    match e["type"].as_str().unwrap() {
        "snapshot" => *state = p.clone(),
        "pairingLinkUpserted" => upsert(&mut state["pairingLinks"], "id", p),
        "pairingLinkRemoved" => state["pairingLinks"]
            .as_array_mut()
            .unwrap()
            .retain(|x| x["id"] != p["id"]),
        "clientUpserted" => upsert(&mut state["clientSessions"], "sessionId", p),
        "clientRemoved" => state["clientSessions"]
            .as_array_mut()
            .unwrap()
            .retain(|x| x["sessionId"] != p["sessionId"]),
        t => panic!("unknown event {t}"),
    }
}

/// `list` sorted by `key`, for order-free comparison.
fn by_key(list: &serde_json::Value, key: &str) -> Vec<serde_json::Value> {
    let mut v = list.as_array().unwrap().clone();
    v.sort_by_key(|x| x[key].as_str().unwrap().to_owned());
    v
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn auth_ws(port: &str, cookie: &str) -> Ws {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("ws://127.0.0.1:{port}/ws?orchestrationProtocol=2")
        .into_client_request()
        .unwrap();
    req.headers_mut().insert("cookie", cookie.parse().unwrap());
    tokio_tungstenite::connect_async(req).await.unwrap().0
}

/// Subscribes on `c` with request id `id`; returns the first Chunk's raw `values` text.
async fn subscribe_first_chunk(c: &mut Ws, id: u64) -> String {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let req = serde_json::json!({"_tag":"Request","id":id,"tag":"subscribeAuthAccess","payload":{},"headers":[]});
    c.send(Message::text(req.to_string())).await.unwrap();
    loop {
        let m = tokio::time::timeout(Duration::from_secs(20), c.next()).await;
        let Ok(Some(Ok(Message::Text(t)))) = m else {
            panic!("no frame: {m:?}")
        };
        let t = t.as_str();
        #[derive(serde::Deserialize)]
        struct F<'a> {
            #[serde(rename = "_tag")]
            tag: &'a str,
            #[serde(rename = "requestId")]
            id: Option<u64>,
            #[serde(borrow)]
            values: Option<&'a serde_json::value::RawValue>,
        }
        if let Ok(f) = serde_json::from_str::<F>(t)
            && f.tag == "Chunk"
            && f.id == Some(id)
        {
            let ack = format!(r#"{{"_tag":"Ack","requestId":{id}}}"#);
            c.send(Message::text(ack)).await.unwrap();
            return f.values.unwrap().get().to_owned();
        }
    }
}

fn post(base: &str, cookie: &str, path: &str, body: &str) -> serde_json::Value {
    let (code, out) = curl(&[
        "-X",
        "POST",
        "-H",
        &format!("cookie: {cookie}"),
        "-H",
        "content-type: application/json",
        "-d",
        body,
        &format!("{base}{path}"),
    ]);
    assert_eq!(code, 200, "{path}: {out}");
    serde_json::from_str(&out).unwrap()
}

fn get(base: &str, cookie: &str, path: &str) -> serde_json::Value {
    let (code, out) = curl(&["-H", &format!("cookie: {cookie}"), &format!("{base}{path}")]);
    assert_eq!(code, 200, "{path}: {out}");
    serde_json::from_str(&out).unwrap()
}

/// Every column of every row of `table`, as JSON objects.
fn dump(db: &rusqlite::Connection, table: &str) -> Vec<serde_json::Value> {
    let mut q = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
    let names: Vec<String> = q.column_names().iter().map(|s| s.to_string()).collect();
    q.query_map([], |r| {
        let mut o = serde_json::Map::new();
        for (i, n) in names.iter().enumerate() {
            let v: Option<String> = r.get(i)?;
            o.insert(n.clone(), serde_json::json!(v));
        }
        Ok(serde_json::Value::Object(o))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn auth_access_snapshot_shadow_matches_node() {
    let Some((d, base, home, token)) = start("access-shadow") else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    // Something in each list: a labelled link, a second session (paired from another link).
    post(
        &base,
        &cookie,
        "/api/auth/pairing-token",
        r#"{"label":"Phone"}"#,
    );
    let second = post(&base, &cookie, "/api/auth/pairing-token", "{}");
    let _b = pair(&base, &home, second["credential"].as_str().unwrap());
    post(
        &base,
        &cookie,
        "/api/auth/pairing-token",
        r#"{"scopes":["access:read"]}"#,
    );
    let port = base.rsplit(':').next().unwrap().to_owned();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (node, now, (sessions, mut links)) = rt.block_on(async {
        let mut c = auth_ws(&port, &cookie).await;
        let mut first = String::new();
        for id in 1..=3 {
            first = subscribe_first_chunk(&mut c, id).await;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        // The rows behind that snapshot, before other sockets change `last_connected_at`.
        let db = rusqlite::Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
        let rows = (dump(&db, "auth_sessions"), dump(&db, "auth_pairing_links"));
        // A second socket of the same session, then a socket of the other session.
        let mut c2 = auth_ws(&port, &cookie).await;
        subscribe_first_chunk(&mut c2, 1).await;
        let mut c3 = auth_ws(&port, &_b).await;
        // `_b` has access:read too (standard scopes).
        subscribe_first_chunk(&mut c3, 1).await;
        // Rust's side of the last comparison may still be reading; the sockets must stay open.
        tokio::time::sleep(Duration::from_millis(500)).await;
        (first, now, rows)
    });
    println!("Node's first chunk: {node}");
    let (matches, mismatches) = shadow_counts(&home, "subscribeAuthAccess");
    println!("subscribeAuthAccess shadow: {matches} match, {mismatches} mismatch");
    assert_eq!(mismatches, 0);
    assert_eq!(matches, 5, "every subscription compared");
    if std::env::var_os("VEKREL_WRITE_GOLDEN").is_some() {
        // Node's own snapshot plus the rows it came from: the offline golden.
        let v: serde_json::Value = serde_json::from_str(&node).unwrap();
        let current = v[0]["payload"]["clientSessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["current"] == true)
            .unwrap()["sessionId"]
            .clone();
        for (i, l) in links.iter_mut().enumerate() {
            l["credential"] = serde_json::json!(format!("REDACTED-{i}"));
        }
        let golden = serde_json::json!({
            "now": now,
            "current": current,
            "connected": [current],
            "auth_sessions": sessions,
            "auth_pairing_links": links,
            "node_values": node,
        });
        let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden/auth_access_snapshot.json");
        std::fs::write(&out, serde_json::to_string_pretty(&golden).unwrap() + "\n").unwrap();
        println!("wrote {}", out.display());
    }
    drop(d);
    assert!(!home.exists());
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn auth_access_served_events_converge_to_a_fresh_snapshot() {
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use tokio_tungstenite::tungstenite::Message;

    let Some((d, base, home, token)) = start_with("access-serve", |home, _| {
        let cfg = home.join("vekrel.toml");
        let t = std::fs::read_to_string(&cfg).unwrap() + "\"subscribeAuthAccess\" = \"serve\"\n";
        std::fs::write(&cfg, t).unwrap();
    }) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let port = base.rsplit(':').next().unwrap().to_owned();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut c = rt.block_on(auth_ws(&port, &cookie));
    let first = rt.block_on(subscribe_first_chunk(&mut c, 1));
    let mut state = json!({});
    let mut revisions = vec![];
    for e in serde_json::from_str::<Vec<Value>>(&first).unwrap() {
        revisions.push(e["revision"].as_i64().unwrap());
        apply_auth_event(&mut state, &e);
    }
    // Reads events (acking each Chunk) until `quiet` passes without one.
    let drain = |c: &mut Ws, quiet: Duration, state: &mut Value, revisions: &mut Vec<i64>| {
        rt.block_on(async {
            loop {
                let Ok(m) = tokio::time::timeout(quiet, c.next()).await else {
                    return;
                };
                let Some(Ok(Message::Text(t))) = m else {
                    panic!("socket ended: {m:?}")
                };
                let f: Value = serde_json::from_str(t.as_str()).unwrap();
                if f["requestId"] != 1 {
                    continue;
                }
                assert_eq!(f["_tag"], "Chunk", "{f}");
                for e in f["values"].as_array().unwrap() {
                    revisions.push(e["revision"].as_i64().unwrap());
                    apply_auth_event(state, e);
                }
                c.send(Message::text(r#"{"_tag":"Ack","requestId":1}"#))
                    .await
                    .unwrap();
            }
        })
    };
    let quiet = Duration::from_millis(1500);
    // Node (its HTTP routes): create two links, revoke one, pair a second client with the other.
    let l1 = post(
        &base,
        &cookie,
        "/api/auth/pairing-token",
        r#"{"label":"One"}"#,
    );
    let l2 = post(&base, &cookie, "/api/auth/pairing-token", "{}");
    drain(&mut c, quiet, &mut state, &mut revisions);
    post(
        &base,
        &cookie,
        "/api/auth/pairing-links/revoke",
        &json!({"id": l1["id"]}).to_string(),
    );
    let b = pair(&base, &home, l2["credential"].as_str().unwrap());
    drain(&mut c, quiet, &mut state, &mut revisions);
    // The second client connects (through Rust), then disconnects.
    let mut cb = rt.block_on(auth_ws(&port, &b));
    drain(&mut c, quiet, &mut state, &mut revisions);
    let connected = |s: &Value, cookie_sid: Option<&str>| {
        s["clientSessions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|x| x["connected"] == true)
            .filter(|x| cookie_sid.is_none_or(|id| x["sessionId"] == id))
            .count()
    };
    assert_eq!(connected(&state, None), 2, "{state}");
    rt.block_on(cb.close(None)).unwrap();
    drop(cb);
    drain(&mut c, quiet, &mut state, &mut revisions);
    assert_eq!(connected(&state, None), 1, "{state}");
    // A CLI-style direct SQL writer: a link and a session, then revokes both.
    let db = rusqlite::Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
    db.busy_timeout(Duration::from_secs(5)).unwrap();
    // `toISOString` text, as Node writes it.
    let iso = |ms: i64| {
        db.query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1 / 1000.0, 'unixepoch')",
            [ms],
            |r| r.get::<_, String>(0),
        )
        .unwrap()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    db.execute(
        "INSERT INTO auth_pairing_links (id, credential, method, scopes, subject, label, created_at, expires_at)
         VALUES ('cli-link', 'CLICRED23456', 'one-time-token', '[\"orchestration:read\"]', 'one-time-token', 'CLI', ?1, ?2)",
        [iso(now), iso(now + 300_000)],
    )
    .unwrap();
    db.execute(
        "INSERT INTO auth_sessions (session_id, subject, scopes, method, client_label, client_device_type, issued_at, expires_at)
         VALUES ('cli-session', 'cli', '[\"orchestration:read\"]', 'bearer-access-token', 'CLI bot', 'bot', ?1, ?2)",
        [iso(now), iso(now + 86_400_000)],
    )
    .unwrap();
    drain(&mut c, quiet, &mut state, &mut revisions);
    assert!(
        state["pairingLinks"].to_string().contains("cli-link"),
        "{state}"
    );
    assert!(
        state["clientSessions"].to_string().contains("cli-session"),
        "{state}"
    );
    db.execute(
        "UPDATE auth_pairing_links SET revoked_at = ?1 WHERE id = 'cli-link'",
        [iso(now + 1)],
    )
    .unwrap();
    db.execute(
        "UPDATE auth_sessions SET revoked_at = ?1 WHERE session_id = 'cli-session'",
        [iso(now + 1)],
    )
    .unwrap();
    // Node revokes the second client.
    let b_sid = state["clientSessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["current"] == false && x["sessionId"] != "cli-session")
        .unwrap()["sessionId"]
        .clone();
    post(
        &base,
        &cookie,
        "/api/auth/clients/revoke",
        &json!({"sessionId": b_sid}).to_string(),
    );
    // The test itself (as Rust's writers will): another link straight into the table.
    db.execute(
        "INSERT INTO auth_pairing_links (id, credential, method, scopes, subject, created_at, expires_at)
         VALUES ('test-link', 'TESTCRED2345', 'one-time-token', '[\"access:read\"]', 'one-time-token', ?1, ?2)",
        [iso(now + 2), iso(now + 300_000)],
    )
    .unwrap();
    drain(&mut c, quiet, &mut state, &mut revisions);
    // A fresh snapshot from Node's own list routes (same caller, so `current` agrees).
    let links = get(&base, &cookie, "/api/auth/pairing-links");
    let clients = get(&base, &cookie, "/api/auth/clients");
    println!("final state: {state}");
    assert_eq!(by_key(&state["pairingLinks"], "id"), by_key(&links, "id"));
    assert_eq!(
        by_key(&state["clientSessions"], "sessionId"),
        by_key(&clients, "sessionId")
    );
    assert!(
        revisions.windows(2).all(|w| w[1] == w[0] + 1),
        "{revisions:?}"
    );
    println!(
        "{} events, revisions 1..={}",
        revisions.len(),
        revisions.last().unwrap()
    );
    let l = log(&home);
    assert!(!l.contains("subscribeAuthAccess declined"), "{l}");
    assert!(!l.contains("rust handler declined"), "{l}");
    assert!(!l.contains("deferred_unverifiable_credential"), "{l}");
    drop(c);
    drop(d);
    assert!(!home.exists());
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn auth_access_hands_off_to_node_when_a_cloud_link_appears() {
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use tokio_tungstenite::tungstenite::Message;

    let Some((d, base, home, token)) = start_with("access-handoff", |home, _| {
        let cfg = home.join("vekrel.toml");
        let t = std::fs::read_to_string(&cfg).unwrap() + "\"subscribeAuthAccess\" = \"serve\"\n";
        std::fs::write(&cfg, t).unwrap();
    }) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let port = base.rsplit(':').next().unwrap().to_owned();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut c = rt.block_on(auth_ws(&port, &cookie));
    let mut state = json!({});
    let mut snapshots = 0;
    for e in
        serde_json::from_str::<Vec<Value>>(&rt.block_on(subscribe_first_chunk(&mut c, 1))).unwrap()
    {
        apply_auth_event(&mut state, &e);
    }
    let drain = |c: &mut Ws, state: &mut Value, snapshots: &mut usize| {
        rt.block_on(async {
            loop {
                let Ok(m) = tokio::time::timeout(Duration::from_millis(1500), c.next()).await
                else {
                    return;
                };
                let Some(Ok(Message::Text(t))) = m else {
                    panic!("socket ended: {m:?}")
                };
                let f: Value = serde_json::from_str(t.as_str()).unwrap();
                if f["requestId"] != 1 {
                    continue;
                }
                assert_eq!(f["_tag"], "Chunk", "{f}");
                for e in f["values"].as_array().unwrap() {
                    *snapshots += usize::from(e["type"] == "snapshot");
                    apply_auth_event(state, e);
                }
                c.send(Message::text(r#"{"_tag":"Ack","requestId":1}"#))
                    .await
                    .unwrap();
            }
        })
    };
    // A cloud link appears: sockets may now reach Node through the tunnel.
    std::fs::write(
        home.join("userdata/secrets/cloud-relay-url.bin"),
        b"https://relay.invalid",
    )
    .unwrap();
    drain(&mut c, &mut state, &mut snapshots);
    assert_eq!(snapshots, 1, "Node's snapshot after the handoff: {state}");
    // Node's stream carries the next change.
    post(
        &base,
        &cookie,
        "/api/auth/pairing-token",
        r#"{"label":"After"}"#,
    );
    drain(&mut c, &mut state, &mut snapshots);
    assert!(
        state["pairingLinks"].to_string().contains("After"),
        "{state}"
    );
    let links = get(&base, &cookie, "/api/auth/pairing-links");
    let clients = get(&base, &cookie, "/api/auth/clients");
    assert_eq!(by_key(&state["pairingLinks"], "id"), by_key(&links, "id"));
    assert_eq!(
        by_key(&state["clientSessions"], "sessionId"),
        by_key(&clients, "sessionId")
    );
    let l = log(&home);
    assert_eq!(l.matches("auth_access_handoff").count(), 1, "{l}");
    drop(c);
    drop(d);
    assert!(!home.exists());
}

// ---- pairing links: create, list, revoke ----

/// The engine's own loopback base URL, from the daemon config `start_with` wrote.
fn engine_base(home: &Path) -> String {
    let cfg: toml::Value =
        toml::from_str(&std::fs::read_to_string(home.join("vekrel.toml")).unwrap()).unwrap();
    format!(
        "http://127.0.0.1:{}",
        cfg["engine"]["port"].as_integer().unwrap()
    )
}

/// `method path` with the session cookie (and a JSON body) → (status, served by Rust, JSON).
fn call(
    base: &str,
    cookie: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (u16, bool, serde_json::Value) {
    let cookie = format!("cookie: {cookie}");
    let url = format!("{base}{path}");
    let mut args = vec!["-i", "-X", method, "-H", &cookie];
    if let Some(b) = body {
        args.extend(["-H", "content-type: application/json", "-d", b]);
    }
    args.push(&url);
    let (code, out) = curl(&args);
    let (head, body) = out.split_once("\r\n\r\n").unwrap();
    let rust = head
        .lines()
        .any(|l| l.eq_ignore_ascii_case("x-vekrel-served-by: rust"));
    (code, rust, serde_json::from_str(body).unwrap())
}

/// Ids, codes, trace ids and times masked.
fn masked(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| {
                    let m = match k.as_str() {
                        "id" | "credential" | "traceId" | "createdAt" | "expiresAt" => {
                            Value::String(format!("<{k}>"))
                        }
                        _ => masked(v),
                    };
                    (k.clone(), m)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(masked).collect()),
        v => v.clone(),
    }
}

/// (name, status, served by Rust, masked body).
type Step = (&'static str, u16, bool, serde_json::Value);

/// The task's scripted scenario through the daemon. Returns each step's (name, status, masked
/// body), whether Rust served it, and the ids of the three links it creates. `wait(event, id)`
/// runs after each write that should reach a `subscribeAuthAccess` stream.
fn pairing_scenario(
    base: &str,
    home: &Path,
    token: &str,
    wait: &mut dyn FnMut(&str, &str),
) -> (Vec<Step>, [String; 3]) {
    let owner = pair(base, home, token);
    let mut steps = vec![];
    let mut step = |name, cookie: &str, method, path, body: Option<&str>| {
        let (code, rust, v) = call(base, cookie, method, path, body);
        steps.push((name, code, rust, masked(&v)));
        v
    };
    const CREATE: &str = "/api/auth/pairing-token";
    const REVOKE: &str = "/api/auth/pairing-links/revoke";
    const LIST: &str = "/api/auth/pairing-links";
    let l1 = step(
        "default",
        &owner,
        "POST",
        CREATE,
        Some(r#"{"label":" Default "}"#),
    );
    let l2 = step(
        "delegated",
        &owner,
        "POST",
        CREATE,
        Some(r#"{"label":"Delegated","scopes":["orchestration:read","access:read"]}"#),
    );
    let l3 = step(
        "narrow",
        &owner,
        "POST",
        CREATE,
        Some(r#"{"scopes":["access:write","orchestration:read"]}"#),
    );
    for l in [&l1, &l2, &l3] {
        wait("pairingLinkUpserted", l["id"].as_str().unwrap());
    }
    // The new code pairs a browser through Node's own port.
    let narrow = pair(&engine_base(home), home, l3["credential"].as_str().unwrap());
    wait("pairingLinkRemoved", l3["id"].as_str().unwrap());
    step(
        "lacks delegated",
        &narrow,
        "POST",
        CREATE,
        Some(r#"{"scopes":["orchestration:read","filesystem:read"]}"#),
    );
    step("lacks default", &narrow, "POST", CREATE, Some("{}"));
    step("narrow list", &narrow, "GET", LIST, None);
    step(
        "duplicate",
        &owner,
        "POST",
        CREATE,
        Some(r#"{"scopes":["access:read","access:read"]}"#),
    );
    step("empty", &owner, "POST", CREATE, Some(r#"{"scopes":[]}"#));
    step("list", &owner, "GET", LIST, None);
    let id = |v: &serde_json::Value| serde_json::json!({ "id": v["id"] }).to_string();
    step("revoke open", &owner, "POST", REVOKE, Some(&id(&l1)));
    wait("pairingLinkRemoved", l1["id"].as_str().unwrap());
    step("revoke consumed", &owner, "POST", REVOKE, Some(&id(&l3)));
    step("revoke again", &owner, "POST", REVOKE, Some(&id(&l1)));
    step("list after", &owner, "GET", LIST, None);
    let ids = [&l1, &l2, &l3].map(|v| v["id"].as_str().unwrap().to_owned());
    (steps, ids)
}

/// `auth_pairing_links` with ids, codes and times normalised (expiry kept relative), sorted.
fn links_normalised(home: &Path) -> Vec<String> {
    let db = rusqlite::Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
    let ms = |v: &serde_json::Value| {
        let s = v.as_str().unwrap();
        db.query_row(
            "SELECT CAST(ROUND((julianday(?1) - 2440587.5) * 86400000) AS INTEGER)",
            [s],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
    };
    let mut out: Vec<String> = dump(&db, "auth_pairing_links")
        .into_iter()
        .map(|mut r| {
            let code = r["credential"].as_str().unwrap();
            if r["subject"] == "one-time-token" {
                let alphabet = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
                assert!(
                    code.len() == 12 && code.bytes().all(|b| alphabet.contains(&b)),
                    "{r}"
                );
            }
            let created = ms(&r["created_at"]);
            for k in ["consumed_at", "revoked_at"] {
                r[k] = serde_json::json!(!r[k].is_null());
            }
            r["expires_at"] = serde_json::json!(ms(&r["expires_at"]) - created);
            for k in ["id", "credential", "created_at"] {
                r[k] = serde_json::json!("<masked>");
            }
            r.to_string()
        })
        .collect();
    out.sort();
    out
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn pairing_links_shadow_matches_and_serve_writes_like_node() {
    use futures_util::{SinkExt, StreamExt};
    use serde_json::Value;
    use tokio_tungstenite::tungstenite::Message;

    // Home A: every route shadow (Node writes). Home B: Rust serves the routes and the stream.
    let Some((da, base_a, home_a, token_a)) = start("links-shadow") else {
        return;
    };
    // The startup token is single-use: a watcher session takes it and mints the owner's link.
    let watcher_a = pair(&base_a, &home_a, &token_a);
    let owner_a = post(&base_a, &watcher_a, "/api/auth/pairing-token", "{}");
    let (steps_a, _) = pairing_scenario(
        &base_a,
        &home_a,
        owner_a["credential"].as_str().unwrap(),
        &mut |_, _| {},
    );
    for route in [
        "POST /api/auth/pairing-token",
        "GET /api/auth/pairing-links",
        "POST /api/auth/pairing-links/revoke",
    ] {
        let (m, mm) = shadow_counts(&home_a, route);
        println!("{route} shadow: {m} match, {mm} mismatch");
        assert_eq!(mm, 0, "{route}");
        assert!(m >= 3, "{route} compared");
    }
    let rows_a = links_normalised(&home_a);

    let Some((db, base_b, home_b, token_b)) = start_with("links-serve", |home, _| {
        let cfg = home.join("vekrel.toml");
        let t = std::fs::read_to_string(&cfg).unwrap()
            + "\"POST /api/auth/pairing-token\" = \"serve\"\n\
               \"GET /api/auth/pairing-links\" = \"serve\"\n\
               \"POST /api/auth/pairing-links/revoke\" = \"serve\"\n\
               \"subscribeAuthAccess\" = \"serve\"\n";
        std::fs::write(&cfg, t).unwrap();
    }) else {
        return;
    };
    // A Rust-served stream opened by a separate admin session before Rust's writes.
    let watcher = pair(&base_b, &home_b, &token_b);
    let port = base_b.rsplit(':').next().unwrap().to_owned();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut ws = rt.block_on(auth_ws(&port, &watcher));
    rt.block_on(subscribe_first_chunk(&mut ws, 1));
    let owner_link = post(&base_b, &watcher, "/api/auth/pairing-token", "{}");
    // Reads the stream (acking each Chunk) until `(event, id)` arrives.
    let mut events: Vec<(String, Option<String>)> = vec![];
    let mut wait = |want: &str, want_id: &str| {
        rt.block_on(async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while !events
                .iter()
                .any(|e| e.0 == want && e.1.as_deref() == Some(want_id))
            {
                let m = tokio::time::timeout_at(deadline, ws.next()).await;
                let Ok(Some(Ok(Message::Text(t)))) = m else {
                    panic!("no {want} {want_id} on the stream: {m:?} after {events:?}")
                };
                let f: Value = serde_json::from_str(t.as_str()).unwrap();
                if f["requestId"] != 1 {
                    continue;
                }
                assert_eq!(f["_tag"], "Chunk", "{f}");
                for e in f["values"].as_array().unwrap() {
                    let id = e["payload"]["id"].as_str().map(str::to_owned);
                    events.push((e["type"].as_str().unwrap().to_owned(), id));
                }
                ws.send(Message::text(r#"{"_tag":"Ack","requestId":1}"#))
                    .await
                    .unwrap();
            }
        })
    };
    let (steps_b, ids) = pairing_scenario(
        &base_b,
        &home_b,
        owner_link["credential"].as_str().unwrap(),
        &mut wait,
    );
    println!("stream events: {events:?}");
    let has = |t: &str, id: &str| {
        events
            .iter()
            .any(|e| e.0 == t && e.1.as_deref() == Some(id))
    };
    for id in &ids {
        assert!(has("pairingLinkUpserted", id), "upsert {id}");
    }
    assert!(has("pairingLinkRemoved", &ids[0]), "revoked link removed");
    assert!(has("pairingLinkRemoved", &ids[2]), "consumed link removed");
    assert!(!has("pairingLinkRemoved", &ids[1]));
    drop(ws);

    // Same answers; A from Node, B from Rust (except nothing declined).
    assert_eq!(steps_a.len(), steps_b.len());
    for (a, b) in steps_a.iter().zip(&steps_b) {
        println!("{}: {} {}", a.0, a.1, a.3);
        assert_eq!((a.0, a.1, &a.3), (b.0, b.1, &b.3), "step {}", a.0);
        assert!(!a.2, "A is Node's: {}", a.0);
        assert!(b.2, "B is Rust's: {}", b.0);
    }
    let rows_b = links_normalised(&home_b);
    println!(
        "A rows:\n{}\nB rows:\n{}",
        rows_a.join("\n"),
        rows_b.join("\n")
    );
    assert_eq!(rows_a, rows_b, "auth_pairing_links differ");
    // A cloud link means Node's own stream may have clients: serve hands the writes to Node.
    std::fs::write(home_b.join("userdata/secrets/cloud-relay-url.bin"), "x").unwrap();
    let (code, rust, l) = call(
        &base_b,
        &watcher,
        "POST",
        "/api/auth/pairing-token",
        Some(r#"{"label":"Via Node"}"#),
    );
    assert_eq!((code, rust), (200, false), "{l}");
    let body = serde_json::json!({ "id": l["id"] }).to_string();
    let (code, rust, r) = call(
        &base_b,
        &watcher,
        "POST",
        "/api/auth/pairing-links/revoke",
        Some(&body),
    );
    assert_eq!(
        (code, rust, &r),
        (200, false, &serde_json::json!({"revoked": true}))
    );
    let logged = log(&home_b);
    assert_eq!(
        logged.matches(r#"why="cloud_link""#).count(),
        2,
        "both writes declined for the cloud link"
    );
    drop((da, db));
    assert!(!home_a.exists() && !home_b.exists());
}

// ---- pairing consume: POST /api/auth/browser-session, POST /oauth/token ----

/// The engine port from a live home's config.
fn engine_port(home: &Path) -> String {
    let cfg = std::fs::read_to_string(home.join("vekrel.toml")).unwrap();
    cfg.split("[engine]")
        .nth(1)
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("port = ")))
        .unwrap()
        .to_owned()
}

/// One response, normalised: status, the credential headers, the body with tokens, trace ids
/// and times replaced (`expires_in` rounded to the minute), and whether Rust served it.
#[derive(Debug, Clone, PartialEq)]
struct Seen {
    status: u16,
    headers: Vec<String>,
    body: String,
    rust: bool,
    /// The access token or session cookie value, when one was issued.
    token: Option<String>,
}

async fn send(http: &reqwest::Client, url: String, h: &[(&str, String)], body: String) -> Seen {
    let mut r = http.post(url).body(body);
    for (k, v) in h {
        r = r.header(*k, v);
    }
    let r = r.send().await.unwrap();
    let status = r.status().as_u16();
    let hv = |k: &str| {
        r.headers()
            .get_all(k)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let cookie = hv("set-cookie");
    let mut token = cookie
        .first()
        .and_then(|c| Some(c.split_once('=')?.1.split(';').next()?.to_owned()));
    let mut headers: Vec<String> = ["cache-control", "pragma", "www-authenticate"]
        .iter()
        .flat_map(|k| hv(k).into_iter().map(move |v| format!("{k}: {v}")))
        .collect();
    headers.extend(cookie.iter().map(|c| {
        // The name hashes the state dir, so it differs between homes.
        let rest = c.split_once('=').unwrap().1;
        let attrs: Vec<&str> = rest
            .split("; ")
            .skip(1)
            .filter(|a| !a.starts_with("Expires="))
            .collect();
        format!("set-cookie: <name>=<token>; {}", attrs.join("; "))
    }));
    let rust = r.headers().contains_key("x-vekrel-served-by");
    let mut v: serde_json::Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
    if let Some(o) = v.as_object_mut() {
        for k in ["traceId", "expiresAt"] {
            if o.contains_key(k) {
                o.insert(k.into(), "<x>".into());
            }
        }
        if let Some(t) = o.insert("access_token".into(), "<token>".into()) {
            token = t.as_str().map(str::to_owned);
        } else {
            o.remove("access_token");
        }
        if let Some(n) = o.get("expires_in").and_then(|n| n.as_i64()) {
            o.insert("expires_in".into(), ((n + 30) / 60).into());
        }
    }
    Seen {
        status,
        headers,
        body: v.to_string(),
        rust,
        token,
    }
}

/// Both auth tables with ids, credentials, tokens and times normalised (session and link ids by
/// first appearance; each timestamp as set/null plus the session and link TTLs in seconds) and
/// `client_ip_address` as set/null (Rust stores the client's, Node the proxy's).
fn normalised_tables(db: &rusqlite::Connection) -> serde_json::Value {
    use serde_json::{Value, json};
    let mut ids: Vec<String> = Vec::new();
    let mut id = |s: &str| {
        let i = ids.iter().position(|x| x == s).unwrap_or_else(|| {
            ids.push(s.to_owned());
            ids.len() - 1
        });
        format!("<id{i}>")
    };
    let ms = |db: &rusqlite::Connection, a: &str, b: &str| -> i64 {
        db.query_row(
            "SELECT CAST(ROUND((unixepoch(?2, 'subsec') - unixepoch(?1, 'subsec'))) AS INTEGER)",
            [a, b],
            |r| r.get(0),
        )
        .unwrap()
    };
    let set = |v: &Value| json!(if v.is_null() { "null" } else { "set" });
    let mut sessions = vec![];
    for mut r in dump_ordered(db, "auth_sessions") {
        let o = r.as_object_mut().unwrap();
        let ttl = ms(
            db,
            o["issued_at"].as_str().unwrap(),
            o["expires_at"].as_str().unwrap(),
        );
        o.insert("ttl_s".into(), ttl.into());
        o.insert(
            "session_id".into(),
            id(o["session_id"].as_str().unwrap()).into(),
        );
        for k in [
            "issued_at",
            "expires_at",
            "revoked_at",
            "last_connected_at",
            "client_ip_address",
        ] {
            let v = set(&o[k]);
            o.insert(k.into(), v);
        }
        sessions.push(r);
    }
    let mut links = vec![];
    for mut r in dump_ordered(db, "auth_pairing_links") {
        let o = r.as_object_mut().unwrap();
        let ttl = ms(
            db,
            o["created_at"].as_str().unwrap(),
            o["expires_at"].as_str().unwrap(),
        );
        o.insert("ttl_s".into(), ttl.into());
        for k in ["id", "credential"] {
            let v = id(o[k].as_str().unwrap());
            o.insert(k.into(), v.into());
        }
        for k in ["created_at", "expires_at", "consumed_at", "revoked_at"] {
            let v = set(&o[k]);
            o.insert(k.into(), v);
        }
        links.push(r);
    }
    json!({"auth_sessions": sessions, "auth_pairing_links": links})
}

/// `dump` in insert order.
fn dump_ordered(db: &rusqlite::Connection, table: &str) -> Vec<serde_json::Value> {
    let mut q = db
        .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
        .unwrap();
    let names: Vec<String> = q.column_names().iter().map(|s| s.to_string()).collect();
    q.query_map([], |r| {
        let mut o = serde_json::Map::new();
        for (i, n) in names.iter().enumerate() {
            let v: Option<String> = r.get(i)?;
            o.insert(n.clone(), serde_json::json!(v));
        }
        Ok(serde_json::Value::Object(o))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

fn token_form(cred: &str, extra: &[(&str, &str)]) -> String {
    let mut f = url::form_urlencoded::Serializer::new(String::new());
    f.append_pair(
        "grant_type",
        "urn:ietf:params:oauth:grant-type:token-exchange",
    )
    .append_pair("subject_token", cred)
    .append_pair(
        "subject_token_type",
        "urn:t3:params:oauth:token-type:machine-bootstrap",
    )
    .append_pair(
        "requested_token_type",
        "urn:ietf:params:oauth:token-type:access_token",
    );
    f.extend_pairs(extra.iter().copied());
    f.finish()
}

const FORM: &str = "application/x-www-form-urlencoded";
const BROWSER_UA: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/141.0 Safari/537.36";

/// The scripted pairing scenarios against one live home. `serve`: Rust answers (proofs sign the
/// public URL); otherwise Node does (proofs sign the engine's URL, which Node behind the proxy
/// checks). Returns each step's normalised response and the final normalised tables. With
/// `watch`, a served `subscribeAuthAccess` watches the native bearer pairing.
fn pairing_scenarios(
    base: &str,
    home: &Path,
    startup: &str,
    serve: bool,
    watch: bool,
) -> (Vec<(&'static str, Seen)>, serde_json::Value) {
    use serde_json::{Value, json};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let http = reqwest::Client::new();
    let port = base.rsplit(':').next().unwrap().to_owned();
    let htu_base = if serve {
        base.to_owned()
    } else {
        format!("http://127.0.0.1:{}", engine_port(home))
    };
    let key = p256::ecdsa::SigningKey::from_slice(&[21; 32]).unwrap();
    let mut steps: Vec<(&'static str, Seen)> = vec![];
    let browser = |cred: &str, cookie: Option<&str>| {
        let mut h = vec![
            ("content-type", "application/json".to_owned()),
            ("user-agent", BROWSER_UA.to_owned()),
        ];
        if let Some(c) = cookie {
            h.push(("cookie", c.to_owned()));
        }
        let body = json!({ "credential": cred }).to_string();
        rt.block_on(send(
            &http,
            format!("{base}/api/auth/browser-session"),
            &h,
            body,
        ))
    };
    let token = |cred: &str, extra: &[(&str, &str)], proof: bool| {
        let mut h = vec![
            ("content-type", FORM.to_owned()),
            ("user-agent", "vekrel-native/1.0".to_owned()),
        ];
        if proof {
            h.push((
                "dpop",
                dpop_proof(&key, "POST", &format!("{htu_base}/oauth/token"), None),
            ));
        }
        rt.block_on(send(
            &http,
            format!("{base}/oauth/token"),
            &h,
            token_form(cred, extra),
        ))
    };
    let cookie_of = |s: &Seen, name: &str| format!("{name}={}", s.token.clone().unwrap());

    // 1. Pair a browser with the startup token.
    let owner = browser(startup, None);
    assert_eq!(owner.status, 200, "{owner:?}");
    let name = get(base, "", "/api/auth/session")["auth"]["sessionCookieName"]
        .as_str()
        .unwrap()
        .to_owned();
    let owner_cookie = cookie_of(&owner, &name);
    steps.push(("pair browser", owner));
    // Links from Node's own route, plus a key-bound and an expired one as the cloud mint / time would leave them.
    let link = |body: Value| {
        post(
            base,
            &owner_cookie,
            "/api/auth/pairing-token",
            &body.to_string(),
        )["credential"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let re = link(json!({"label": "Re-pair"}));
    let bearer = link(json!({"scopes": ["orchestration:read", "filesystem:read"]}));
    let dpop = link(json!({"label": "Phone", "scopes": ["orchestration:read"]}));
    let narrow = link(json!({"scopes": ["orchestration:read"]}));
    let db = rusqlite::Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
    db.busy_timeout(Duration::from_secs(5)).unwrap();
    let thumb = {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        use sha2::Digest;
        let p = key.verifying_key().to_sec1_point(false);
        let b = p.as_bytes();
        let (x, y) = (B64.encode(&b[1..33]), B64.encode(&b[33..65]));
        B64.encode(sha2::Sha256::digest(format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#
        )))
    };
    db.execute(
        "INSERT INTO auth_pairing_links (id, credential, method, scopes, subject, label, proof_key_thumbprint, created_at, expires_at)
         VALUES ('bound-link', 'BOUNDCRED234', 'one-time-token', '[\"orchestration:read\"]', 'cloud-connect', NULL, ?1,
                 strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+120 seconds')),
                ('expired-link', 'EXPIRED23456', 'one-time-token', '[\"orchestration:read\"]', 'one-time-token', NULL, NULL,
                 strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-600 seconds'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-300 seconds'))",
        [&thumb],
    )
    .unwrap();

    // 2. Re-pair a browser that already has a cookie: the old cookie session is replaced.
    let s = browser(&re, Some(&owner_cookie));
    let repaired = cookie_of(&s, &name);
    steps.push(("re-pair browser (replace)", s));
    // Watch the access stream (served by Rust) from the new browser session.
    let mut ws = watch.then(|| {
        let mut c = rt.block_on(auth_ws(&port, &repaired));
        rt.block_on(subscribe_first_chunk(&mut c, 1));
        c
    });
    // 3. A native client with a Bearer token (requested scopes: one granted, one not).
    let s = token(
        &bearer,
        &[
            ("scope", "filesystem:read orchestration:operate"),
            ("client_label", "cli"),
            ("client_device_type", "desktop"),
            ("client_os", "Plan9"),
        ],
        false,
    );
    // Node's own stream can miss a write made right after it subscribes (its PubSub subscription
    // races the snapshot), so only Rust's served stream is waited on.
    if let Some(c) = ws.as_mut().filter(|_| serve) {
        use futures_util::{SinkExt, StreamExt};
        let sid = {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
            let t = s.token.clone().unwrap();
            let claims: Value =
                serde_json::from_slice(&B64.decode(t.split('.').next().unwrap()).unwrap()).unwrap();
            claims["sid"].as_str().unwrap().to_owned()
        };
        let t0 = Instant::now();
        let mut seen = (false, false);
        let mut frames = vec![];
        rt.block_on(async {
            while !(seen.0 && seen.1) {
                let Ok(m) = tokio::time::timeout(Duration::from_secs(10), c.next()).await else {
                    panic!("serve={serve}: no stream event for {sid}; frames: {frames:?}")
                };
                let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t))) = m else {
                    panic!("{m:?}")
                };
                let f: Value = serde_json::from_str(t.as_str()).unwrap();
                frames.push(f.clone());
                if f["_tag"] != "Chunk" {
                    continue;
                }
                for e in f["values"].as_array().unwrap() {
                    seen.0 |=
                        e["type"] == "clientUpserted" && e["payload"]["sessionId"] == sid.as_str();
                    seen.1 |= e["type"] == "pairingLinkRemoved";
                }
                c.send(tokio_tungstenite::tungstenite::Message::text(
                    r#"{"_tag":"Ack","requestId":1}"#,
                ))
                .await
                .unwrap();
            }
        });
        println!(
            "subscribeAuthAccess (served by Rust) saw the Rust-written client and link removal after {:?}",
            t0.elapsed()
        );
    }
    steps.push(("native bearer", s));
    // 4. A native client with DPoP, on an unbound and on a key-bound link.
    steps.push(("native dpop", token(&dpop, &[], true)));
    steps.push((
        "bound link without proof",
        token("BOUNDCRED234", &[], false),
    ));
    steps.push(("bound link with its key", token("BOUNDCRED234", &[], true)));
    // 5. Invalid credential (no link: Node answers in both homes), reuse, expiry.
    steps.push((
        "invalid credential (browser)",
        browser("NOPE23456789", None),
    ));
    steps.push((
        "invalid credential (token)",
        token("NOPE23456789", &[], false),
    ));
    steps.push(("consumed credential", token(&bearer, &[], false)));
    steps.push(("expired credential", token("EXPIRED23456", &[], false)));
    // 6. Scope not granted (the link stays usable), then a malformed scope.
    steps.push((
        "scope not granted",
        token(&narrow, &[("scope", "access:read")], false),
    ));
    steps.push((
        "invalid scope",
        token(&narrow, &[("scope", "bad  scope")], false),
    ));
    drop(ws);
    (steps, normalised_tables(&db))
}

/// (a) + (b): one home with Rust in shadow (Node writes, Rust dry-runs every request first) and
/// one with Rust serving; the same scenarios give the same responses and, normalised, the same
/// `auth_sessions` and `auth_pairing_links`.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn pairing_consume_db_diff_shadow_vs_serve() {
    let Some((shadow_d, shadow_base, shadow_home, shadow_token)) = start_with(
        "pair-shadow",
        |home, _| {
            let cfg = home.join("vekrel.toml");
            let t = std::fs::read_to_string(&cfg).unwrap()
                + "\"POST /api/auth/browser-session\" = \"shadow\"\n\"POST /oauth/token\" = \"shadow\"\n";
            std::fs::write(&cfg, t).unwrap();
        },
    ) else {
        return;
    };
    let (shadow_steps, shadow_tables) =
        pairing_scenarios(&shadow_base, &shadow_home, &shadow_token, false, true);
    std::thread::sleep(Duration::from_millis(500));
    let l = log(&shadow_home);
    let dry: Vec<&str> = l.lines().filter(|l| l.contains("rust dry run")).collect();
    let resp: Vec<&str> = l
        .lines()
        .filter(|l| {
            l.contains("rust shadow")
                && (l.contains("browser-session") || l.contains("oauth/token"))
        })
        .collect();
    let declines = l
        .lines()
        .filter(|l| l.contains("rust handler declined"))
        .count();
    println!(
        "shadow: {} response comparisons, {} dry-run row checks, {declines} declines",
        resp.len(),
        dry.len()
    );
    for x in resp
        .iter()
        .chain(&dry)
        .filter(|x| !x.contains("outcome=\"match\""))
    {
        println!("  {x}");
    }
    assert!(
        dry.iter().all(|x| x.contains("outcome=\"match\"")),
        "{dry:#?}"
    );
    // Node behind the proxy checks DPoP against its rewritten Host, so the client signs the
    // engine's URL here and Rust (which checks the client's URL) predicts request_mismatch:
    // exactly the two successful DPoP pairings. Everything else matches.
    let mismatched: Vec<&&str> = resp
        .iter()
        .filter(|x| !x.contains("outcome=\"match\""))
        .collect();
    assert_eq!(mismatched.len(), 2, "{mismatched:#?}");
    assert!(
        mismatched
            .iter()
            .all(|x| x.contains("oauth/token") && x.contains("field=\"status\""))
    );
    // The two invalid credentials have no link: declined, Node answers.
    assert_eq!(declines, 2, "{l}");
    drop(shadow_d);

    let Some((serve_d, serve_base, serve_home, serve_token)) = start_with(
        "pair-serve",
        |home, _| {
            let cfg = home.join("vekrel.toml");
            let t = std::fs::read_to_string(&cfg).unwrap()
                + "\"POST /api/auth/browser-session\" = \"serve\"\n\"POST /oauth/token\" = \"serve\"\n\"subscribeAuthAccess\" = \"serve\"\n";
            std::fs::write(&cfg, t).unwrap();
        },
    ) else {
        return;
    };
    let (serve_steps, serve_tables) =
        pairing_scenarios(&serve_base, &serve_home, &serve_token, true, true);
    for ((name, a), (_, b)) in shadow_steps.iter().zip(&serve_steps) {
        println!(
            "{name}: node {} / rust {} served_by_rust={}",
            a.status, b.status, b.rust
        );
        assert_eq!(
            (a.status, &a.headers, &a.body),
            (b.status, &b.headers, &b.body),
            "{name}"
        );
        assert!(!a.rust);
        assert_eq!(b.rust, !name.starts_with("invalid credential"), "{name}");
    }
    let (a, b) = (
        serde_json::to_string_pretty(&shadow_tables).unwrap(),
        serde_json::to_string_pretty(&serve_tables).unwrap(),
    );
    println!("normalised tables (identical in both homes):\n{b}");
    assert_eq!(a, b, "DB diff");
    // Rust stores the client's own address; through loopback that is 127.0.0.1 as well.
    drop(serve_d);
    assert!(!shadow_home.exists() && !serve_home.exists());
}

/// (c) Review Focus 2: the same credential at Rust (public port) and Node (engine port) at once,
/// 20 times: exactly one success each time, one session per link.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn pairing_consume_race_rust_vs_node() {
    let Some((d, base, home, token)) = start_with("pair-race", |home, _| {
        let cfg = home.join("vekrel.toml");
        // Writes serve only with the stream serving (the startup guard).
        let t = std::fs::read_to_string(&cfg).unwrap()
            + "\"POST /api/auth/browser-session\" = \"serve\"\n\"POST /oauth/token\" = \"serve\"\n\"subscribeAuthAccess\" = \"serve\"\n";
        std::fs::write(&cfg, t).unwrap();
    }) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let internal = format!("http://127.0.0.1:{}", engine_port(&home));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let http = reqwest::Client::new();
    let h = [("content-type", FORM.to_owned())];
    let (mut rust_wins, mut node_wins) = (0, 0);
    for i in 0..20u64 {
        let cred = post(
            &base,
            &cookie,
            "/api/auth/pairing-token",
            &format!(r#"{{"label":"race {i}"}}"#),
        )["credential"]
            .as_str()
            .unwrap()
            .to_owned();
        // Sweep the start offset from Rust 2 ms late to Node 2 ms late.
        let (rust_delay, node_delay) = (200 * 10u64.saturating_sub(i), 200 * i.saturating_sub(10));
        let at = |url: String, delay: u64| {
            let (http, h, body) = (&http, &h, token_form(&cred, &[]));
            async move {
                tokio::time::sleep(Duration::from_micros(delay)).await;
                send(http, url, h, body).await
            }
        };
        let (a, b) = rt.block_on(async {
            tokio::join!(
                at(format!("{base}/oauth/token"), rust_delay),
                at(format!("{internal}/oauth/token"), node_delay),
            )
        });
        let ok = [a.status, b.status];
        assert_eq!(
            ok.iter().filter(|s| **s == 200).count(),
            1,
            "round {i}: {a:?} {b:?}"
        );
        assert!(ok.contains(&401), "round {i}: {ok:?}");
        // Rust answers its request either way (win or 401), never declines it to Node.
        assert!(a.rust, "round {i}: Rust declined");
        if a.status == 200 {
            rust_wins += 1;
        } else {
            node_wins += 1;
        }
    }
    assert!(
        rust_wins > 0 && node_wins > 0,
        "rust {rust_wins}, node {node_wins}"
    );
    let db = rusqlite::Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
    let per_link: i64 = db
        .query_row(
            "SELECT count(*) FROM auth_sessions WHERE client_label LIKE 'race %' GROUP BY client_label HAVING count(*) <> 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let total: i64 = db
        .query_row(
            "SELECT count(*) FROM auth_sessions WHERE client_label LIKE 'race %'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    println!(
        "race: 20 rounds, exactly one success each (rust {rust_wins}, node {node_wins}); {total} sessions"
    );
    assert_eq!((per_link, total), (0, 20));
    drop(d);
    assert!(!home.exists());
}

// ---- clients: list, revoke, revoke-others ----

/// Session ids, trace ids and times masked (`lastConnectedAt` keeps null vs set).
fn masked_clients(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| {
                    let m = match k.as_str() {
                        "sessionId" | "traceId" | "issuedAt" | "expiresAt" | "ipAddress" => {
                            Value::String(format!("<{k}>"))
                        }
                        "lastConnectedAt" if !v.is_null() => Value::String("<set>".into()),
                        _ => masked_clients(v),
                    };
                    (k.clone(), m)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(masked_clients).collect()),
        v => v.clone(),
    }
}

/// Waits (up to `limit`) for `ws` to close; returns when, and the close frame it got.
fn on_close(
    rt: &tokio::runtime::Runtime,
    mut ws: Ws,
    limit: Duration,
) -> tokio::task::JoinHandle<(Instant, String)> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    rt.spawn(async move {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            match tokio::time::timeout_at(deadline, ws.next()).await {
                Err(_) => panic!("socket still open after {limit:?}"),
                Ok(Some(Ok(Message::Close(f)))) => {
                    return (
                        Instant::now(),
                        format!("{:?}", f.map(|f| (u16::from(f.code), f.reason.to_string()))),
                    );
                }
                Ok(None | Some(Err(_))) => return (Instant::now(), "no close frame".into()),
                Ok(Some(Ok(_))) => {}
            }
        }
    })
}

/// What one clients scenario saw: each step, the close frame and delay of the revoked proxied
/// socket (`B`) and of the socket that went straight to Node (`D`), and the session ids.
struct ClientsRun {
    steps: Vec<Step>,
    proxied: (Duration, String),
    direct: (Duration, String),
    ids: [String; 4],
}

/// The scripted scenario: W (caller, admin) pairs B (access:read only), C and D; B and C connect
/// through Rust, D straight to Node (only before revoke-others: Rust cannot see it); C's row is then expired while connected; an expired row E is
/// inserted. Then: lists, B's 403, W's self-revoke 403, revoke B (proxied socket closes),
/// repeats, revoke-others (D's direct socket closes), final list. `before_revoke` runs right
/// before revoking B.
fn clients_scenario(
    base: &str,
    home: &Path,
    rt: &tokio::runtime::Runtime,
    w: &str,
    before_revoke: &mut dyn FnMut(),
) -> ClientsRun {
    let link = |body: &str| {
        post(base, w, "/api/auth/pairing-token", body)["credential"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let b = pair(
        base,
        home,
        &link(r#"{"label":"B","scopes":["orchestration:read","access:read"]}"#),
    );
    let c = pair(base, home, &link(r#"{"label":"C"}"#));
    let d = pair(base, home, &link(r#"{"label":"D"}"#));
    let db = rusqlite::Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
    db.execute(
        "INSERT INTO auth_sessions (session_id, subject, scopes, method, client_device_type,
           issued_at, expires_at)
         VALUES ('e-expired', 'one-time-token', '[\"orchestration:read\"]', 'bearer-access-token',
           'unknown', '2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z')",
        [],
    )
    .unwrap();
    let port = base.rsplit(':').next().unwrap().to_owned();
    let ws_b = rt.block_on(auth_ws(&port, &b));
    let ws_c = rt.block_on(auth_ws(&port, &c));
    std::thread::sleep(Duration::from_millis(300));

    let mut steps: Vec<Step> = vec![];
    let mut step =
        |name: &'static str, cookie: &str, method: &str, path: &str, body: Option<&str>| {
            let (code, rust, v) = call(base, cookie, method, path, body);
            steps.push((name, code, rust, masked_clients(&v)));
            v
        };
    let list = step("list", w, "GET", "/api/auth/clients", None);
    let sid = |label: &str| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|c| c["client"]["label"] == label)
            .map(|c| c["sessionId"].as_str().unwrap().to_owned())
            .unwrap()
    };
    let me = list
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["current"] == true)
        .unwrap()["sessionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let ids = [sid("B"), sid("C"), sid("D"), me.clone()];
    // C stays listed while connected even once expired (until Node's 5 s re-check closes it).
    db.execute(
        // A day before issue: in the past, with the same TTL in both homes.
        "UPDATE auth_sessions SET expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', issued_at, '-1 day')
         WHERE session_id = ?1",
        [&ids[1]],
    )
    .unwrap();
    step(
        "list with C expired but connected",
        w,
        "GET",
        "/api/auth/clients",
        None,
    );
    rt.block_on(on_close(rt, ws_c, Duration::from_secs(8)))
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    step("list after C closed", w, "GET", "/api/auth/clients", None);
    step("list as B", &b, "GET", "/api/auth/clients", None);
    let body = |s: &str| serde_json::json!({ "sessionId": s }).to_string();
    step(
        "revoke as B",
        &b,
        "POST",
        "/api/auth/clients/revoke",
        Some(&body(&ids[0])),
    );
    step(
        "revoke-others as B",
        &b,
        "POST",
        "/api/auth/clients/revoke-others",
        None,
    );
    step(
        "revoke self",
        w,
        "POST",
        "/api/auth/clients/revoke",
        Some(&body(&me)),
    );

    let closed_b = on_close(rt, ws_b, Duration::from_secs(8));
    before_revoke();
    let t = Instant::now();
    step(
        "revoke B",
        w,
        "POST",
        "/api/auth/clients/revoke",
        Some(&body(&ids[0])),
    );
    let (at, frame) = rt.block_on(closed_b).unwrap();
    let proxied = (at - t, frame);
    step(
        "revoke B again",
        w,
        "POST",
        "/api/auth/clients/revoke",
        Some(&body(&ids[0])),
    );
    step(
        "revoke unknown",
        w,
        "POST",
        "/api/auth/clients/revoke",
        Some(&body("nope")),
    );
    step("list after revoke", w, "GET", "/api/auth/clients", None);
    // A socket Rust never sees: connected only now, so no list above depends on it.
    let ws_d = rt.block_on(auth_ws(&engine_port(home), &d));
    std::thread::sleep(Duration::from_millis(300));

    let closed_d = on_close(rt, ws_d, Duration::from_secs(10));
    let t = Instant::now();
    step(
        "revoke-others",
        w,
        "POST",
        "/api/auth/clients/revoke-others",
        None,
    );
    let (at, frame) = rt.block_on(closed_d).unwrap();
    let direct = (at - t, frame);
    std::thread::sleep(Duration::from_millis(300));
    step(
        "list after revoke-others",
        w,
        "GET",
        "/api/auth/clients",
        None,
    );
    step(
        "revoke-others again",
        w,
        "POST",
        "/api/auth/clients/revoke-others",
        None,
    );
    ClientsRun {
        steps,
        proxied,
        direct,
        ids,
    }
}

/// Home A: every route shadow (Node writes; Rust's list and revoke predictions are compared).
/// Home B: Rust serves the three routes and `subscribeAuthAccess`. Same answers, same normalised
/// tables; B's revoked proxied socket closes within 1 s, the direct-to-Node one within ~6 s,
/// and the Rust-served stream shows `clientRemoved` for Rust's revoke.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn clients_shadow_matches_and_serve_revokes_like_node() {
    use futures_util::{SinkExt, StreamExt};
    use serde_json::Value;
    use tokio_tungstenite::tungstenite::Message;
    const ROUTES: [&str; 3] = [
        "GET /api/auth/clients",
        "POST /api/auth/clients/revoke",
        "POST /api/auth/clients/revoke-others",
    ];
    let rt = tokio::runtime::Runtime::new().unwrap();

    let Some((da, base_a, home_a, token_a)) = start("clients-shadow") else {
        return;
    };
    let w_a = pair(&base_a, &home_a, &token_a);
    // W holds a socket in both homes (B: its stream).
    let port_a = base_a.rsplit(':').next().unwrap().to_owned();
    let ws_a = rt.block_on(auth_ws(&port_a, &w_a));
    let a = clients_scenario(&base_a, &home_a, &rt, &w_a, &mut || {});
    for route in ROUTES {
        let (m, mm) = shadow_counts(&home_a, route);
        println!("{route} shadow: {m} match, {mm} mismatch");
        assert_eq!(mm, 0, "{route}");
        assert!(m >= 3, "{route} compared");
    }
    let db_a = rusqlite::Connection::open(home_a.join("userdata/statev2.sqlite")).unwrap();
    let rows_a = normalised_tables(&db_a);
    drop(ws_a);

    let Some((db, base_b, home_b, token_b)) = start_with("clients-serve", |home, _| {
        let cfg = home.join("vekrel.toml");
        let mut t = std::fs::read_to_string(&cfg).unwrap();
        for r in ROUTES.iter().chain(&["subscribeAuthAccess"]) {
            t += &format!("\"{r}\" = \"serve\"\n");
        }
        std::fs::write(&cfg, t).unwrap();
    }) else {
        return;
    };
    let w_b = pair(&base_b, &home_b, &token_b);
    let port = base_b.rsplit(':').next().unwrap().to_owned();
    let mut ws = rt.block_on(auth_ws(&port, &w_b));
    rt.block_on(subscribe_first_chunk(&mut ws, 1));
    // Drains the stream from here on, acking each Chunk; stops at the first `clientRemoved` seen
    // after `armed` is set.
    let armed = std::sync::Arc::new(std::sync::Mutex::new(None::<Instant>));
    let armed2 = armed.clone();
    let stream = rt.spawn(async move {
        let mut removed = vec![];
        loop {
            let m = tokio::time::timeout(Duration::from_secs(60), ws.next()).await;
            let Ok(Some(Ok(Message::Text(t)))) = m else {
                panic!("stream ended: {m:?}")
            };
            let f: Value = serde_json::from_str(t.as_str()).unwrap();
            if f["requestId"] != 1 {
                continue;
            }
            assert_eq!(f["_tag"], "Chunk", "{f}");
            for e in f["values"].as_array().unwrap() {
                if e["type"] == "clientRemoved" && armed2.lock().unwrap().is_some() {
                    let at = armed2.lock().unwrap().unwrap();
                    removed.push((
                        e["payload"]["sessionId"].as_str().unwrap().to_owned(),
                        at.elapsed(),
                    ));
                }
            }
            ws.send(Message::text(r#"{"_tag":"Ack","requestId":1}"#))
                .await
                .unwrap();
            if !removed.is_empty() {
                return (removed, ws);
            }
        }
    });
    let b = clients_scenario(&base_b, &home_b, &rt, &w_b, &mut || {
        *armed.lock().unwrap() = Some(Instant::now());
    });
    let (removed, ws) = rt.block_on(stream).unwrap();
    drop(ws);
    println!("stream clientRemoved after Rust's revoke: {removed:?}");
    assert_eq!(removed[0].0, b.ids[0], "clientRemoved for B");

    for (x, y) in a.steps.iter().zip(&b.steps) {
        println!("{}: {} {}", x.0, x.1, x.3);
        assert_eq!((x.0, x.1, &x.3), (y.0, y.1, &y.3), "step {}", x.0);
        assert!(!x.2, "A is Node's: {}", x.0);
        assert!(y.2, "B is Rust's: {}", y.0);
    }
    assert_eq!(a.steps.len(), b.steps.len());
    let last = &b.steps[b.steps.len() - 2].3;
    assert_eq!(
        last.as_array().unwrap().len(),
        1,
        "only the current session: {last}"
    );
    assert_eq!(
        b.steps[b.steps.len() - 1].3,
        serde_json::json!({"revokedCount": 0})
    );
    println!(
        "proxied socket close: Node (A) {:?} {}, Rust (B) {:?} {}",
        a.proxied.0, a.proxied.1, b.proxied.0, b.proxied.1
    );
    println!(
        "direct socket close: Node (A) {:?} {}, Rust (B) {:?} {}",
        a.direct.0, a.direct.1, b.direct.0, b.direct.1
    );
    assert!(
        b.proxied.0 < Duration::from_secs(1),
        "proxied close {:?}",
        b.proxied.0
    );
    assert!(
        b.direct.0 < Duration::from_millis(6500),
        "direct close {:?}",
        b.direct.0
    );
    assert_eq!(a.proxied.1, b.proxied.1, "same close frame as Node's");

    let db_b = rusqlite::Connection::open(home_b.join("userdata/statev2.sqlite")).unwrap();
    let rows_b = normalised_tables(&db_b);
    println!("A rows: {rows_a:#}\nB rows: {rows_b:#}");
    assert_eq!(rows_a, rows_b, "auth tables differ");
    drop((db_a, db_b, da, db));
    assert!(!home_a.exists() && !home_b.exists());
}

/// `POST /api/connect/link-proof` as the web client sends it (`linkMachine.ts`: the origin port
/// is the port it talks to) → (status, JWT header + payload with per-call values masked, or the
/// raw body).
fn link_proof(base: &str, cookie: &str) -> (u16, serde_json::Value) {
    use base64::Engine as _;
    let port: u16 = base.rsplit(':').next().unwrap().parse().unwrap();
    let body = serde_json::json!({
        "challenge": "live-test-challenge",
        "relayIssuer": "https://relay.invalid",
        "endpoint": {
            "httpBaseUrl": "http://127.0.0.1:1",
            "wsBaseUrl": "ws://127.0.0.1:1",
            "providerKind": "manual"
        },
        "origin": { "localHttpHost": "127.0.0.1", "localHttpPort": port }
    });
    let (code, out) = curl(&[
        "-X",
        "POST",
        "-H",
        &format!("cookie: {cookie}"),
        "-H",
        "content-type: application/json",
        "-d",
        &body.to_string(),
        &format!("{base}/api/connect/link-proof"),
    ]);
    let Ok(serde_json::Value::String(jwt)) = serde_json::from_str(&out) else {
        return (code, serde_json::Value::String(out));
    };
    let part = |i: usize| -> serde_json::Value {
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(i).unwrap())
            .unwrap();
        serde_json::from_slice(&b).unwrap()
    };
    let mut payload = part(1);
    for k in ["jti", "iat", "exp"] {
        payload[k] = "<masked>".into();
    }
    payload["origin"]["localHttpPort"] = "<port>".into();
    (
        code,
        serde_json::json!({ "header": part(0), "payload": payload }),
    )
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn link_proof_through_daemon_matches_direct() {
    let Some((_d, base, home, token)) = start("link-proof") else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let direct = link_proof(&engine_base(&home), &cookie);
    let proxied = link_proof(&base, &cookie);
    assert_eq!(direct.0, 200, "direct: {}", direct.1);
    assert_eq!(proxied, direct);
}

/// One raw GET (reqwest sends no `accept-encoding` of its own here): (status, headers, body).
async fn raw_get(
    http: &reqwest::Client,
    url: &str,
    h: &[(&str, &str)],
) -> (u16, reqwest::header::HeaderMap, Vec<u8>) {
    let mut r = http.get(url);
    for (k, v) in h {
        r = r.header(*k, *v);
    }
    let r = r.send().await.unwrap();
    let (status, headers) = (r.status().as_u16(), r.headers().clone());
    (status, headers, r.bytes().await.unwrap().to_vec())
}

/// Plan 6B Task 3 against Node: the schema gate accepts the engine's DB, Node rejects requests
/// without the protocol header (so Rust declines them), Rust's 404 body is Node's, and Rust's
/// compression picks Node's encoding and headers for every `accept-encoding` on a small, a
/// threshold and a large JSON body (decoded bytes equal; compressed-byte identity reported).
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn read_plumbing_matches_node() {
    use axum::http::Response;
    use vekrel::{compression, http_errors, http_seam};
    // cwd = the temp home: the engine's automatic cwd project stays small (no git identity).
    let Some((d, base, home, token)) = start_with("plumbing", |home, cmd| {
        cmd.current_dir(home);
    }) else {
        return;
    };
    let cookie = format!("cookie: {}", pair(&base, &home, &token));
    let ck = cookie.trim_start_matches("cookie: ").to_owned();

    // The gate accepts the DB the engine just migrated.
    let db = vekrel::db::read::StateDb::new(&home.join("userdata"));
    let n = db.read(|c| {
        c.query_row("SELECT count(*) FROM projection_projects", [], |r| {
            r.get::<_, i64>(0)
        })
    });
    assert!(n.is_ok(), "gate or read failed: {n:?}");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let http = reqwest::Client::new();
    let proto = ("x-t3-orchestration-protocol", "2");
    rt.block_on(async {
        let shell = format!("{base}/api/orchestration/shell");
        let c = ("cookie", ck.as_str());
        for (h, want) in [
            (vec![c], 400),
            (vec![c, ("x-t3-orchestration-protocol", "1")], 400),
            (vec![c, proto], 200),
        ] {
            let (s, _, _) = raw_get(&http, &shell, &h).await;
            assert_eq!(s, want, "{h:?}");
        }
        // Node's 404 body and headers, traceId aside.
        let (s, h, body) = raw_get(
            &http,
            &format!("{base}/api/orchestration/threads/nope"),
            &[c, proto],
        )
        .await;
        assert_eq!(s, 404);
        let rust = http_errors::not_found("thread_not_found");
        let mask = |b: &[u8]| {
            let mut v: serde_json::Value = serde_json::from_slice(b).unwrap();
            v["traceId"] = "T".into();
            v.to_string()
        };
        assert_eq!(mask(&body), mask(rust.body()));
        assert_eq!(
            body.len(),
            rust.body().len(),
            "same bytes once the 32-char id is swapped"
        );
        for k in ["content-type", "vary", "access-control-allow-origin"] {
            assert_eq!(h.get(k), rust.headers().get(k), "{k}");
        }
    });

    let mutate =
        |body: serde_json::Value| post(&base, &ck, "/api/projects/mutate", &body.to_string());
    let ws = home.join("projects");
    let create = |i: usize, title: &str| {
        mutate(serde_json::json!({
            "type": "project.create", "commandId": format!("cmd-create-{i}"),
            "projectId": format!("project-{i}"), "title": title,
            "workspaceRoot": ws.join(format!("p{i}")).to_string_lossy(),
            "createWorkspaceRootIfMissing": true,
        }))
    };
    let projects = format!("{base}/api/projects");
    let len = || {
        rt.block_on(raw_get(&http, &projects, &[("cookie", &ck)]))
            .2
            .len()
    };
    let accepts: [Option<&str>; 20] = [
        None,
        Some(""),
        Some("gzip"),
        Some("br"),
        Some("deflate"),
        Some("gzip, br"),
        Some("gzip, deflate, br, zstd"),
        Some("br;q=0, gzip"),
        Some("gzip;q=0.5, deflate;q=0.9"),
        Some("identity"),
        Some("*"),
        Some("*;q=0"),
        Some("br;q=0, *"),
        Some("GZIP"),
        Some("gzip;q=0.000"),
        Some("gzip ; Q=0.001"),
        Some("gzip;q=1.5, br"),
        Some("gzip;level=1, br"),
        Some("zstd"),
        Some("x-gzip, gzip;q=0"),
    ];
    let mut identical = std::collections::BTreeMap::<&str, (usize, usize)>::new();
    let mut matrix = |label: &str| {
        for ae in accepts {
            let mut h = vec![("cookie", ck.as_str())];
            if let Some(ae) = ae {
                h.push(("accept-encoding", ae));
            }
            let (s, nh, nb) = rt.block_on(raw_get(&http, &projects, &h));
            assert_eq!(s, 200);
            let enc = nh.get("content-encoding");
            let plain = http_seam::decoded(enc, nb.clone().into()).expect("decodable");
            let input = Response::builder()
                .header("content-type", nh["content-type"].clone())
                .header("access-control-allow-origin", "*")
                .body(plain.clone())
                .unwrap();
            let r = compression::compress(ae, input);
            let what = format!("{label} ({} bytes) accept-encoding {ae:?}", plain.len());
            assert_eq!(r.headers().get("content-encoding"), enc, "{what}");
            assert_eq!(r.headers().get("vary"), nh.get("vary"), "{what}");
            // Node sends a length, never chunked; Rust's length is the body's (hyper sets it).
            assert_eq!(nh.get("transfer-encoding"), None, "{what}");
            assert_eq!(nh["content-length"], nb.len().to_string(), "{what}");
            let names = |m: &reqwest::header::HeaderMap| {
                let mut v: Vec<String> = m
                    .keys()
                    .map(|k| k.to_string())
                    .filter(|k| {
                        !["date", "connection", "keep-alive", "content-length"]
                            .contains(&k.as_str())
                    })
                    .collect();
                v.sort();
                v
            };
            assert_eq!(names(r.headers()), names(&nh), "{what}");
            let rd =
                http_seam::decoded(r.headers().get("content-encoding"), r.body().clone()).unwrap();
            assert_eq!(rd, plain, "{what}");
            if let Some(e) = enc {
                let e = e.to_str().unwrap().to_owned().leak();
                let t = identical.entry(e).or_default();
                t.1 += 1;
                if r.body()[..] == nb[..] {
                    t.0 += 1;
                }
            }
        }
        println!("{label}: {} accept-encodings agree", accepts.len());
    };
    matrix("the cwd project");
    // One project, titled so the body is 1023 bytes, then 1024 (Effect's threshold).
    create(0, "t");
    let pad = 1023 - len() as i64;
    assert!(pad >= 0, "two projects already over 1 KiB");
    let rename = |i: usize, title: String| {
        mutate(serde_json::json!({
            "type": "project.update", "commandId": format!("cmd-rename-{i}-{}", title.len()),
            "projectId": format!("project-{i}"), "title": title,
        }))
    };
    rename(0, "t".repeat(1 + pad as usize));
    assert_eq!(len(), 1023);
    matrix("just under the threshold");
    rename(0, "t".repeat(2 + pad as usize));
    assert_eq!(len(), 1024);
    matrix("at the threshold");
    for i in 1..40 {
        create(
            i,
            &format!("Project {i} with a longer title for a body of some size"),
        );
    }
    matrix("40 projects");
    for (e, (same, all)) in &identical {
        println!("compressed bytes identical to Node's: {e} {same}/{all}");
    }
    drop(d);
    assert!(!home.exists());
}

/// Every row of every `orchestration_*`, `projection_*` and legacy-import table, for "Rust wrote
/// nothing" checks.
fn data_tables(db: &rusqlite::Connection) -> Vec<(String, Vec<String>)> {
    let mut q = db
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND (name LIKE 'orchestration%' \
             OR name LIKE 'projection%') ORDER BY name",
        )
        .unwrap();
    let names: Vec<String> = q
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    names
        .into_iter()
        .map(|t| {
            let mut q = db.prepare(&format!("SELECT * FROM \"{t}\"")).unwrap();
            let n = q.column_count();
            let mut rows: Vec<String> = q
                .query_map([], |r| {
                    let cols: Vec<rusqlite::types::Value> =
                        (0..n).map(|i| r.get(i)).collect::<Result<_, _>>()?;
                    Ok(format!("{cols:?}"))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            rows.sort();
            (t, rows)
        })
        .collect()
}

/// Sends each payload as `orchestration.searchThreads` on one socket, one request at a time.
/// Returns the client's raw `exit` text and Rust's log outcome for it: `match` / `mismatch` /
/// `declined` (shadow waits for one of them), or `served` (serve mode, no decline line).
fn search_threads(
    base: &str,
    home: &Path,
    cookie: &str,
    payloads: &[serde_json::Value],
    serve: bool,
) -> Vec<(String, String)> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let outcomes = || -> Vec<String> {
        log(home)
            .lines()
            .filter(|l| l.contains("tag=\"orchestration.searchThreads\""))
            .filter_map(|l| {
                ["match", "mismatch", "declined"]
                    .into_iter()
                    .find(|o| l.contains(&format!("outcome=\"{o}\"")))
                    .map(str::to_owned)
            })
            .collect()
    };
    let port = base.rsplit(':').next().unwrap().to_owned();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut c = auth_ws(&port, cookie).await;
        let mut out = Vec::new();
        for (id, payload) in payloads.iter().enumerate() {
            let seen = outcomes().len();
            let r = serde_json::json!({"_tag":"Request","id":id.to_string(),
                "tag":"orchestration.searchThreads","payload":payload,"headers":[]});
            c.send(Message::text(r.to_string())).await.unwrap();
            let exit = loop {
                let m = tokio::time::timeout(Duration::from_secs(60), c.next()).await;
                let Ok(Some(Ok(Message::Text(t)))) = m else {
                    panic!("no frame: {m:?}")
                };
                #[derive(serde::Deserialize)]
                struct F<'a> {
                    #[serde(rename = "_tag")]
                    tag: &'a str,
                    #[serde(rename = "requestId")]
                    id: Option<String>,
                    #[serde(borrow)]
                    exit: Option<&'a serde_json::value::RawValue>,
                }
                if let Ok(f) = serde_json::from_str::<F>(t.as_str())
                    && f.tag == "Exit"
                    && f.id == Some(id.to_string())
                {
                    break f.exit.unwrap().get().to_owned();
                }
            };
            // Shadow: Rust's line comes when both answers are in; serve: a decline is logged
            // before Node is asked.
            let deadline = Instant::now() + Duration::from_secs(if serve { 0 } else { 60 });
            let outcome = loop {
                if let Some(o) = outcomes().get(seen) {
                    break o.clone();
                }
                if Instant::now() >= deadline {
                    break if serve { "served" } else { "none" }.to_owned();
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            out.push((exit, outcome));
        }
        out
    })
}

/// The payloads of `tests/golden/thread_search.json`, over `tests/fixtures/thread_search.sql`.
fn thread_search_payloads() -> Vec<serde_json::Value> {
    use serde_json::json;
    let q = |s: &str| json!({ "query": s });
    let mut v: Vec<serde_json::Value> = [
        "foo",
        "FOO",
        "hello",
        "HELLO world",
        "Hello World foo",
        "100%",
        "e_w",
        "h!",
        "%%",
        "__",
        "!!",
        "!%",
        "ärger",
        "Ärger",
        "Öl 🎉",
        "🎉",
        "midneedle",
        "MIDNEEDLE",
        "startneedle",
        "endneedle",
        "exactfit",
        "overfit",
        "emojicut",
        "emojiend",
        "emojiin",
        "wsmark",
        "line",
        "double  space",
        "Double SPACE",
        "spacedcut",
        "tie break",
        " foo ",
        "\u{a0}foo\u{feff}",
        "\tfoo\n",
        "paddedid",
        "345",
        "hiddenkey",
        "streamingonly",
        "systemonly",
        "archivedonly",
        "deletedonly",
        "goneproject",
        "bulk item",
        "item 0",
        "nomatchatall",
        "",
        " a ",
        "   ",
        "ab",
    ]
    .iter()
    .map(|s| q(s))
    .collect();
    v.extend([
        q(&"b".repeat(200)),
        q(&"b".repeat(201)),
        q(&format!("  {}  ", "b".repeat(200))),
        q(&"🎉".repeat(100)),
        q(&"🎉".repeat(101)),
        json!({"query": "bulk item", "limit": 1}),
        json!({"query": "bulk item", "limit": 50}),
        json!({"query": "bulk item", "limit": 7}),
        json!({"query": "bulk item", "limit": 10.0}),
        json!({"query": "bulk item", "limit": 0}),
        json!({"query": "bulk item", "limit": 51}),
        json!({"query": "bulk item", "limit": 1.5}),
        json!({"query": "bulk item", "limit": -1}),
        json!({"query": "bulk item", "limit": "2"}),
        json!({"query": "bulk item", "limit": null}),
        json!({"query": "foo", "extra": true}),
        json!({"query": 5}),
        json!({"query": null}),
        json!({}),
        json!("foo"),
        json!(null),
    ]);
    v
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn thread_search_shadow_matches_node() {
    let golden_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/thread_search.json"
    );
    let fixture = include_str!("fixtures/thread_search.sql");
    let payloads = thread_search_payloads();
    let load = |home: &Path| {
        let db = rusqlite::Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
        db.busy_timeout(Duration::from_secs(10)).unwrap();
        db.execute_batch(fixture).unwrap();
        db
    };

    // Shadow: Node answers; Rust's answer is compared in the daemon.
    let Some((d, base, home, token)) = start_with("search", |home, cmd| {
        cmd.current_dir(home);
    }) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let db = load(&home);
    let before = data_tables(&db);
    let shadow = search_threads(&base, &home, &cookie, &payloads, false);
    assert_eq!(
        before,
        data_tables(&db),
        "the DB changed during a shadow run"
    );
    drop((db, d));

    let golden: Vec<serde_json::Value> = payloads
        .iter()
        .zip(&shadow)
        .map(|(p, (exit, o))| {
            let rust = if o == "declined" {
                "declined"
            } else {
                "served"
            };
            serde_json::json!({"payload": p, "rust": rust, "exit": exit})
        })
        .collect();
    let count = |o: &str| shadow.iter().filter(|s| s.1 == o).count();
    println!(
        "searchThreads shadow: {} match, {} mismatch, {} declined, {} without a line (of {})",
        count("match"),
        count("mismatch"),
        count("declined"),
        count("none"),
        shadow.len()
    );
    for (p, (exit, o)) in payloads.iter().zip(&shadow) {
        if o != "match" && o != "declined" {
            println!("{o}: {p} -> {exit}");
        }
    }
    assert_eq!(count("mismatch") + count("none"), 0);
    if std::env::var_os("VEKREL_WRITE_GOLDEN").is_some() {
        let text = serde_json::to_string_pretty(&golden).unwrap() + "\n";
        std::fs::write(golden_path, text).unwrap();
    }
    let committed: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(golden_path).unwrap()).unwrap();
    assert_eq!(golden, committed, "Node no longer answers like the golden");

    // Serve: Rust answers what it served in shadow, byte for byte, and writes nothing.
    let Some((d, base, home, token)) = start_with("search-serve", |home, cmd| {
        cmd.current_dir(home);
        let cfg = home.join("vekrel.toml");
        let t = std::fs::read_to_string(&cfg).unwrap();
        std::fs::write(&cfg, t + "\"orchestration.searchThreads\" = \"serve\"\n").unwrap();
    }) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let db = load(&home);
    let before = data_tables(&db);
    let served = search_threads(&base, &home, &cookie, &payloads, true);
    assert_eq!(
        before,
        data_tables(&db),
        "the DB changed during a served run"
    );
    drop((db, d));
    for (g, (exit, o)) in golden.iter().zip(&served) {
        assert_eq!(g["rust"], o.as_str(), "{}", g["payload"]);
        assert_eq!(g["exit"], exit.as_str(), "{}", g["payload"]);
    }
    assert!(!home.exists());
}

mod support {
    pub mod real_db;
}

/// `VEKREL_REAL_DB`: the owner's projects, threads and messages copied into the live engine's
/// temp DB, then queries drawn from the threads' own titles, compared in shadow. Nothing from the
/// copy is printed or written outside the temp dirs.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs> and VEKREL_REAL_DB"]
fn thread_search_real_db_shadow_matches_node() {
    use rusqlite::{Connection, OpenFlags};
    let Some(copy) = support::real_db::real_db() else {
        return;
    };
    let titles: Vec<String> = {
        let c = Connection::open_with_flags(copy, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let mut q = c
            .prepare(
                "SELECT title FROM orchestration_v2_projection_threads \
                 WHERE deleted_at IS NULL ORDER BY thread_id",
            )
            .unwrap();
        q.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let n = 60.min(titles.len());
    let payloads: Vec<serde_json::Value> = (0..n)
        .map(|i| {
            let title = &titles[i * titles.len() / n];
            let words: Vec<&str> = title.split_whitespace().collect();
            let longest = words
                .iter()
                .copied()
                .max_by_key(|w| w.chars().count())
                .unwrap_or(title.as_str());
            let query = match i % 4 {
                0 => longest.to_owned(),
                1 => longest.to_ascii_uppercase(),
                _ => words.iter().take(3).copied().collect::<Vec<_>>().join(" "),
            };
            match i % 4 {
                3 => serde_json::json!({"query": query, "limit": i % 50 + 1}),
                _ => serde_json::json!({ "query": query }),
            }
        })
        .collect();

    let Some((d, base, home, token)) = start_with("search-real", |home, cmd| {
        cmd.current_dir(home);
    }) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let db = Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    db.execute("ATTACH DATABASE ?1 AS r", [copy.to_str().unwrap()])
        .unwrap();
    for t in [
        "projection_projects",
        "orchestration_v2_projection_threads",
        "orchestration_v2_projection_messages",
    ] {
        db.execute(
            &format!("INSERT OR IGNORE INTO main.{t} SELECT * FROM r.{t}"),
            [],
        )
        .unwrap();
    }
    db.execute_batch("DETACH DATABASE r").unwrap();
    let before = data_tables(&db);
    let shadow = search_threads(&base, &home, &cookie, &payloads, false);
    assert_eq!(
        before,
        data_tables(&db),
        "the DB changed during a shadow run"
    );
    drop((db, d));
    let count = |o: &str| shadow.iter().filter(|s| s.1 == o).count();
    let hits = shadow
        .iter()
        .filter(|s| {
            s.0.starts_with(r#"{"_tag":"Success","value":{"matches":[{"#)
        })
        .count();
    println!(
        "searchThreads over the owner DB: {} match, {} mismatch, {} declined, {} without a line \
         (of {}; {hits} with at least one match)",
        count("match"),
        count("mismatch"),
        count("declined"),
        count("none"),
        shadow.len()
    );
    assert_eq!(count("mismatch") + count("none"), 0);
    assert!(count("match") * 10 >= shadow.len() * 9, "too many declines");
    assert!(!home.exists());
}

const PROJECTS: &str = "GET /api/projects";
const PROJECT_COLS: &str = "project_id, title, workspace_root, default_model_selection_json, \
    default_thread_env_mode, auto_pull, favicon_path, project_icon_json, scripts_json, \
    created_at, updated_at, deleted_at";

/// Replaces the engine's `projection_projects` rows (the test's own temp DB, behind Node's back:
/// `ProjectService.snapshot` reads the table on every request).
fn set_projects(home: &Path, values: &str) {
    let c = rusqlite::Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
    c.busy_timeout(Duration::from_secs(10)).unwrap();
    c.execute_batch("DELETE FROM projection_projects").unwrap();
    if !values.is_empty() {
        c.execute_batch(&format!(
            "INSERT INTO projection_projects ({PROJECT_COLS}) VALUES {values}"
        ))
        .unwrap();
    }
}

/// A mismatch only at `repositoryIdentity` / `faviconPath` (Node's warm cache, Rust's `null`).
const ENRICHED: &str = "mismatch(enrichment)";

/// Shadow outcomes logged for `GET /api/projects`, by outcome.
fn projects_outcomes(home: &Path) -> std::collections::BTreeMap<String, usize> {
    std::thread::sleep(Duration::from_millis(300));
    let mut m = std::collections::BTreeMap::new();
    for l in log(home).lines() {
        if !l.contains(&format!("route=\"{PROJECTS}\"")) {
            continue;
        }
        if let Some(o) = l.split("outcome=").nth(1) {
            let mut o = o.split_whitespace().next().unwrap().trim_matches('"');
            // Enrichment-only differences are mismatches, labelled by `field`.
            if o == "mismatch" && l.contains("field=\"enrichment\"") {
                o = ENRICHED;
            }
            *m.entry(o.to_owned()).or_default() += 1;
            if !["match", "declined", ENRICHED].contains(&o) {
                println!("{l}");
            }
        }
    }
    m
}

/// Plan 6B Task 5: `GET /api/projects` in shadow (its default) over the engine's cwd project, the
/// golden rows (Node's body is the golden), rows Rust must decline, a git workspace Node enriches,
/// and with `VEKREL_REAL_DB` the owner's real project rows. Every compared answer matches.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn projects_shadow_matches_node() {
    let Some((d, base, home, token)) = start_with("projects", |home, cmd| {
        cmd.current_dir(home);
    }) else {
        return;
    };
    let ck = pair(&base, &home, &token);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let http = reqwest::Client::new();
    let url = format!("{base}/api/projects");
    let fetch = |ae: Option<&str>| {
        let mut h = vec![("cookie", ck.as_str())];
        if let Some(ae) = ae {
            h.push(("accept-encoding", ae));
        }
        let (s, nh, nb) = rt.block_on(raw_get(&http, &url, &h));
        assert_eq!(s, 200);
        assert!(
            nh.get("x-vekrel-served-by").is_none(),
            "shadow: Node answers"
        );
        let plain = vekrel::http_seam::decoded(nh.get("content-encoding"), nb.into()).unwrap();
        String::from_utf8(plain.to_vec()).unwrap()
    };
    let round = || {
        for ae in [None, Some("gzip"), Some("br"), Some("gzip, deflate, br")] {
            fetch(ae);
        }
    };
    round();

    // The golden rows: Node's body, `updatedAt` pinned, is the golden Rust's unit test renders.
    set_projects(&home, include_str!("golden/projects_rows.sql"));
    let node = fetch(None);
    let mut v: serde_json::Value = serde_json::from_str(&node).unwrap();
    v["updatedAt"] = "2030-01-01T00:00:00.123Z".into();
    let pinned = serde_json::to_string(&v).unwrap();
    println!("NODE_GOLDEN={pinned}");
    assert_eq!(
        pinned,
        include_str!("golden/projects.json").trim_end(),
        "Node's body for the golden rows"
    );
    round();
    let after_golden = projects_outcomes(&home);

    // Rows Node reshapes (trims) or rejects (500): Rust declines each.
    let declines = [
        "('p', ' padded', '/w', NULL, NULL, 0, NULL, NULL, '[]', 'c', 'u', NULL)",
        r#"('p', 'T', '/w', '{"provider":"codex","model":"m"}', NULL, 0, NULL, NULL, '[]', 'c', 'u', NULL)"#,
        r#"('p', 'T', '/w', NULL, NULL, 0, NULL, '{"kind":"lucide","name":"a","color":"red","monogramText":"AB"}', '[]', 'c', 'u', NULL)"#,
        "('p', 'T', '/w', NULL, NULL, 2, NULL, NULL, '[]', 'c', 'u', NULL)",
    ];
    let before = projects_outcomes(&home)
        .get("declined")
        .copied()
        .unwrap_or(0);
    for row in declines {
        set_projects(&home, row);
        let (s, _, _) = rt.block_on(raw_get(&http, &url, &[("cookie", ck.as_str())]));
        println!("Node answers {s} for {row}");
    }
    let after = projects_outcomes(&home)
        .get("declined")
        .copied()
        .unwrap_or(0);
    assert_eq!(after - before, declines.len(), "each row declines");

    // A git workspace: once Node's enrichment cache is warm, its repositoryIdentity is counted.
    let repo = env!("CARGO_MANIFEST_DIR");
    set_projects(
        &home,
        &format!("('git', 'Daemon', '{repo}', NULL, NULL, 0, NULL, NULL, '[]', 'c', 'u', NULL)"),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let v: serde_json::Value = serde_json::from_str(&fetch(None)).unwrap();
        if !v["projects"][0]["repositoryIdentity"].is_null() {
            break;
        }
        assert!(Instant::now() < deadline, "Node never enriched the repo");
        std::thread::sleep(Duration::from_millis(500));
    }
    let warm = projects_outcomes(&home);
    assert!(warm.get(ENRICHED).copied().unwrap_or(0) >= 1, "{warm:?}");

    // The owner's real projects (rows only, from the local copy; nothing is written to the repo).
    if let Some(copy) = support::real_db::real_db() {
        let src = home.join("userdata/statev2.sqlite");
        let live = rusqlite::Connection::open(&src).unwrap();
        live.busy_timeout(Duration::from_secs(10)).unwrap();
        let ro = format!("file:{}?mode=ro", copy.display());
        live.execute("ATTACH ?1 AS real", [ro]).unwrap();
        live.execute_batch(&format!(
            "DELETE FROM projection_projects; INSERT INTO projection_projects ({PROJECT_COLS}) \
             SELECT {PROJECT_COLS} FROM real.projection_projects; DETACH real;"
        ))
        .unwrap();
        let n: i64 = live
            .query_row(
                "SELECT count(*) FROM projection_projects WHERE deleted_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        drop(live);
        let before = projects_outcomes(&home);
        for _ in 0..3 {
            round();
            std::thread::sleep(Duration::from_secs(1));
        }
        let after = projects_outcomes(&home);
        let delta =
            |k: &str| after.get(k).copied().unwrap_or(0) - before.get(k).copied().unwrap_or(0);
        println!(
            "owner DB: {n} live projects; match {}, mismatch(enrichment) {}, declined {}",
            delta("match"),
            delta(ENRICHED),
            delta("declined")
        );
        assert_eq!(delta("declined"), 0, "Rust serves every real row");
        assert_eq!(delta("match") + delta(ENRICHED), 12);
    }

    let all = projects_outcomes(&home);
    println!("GET /api/projects shadow outcomes: {all:?} (after golden: {after_golden:?})");
    let compared = all.get("match").copied().unwrap_or(0) + all.get(ENRICHED).copied().unwrap_or(0);
    let other: usize = all
        .iter()
        .filter(|(k, _)| !["match", "declined", ENRICHED].contains(&k.as_str()))
        .map(|(_, n)| n)
        .sum();
    assert_eq!(other, 0, "no mismatch or skipped comparison: {all:?}");
    assert!(
        after_golden.get("match").copied().unwrap_or(0) >= 9,
        "{after_golden:?}"
    );
    assert!(compared >= 10);
    drop(d);
    assert!(!home.exists());
}

/// Plan 6B Task 5: `GET /api/projects` configured `serve` is downgraded to `shadow` at startup
/// (Rust cannot see Node's enrichment cache): a warning, Node answers every request, and Rust's
/// answer is still compared.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn projects_serve_config_is_downgraded_to_shadow() {
    let Some((d, base, home, token)) = start_with("projects-serve", |home, cmd| {
        cmd.current_dir(home);
        let cfg = home.join("vekrel.toml");
        let t = std::fs::read_to_string(&cfg).unwrap();
        std::fs::write(&cfg, t + &format!("\"{PROJECTS}\" = \"serve\"\n")).unwrap();
    }) else {
        return;
    };
    assert!(
        log(&home).contains("GET /api/projects runs in shadow"),
        "startup warning"
    );
    let ck = pair(&base, &home, &token);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let http = reqwest::Client::new();
    for ae in [None, Some("gzip"), Some("br")] {
        let mut h = vec![("cookie", ck.as_str())];
        if let Some(ae) = ae {
            h.push(("accept-encoding", ae));
        }
        let (s, rh, _) = rt.block_on(raw_get(&http, &format!("{base}/api/projects"), &h));
        assert_eq!(s, 200);
        assert!(rh.get("x-vekrel-served-by").is_none(), "Node answers");
    }
    // Unauthenticated too: Node's own 401.
    let (s, rh, _) = rt.block_on(raw_get(&http, &format!("{base}/api/projects"), &[]));
    assert_eq!(s, 401);
    assert!(rh.get("x-vekrel-served-by").is_none());
    let o = projects_outcomes(&home);
    assert!(
        o.get("match").copied().unwrap_or(0) >= 3,
        "still shadowed: {o:?}"
    );
    drop(d);
    assert!(!home.exists());
}

/// The engine may not reach an AI provider: no provider CLI on `PATH` (the engine runs from an
/// absolute `node`), an empty `HOME` (no provider credentials), and no restart continuation of the
/// runs a copied DB holds (`continueThreadsAfterServerUpdate` defaults to true).
fn isolate_engine(home: &Path, cmd: &mut Command) {
    let node = std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("node"))
                .find(|n| n.is_file())
        })
        .expect("node on PATH");
    let cfg = home.join("vekrel.toml");
    let t = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        t.replace("command = \"node\"", &format!("command = {:?}", node)),
    )
    .unwrap();
    std::fs::create_dir_all(home.join("userdata")).unwrap();
    std::fs::create_dir_all(home.join("fakehome")).unwrap();
    std::fs::write(
        home.join("userdata/settings.json"),
        r#"{"continueThreadsAfterServerUpdate":false}"#,
    )
    .unwrap();
    cmd.current_dir(home)
        .env("HOME", home.join("fakehome"))
        .env("PATH", "/usr/bin:/bin");
}

/// Node's `GET /api/orchestration/shell` from the engine port: (status, snapshotSequence, raw
/// thread texts, body).
fn node_shell(home: &Path, cookie: &str) -> (u16, i64, Vec<String>, String) {
    let (code, body) = curl(&[
        "-H",
        &format!("cookie: {cookie}"),
        "-H",
        "x-t3-orchestration-protocol: 2",
        &format!("{}/api/orchestration/shell", engine_base(home)),
    ]);
    if code != 200 {
        return (code, 0, vec![], body);
    }
    let (seq, threads) = raw_threads(&body);
    (code, seq, threads, body)
}

/// `snapshotSequence` and each `threads[i]` as Node's bytes.
fn raw_threads(body: &str) -> (i64, Vec<String>) {
    #[derive(serde::Deserialize)]
    struct Shell<'a> {
        #[serde(rename = "snapshotSequence")]
        seq: i64,
        #[serde(borrow)]
        threads: Vec<&'a serde_json::value::RawValue>,
    }
    let s: Shell = serde_json::from_str(body).unwrap();
    (
        s.seq,
        s.threads.iter().map(|t| t.get().to_owned()).collect(),
    )
}

/// Node's `orchestration.getArchivedShellSnapshot` over the daemon's WS: (snapshotSequence,
/// threads re-encoded with `effect_json`, the bytes `JSON.stringify` gives for parsed JSON).
fn node_archived(base: &str, cookie: &str) -> (i64, Vec<String>) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let port = base.rsplit(':').next().unwrap().to_owned();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut c = auth_ws(&port, cookie).await;
        let r = serde_json::json!({"_tag":"Request","id":41,"tag":"orchestration.getArchivedShellSnapshot",
            "payload":{},"headers":[]});
        c.send(Message::text(r.to_string())).await.unwrap();
        loop {
            let m = tokio::time::timeout(Duration::from_secs(60), c.next()).await;
            let Ok(Some(Ok(Message::Text(t)))) = m else {
                panic!("no frame: {m:?}")
            };
            let v: serde_json::Value = vekrel::effect_json::parse(t.as_str()).unwrap();
            let Some(exit) = v
                .as_array()
                .cloned()
                .unwrap_or(vec![v])
                .into_iter()
                .find(|m| m["_tag"] == "Exit" && m["requestId"] == 41)
            else {
                continue;
            };
            assert_eq!(exit["exit"]["_tag"], "Success", "{exit}");
            let value = &exit["exit"]["value"];
            let threads = value["threads"].as_array().unwrap();
            return (
                value["snapshotSequence"].as_i64().unwrap(),
                threads
                    .iter()
                    .map(|t| String::from_utf8(vekrel::effect_json::to_vec(t)).unwrap())
                    .collect(),
            );
        }
    })
}

/// Rust's builder on `home`'s DB: (latestApplicationSequence, threads), one read transaction.
fn rust_shell(
    home: &Path,
    location: vekrel::shell::Location,
) -> (i64, Result<Vec<serde_json::Value>, vekrel::shell::Decline>) {
    let db = vekrel::db::read::StateDb::new(&home.join("userdata"));
    db.read(|c| {
        Ok((
            vekrel::shell::latest_application_sequence(c)?,
            vekrel::shell::build_threads(c, location),
        ))
    })
    .unwrap_or_else(|e| panic!("read: {e:?}"))
}

/// Every JSON path (array indexes as `[]`) where `a` and `b` differ, key order included.
fn diff_paths(a: &serde_json::Value, b: &serde_json::Value, path: &str, out: &mut Vec<String>) {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            if !x.keys().eq(y.keys()) {
                out.push(format!("{path}.<key order>"));
            }
            for (k, v) in x {
                match y.get(k) {
                    Some(w) => diff_paths(v, w, &format!("{path}.{k}"), out),
                    None => out.push(format!("{path}.{k} <only node>")),
                }
            }
            for k in y.keys().filter(|k| !x.contains_key(*k)) {
                out.push(format!("{path}.{k} <only rust>"));
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            if x.len() != y.len() {
                out.push(format!("{path}.length"));
            }
            for (v, w) in x.iter().zip(y) {
                diff_paths(v, w, &format!("{path}[]"), out);
            }
        }
        _ if vekrel::effect_json::to_vec(a) != vekrel::effect_json::to_vec(b) => {
            out.push(path.to_owned())
        }
        _ => {}
    }
}

/// Node's thread texts against Rust's values: mismatch counts by JSON path and the differing
/// thread ids (ids and paths only, never content).
fn shell_mismatches(
    node: &[String],
    rust: &[serde_json::Value],
) -> (std::collections::BTreeMap<String, usize>, Vec<String>) {
    let mut paths = std::collections::BTreeMap::<String, usize>::new();
    let mut ids = Vec::new();
    let rust_text: Vec<Vec<u8>> = rust.iter().map(vekrel::effect_json::to_vec).collect();
    if node.len() != rust.len() {
        *paths.entry("threads.length".into()).or_default() += 1;
    }
    for (i, n) in node.iter().enumerate() {
        let nv: serde_json::Value = vekrel::effect_json::parse(n).unwrap();
        let id = nv["id"].as_str().unwrap_or_default().to_owned();
        let Some(j) = rust.iter().position(|r| r["id"] == nv["id"]) else {
            *paths.entry("threads[] <only node>".into()).or_default() += 1;
            ids.push(id);
            continue;
        };
        if i != j {
            *paths.entry("threads[] <order>".into()).or_default() += 1;
        }
        if rust_text[j] != n.as_bytes() {
            let mut out = vec![];
            diff_paths(&nv, &rust[j], "threads[]", &mut out);
            if out.is_empty() {
                out.push("threads[] <bytes>".into());
            }
            for p in out {
                *paths.entry(p).or_default() += 1;
            }
            ids.push(id);
        }
    }
    (paths, ids)
}

/// Plan 6B Task 6: the shell builder against Node on the synthetic scenarios (one thread per
/// branch of the TypeScript), active over HTTP and archived over the WS RPC, at the same
/// sequence; plus Node's answer where Rust declines (a drifted payload is Node's 500 too).
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn shell_builder_matches_node_on_fixtures() {
    use vekrel::shell::{Decline, Location, fixture};
    let Some((d, base, home, token)) = start_with("shell-fx", isolate_engine) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let write = |sql: &str| {
        let c = rusqlite::Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
        c.busy_timeout(Duration::from_secs(20)).unwrap();
        c.execute_batch(&format!("BEGIN IMMEDIATE; {sql} COMMIT;"))
            .unwrap();
    };
    write(&fixture::scenarios().0);
    let mut compared = (0, 0);
    for (label, location) in [("active", Location::Active), ("archive", Location::Archive)] {
        let (node, rust) = (0..5)
            .find_map(|_| {
                let (seq, node) = match location {
                    Location::Active => {
                        let (code, seq, threads, body) = node_shell(&home, &cookie);
                        assert_eq!(code, 200, "{body}");
                        (seq, threads)
                    }
                    Location::Archive => node_archived(&base, &cookie),
                };
                let (rseq, rust) = rust_shell(&home, location);
                (rseq == seq).then(|| (node, rust.expect("Rust builds every scenario")))
            })
            .expect("a write moved the sequence between the reads 5 times");
        let fx = node.iter().filter(|t| t.contains(r#""id":"fx-"#)).count();
        let (paths, ids) = shell_mismatches(&node, &rust);
        println!(
            "{label}: {} threads ({fx} fixtures), mismatches {paths:?} in {ids:?}",
            node.len()
        );
        assert!(paths.is_empty(), "{label}: {paths:?} {ids:?}");
        match location {
            Location::Active => compared.0 = fx,
            Location::Archive => compared.1 = fx,
        }
    }
    assert_eq!(compared, (34, 4), "every scenario reached both");

    // A payload Effect rejects: Node's snapshot fails (500), Rust declines with the path.
    let mut drift = fixture::Fx::default();
    drift.thread("fx-drift", 40, serde_json::json!({"runtimeMode": "turbo"}));
    write(&drift.0);
    let (code, _, _, body) = node_shell(&home, &cookie);
    assert_eq!(code, 500, "{body}");
    assert!(body.contains("orchestration_snapshot_failed"), "{body}");
    assert_eq!(
        rust_shell(&home, Location::Active).1,
        Err(Decline::PayloadDrift {
            thread_id: "fx-drift".into(),
            path: "thread.runtimeMode".into()
        })
    );
    write("DELETE FROM orchestration_v2_projection_threads WHERE thread_id = 'fx-drift';");
    // An icon Effect rejects on the presented run's terminal failure: Node 500, Rust declines.
    let mut icon = fixture::Fx::default();
    icon.thread("fx-bad-icon", 41, serde_json::json!({}))
        .run("fx-bad-icon", 1, "failed", serde_json::json!({}))
        .item(
            "fx-bad-icon",
            "fx-bad-icon-e",
            Some(1),
            "error",
            "failed",
            serde_json::json!({
            "nodeId": "fx-bad-icon:run:1:root", "toolIcon": {"_tag": "website"},
            "failure": {"class": "unknown", "message": "m", "code": null, "retryable": null}}),
        );
    write(&icon.0);
    let (code, _, _, body) = node_shell(&home, &cookie);
    assert_eq!(code, 500, "{body}");
    assert_eq!(
        rust_shell(&home, Location::Active).1,
        Err(Decline::PayloadDrift {
            thread_id: "fx-bad-icon".into(),
            path: "terminalFailure.toolIcon".into()
        })
    );
    write("DELETE FROM orchestration_v2_projection_threads WHERE thread_id = 'fx-bad-icon';");
    // A legacy single linked PR: Node answers, Rust declines (URL parser not ported).
    let mut legacy = fixture::Fx::default();
    let mut p = fixture::thread_payload(
        "fx-legacy-pr",
        serde_json::json!({"linkedPullRequest": {"projectId": "p", "repository": "o/r", "number": 1,
            "url": "https://github.com/o/r/pull/1"}}),
    );
    p.as_object_mut().unwrap().remove("pullRequests");
    legacy.thread_raw("fx-legacy-pr", &p);
    write(&legacy.0);
    assert_eq!(node_shell(&home, &cookie).0, 200);
    assert_eq!(
        rust_shell(&home, Location::Active).1.unwrap_err().reason(),
        "not_ported"
    );
    drop(d);
    assert!(!home.exists());
}

/// Plan 6B Task 6, Review Focus 3: the builder against Node on a copy of the owner's DB
/// (`VEKREL_REAL_DB`). The engine runs on the copy (isolated: no provider can start); Node's shell
/// is captured once into a temp dir and compared per thread at the same sequence. Prints
/// mismatch counts by JSON path and the differing thread ids, never content. Rust must neither
/// decline (declined == 0) nor differ.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs> and VEKREL_REAL_DB=<statev2.sqlite>"]
fn shell_builder_matches_node_on_owner_db() {
    use vekrel::shell::Location;
    let Some(src) = std::env::var_os("VEKREL_REAL_DB") else {
        eprintln!("VEKREL_REAL_DB unset: skipping the owner-DB test");
        return;
    };
    let Some((d, base, home, token)) = start_with("shell-owner", |home, cmd| {
        isolate_engine(home, cmd);
        let (dir, copy) = support::real_db::copy_from(Some(src)).unwrap();
        std::fs::rename(&copy, home.join("userdata/statev2.sqlite")).unwrap();
        drop(dir);
    }) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let golden = tempfile::Builder::new()
        .prefix(&support::real_db::pid_prefix("vekrel-shell-golden-"))
        .tempdir()
        .unwrap();
    for (label, location) in [("active", Location::Active), ("archive", Location::Archive)] {
        let mut attempt = 0;
        let (node, rust, node_ms, rust_ms) = loop {
            attempt += 1;
            assert!(attempt <= 5, "sequence moved 5 times");
            let t = Instant::now();
            let (seq, node) = match location {
                Location::Active => {
                    let (code, seq, _, body) = node_shell(&home, &cookie);
                    assert_eq!(code, 200, "Node's shell failed");
                    // Captured once, kept only in the temp dir.
                    let f = golden.path().join("node-shell.json");
                    std::fs::write(&f, &body).unwrap();
                    let (s, threads) = raw_threads(&std::fs::read_to_string(&f).unwrap());
                    assert_eq!(s, seq);
                    (seq, threads)
                }
                Location::Archive => node_archived(&base, &cookie),
            };
            let node_ms = t.elapsed().as_millis();
            let t = Instant::now();
            let (rseq, rust) = rust_shell(&home, location);
            let rust_ms = t.elapsed().as_millis();
            if rseq == seq {
                break (node, rust, node_ms, rust_ms);
            }
            println!("{label}: sequence_skew (Node {seq}, Rust {rseq}), retrying");
        };
        match rust {
            Err(e) => panic!(
                "GOLDEN {label}: Rust declined ({}: {e:?}); Node {} threads",
                e.reason(),
                node.len()
            ),
            Ok(rust) => {
                let (paths, ids) = shell_mismatches(&node, &rust);
                println!(
                    "GOLDEN {label}: {} threads, {} differ, mismatches by path {paths:?}, ids {ids:?}; Node {node_ms} ms, Rust {rust_ms} ms",
                    node.len(),
                    ids.len()
                );
                assert!(paths.is_empty(), "{label}: {paths:?} {ids:?}");
            }
        }
    }
    drop(golden);
    drop(d);
    assert!(!home.exists());
}

/// `orchestration.getTurnItem` requests, one at a time on one socket: each Exit's raw `exit` JSON.
/// Shadow (`home` set): after each Exit, waits until Rust's outcome for it is logged, so Rust's
/// slower reads are neither cut off by the socket closing nor skipped by the shadow limiter.
fn turn_item_exits(
    base: &str,
    cookie: &str,
    payloads: &[serde_json::Value],
    home: Option<&Path>,
) -> Vec<String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
    #[derive(serde::Deserialize)]
    struct Msg {
        #[serde(rename = "_tag")]
        tag: String,
        #[serde(rename = "requestId")]
        request_id: Option<serde_json::Value>,
        exit: Option<Box<serde_json::value::RawValue>>,
    }
    let ws = base.replace("http://", "ws://") + "/ws?orchestrationProtocol=2";
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut req = ws.into_client_request().unwrap();
        let h = req.headers_mut();
        h.insert("cookie", cookie.parse().unwrap());
        h.insert("origin", base.parse().unwrap());
        let (mut c, _) = tokio_tungstenite::connect_async(req).await.expect("ws");
        let mut exits = Vec::new();
        let logged = home.map_or(0, outcome_count);
        for (id, payload) in payloads.iter().enumerate() {
            let r = serde_json::json!({"_tag":"Request","id":id.to_string(),
                "tag":"orchestration.getTurnItem","payload":payload,
                "traceId":"0123456789abcdef0123456789abcdef","spanId":"0123456789abcdef",
                "sampled":true,"headers":[]});
            c.send(Message::text(r.to_string())).await.unwrap();
            loop {
                let m = tokio::time::timeout(Duration::from_secs(30), c.next())
                    .await
                    .expect("reply")
                    .unwrap()
                    .unwrap();
                let Message::Text(t) = m else { continue };
                let msgs: Vec<Msg> = if t.trim_start().starts_with('[') {
                    serde_json::from_str(t.as_str()).unwrap()
                } else {
                    vec![serde_json::from_str(t.as_str()).unwrap()]
                };
                let rid = |m: &Msg| {
                    m.request_id.as_ref().map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        v => v.to_string(),
                    })
                };
                let hit = msgs
                    .into_iter()
                    .find(|m| m.tag == "Exit" && rid(m) == Some(id.to_string()));
                if let Some(m) = hit {
                    exits.push(m.exit.unwrap().get().to_owned());
                    break;
                }
            }
            if let Some(home) = home {
                let deadline = Instant::now() + Duration::from_secs(30);
                while outcome_count(home) < logged + id + 1 && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        exits
    })
}

/// (match, mismatch, declines by reason) among this run's getTurnItem log lines; prints
/// mismatching lines (paths only).
/// Waits (load-tolerant, up to 60 s) until `expect` requests have an outcome logged.
fn turn_item_outcomes(
    home: &Path,
    expect: usize,
) -> (usize, usize, std::collections::BTreeMap<String, usize>) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let r = turn_item_outcomes_now(home);
        if r.0 + r.1 + r.2.values().sum::<usize>() >= expect || Instant::now() > deadline {
            return r;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn outcome_count(home: &Path) -> usize {
    let r = turn_item_outcomes_now(home);
    r.0 + r.1 + r.2.values().sum::<usize>()
}

fn turn_item_outcomes_now(
    home: &Path,
) -> (usize, usize, std::collections::BTreeMap<String, usize>) {
    let l = log(home);
    let tag = "tag=\"orchestration.getTurnItem\"";
    let lines: Vec<&str> = l.lines().filter(|l| l.contains(tag)).collect();
    let count = |o: &str| {
        lines
            .iter()
            .filter(|l| l.contains("rust shadow") && l.contains(&format!("outcome=\"{o}\"")))
            .count()
    };
    let mut reasons = std::collections::BTreeMap::new();
    for l in lines.iter().filter(|l| l.contains("turn item declined")) {
        let r = l
            .split("reason=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        *reasons.entry(r.to_owned()).or_insert(0) += 1;
    }
    (count("match"), count("mismatch"), reasons)
}

fn print_mismatches(home: &Path) {
    let l = log(home);
    let tag = "tag=\"orchestration.getTurnItem\"";
    for m in l
        .lines()
        .filter(|l| l.contains(tag) && l.contains("\"mismatch\""))
    {
        println!("{m}");
    }
}

/// Every row of every `orchestration*` / `projection*` table, as text.
fn dump_orchestration(db: &Path) -> Vec<String> {
    let c = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    let tables: Vec<String> = c
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND (name LIKE 'orchestration%' OR name LIKE 'projection%') ORDER BY name",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut out = Vec::new();
    for t in tables {
        let mut q = c
            .prepare(&format!("SELECT * FROM \"{t}\" ORDER BY rowid"))
            .unwrap();
        let n = q.column_count();
        let rows = q
            .query_map([], |r| {
                (0..n)
                    .map(|i| {
                        r.get::<_, rusqlite::types::Value>(i)
                            .map(|v| format!("{v:?}"))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        for row in rows {
            out.push(format!("{t}: {}", row.unwrap().join(", ")));
        }
    }
    out
}

/// The fixture items (`tests/fixtures/turn_items.json`) plus a pending legacy thread, written
/// into the engine's own DB, then: shadow (Node answers, Rust compares) or serve (Rust answers
/// what it can). Returns the Exits and the decline reasons; serve also checks that the
/// Rust-served requests left every orchestration table unchanged.
fn turn_item_run(mode: &str) -> Option<(Vec<String>, std::collections::BTreeMap<String, usize>)> {
    let (d, base, home, token) = start_with(&format!("turn-item-{mode}"), |h, _| {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(h.join("vekrel.toml"))
            .unwrap();
        writeln!(f, "\"orchestration.getTurnItem\" = \"{mode}\"").unwrap();
    })?;
    let cookie = pair(&base, &home, &token);
    let db_path = home.join("userdata/statev2.sqlite");
    let fixture: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/turn_items.json")).unwrap();
    {
        let c = rusqlite::Connection::open(&db_path).unwrap();
        c.busy_timeout(Duration::from_secs(10)).unwrap();
        let put = |thread: &str, item: &serde_json::Value| {
            c.execute(
                "INSERT INTO orchestration_v2_projection_turn_items VALUES \
                 (?1, ?2, NULL, NULL, NULL, NULL, NULL, 0, ?3, 'completed', ?4, ?5)",
                rusqlite::params![
                    item["id"].as_str().unwrap(),
                    thread,
                    item["type"].as_str().unwrap(),
                    "2026-10-23T01:02:06.000Z",
                    item.to_string()
                ],
            )
            .unwrap();
        };
        for e in &fixture {
            put("thread-a", &e["item"]);
        }
        let mut legacy = fixture[0]["item"].clone();
        legacy["id"] = "ti-legacy".into();
        legacy["threadId"] = "thread-legacy".into();
        put("thread-legacy", &legacy);
        c.execute(
            "INSERT INTO orchestration_v2_legacy_imports VALUES \
             ('thread-legacy', '2026-10-23T00:00:00.000Z', '2026-10-23T00:00:00.000Z', NULL, 0, NULL)",
            [],
        )
        .unwrap();
    }
    let req = |t: &str, i: &str| serde_json::json!({"threadId": t, "itemId": i});
    let mut payloads: Vec<serde_json::Value> = fixture
        .iter()
        .map(|e| req("thread-a", e["item"]["id"].as_str().unwrap()))
        .collect();
    payloads.extend([
        req("thread-a", "missing"),
        req("thread-nowhere", "ti-cmd"),
        serde_json::json!({"threadId": "thread-a", "itemId": "ti-cmd", "revision": "rev-1"}),
        serde_json::json!({"threadId": " thread-a ", "itemId": "ti-cmd"}),
        serde_json::json!({"threadId": "thread-a", "itemId": "ti-cmd", "extra": true}),
    ]);
    let before = dump_orchestration(&db_path);
    let shadow = (mode == "shadow").then_some(home.as_path());
    let mut exits = turn_item_exits(&base, &cookie, &payloads, shadow);
    if mode == "serve" {
        // Rust served or declined every request above; Node answered the declined ones but
        // none of them reaches a legacy thread, so nothing may have been written.
        assert_eq!(
            dump_orchestration(&db_path),
            before,
            "Rust-served run wrote the DB"
        );
    }
    let pending = |db: &Path| -> bool {
        let c =
            rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        c.query_row(
            "SELECT transcript_imported_at IS NULL FROM orchestration_v2_legacy_imports \
             WHERE thread_id = 'thread-legacy'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert!(
        pending(&db_path),
        "legacy import still pending before its first read"
    );
    // Rust declines both; Node imports on the first (a write only Node makes).
    exits.extend(turn_item_exits(
        &base,
        &cookie,
        &[
            req("thread-legacy", "ti-legacy"),
            req("thread-legacy", "ti-legacy"),
        ],
        shadow,
    ));
    assert!(!pending(&db_path), "Node imported the legacy transcript");
    let served = fixture.iter().filter(|e| e["served"] == true).count() + 3;
    let expect = if mode == "shadow" {
        payloads.len() + 2
    } else {
        payloads.len() + 2 - served
    };
    let (matches, mismatches, reasons) = turn_item_outcomes(&home, expect);
    println!("getTurnItem {mode}: {matches} match, {mismatches} mismatch, declined {reasons:?}");
    print_mismatches(&home);
    assert_eq!(mismatches, 0);
    let declined = payloads.len() + 2 - served;
    assert_eq!(reasons.values().sum::<usize>(), declined, "{reasons:?}");
    assert_eq!(reasons.get("legacy_thread"), Some(&2));
    assert_eq!(reasons.get("payload"), Some(&2));
    if mode == "shadow" {
        assert_eq!(matches, served, "every answerable request compared");
    }
    drop(d);
    assert!(!home.exists());
    Some((exits, reasons))
}

/// Synthetic rows of every ported type: shadow logs only matches; serve sends Node's exact
/// bytes, writes nothing, and leaves legacy threads (and Node's import) to Node.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn turn_item_shadow_matches_node_and_serve_sends_its_bytes() {
    let Some((node, shadow_reasons)) = turn_item_run("shadow") else {
        return;
    };
    let (rust, serve_reasons) = turn_item_run("serve").unwrap();
    assert_eq!(shadow_reasons, serve_reasons);
    for (i, (n, r)) in node.iter().zip(&rust).enumerate() {
        assert_eq!(n, r, "request {i}: served bytes differ from Node's");
    }
    assert_eq!(node.len(), rust.len());
    assert!(node.iter().any(|e| e.contains(r#""item":null"#)));
}

/// `VEKREL_REAL_DB`: turn items sampled across the owner's DB, every legacy thread included,
/// through the engine running on a copy. Rust's answers match Node's, and every legacy thread
/// declines.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs> and VEKREL_REAL_DB"]
fn turn_item_real_db_shadow_matches_node() {
    if std::env::var_os("VEKREL_REAL_DB").is_none() {
        eprintln!("VEKREL_REAL_DB unset; skipping");
        return;
    }
    let mut payloads = Vec::new();
    let mut legacy = 0;
    let Some((d, base, home, token)) = start_with("turn-item-real", |h, _| {
        let (dir, copy) = support::real_db::copy_from(std::env::var_os("VEKREL_REAL_DB")).unwrap();
        std::fs::create_dir_all(h.join("userdata")).unwrap();
        let dest = h.join("userdata/statev2.sqlite");
        std::fs::rename(&copy, &dest).unwrap();
        drop(dir);
        let c = rusqlite::Connection::open_with_flags(
            &dest,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let rows = |sql: &str| -> Vec<(String, String)> {
            c.prepare(sql)
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let not_legacy = "thread_id NOT IN (SELECT thread_id FROM orchestration_v2_legacy_imports)";
        let types = rows(&format!(
            "SELECT DISTINCT type, '' FROM orchestration_v2_projection_turn_items WHERE {not_legacy}"
        ));
        let mut sample = Vec::new();
        for (ty, _) in types {
            // Spread over the table by id suffix; plus each type's largest rows.
            for order in ["substr(turn_item_id, -5)", "length(payload_json) DESC"] {
                sample.extend(rows(&format!(
                    "SELECT thread_id, turn_item_id FROM orchestration_v2_projection_turn_items \
                     WHERE type = '{ty}' AND {not_legacy} ORDER BY {order} LIMIT 25"
                )));
            }
        }
        let l = rows(
            "SELECT l.thread_id, coalesce((SELECT turn_item_id FROM orchestration_v2_projection_turn_items t \
             WHERE t.thread_id = l.thread_id ORDER BY ordinal LIMIT 1), 'missing') \
             FROM orchestration_v2_legacy_imports l",
        );
        legacy = l.len();
        sample.sort();
        sample.dedup();
        for (t, i) in sample.iter().chain(&l) {
            payloads.push(serde_json::json!({"threadId": t, "itemId": i, "revision": "r"}));
        }
    }) else {
        return;
    };
    let cookie = pair(&base, &home, &token);
    let exits = turn_item_exits(&base, &cookie, &payloads, Some(&home));
    assert_eq!(exits.len(), payloads.len());
    let (matches, mismatches, reasons) = turn_item_outcomes(&home, payloads.len());
    println!(
        "getTurnItem owner DB: {} requests ({legacy} legacy threads): {matches} match, {mismatches} mismatch, declined {reasons:?}",
        payloads.len()
    );
    print_mismatches(&home);
    assert_eq!(mismatches, 0);
    assert_eq!(reasons.get("legacy_thread").copied().unwrap_or(0), legacy);
    assert_eq!(matches + reasons.values().sum::<usize>(), payloads.len());
    drop(d);
    assert!(!home.exists());
}

/// Sends each `(tag, payload)` over one daemon WS (all at once, so they interleave in Node) and
/// returns each request's Exit text, in order. The socket stays open until `settled()` (up to
/// 120 s): closing it cancels shadow computations still running.
fn ws_exits(
    base: &str,
    cookie: &str,
    reqs: &[(&str, serde_json::Value)],
    settled: impl Fn() -> bool,
) -> Vec<String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let port = base.rsplit(':').next().unwrap().to_owned();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut c = auth_ws(&port, cookie).await;
        for (id, (tag, payload)) in reqs.iter().enumerate() {
            let r = serde_json::json!({"_tag":"Request","id":id.to_string(),"tag":tag,
                "payload":payload,"traceId":"0123456789abcdef0123456789abcdef",
                "spanId":"0123456789abcdef","sampled":true,"headers":[]});
            c.send(Message::text(r.to_string())).await.unwrap();
        }
        let mut exits = vec![None; reqs.len()];
        while exits.iter().any(Option::is_none) {
            let m = tokio::time::timeout(Duration::from_secs(60), c.next())
                .await
                .expect("reply")
                .unwrap()
                .unwrap();
            let Message::Text(t) = m else { continue };
            let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
            for m in v.as_array().cloned().unwrap_or(vec![v]) {
                if m["_tag"] == "Exit" {
                    let i: usize = m["requestId"].as_str().unwrap().parse().unwrap();
                    exits[i] = Some(m["exit"].to_string());
                }
            }
        }
        let deadline = Instant::now() + Duration::from_secs(120);
        while !settled() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        exits.into_iter().map(Option::unwrap).collect()
    })
}

/// getArchivedShellSnapshot log outcomes: shadow outcomes (`match`, `mismatch`,
/// `sequence_skew`) and decline reasons; mismatch lines (paths only) are printed.
fn archived_outcomes(home: &Path) -> std::collections::BTreeMap<String, usize> {
    let mut out = std::collections::BTreeMap::new();
    let tag = "tag=\"orchestration.getArchivedShellSnapshot\"";
    for l in log(home).lines().filter(|l| l.contains(tag)) {
        let field = |k: &str| l.split(&format!("{k}=\"")).nth(1)?.split('"').next();
        let key = if l.contains("rust shadow") {
            field("outcome").unwrap().to_owned()
        } else if l.contains("archived shell declined") {
            format!("declined:{}", field("reason").unwrap())
        } else {
            continue;
        };
        if key == "mismatch" {
            println!("{l}");
        }
        *out.entry(key).or_insert(0) += 1;
    }
    out
}

/// Plan 6B Task 9: `orchestration.getArchivedShellSnapshot` configured `serve` runs in shadow
/// (Node's enrichment cache), and Rust's answer equals Node's on the synthetic scenarios while
/// Node archives and unarchives threads during the run (a write between the two reads is
/// `sequence_skew`, never a mismatch). Requests alone write nothing.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn archived_shell_shadow_matches_node_while_threads_move() {
    use vekrel::shell::fixture;
    const TAG: &str = "orchestration.getArchivedShellSnapshot";
    let Some((d, base, home, token)) = start_with("archived", |h, cmd| {
        isolate_engine(h, cmd);
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(h.join("vekrel.toml"))
            .unwrap();
        writeln!(f, "\"{TAG}\" = \"serve\"").unwrap();
    }) else {
        return;
    };
    assert!(
        log(&home).contains(&format!("{TAG} runs in shadow")),
        "serve downgraded:\n{}",
        log(&home)
    );
    let cookie = pair(&base, &home, &token);
    let db_path = home.join("userdata/statev2.sqlite");
    {
        let c = rusqlite::Connection::open(&db_path).unwrap();
        c.busy_timeout(Duration::from_secs(20)).unwrap();
        // Threads Node can move: plain ones (like `fx-empty`), one active, one archived.
        let mut fx = fixture::scenarios();
        fx.thread("mv-a", 50, serde_json::json!({}));
        fx.thread("mv-b", 51, serde_json::json!({"archivedAt": fixture::T0}));
        c.execute_batch(&format!("BEGIN IMMEDIATE; {} COMMIT;", fx.0))
            .unwrap();
    }
    let wait = |n: usize| {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let o = archived_outcomes(&home);
            if o.values().sum::<usize>() >= n || Instant::now() > deadline {
                return o;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    };
    let snap = || (TAG, serde_json::json!({}));
    // Reads alone. (No DB dump here: Node's own background jobs, such as auto-settle, write
    // during the run; the unit test `snapshot_leaves_the_db_file_unchanged` covers Rust.)
    let total = || archived_outcomes(&home).values().sum::<usize>();
    let exits = ws_exits(&base, &cookie, &vec![snap(); 10], || total() >= 10);
    assert!(exits.iter().all(|e| e.contains(r#""_tag":"Success""#)));
    assert!(
        exits[0].contains(r#""id":"fx-root""#),
        "archived fixtures reached"
    );
    let o = wait(10);
    assert_eq!(
        o.get("match").unwrap_or(&0) + o.get("sequence_skew").unwrap_or(&0),
        10,
        "{o:?}"
    );
    // Node moves threads while snapshots are in flight.
    let movers = ["fx-empty", "mv-a", "mv-b"];
    for i in 0..12 {
        let id = movers[i % movers.len()];
        let kind = if (i / movers.len()).is_multiple_of(2) {
            if id == "mv-b" {
                "thread.unarchive"
            } else {
                "thread.archive"
            }
        } else if id != "mv-b" {
            "thread.unarchive"
        } else {
            "thread.archive"
        };
        let cmd =
            serde_json::json!({"type": kind, "commandId": format!("cmd-{i}"), "threadId": id});
        // One snapshot races the command; three follow its commit.
        let n = 10 + 4 * i;
        let racing = [("orchestration.dispatchCommand", cmd), snap()];
        let exits = ws_exits(&base, &cookie, &racing, || total() > n);
        assert!(
            exits[0].contains(r#""_tag":"Success""#),
            "command {i}: {}",
            exits[0]
        );
        ws_exits(&base, &cookie, &[snap(), snap(), snap()], || {
            total() >= n + 4
        });
    }
    let o = wait(58);
    println!("getArchivedShellSnapshot: {o:?}");
    assert_eq!(o.get("mismatch"), None, "{o:?}");
    assert_eq!(
        o.get("match").unwrap_or(&0) + o.get("sequence_skew").unwrap_or(&0),
        58,
        "every snapshot compared (10 + 48): {o:?}"
    );
    assert!(
        o.get("match").unwrap_or(&0) > &10,
        "some compared while moving: {o:?}"
    );
    assert!(o.keys().all(|k| !k.starts_with("declined")), "{o:?}");
    // Nothing reached Node unanswered: no `x-vekrel` serve path for this tag.
    assert!(!log(&home).contains("mode=\"serve\" outcome=\"declined\""));
    drop(d);
    assert!(!home.exists());
}

// ---- GET /api/orchestration/shell (plan 6B Task 8) ----

const SHELL: &str = "GET /api/orchestration/shell";

/// Shadow outcomes logged for `route`, by outcome; an enrichment-only mismatch is `ENRICHED`.
/// Prints every line that is not a match, decline, enrichment or sequence skew.
fn route_outcomes(home: &Path, route: &str) -> std::collections::BTreeMap<String, usize> {
    std::thread::sleep(Duration::from_millis(300));
    let mut m = std::collections::BTreeMap::new();
    for l in log(home).lines() {
        if !l.contains(&format!("route=\"{route}\"")) || l.contains("rust shell builder") {
            continue;
        }
        if let Some(o) = l.split("outcome=").nth(1) {
            let mut o = o.split_whitespace().next().unwrap().trim_matches('"');
            if o == "mismatch" && l.contains("field=\"enrichment\"") {
                o = ENRICHED;
            }
            // Effect's chunked 400 for a missing protocol header, which Rust declines anyway.
            if o == "shadow_skipped_large" && l.contains("status=400") {
                o = "skipped_400";
            }
            *m.entry(o.to_owned()).or_default() += 1;
            if ![
                "match",
                "declined",
                ENRICHED,
                "sequence_skew",
                "skipped_400",
            ]
            .contains(&o)
            {
                println!("{l}");
            }
        }
    }
    m
}

/// Outcomes other than match / declined / enrichment / skew.
fn bad_outcomes(o: &std::collections::BTreeMap<String, usize>) -> usize {
    o.iter()
        .filter(|(k, _)| {
            ![
                "match",
                "declined",
                ENRICHED,
                "sequence_skew",
                "skipped_400",
            ]
            .contains(&k.as_str())
        })
        .map(|(_, n)| n)
        .sum()
}

/// `GET /api/orchestration/shell` through `base` → (status, headers, decoded body).
fn shell_get(
    rt: &tokio::runtime::Runtime,
    http: &reqwest::Client,
    base: &str,
    cookie: Option<&str>,
    ae: Option<&str>,
) -> (u16, reqwest::header::HeaderMap, String) {
    let mut h = vec![("x-t3-orchestration-protocol", "2")];
    if let Some(c) = cookie {
        h.push(("cookie", c));
    }
    if let Some(ae) = ae {
        h.push(("accept-encoding", ae));
    }
    let (s, nh, nb) = rt.block_on(raw_get(
        http,
        &format!("{base}/api/orchestration/shell"),
        &h,
    ));
    let plain =
        vekrel::http_seam::decoded_up_to(nh.get("content-encoding"), nb.into(), 1 << 30).unwrap();
    (s, nh, String::from_utf8(plain.to_vec()).unwrap())
}

/// Plan 6B Task 8: the shell route in shadow over the Task 6 scenarios, a git workspace Node
/// enriches, rows and threads Rust declines, Node's 401 and the protocol-header 400. Configured
/// `serve`, it is downgraded to shadow at startup (Rust cannot see Node's enrichment cache).
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn shell_shadow_matches_node() {
    use vekrel::shell::fixture;
    let Some((d, base, home, token)) = start_with("shell-shadow", |home, cmd| {
        isolate_engine(home, cmd);
        let cfg = home.join("vekrel.toml");
        let t = std::fs::read_to_string(&cfg).unwrap();
        std::fs::write(&cfg, t + &format!("\"{SHELL}\" = \"serve\"\n")).unwrap();
    }) else {
        return;
    };
    assert!(
        log(&home).contains("GET /api/orchestration/shell runs in shadow"),
        "startup warning"
    );
    let ck = pair(&base, &home, &token);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let http = reqwest::Client::new();
    let write = |sql: &str| {
        let c = rusqlite::Connection::open(home.join("userdata/statev2.sqlite")).unwrap();
        c.busy_timeout(Duration::from_secs(20)).unwrap();
        c.execute_batch(&format!("BEGIN IMMEDIATE; {sql} COMMIT;"))
            .unwrap();
    };
    let round = || {
        for ae in [None, Some("gzip"), Some("br"), Some("gzip, deflate, br")] {
            let (s, h, _) = shell_get(&rt, &http, &base, Some(&ck), ae);
            assert_eq!(s, 200);
            assert!(h.get("x-vekrel-served-by").is_none(), "Node answers");
        }
    };
    round();
    write(&fixture::scenarios().0);
    let before_db = dump_orchestration(&home.join("userdata/statev2.sqlite"));
    round();
    round();
    let (_, _, body) = shell_get(&rt, &http, &base, Some(&ck), None);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    println!(
        "fixture shell: {} threads, {} bytes",
        v["threads"].as_array().unwrap().len(),
        body.len()
    );
    let fixtures = route_outcomes(&home, SHELL);
    // Reads change nothing (no writer runs on this isolated engine).
    assert_eq!(
        before_db,
        dump_orchestration(&home.join("userdata/statev2.sqlite")),
        "tables unchanged"
    );

    // Node's 401 without a session; without the protocol header Node's 400 and Rust declines.
    let (s, _, _) = shell_get(&rt, &http, &base, None, None);
    assert_eq!(s, 401);
    let declined_before = fixtures.get("declined").copied().unwrap_or(0);
    let (s, _, _) = rt.block_on(raw_get(
        &http,
        &format!("{base}/api/orchestration/shell"),
        &[("cookie", ck.as_str())],
    ));
    assert_eq!(s, 400);

    // A drifted thread: Node 500, Rust declines.
    let mut drift = fixture::Fx::default();
    drift.thread("fx-drift", 40, serde_json::json!({"runtimeMode": "turbo"}));
    write(&drift.0);
    assert_eq!(shell_get(&rt, &http, &base, Some(&ck), None).0, 500);
    write("DELETE FROM orchestration_v2_projection_threads WHERE thread_id = 'fx-drift';");
    // A project row Node reshapes (an untrimmed title): Rust declines.
    write(&format!(
        "INSERT INTO projection_projects ({PROJECT_COLS}) VALUES \
         ('p-pad', ' padded', '/w', NULL, NULL, 0, NULL, NULL, '[]', 'c', 'u', NULL);"
    ));
    shell_get(&rt, &http, &base, Some(&ck), None);
    write("DELETE FROM projection_projects WHERE project_id = 'p-pad';");
    let declines = route_outcomes(&home, SHELL)
        .get("declined")
        .copied()
        .unwrap_or(0);
    assert_eq!(declines - declined_before, 3, "header, drift, row");

    // A git workspace: once Node's cache is warm its repositoryIdentity differs from Rust's null.
    let repo = env!("CARGO_MANIFEST_DIR");
    write(&format!(
        "INSERT INTO projection_projects ({PROJECT_COLS}) VALUES \
         ('git', 'Daemon', '{repo}', NULL, NULL, 0, NULL, NULL, '[]', 'c', 'u', NULL);"
    ));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (_, _, b) = shell_get(&rt, &http, &base, Some(&ck), None);
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        let git = v["projects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == "git")
            .cloned();
        if git.is_some_and(|p| !p["repositoryIdentity"].is_null()) {
            break;
        }
        assert!(Instant::now() < deadline, "Node never enriched the repo");
        std::thread::sleep(Duration::from_millis(500));
    }
    let all = route_outcomes(&home, SHELL);
    println!("{SHELL} shadow outcomes: fixtures {fixtures:?}, all {all:?}");
    assert_eq!(
        bad_outcomes(&all),
        0,
        "no mismatch or skipped comparison: {all:?}"
    );
    assert!(
        fixtures.get("match").copied().unwrap_or(0) >= 10,
        "{fixtures:?}"
    );
    assert!(all.get(ENRICHED).copied().unwrap_or(0) >= 1, "{all:?}");
    drop(d);
    assert!(!home.exists());
}

// ---- convergence: Rust's snapshot, then Node's stream ----

/// `mergeShellSnapshotProjects` + `applyShellStreamEvent` from Vekrel-Web
/// `packages/client-runtime/src/state/shellReducer.ts` and `shell.ts` `applyItems`.
#[derive(Default)]
struct ShellClient {
    state: Option<serde_json::Value>,
    synchronized: bool,
}

impl ShellClient {
    fn apply(&mut self, item: &serde_json::Value) {
        use serde_json::Value;
        let retain = |prev: Option<&Value>, next: &mut Value| {
            if let Some(p) = prev
                && next["repositoryIdentity"].is_null()
                && !p["repositoryIdentity"].is_null()
                && p["workspaceRoot"] == next["workspaceRoot"]
            {
                next["repositoryIdentity"] = p["repositoryIdentity"].clone();
            }
        };
        let find = |s: &Value, key: &str, id: &Value| -> Option<Value> {
            s[key]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["id"] == *id)
                .cloned()
        };
        match item["kind"].as_str().unwrap() {
            "synchronized" => self.synchronized = true,
            "snapshot" => {
                let next = item["snapshot"].clone();
                let Some(prev) = self.state.take() else {
                    self.state = Some(next);
                    return;
                };
                if let Some(roots) = item["resolvedRepositoryIdentityRoots"].as_array() {
                    let mut s = prev;
                    for p in s["projects"].as_array_mut().unwrap() {
                        let Some(c) = find(&next, "projects", &p["id"]) else {
                            continue;
                        };
                        if c["workspaceRoot"] != p["workspaceRoot"] {
                            continue;
                        }
                        if roots.contains(&p["workspaceRoot"])
                            || (p["repositoryIdentity"].is_null()
                                && !c["repositoryIdentity"].is_null())
                        {
                            p["repositoryIdentity"] = c["repositoryIdentity"].clone();
                        }
                    }
                    self.state = Some(s);
                } else {
                    let mut n = next;
                    for p in n["projects"].as_array_mut().unwrap() {
                        let prior = find(&prev, "projects", &p["id"]);
                        retain(prior.as_ref(), p);
                    }
                    self.state = Some(n);
                }
            }
            kind => {
                let Some(s) = self.state.as_mut() else { return };
                let seq = item["sequence"].as_i64().unwrap();
                if seq <= s["snapshotSequence"].as_i64().unwrap() {
                    return;
                }
                let upsert = |list: &mut Value, v: Value| {
                    let a = list.as_array_mut().unwrap();
                    match a.iter().position(|x| x["id"] == v["id"]) {
                        Some(i) => a[i] = v,
                        None => a.push(v),
                    }
                };
                let without = |list: &mut Value, id: &Value| {
                    list.as_array_mut().unwrap().retain(|x| x["id"] != *id)
                };
                match kind {
                    "project.updated" => {
                        let mut p = item["project"].clone();
                        let prior = find(s, "projects", &p["id"]);
                        retain(prior.as_ref(), &mut p);
                        upsert(&mut s["projects"], p);
                    }
                    "project.removed" => without(&mut s["projects"], &item["projectId"]),
                    "thread.updated" => {
                        let t = item["thread"].clone();
                        if item["location"] == "active" {
                            upsert(&mut s["threads"], t.clone());
                        } else {
                            without(&mut s["threads"], &t["id"]);
                        }
                        without(&mut s["archivedThreads"], &t["id"]);
                    }
                    "thread.removed" => {
                        without(&mut s["threads"], &item["threadId"]);
                        without(&mut s["archivedThreads"], &item["threadId"]);
                    }
                    _ => return,
                }
                s["snapshotSequence"] = seq.into();
            }
        }
    }
}

/// A shell state by id, order-free, `repositoryIdentity` removed (Node's warm cache, Rust's null).
fn shell_state(s: &serde_json::Value) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for key in ["projects", "threads", "archivedThreads"] {
        for x in s[key].as_array().unwrap() {
            let mut x = x.clone();
            x.as_object_mut().unwrap().remove("repositoryIdentity");
            let text = String::from_utf8(vekrel::effect_json::to_vec(&x)).unwrap();
            out.insert(format!("{key}:{}", x["id"].as_str().unwrap()), text);
        }
    }
    out
}

/// Sends `{_tag: Request}` and returns the Exit's `exit` for unary `tag`.
async fn ws_unary(c: &mut Ws, id: u64, tag: &str, payload: serde_json::Value) -> serde_json::Value {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let r = serde_json::json!({"_tag":"Request","id":id,"tag":tag,"payload":payload,"headers":[]});
    c.send(Message::text(r.to_string())).await.unwrap();
    loop {
        let m = tokio::time::timeout(Duration::from_secs(60), c.next()).await;
        let Ok(Some(Ok(Message::Text(t)))) = m else {
            panic!("no frame: {m:?}")
        };
        let v: serde_json::Value = vekrel::effect_json::parse(t.as_str()).unwrap();
        for f in v.as_array().cloned().unwrap_or(vec![v]) {
            if f["_tag"] == "Exit" && f["requestId"] == id {
                return f["exit"].clone();
            }
        }
    }
}

/// One `orchestration.subscribeShell` on its own socket: Chunks are acked and their items queued.
async fn subscribe_shell(
    port: String,
    cookie: String,
    after: Option<i64>,
    tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>,
) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let mut c = auth_ws(&port, &cookie).await;
    let mut payload = serde_json::json!({"requestCompletionMarker": true});
    if let Some(a) = after {
        payload["afterSequence"] = a.into();
    }
    let r = serde_json::json!({"_tag":"Request","id":7,"tag":"orchestration.subscribeShell",
        "payload":payload,"headers":[]});
    c.send(Message::text(r.to_string())).await.unwrap();
    while let Some(Ok(m)) = c.next().await {
        let Message::Text(t) = m else { continue };
        let v: serde_json::Value = vekrel::effect_json::parse(t.as_str()).unwrap();
        for f in v.as_array().cloned().unwrap_or(vec![v]) {
            if f["_tag"] == "Chunk" && f["requestId"] == 7 {
                c.send(Message::text(r#"{"_tag":"Ack","requestId":7}"#))
                    .await
                    .unwrap();
                for i in f["values"].as_array().unwrap() {
                    if tx.send(i.clone()).is_err() {
                        return;
                    }
                }
            } else if f["_tag"] == "Exit" {
                panic!("shell stream ended: {f}");
            }
        }
    }
}

/// Plan 6B Task 8, Review Focus 2. Each iteration: a Node writer creates and renames projects and
/// threads and archives a thread through Node's RPCs (no turn, no provider); meanwhile client A
/// takes Rust's shell snapshot (the route's exact bytes, `handlers::shell::snapshot`) and opens
/// Node's `subscribeShell(afterSequence)`, and client B does the same from Node's HTTP shell. Once
/// the writer is done and both streams are quiet, A, B and a fresh Node snapshot hold the same
/// projects and threads (`repositoryIdentity` excluded).
fn shell_convergence(tag: &str, owner_db: Option<std::ffi::OsString>, iterations: usize) {
    use vekrel::shell::fixture;
    let Some((d, base, home, token)) = start_with(tag, |home, cmd| {
        isolate_engine(home, cmd);
        if let Some(src) = owner_db.clone() {
            let (dir, copy) = support::real_db::copy_from(Some(src)).unwrap();
            std::fs::rename(&copy, home.join("userdata/statev2.sqlite")).unwrap();
            drop(dir);
        }
    }) else {
        return;
    };
    let ck = pair(&base, &home, &token);
    let db_path = home.join("userdata/statev2.sqlite");
    if owner_db.is_none() {
        let c = rusqlite::Connection::open(&db_path).unwrap();
        c.busy_timeout(Duration::from_secs(20)).unwrap();
        c.execute_batch(&format!(
            "BEGIN IMMEDIATE; {} COMMIT;",
            fixture::scenarios().0
        ))
        .unwrap();
    }
    let port = base.rsplit(':').next().unwrap().to_owned();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let http = reqwest::Client::new();
    let db = std::sync::Arc::new(vekrel::db::read::StateDb::new(&home.join("userdata")));
    rt.block_on(async {
        let mut c = auth_ws(&port, &ck).await;
        let base = serde_json::json!({"type": "project.create", "commandId": "cv-cmd-base",
            "projectId": "cv-base", "title": "Base", "workspaceRoot": home.join("ws-base").to_str().unwrap(),
            "createWorkspaceRootIfMissing": true});
        let exit = ws_unary(&mut c, 1, "projects.mutate", base).await;
        assert_eq!(exit["_tag"], "Success", "{exit}");
    });
    let mut handoff_events = 0;
    for i in 0..iterations {
        let (ws_root, home2) = (home.join(format!("ws-{i}")), home.clone());
        // Client A: Rust's snapshot first; Node's stream opens only after Node has written.
        let (ta, mut ra) = tokio::sync::mpsc::unbounded_channel();
        let (tb, mut rb) = tokio::sync::mpsc::unbounded_channel();
        let snap = {
            let db = db.clone();
            rt.block_on(rt.spawn_blocking(move || vekrel::handlers::shell::snapshot(&db)))
                .unwrap()
                .unwrap_or_else(|why| panic!("Rust declined: {why}"))
        };
        let mut a = ShellClient::default();
        let a_snap: serde_json::Value =
            vekrel::effect_json::parse(std::str::from_utf8(&snap).unwrap()).unwrap();
        let a_seq = a_snap["snapshotSequence"].as_i64().unwrap();
        a.apply(&serde_json::json!({"kind": "snapshot", "snapshot": a_snap}));
        let (first_tx, first_rx) = tokio::sync::oneshot::channel::<()>();
        let writer = {
            let (port, ck) = (port.clone(), ck.clone());
            rt.spawn(async move {
                let mut c = auth_ws(&port, &ck).await;
                let (p, t1, t2) = (
                    format!("cv-p-{i}"),
                    format!("cv-t-{i}-a"),
                    format!("cv-t-{i}-b"),
                );
                let model = serde_json::json!({"instanceId": "codex", "model": "gpt-5-codex"});
                let create = |t: &str, n: u64| {
                    serde_json::json!({"type": "thread.create",
                    "commandId": format!("cv-cmd-{i}-{n}"), "threadId": t, "projectId": p,
                    "title": format!("Thread {t}"), "modelSelection": model,
                    "runtimeMode": "full-access", "interactionMode": "default",
                    "branch": null, "worktreePath": null,
                    "createdBy": "user", "creationSource": "web"})
                };
                let ops: Vec<(&str, serde_json::Value)> = vec![
                    (
                        "projects.mutate",
                        serde_json::json!({"type": "project.create",
                        "commandId": format!("cv-cmd-{i}-0"), "projectId": p,
                        "title": format!("Project {i}"),
                        "workspaceRoot": ws_root.to_str().unwrap(),
                        "createWorkspaceRootIfMissing": true}),
                    ),
                    ("orchestration.dispatchCommand", create(&t1, 1)),
                    (
                        "orchestration.dispatchCommand",
                        serde_json::json!({"type": "thread.metadata.update",
                        "commandId": format!("cv-cmd-{i}-2"), "threadId": t1,
                        "title": format!("Renamed {i}")}),
                    ),
                    (
                        "projects.mutate",
                        serde_json::json!({"type": "project.update",
                        "commandId": format!("cv-cmd-{i}-3"), "projectId": p,
                        "title": format!("Project {i} renamed")}),
                    ),
                    ("orchestration.dispatchCommand", create(&t2, 4)),
                    (
                        "orchestration.dispatchCommand",
                        serde_json::json!({"type": "thread.archive",
                        "commandId": format!("cv-cmd-{i}-5"), "threadId": t1}),
                    ),
                ];
                // A thread no later op touches: its events reach client A only through the
                // replay after Rust's sequence (a snapshot sequence ahead of its rows loses it).
                let mut lone = create(&format!("cv-t-{i}-lone"), 9);
                lone["projectId"] = "cv-base".into();
                let exit = ws_unary(&mut c, 99, "orchestration.dispatchCommand", lone).await;
                assert_eq!(exit["_tag"], "Success", "{exit}");
                let _ = first_tx.send(());
                for (n, (tag, payload)) in ops.into_iter().enumerate() {
                    let exit = ws_unary(&mut c, 100 + n as u64, tag, payload).await;
                    assert_eq!(exit["_tag"], "Success", "{tag}: {exit}");
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                drop(home2);
            })
        };
        rt.block_on(first_rx).unwrap();
        std::thread::sleep(Duration::from_millis(40));
        let sub_a = rt.spawn(subscribe_shell(port.clone(), ck.clone(), Some(a_seq), ta));
        // Client B: Node's HTTP snapshot, then Node's stream.
        let (s, _, body) = shell_get(&rt, &http, &base, Some(&ck), Some("br"));
        assert_eq!(s, 200, "{body}");
        let mut b = ShellClient::default();
        let b_snap = vekrel::effect_json::parse(&body).unwrap();
        let b_seq = b_snap["snapshotSequence"].as_i64().unwrap();
        b.apply(&serde_json::json!({"kind": "snapshot", "snapshot": b_snap}));
        let sub_b = rt.spawn(subscribe_shell(port.clone(), ck.clone(), Some(b_seq), tb));
        rt.block_on(writer).unwrap();
        // Settle: both synchronized and 1.5 s without an item.
        let mut a_items = 0;
        rt.block_on(async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
            loop {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "streams never settled"
                );
                tokio::select! {
                    Some(x) = ra.recv() => { a_items += 1; a.apply(&x) }
                    Some(x) = rb.recv() => b.apply(&x),
                    _ = tokio::time::sleep(Duration::from_millis(1500)) => {
                        if a.synchronized && b.synchronized { break }
                    }
                }
            }
        });
        let (s, _, fresh) = shell_get(&rt, &http, &base, Some(&ck), None);
        assert_eq!(s, 200);
        let fresh = shell_state(&vekrel::effect_json::parse(&fresh).unwrap());
        let (sa, sb) = (
            shell_state(a.state.as_ref().unwrap()),
            shell_state(b.state.as_ref().unwrap()),
        );
        let diff = |x: &std::collections::BTreeMap<String, String>| -> Vec<String> {
            fresh
                .iter()
                .filter(|(k, v)| x.get(*k) != Some(v))
                .map(|(k, _)| k.clone())
                .chain(x.keys().filter(|k| !fresh.contains_key(*k)).cloned())
                .collect()
        };
        println!(
            "iteration {i}: Rust seq {a_seq}, Node seq {b_seq}, {a_items} items after Rust's snapshot, {} entries; differ A {:?} B {:?}",
            fresh.len(),
            diff(&sa),
            diff(&sb)
        );
        assert!(
            diff(&sa).is_empty() && diff(&sb).is_empty(),
            "iteration {i} did not converge"
        );
        assert!(sa.contains_key(&format!("threads:cv-t-{i}-b")));
        assert!(sa.contains_key(&format!("threads:cv-t-{i}-lone")));
        assert!(
            !sa.contains_key(&format!("threads:cv-t-{i}-a")),
            "archived thread left the shell"
        );
        handoff_events += a_items;
        sub_a.abort();
        sub_b.abort();
    }
    println!(
        "CONVERGENCE {tag}: {iterations}/{iterations} iterations converged, {handoff_events} stream items after Rust's snapshots"
    );
    drop(db);
    drop(d);
    assert!(!home.exists());
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs>"]
fn shell_rust_snapshot_then_node_stream_converges() {
    shell_convergence("shell-converge", None, 20);
}

#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs> and VEKREL_REAL_DB"]
fn shell_rust_snapshot_then_node_stream_converges_on_owner_db() {
    let Some(src) = std::env::var_os("VEKREL_REAL_DB") else {
        eprintln!("VEKREL_REAL_DB unset: skipping the owner-DB test");
        return;
    };
    shell_convergence("shell-converge-owner", Some(src), 20);
}

/// A cheap fingerprint of every `orchestration*` / `projection*` table: row count and max rowid.
fn table_fingerprint(db: &Path) -> Vec<(String, i64, Option<i64>)> {
    let c = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    let tables: Vec<String> = c
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND (name LIKE 'orchestration%' OR name LIKE 'projection%') ORDER BY name",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    tables
        .into_iter()
        .map(|t| {
            let (n, m) = c
                .query_row(
                    &format!("SELECT count(*), max(rowid) FROM \"{t}\""),
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            (t, n, m)
        })
        .collect()
}

/// Plan 6B Task 8 on a copy of the owner's DB: the shadowed route matches Node (0 mismatches
/// beyond enrichment), Rust declines nothing, Rust's reads leave the tables as they were, and
/// timing for both sides.
#[test]
#[ignore = "needs VEKREL_LIVE_ENGINE=<engine bin.mjs> and VEKREL_REAL_DB"]
fn shell_shadow_matches_node_on_owner_db() {
    let Some(src) = std::env::var_os("VEKREL_REAL_DB") else {
        eprintln!("VEKREL_REAL_DB unset: skipping the owner-DB test");
        return;
    };
    let Some((d, base, home, token)) = start_with("shell-owner-shadow", |home, cmd| {
        isolate_engine(home, cmd);
        let (dir, copy) = support::real_db::copy_from(Some(src)).unwrap();
        std::fs::rename(&copy, home.join("userdata/statev2.sqlite")).unwrap();
        drop(dir);
    }) else {
        return;
    };
    let ck = pair(&base, &home, &token);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let http = reqwest::Client::new();
    let mut size = 0;
    for ae in [
        None,
        Some("gzip"),
        Some("br"),
        Some("gzip, deflate, br"),
        None,
        Some("br"),
    ] {
        let (s, h, b) = shell_get(&rt, &http, &base, Some(&ck), ae);
        assert_eq!(s, 200);
        assert!(h.get("x-vekrel-served-by").is_none());
        size = b.len();
        std::thread::sleep(Duration::from_millis(500));
    }
    std::thread::sleep(Duration::from_secs(3));
    let o = route_outcomes(&home, SHELL);
    println!("OWNER shell shadow: {size} bytes, outcomes {o:?}");
    assert_eq!(bad_outcomes(&o), 0, "{o:?}");
    assert_eq!(o.get("declined").copied().unwrap_or(0), 0, "{o:?}");
    let compared = o.get("match").copied().unwrap_or(0)
        + o.get(ENRICHED).copied().unwrap_or(0)
        + o.get("sequence_skew").copied().unwrap_or(0);
    assert_eq!(compared, 6, "{o:?}");

    // Timing: Node on its own port (uncompressed and br) vs Rust's route body, warm connection.
    let median = |mut v: Vec<u128>| {
        v.sort();
        v[v.len() / 2]
    };
    let engine = engine_base(&home);
    let mut node = (vec![], vec![]);
    for _ in 0..7 {
        let t = Instant::now();
        assert_eq!(shell_get(&rt, &http, &engine, Some(&ck), None).0, 200);
        node.0.push(t.elapsed().as_millis());
        let t = Instant::now();
        assert_eq!(shell_get(&rt, &http, &engine, Some(&ck), Some("br")).0, 200);
        node.1.push(t.elapsed().as_millis());
    }
    let db_path = home.join("userdata/statev2.sqlite");
    let before = table_fingerprint(&db_path);
    let db = vekrel::db::read::StateDb::new(&home.join("userdata"));
    let (mut rust, mut br) = (vec![], vec![]);
    let t = Instant::now();
    vekrel::handlers::shell::snapshot(&db).unwrap();
    let cold = t.elapsed().as_millis();
    for _ in 0..7 {
        let t = Instant::now();
        let body = vekrel::handlers::shell::snapshot(&db).unwrap();
        rust.push(t.elapsed().as_millis());
        let t = Instant::now();
        let _ = vekrel::compression::compress(
            Some("br"),
            vekrel::http_errors::json_bytes(axum::http::StatusCode::OK, body),
        );
        br.push(t.elapsed().as_millis());
    }
    let after = table_fingerprint(&db_path);
    println!(
        "TIMING owner shell ({}): Node median {} ms (identity), {} ms (br), over HTTP; Rust median {} ms (body) + {} ms (br), first read {cold} ms, in process",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        median(node.0),
        median(node.1),
        median(rust),
        median(br)
    );
    assert_eq!(
        before, after,
        "orchestration/projection tables unchanged by Rust's reads"
    );
    drop(d);
    assert!(!home.exists());
}
