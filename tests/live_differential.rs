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
             [rust.handlers]\n\"GET /api/auth/session\" = \"shadow\"\n\
             \"GET /.well-known/vekrel/machine\" = \"shadow\"\n\
             \"projects.readFile\" = \"shadow\"\n\"filesystem.browse\" = \"shadow\"\n"
        ),
    )
    .unwrap();
    let out = std::fs::File::create(home.join("serve.log")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vekrel"));
    prep(&home, &mut cmd);
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
    let (matches, mismatches) = shadow_counts(&home, "GET /.well-known/vekrel/machine");
    println!("machine shadow log: {matches} match, {mismatches} mismatch");
    assert_eq!(mismatches, 0);
    assert_eq!(matches, 20, "every request compared");
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
            (f.len() == 7 && f[5].starts_with("t3_session")).then(|| format!("{}={}", f[5], f[6]))
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
        .filter(|l| l.contains("rust shadow") && l.contains("tag=\"filesystem.browse\""))
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
