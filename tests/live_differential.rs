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
