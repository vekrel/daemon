use std::process::{Child, Command};
use std::time::Duration;

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        // SIGTERM so vekrel reaps its engine child; SIGKILL would orphan it.
        let _ = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status();
        // vekrel gives its engine up to 5 s to exit gracefully.
        for _ in 0..140 {
            if !matches!(self.0.try_wait(), Ok(None)) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(name: &str, command: &str, args: &[&str]) -> (Guard, u16) {
    // Retried: another process can take the freed port before vekrel binds it.
    for _ in 0..3 {
        if let Some(started) = try_start(name, command, args) {
            return started;
        }
    }
    panic!("vekrel never started listening");
}

/// Spawns vekrel and waits (up to 10 s) until it accepts connections, so test windows
/// start once it is up; None if it exited first.
fn try_start(name: &str, command: &str, args: &[&str]) -> Option<(Guard, u16)> {
    let health = free_port(); // the public server port
    let args_toml = args
        .iter()
        .map(|a| format!("{a:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let cfg = format!(
        "[server]\nport = {health}\n[engine]\ncommand = {command:?}\nargs = [{args_toml}]\n"
    );
    let path = std::env::temp_dir().join(format!("vekrel-test-{}-{name}.toml", std::process::id()));
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_vekrel"))
        .args(["serve", "--config"])
        .arg(&path)
        .spawn()
        .unwrap();
    let mut g = Guard(child);
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < end {
        if g.0.try_wait().unwrap().is_some() {
            return None;
        }
        if std::net::TcpStream::connect(("127.0.0.1", health)).is_ok() {
            return Some((g, health));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

async fn health(port: u16) -> Option<(String, u64)> {
    let v: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{port}/healthz"))
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    Some((v["engine"].as_str()?.to_string(), v["restarts"].as_u64()?))
}

/// Polls until `done` or timeout; returns every observation.
async fn poll(
    port: u16,
    total: Duration,
    mut done: impl FnMut(&(String, u64)) -> bool,
) -> Vec<(String, u64)> {
    let end = tokio::time::Instant::now() + total;
    let mut seen = vec![];
    while tokio::time::Instant::now() < end {
        if let Some(h) = health(port).await {
            let d = done(&h);
            seen.push(h);
            if d {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    seen
}

#[tokio::test]
async fn crash_loop_increments_restarts_and_reports_down() {
    let (_g, port) = start("crash", "sh", &["-c", "exit 1"]);
    // observe through the window so a "down" sample is certain
    let seen = poll(port, Duration::from_secs(3), |_| false).await;
    assert!(seen.iter().any(|h| h.0 == "down"), "{seen:?}");
    assert!(seen.last().unwrap().1 >= 2, "{seen:?}");
}

#[tokio::test]
async fn clean_exit_is_not_restarted() {
    let (_g, port) = start("clean", "sh", &["-c", "exit 0"]);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let h = health(port).await.expect("health up");
    assert_eq!(h, ("down".to_string(), 0));
}

#[tokio::test]
async fn missing_binary_reports_down_without_panic() {
    let (mut g, port) = start("missing", "/nonexistent/node", &[]);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(g.0.try_wait().unwrap().is_none(), "daemon exited");
    assert_eq!(health(port).await.expect("health up").0, "down");
}

#[tokio::test]
async fn running_engine_reports_up() {
    let (_g, port) = start("up", "sleep", &["30"]);
    let seen = poll(port, Duration::from_secs(5), |h| h.0 == "up").await;
    assert_eq!(seen.last(), Some(&("up".to_string(), 0)), "{seen:?}");
}

#[tokio::test]
async fn sigterm_stops_engine_child() {
    let marker = format!("3{}", std::process::id()); // unique sleep arg to find the child
    let (mut g, port) = start("sigterm", "sleep", &[&marker]);
    let seen = poll(port, Duration::from_secs(2), |h| h.0 == "up").await;
    assert_eq!(seen.last().map(|h| h.0.as_str()), Some("up"), "{seen:?}");
    let pattern = format!("sleep {marker}");
    let found = || {
        Command::new("pgrep")
            .args(["-f", &pattern])
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(found(), "engine child not running");
    Command::new("kill")
        .args(["-TERM", &g.0.id().to_string()])
        .status()
        .unwrap();
    let end = tokio::time::Instant::now() + Duration::from_secs(3);
    while g.0.try_wait().unwrap().is_none() {
        assert!(tokio::time::Instant::now() < end, "vekrel did not exit");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(g.0.try_wait().unwrap().unwrap().success());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!found(), "engine child orphaned");
}

#[tokio::test]
async fn child_receives_vekrel_port_env() {
    let dir = std::env::temp_dir().join(format!("vekrel-env-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (a, b) = (dir.join("port"), dir.join("rest"));
    let script = format!(
        "echo $VEKREL_PORT > {}; echo $VEKREL_HOST $VEKREL_NO_BROWSER > {}; sleep 30",
        a.display(),
        b.display()
    );
    let (_g, port) = start("env", "sh", &["-c", &script]);
    poll(port, Duration::from_secs(2), |h| h.0 == "up").await;
    wait_for(Duration::from_secs(5), || {
        [&a, &b]
            .iter()
            .all(|p| std::fs::read_to_string(p).is_ok_and(|s| s.ends_with('\n')))
    })
    .await;
    assert_eq!(
        std::fs::read_to_string(a).unwrap().trim(),
        (port + 10).to_string()
    );
    assert_eq!(std::fs::read_to_string(b).unwrap().trim(), "127.0.0.1 1");
    let _ = std::fs::remove_dir_all(dir);
}

async fn wait_for(total: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = tokio::time::Instant::now() + total;
    while tokio::time::Instant::now() < end {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    done()
}

fn running(pattern: &str) -> bool {
    Command::new("pgrep")
        .args(["-f", pattern])
        .output()
        .unwrap()
        .status
        .success()
}

/// SIGTERMs vekrel and returns how long it took to exit, and whether it exited 0.
async fn sigterm_and_wait(g: &mut Guard, limit: Duration) -> (Duration, bool) {
    let t0 = tokio::time::Instant::now();
    Command::new("kill")
        .args(["-TERM", &g.0.id().to_string()])
        .status()
        .unwrap();
    while g.0.try_wait().unwrap().is_none() {
        assert!(t0.elapsed() < limit, "vekrel did not exit within {limit:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (t0.elapsed(), g.0.try_wait().unwrap().unwrap().success())
}

#[tokio::test]
async fn sigterm_sends_sigterm_to_engine_and_waits() {
    let file = std::env::temp_dir().join(format!("vekrel-graceful-{}", std::process::id()));
    let _ = std::fs::remove_file(&file);
    let script = format!(
        "trap 'echo graceful > {}; exit 0' TERM; while true; do sleep 0.1; done",
        file.display()
    );
    let (mut g, port) = start("graceful", "sh", &["-c", &script]);
    let seen = poll(port, Duration::from_secs(5), |h| h.0 == "up").await;
    assert_eq!(seen.last().map(|h| h.0.as_str()), Some("up"), "{seen:?}");
    tokio::time::sleep(Duration::from_millis(200)).await; // let sh install its trap
    let (_, ok) = sigterm_and_wait(&mut g, Duration::from_secs(7)).await;
    assert!(ok, "vekrel exit status not 0");
    let got = std::fs::read_to_string(&file).unwrap_or_default();
    let _ = std::fs::remove_file(&file);
    assert_eq!(got.trim(), "graceful");
}

#[tokio::test]
async fn engine_ignoring_sigterm_is_killed_after_grace() {
    let marker = format!("stubborn-{}", std::process::id());
    let script = format!("trap '' TERM; while true; do sleep 0.1; done # {marker}");
    let (mut g, port) = start("stubborn", "sh", &["-c", &script]);
    let seen = poll(port, Duration::from_secs(5), |h| h.0 == "up").await;
    assert_eq!(seen.last().map(|h| h.0.as_str()), Some("up"), "{seen:?}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(running(&marker), "engine child not running");
    let (took, ok) = sigterm_and_wait(&mut g, Duration::from_millis(6500)).await;
    assert!(ok, "vekrel exit status not 0");
    assert!(
        took >= Duration::from_secs(4),
        "did not wait for grace: {took:?}"
    );
    assert!(
        wait_for(Duration::from_secs(1), || !running(&marker)).await,
        "engine child still running"
    );
}
