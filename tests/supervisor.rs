use std::process::{Child, Command};
use std::time::Duration;

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start(name: &str, command: &str, args: &[&str]) -> (Guard, u16) {
    let health = free_port();
    let args_toml = args.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>().join(", ");
    let cfg = format!(
        "[engine]\ncommand = {command:?}\nargs = [{args_toml}]\nport = {}\n[daemon]\nhealth_port = {health}\n",
        free_port()
    );
    let path = std::env::temp_dir().join(format!("vekreld-test-{}-{name}.toml", std::process::id()));
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_vekreld"))
        .args(["serve", "--config"])
        .arg(&path)
        .spawn()
        .unwrap();
    (Guard(child), health)
}

async fn health(port: u16) -> Option<(String, u64)> {
    let v: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{port}/healthz"))
        .await.ok()?.json().await.ok()?;
    Some((v["engine"].as_str()?.to_string(), v["restarts"].as_u64()?))
}

/// Polls until `done` or timeout; returns every observation.
async fn poll(port: u16, total: Duration, mut done: impl FnMut(&(String, u64)) -> bool) -> Vec<(String, u64)> {
    let end = tokio::time::Instant::now() + total;
    let mut seen = vec![];
    while tokio::time::Instant::now() < end {
        if let Some(h) = health(port).await {
            let d = done(&h);
            seen.push(h);
            if d { break; }
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
    let seen = poll(port, Duration::from_secs(1), |h| h.0 == "up").await;
    assert_eq!(seen.last(), Some(&("up".to_string(), 0)), "{seen:?}");
}
