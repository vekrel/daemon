use crate::config::EngineConfig;
use futures_util::FutureExt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::{
    process::{Child, Command},
    sync::watch,
};

#[derive(Default)]
pub struct State {
    pub engine_up: AtomicBool,
    pub restarts: AtomicU32,
    /// Bumped on every (re)spawn; proxied sockets compare it to detect a restart.
    pub generation: AtomicU64,
    /// Same value as `generation`, for tasks that await a restart.
    pub generation_tx: watch::Sender<u64>,
    /// Flips to true once on shutdown; the supervisor stops the engine and sockets close with 1001.
    pub shutdown_tx: watch::Sender<bool>,
}

impl State {
    pub fn bump_generation(&self) {
        let g = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.generation_tx.send_replace(g);
    }

    pub fn shutdown(&self) {
        self.shutdown_tx.send_replace(true);
    }
}

/// How long the engine gets to exit after SIGTERM before it is SIGKILLed.
pub const GRACE: Duration = Duration::from_secs(5);

/// 1s doubling, capped at 30s.
pub fn backoff_delay(attempt: u32) -> Duration {
    Duration::from_secs(1u64 << attempt.min(5)).min(Duration::from_secs(30))
}

pub async fn run(cfg: EngineConfig, port: u16, state: Arc<State>) {
    // attempt drives backoff and resets after 60s up; restarts only ever grows.
    let mut attempt: u32 = 0;
    let mut shutdown = state.shutdown_tx.subscribe();
    loop {
        let started = Instant::now();
        state.bump_generation();
        let spawned = Command::new(&cfg.command)
            .args(&cfg.args)
            .env("VEKREL_PORT", port.to_string())
            .env("VEKREL_HOST", "127.0.0.1")
            .env("VEKREL_NO_BROWSER", "1")
            .kill_on_drop(true)
            .spawn();
        match spawned {
            Ok(mut child) => {
                state.engine_up.store(true, Ordering::SeqCst);
                let status = tokio::select! {
                    s = child.wait() => s,
                    _ = shutdown.wait_for(|&s| s).map(drop) => {
                        stop(&mut child).await;
                        state.engine_up.store(false, Ordering::SeqCst);
                        return;
                    }
                };
                state.engine_up.store(false, Ordering::SeqCst);
                match status {
                    Ok(s) if s.success() => {
                        tracing::info!("engine exited cleanly");
                        return;
                    }
                    Ok(s) => {
                        tracing::error!("engine exited: {s}");
                    }
                    Err(e) => {
                        tracing::error!("engine wait failed: {e}");
                    }
                }
            }
            Err(e) => {
                tracing::error!("engine spawn failed: {e}");
            }
        }
        if started.elapsed() >= Duration::from_secs(60) {
            attempt = 0;
        }
        state.restarts.fetch_add(1, Ordering::SeqCst);
        tokio::select! {
            _ = tokio::time::sleep(backoff_delay(attempt)) => {}
            _ = shutdown.wait_for(|&s| s).map(drop) => return,
        }
        attempt += 1;
    }
}

/// SIGTERM, then SIGKILL after `GRACE`, so the engine can stop the agents it started.
async fn stop(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: plain syscall; pid is our own unreaped child, so it cannot be recycled.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        match tokio::time::timeout(GRACE, child.wait()).await {
            Ok(_) => {
                tracing::info!("engine stopped");
                return;
            }
            Err(_) => tracing::warn!("engine ignored SIGTERM for {GRACE:?}, killing it"),
        }
    }
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff_delay(0), Duration::from_secs(1));
        assert_eq!(backoff_delay(1), Duration::from_secs(2));
        assert_eq!(backoff_delay(4), Duration::from_secs(16));
        assert_eq!(backoff_delay(10), Duration::from_secs(30));
    }
}
