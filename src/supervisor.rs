use crate::config::EngineConfig;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use std::time::{Duration, Instant};
use tokio::process::Command;

#[derive(Default)]
pub struct State {
    pub engine_up: AtomicBool,
    pub restarts: AtomicU32,
}


/// 1s doubling, capped at 30s.
pub fn backoff_delay(attempt: u32) -> Duration {
    Duration::from_secs(1u64 << attempt.min(5)).min(Duration::from_secs(30))
}

pub async fn run(cfg: EngineConfig, state: Arc<State>) {
    // attempt drives backoff and resets after 60s up; restarts only ever grows.
    let mut attempt: u32 = 0;
    loop {
        let started = Instant::now();
        let spawned = Command::new(&cfg.command)
            .args(&cfg.args)
            .env("VEKREL_PORT", cfg.port.to_string())
            .kill_on_drop(true)
            .spawn();
        match spawned {
            Ok(mut child) => {
                state.engine_up.store(true, Ordering::SeqCst);
                let status = child.wait().await;
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
        tokio::time::sleep(backoff_delay(attempt)).await;
        attempt += 1;
    }
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
