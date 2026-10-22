use clap::{Parser, Subcommand};
use std::{path::PathBuf, sync::Arc};
use vekrel::{
    config,
    proxy_ws::{FrameTap, NoTap},
    recorder::Recorder,
    server, supervisor,
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Serve {
        #[arg(long)]
        config: PathBuf,
        /// Record WS frames to <state>/recordings (contains session tokens).
        #[arg(long)]
        record: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let Cmd::Serve { config, record } = Cli::parse().cmd;
    let mut cfg = config::load(&config)?;
    cfg.engine.record |= record;
    let engine_port = cfg.engine_port();
    let tap: Arc<dyn FrameTap> = if cfg.engine.record {
        Arc::new(Recorder::create(&state_dir()?.join("recordings"))?)
    } else {
        Arc::new(NoTap)
    };
    let state = Arc::new(supervisor::State::default());
    tokio::spawn(supervisor::run(cfg.engine, engine_port, state.clone()));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", cfg.server.port)).await?;
    // Returning drops the runtime, which drops the supervisor's child (kill_on_drop).
    tokio::select! {
        r = axum::serve(listener, server::build_with_tap(state, server::Upstream::loopback(engine_port), tap)) => r?,
        _ = shutdown_signal() => tracing::info!("shutting down"),
    }
    Ok(())
}

/// `$VEKREL_HOME`, else `~/.vekrel` (same rule as the engine).
fn state_dir() -> Result<PathBuf, &'static str> {
    if let Some(h) = std::env::var_os("VEKREL_HOME") {
        return Ok(h.into());
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    Ok(PathBuf::from(home.ok_or("neither VEKREL_HOME nor HOME is set")?).join(".vekrel"))
}

#[cfg(unix)]
async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
