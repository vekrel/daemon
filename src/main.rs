mod config;
mod server;
mod supervisor;

use clap::{Parser, Subcommand};
use std::{path::PathBuf, sync::Arc};

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
        /// Record WS frames (used by later tasks).
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
    let state = Arc::new(supervisor::State::default());
    tokio::spawn(supervisor::run(cfg.engine, engine_port, state.clone()));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", cfg.server.port)).await?;
    // Returning drops the runtime, which drops the supervisor's child (kill_on_drop).
    tokio::select! {
        r = axum::serve(listener, server::build(state, server::Upstream::loopback(engine_port))) => r?,
        _ = shutdown_signal() => tracing::info!("shutting down"),
    }
    Ok(())
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
