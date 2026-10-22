mod config;
mod health;
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
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let Cmd::Serve { config } = Cli::parse().cmd;
    let cfg = config::load(&config)?;
    let state = Arc::new(supervisor::State::default());
    tokio::spawn(supervisor::run(cfg.engine, state.clone()));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", cfg.daemon.health_port)).await?;
    // Returning drops the runtime, which drops the supervisor's child (kill_on_drop).
    tokio::select! {
        r = axum::serve(listener, health::router(state)) => r?,
        _ = shutdown_signal() => tracing::info!("shutting down"),
    }
    Ok(())
}

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
