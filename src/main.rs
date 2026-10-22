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
    axum::serve(listener, health::router(state)).await?;
    Ok(())
}
