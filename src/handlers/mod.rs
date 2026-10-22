//! Rust answers for requests Node would otherwise handle. See `http_seam` for how they are wired.
pub mod auth_session;

use std::path::PathBuf;

/// What a handler may need about the machine. Shared by the HTTP seam and (Task 2) the WS seam;
/// add fields only when a handler needs them.
#[derive(Debug, Clone, Default)]
pub struct HandlerCtx {
    /// The engine's working directory (the daemon's cwd; the engine inherits it).
    pub cwd: PathBuf,
    /// The engine's `config.stateDir`: `<VEKREL_HOME>/userdata`.
    pub state_dir: PathBuf,
    /// The engine's loopback port (not the public one).
    pub engine_port: u16,
}
