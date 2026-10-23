//! Rust answers for requests Node would otherwise handle. See `http_seam` and `rpc_seam` for how
//! they are wired.
pub mod auth_session;
pub mod browse;
pub mod machine_descriptor;
pub mod read_file;
pub mod ws_ticket;

pub use auth_session::VerifiedSession;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// What a handler may need about the machine. Shared by the HTTP and WS seams; add fields only
/// when a handler needs them.
#[derive(Debug, Clone, Default)]
pub struct HandlerCtx {
    /// The engine's working directory (the daemon's cwd; the engine inherits it).
    pub cwd: PathBuf,
    /// The engine's `config.stateDir`: `<VEKREL_HOME>/userdata`.
    pub state_dir: PathBuf,
    /// The engine's loopback port (not the public one).
    pub engine_port: u16,
    /// WS: the connection's session, verified like Node's (always set when a WS handler runs).
    pub session: Option<VerifiedSession>,
    /// WS: cancelled when the client interrupts the request or the socket closes.
    pub cancel: CancellationToken,
}
