//! Rust answers for requests Node would otherwise handle. See `http_seam` and `rpc_seam` for how
//! they are wired.
pub mod archived_shell;
pub mod auth_access;
pub mod auth_session;
pub mod browse;
pub mod clients;
pub mod machine_descriptor;
pub mod pairing;
pub mod pairing_links;
pub mod projects;
pub mod read_file;
pub mod shell;
pub mod thread_search;
pub mod turn_item;
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

/// Routes that write `auth_sessions` / `auth_pairing_links`. Node's in-memory stream never sees
/// Rust's writes, so they may only `serve` while `subscribeAuthAccess` serves too.
pub const WRITE_KEYS: [&str; 6] = [
    pairing_links::CREATE_KEY,
    pairing_links::REVOKE_KEY,
    pairing::BROWSER_SESSION_KEY,
    pairing::TOKEN_KEY,
    clients::REVOKE_KEY,
    clients::REVOKE_OTHERS_KEY,
];

/// `mode` for route `key`, except a write configured `serve` while the stream is not: `shadow`.
pub fn guard_write(
    key: &str,
    mode: crate::config::Mode,
    stream: crate::config::Mode,
) -> crate::config::Mode {
    use crate::config::Mode;
    if mode == Mode::Serve && stream != Mode::Serve && WRITE_KEYS.contains(&key) {
        return Mode::Shadow;
    }
    mode
}

/// Routes that may never `serve`, with the reason the startup warning gives.
/// shortcut: these answer Node's cold-cache enrichment and cannot see Node's warm cache, so
/// serving them breaks byte parity; lift this once Rust owns the shell stream's enrichment cache.
pub const SHADOW_ONLY: [(&str, &str); 3] = [
    (
        projects::KEY,
        "Node fills repositoryIdentity and faviconPath from its warm enrichment cache, which Rust \
         cannot see (Rust answers the cold null and the row's faviconPath); it may serve once Rust \
         owns that cache",
    ),
    (archived_shell::TAG, SHELL_REASON),
    (shell::KEY, SHELL_REASON),
];

const SHELL_REASON: &str = "Node fills projects[*].repositoryIdentity from its warm enrichment \
     cache, which Rust cannot see (Rust answers the cold null); it may serve once Rust owns that \
     cache";

/// Why `key` may not serve, when it is shadow-only.
pub fn shadow_only_reason(key: &str) -> Option<&'static str> {
    SHADOW_ONLY.iter().find(|(k, _)| *k == key).map(|(_, r)| *r)
}

/// `mode` for route `key`, except a shadow-only route configured `serve`: `shadow`.
pub fn guard_shadow_only(key: &str, mode: crate::config::Mode) -> crate::config::Mode {
    use crate::config::Mode;
    if mode == Mode::Serve && shadow_only_reason(key).is_some() {
        return Mode::Shadow;
    }
    mode
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode::{Off, Serve, Shadow};

    #[test]
    fn writes_serve_only_while_the_stream_serves() {
        for key in WRITE_KEYS {
            assert_eq!(guard_write(key, Serve, Serve), Serve, "{key}");
            assert_eq!(guard_write(key, Serve, Shadow), Shadow, "{key}");
            assert_eq!(guard_write(key, Serve, Off), Shadow, "{key}");
            assert_eq!(guard_write(key, Off, Shadow), Off, "{key}");
            assert_eq!(guard_write(key, Shadow, Serve), Shadow, "{key}");
        }
        // Reads are not guarded.
        assert_eq!(guard_write(clients::LIST_KEY, Serve, Shadow), Serve);
        assert_eq!(guard_write("GET /api/auth/session", Serve, Off), Serve);
    }

    #[test]
    fn shadow_only_routes_never_serve() {
        assert_eq!(guard_shadow_only(projects::KEY, Serve), Shadow);
        assert_eq!(guard_shadow_only(projects::KEY, Shadow), Shadow);
        assert_eq!(guard_shadow_only(projects::KEY, Off), Off);
        assert_eq!(guard_shadow_only(archived_shell::TAG, Serve), Shadow);
        assert_eq!(guard_shadow_only(shell::KEY, Serve), Shadow);
        assert_eq!(guard_shadow_only(clients::LIST_KEY, Serve), Serve);
        for (key, _) in SHADOW_ONLY {
            assert!(
                shadow_only_reason(key)
                    .unwrap()
                    .contains("enrichment cache"),
                "{key}"
            );
        }
    }

    #[test]
    fn proven_6b_reads_serve_by_default() {
        use crate::rpc_seam::UnaryHandler;
        assert_eq!(
            thread_search::SearchThreads::default().default_mode(),
            Serve
        );
        assert_eq!(turn_item::TurnItem::default().default_mode(), Serve);
        assert_eq!(
            archived_shell::ArchivedShell::default().default_mode(),
            Shadow
        );
    }
}
