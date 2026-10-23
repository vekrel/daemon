//! Whether some client may reach Node without passing through the daemon, so the daemon's socket
//! registry cannot see it and Node's own `subscribeAuthAccess` may be what that client watches.
//! Rust's access stream then defers to Node, and Rust's auth writes decline so Node makes (and
//! publishes) them itself.
use super::{registry::Registry, shadow::AuthFiles};

/// Secrets a cloud link leaves (`cloud/config.ts`): the relay or the managed tunnel can then
/// carry sockets straight to Node.
const CLOUD_SECRETS: [&str; 3] = [
    "cloud-endpoint-runtime-config.bin",
    "cloud-relay-machine-credential.bin",
    "cloud-relay-url.bin",
];

/// Why, if a bypass may exist: Tailscale Serve (it proxies to Node's own port), no or an
/// unreadable secrets dir, a cloud link, or an open `/ws` whose session Rust could not verify.
pub fn active(files: &AuthFiles, registry: &Registry, tailscale: bool) -> Option<&'static str> {
    if tailscale {
        return Some("tailscale_serve");
    }
    let Some(secrets) = files.secrets_dir() else {
        return Some("no_secrets_dir");
    };
    // `exists` is false on a read error too, so an unreadable dir also declines below.
    if std::fs::read_dir(secrets).is_err() {
        return Some("secrets_unreadable");
    }
    if CLOUD_SECRETS.iter().any(|f| secrets.join(f).exists()) {
        return Some("cloud_link");
    }
    (registry.unattributed() > 0).then_some("unverified_socket")
}
