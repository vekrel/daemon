//! Every `/ws` socket the proxy holds, by session: what `connected` means for sockets that reach
//! Node through Rust, and a hook to close all of a session's sockets (on a Rust-side revoke).
use std::time::Duration;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{Notify, OwnedRwLockReadGuard, RwLock, watch};
use tokio_util::sync::CancellationToken;

pub struct Registry {
    inner: Mutex<Inner>,
    /// Bumped on every open and close.
    changed: watch::Sender<()>,
    /// Shared by each Rust auth writer from its bypass check through its commit (`writing`);
    /// taken once, exclusively, before a socket's first frame Node may serve (`drain`).
    write_gate: Arc<RwLock<()>>,
    /// Signalled when a writer holding the gate passes its bypass check (a sync point for tests;
    /// nothing waits on it in the daemon).
    pub write_checked: Notify,
}

#[derive(Default)]
struct Inner {
    next: u64,
    /// Session id → its open sockets' close tokens.
    sessions: HashMap<String, Vec<(u64, CancellationToken)>>,
    /// Sockets Node accepted whose session Rust could not verify: their `connected` is unknown.
    unattributed: usize,
    /// Open sockets whose `subscribeAuthAccess` Node serves (see `NodeStream`).
    node_streams: usize,
}

impl Default for Registry {
    fn default() -> Self {
        Registry {
            inner: Mutex::default(),
            changed: watch::channel(()).0,
            write_gate: Arc::default(),
            write_checked: Notify::new(),
        }
    }
}

/// One open socket; dropping it unregisters the socket.
pub struct Entry {
    reg: Arc<Registry>,
    sid: Option<String>,
    id: u64,
    /// Cancelled by `close_session`: the proxy then closes both legs.
    pub close: CancellationToken,
}

impl Drop for Entry {
    fn drop(&mut self) {
        let mut i = self.reg.lock();
        match &self.sid {
            None => i.unattributed -= 1,
            Some(sid) => {
                if let Some(v) = i.sessions.get_mut(sid) {
                    v.retain(|(id, _)| *id != self.id);
                    if v.is_empty() {
                        i.sessions.remove(sid);
                    }
                }
            }
        }
        drop(i);
        self.reg.changed.send_replace(());
    }
}

/// Held by a socket whose `subscribeAuthAccess` went to Node (declined or handed off): Node's
/// in-memory stream never sees Rust's writes, so writers decline until the socket closes.
pub struct NodeStream(Arc<Registry>);

impl Drop for NodeStream {
    fn drop(&mut self) {
        self.0.lock().node_streams -= 1;
    }
}

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers a socket Node accepted; `sid` is its verified session (`None`: unverified).
    pub fn open(self: &Arc<Self>, sid: Option<&str>) -> Entry {
        let close = CancellationToken::new();
        let mut i = self.lock();
        i.next += 1;
        let id = i.next;
        match sid {
            None => i.unattributed += 1,
            Some(s) => i
                .sessions
                .entry(s.to_owned())
                .or_default()
                .push((id, close.clone())),
        }
        drop(i);
        self.changed.send_replace(());
        Entry {
            reg: self.clone(),
            sid: sid.map(str::to_owned),
            id,
            close,
        }
    }

    /// Node's `connectedSessionsRef.has(sid)` for sockets that pass through Rust.
    pub fn connected(&self, sid: &str) -> bool {
        self.lock().sessions.contains_key(sid)
    }

    pub fn connected_ids(&self) -> Vec<String> {
        self.lock().sessions.keys().cloned().collect()
    }

    /// Open sockets whose session is unknown to Rust.
    pub fn unattributed(&self) -> usize {
        self.lock().unattributed
    }

    /// Marks one socket's access stream as Node's until the guard drops.
    pub fn node_stream(self: &Arc<Self>) -> NodeStream {
        self.lock().node_streams += 1;
        NodeStream(self.clone())
    }

    /// Open sockets whose access stream Node serves.
    pub fn node_streams(&self) -> usize {
        self.lock().node_streams
    }

    /// Held by a writer from its `bypass::active` check (made after acquiring) to its commit.
    pub async fn writing(&self) -> OwnedRwLockReadGuard<()> {
        self.write_gate.clone().read_owned().await
    }

    /// Waits until every writer that passed its check has committed or declined; `false` if
    /// `limit` ran out first. Call after `node_stream`: writers arriving later (queued behind
    /// this, as tokio's RwLock is fair) then see it and decline.
    pub async fn drain(&self, limit: Duration) -> bool {
        tokio::time::timeout(limit, self.write_gate.write())
            .await
            .is_ok()
    }

    /// Closes every socket of `sid`; returns how many.
    pub fn close_session(&self, sid: &str) -> usize {
        let i = self.lock();
        let socks = i.sessions.get(sid).map_or(&[][..], Vec::as_slice);
        socks.iter().for_each(|(_, c)| c.cancel());
        socks.len()
    }

    /// Wakes on every open and close.
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.changed.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_close_connected_and_close_hook() {
        let r = Arc::new(Registry::default());
        let mut w = r.subscribe();
        let a1 = r.open(Some("a"));
        let a2 = r.open(Some("a"));
        let b = r.open(Some("b"));
        let u = r.open(None);
        assert!(w.has_changed().unwrap());
        w.mark_unchanged();
        assert!(r.connected("a") && r.connected("b") && !r.connected("c"));
        assert_eq!(r.unattributed(), 1);
        let mut ids = r.connected_ids();
        ids.sort();
        assert_eq!(ids, ["a", "b"]);

        assert_eq!(r.close_session("a"), 2);
        assert!(a1.close.is_cancelled() && a2.close.is_cancelled());
        assert!(!b.close.is_cancelled());
        assert_eq!(r.close_session("c"), 0);

        drop(a1);
        assert!(w.has_changed().unwrap());
        assert!(r.connected("a"), "one socket of a is still open");
        drop(a2);
        assert!(!r.connected("a"));
        drop(u);
        assert_eq!(r.unattributed(), 0);
        drop(b);
        assert!(r.connected_ids().is_empty());
    }

    #[tokio::test]
    async fn drain_waits_for_writers_and_gives_up_at_its_limit() {
        let r = Registry::default();
        assert!(r.drain(Duration::ZERO).await, "no writer: no wait");
        let w = r.writing().await;
        let t = std::time::Instant::now();
        assert!(!r.drain(Duration::from_millis(300)).await);
        assert!(t.elapsed() >= Duration::from_millis(300));
        drop(w);
        assert!(r.drain(Duration::ZERO).await);
    }
}
