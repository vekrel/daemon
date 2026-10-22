//! WS takeover for unary RPCs: per-tag Rust handlers in `shadow` (Node answers, Rust's Exit is
//! compared with Node's and logged) or `serve` (Rust answers, Node never sees the request) mode.
//! Routing follows research section 4: frames Rust does not own are forwarded as the original
//! bytes, and the proxy's pump is the only writer to the client socket.
use crate::{
    config::Mode,
    handlers::{
        HandlerCtx, VerifiedSession,
        auth_session::{AuthSession, WsSession},
    },
    http_seam::{ShadowLimit, json_path},
};
use axum::http::HeaderMap;
use futures_util::future::BoxFuture;
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

pub trait UnaryHandler: Send + Sync {
    fn tag(&self) -> &'static str;
    /// The scope `RpcAuthorization.ts` requires for this tag.
    fn required_scope(&self) -> &'static str;
    /// `Ok`: the Exit Success value; `Err`: the tagged error for Exit Failure `[{_tag:"Fail",error}]`.
    fn handle<'a>(
        &'a self,
        payload: Value,
        ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Result<Value, Value>>;
}

#[derive(Default)]
pub struct Seam {
    handlers: Vec<(Arc<dyn UnaryHandler>, Mode)>,
    pub ctx: HandlerCtx,
    /// Verifies the connection's session; without it every session is unverified (denied).
    auth: Option<Arc<AuthSession>>,
}

impl std::fmt::Debug for Seam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let h: Vec<_> = self.handlers.iter().map(|(h, m)| (h.tag(), m)).collect();
        f.debug_struct("Seam").field("handlers", &h).finish()
    }
}

impl Seam {
    pub fn new(handlers: Vec<(Arc<dyn UnaryHandler>, Mode)>) -> Self {
        let handlers = handlers.into_iter().filter(|h| h.1 != Mode::Off).collect();
        Seam {
            handlers,
            ..Seam::default()
        }
    }

    pub fn with_ctx(mut self, ctx: HandlerCtx) -> Self {
        self.ctx = ctx;
        self
    }

    pub fn with_auth(mut self, auth: Arc<AuthSession>) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// The connection's session from the upgrade request Node sees.
    pub(crate) async fn session(&self, h: &HeaderMap, query: Option<&str>) -> WsSession {
        match (&self.auth, self.is_empty()) {
            (Some(a), false) => a.ws_session(h, query).await,
            _ => WsSession::Unverified,
        }
    }

    fn find(&self, tag: &str) -> Option<(&Arc<dyn UnaryHandler>, Mode)> {
        self.handlers
            .iter()
            .find(|(h, _)| h.tag() == tag)
            .map(|(h, m)| (h, *m))
    }
}

/// `rpcAuthorizationError(requiredScope)` (`RpcAuthorization.ts:224-228`): fields in the
/// `MachineAuthorizationError` schema order, `requiredScope` mapped by `authScopeRequiredResponse`.
pub fn authorization_error(required: &str) -> Value {
    json!({
        "_tag": "MachineAuthorizationError",
        "message": format!("The authenticated token is missing required scope: {required}."),
        "requiredScope": legacy_parent(required).unwrap_or(required),
        "requiredPermission": required,
    })
}

/// `legacyParents` in contracts `auth.ts`.
fn legacy_parent(scope: &str) -> Option<&'static str> {
    Some(match scope {
        "filesystem:read" | "diagnostics:read" => "orchestration:read",
        "settings:write"
        | "providers:manage"
        | "machine:maintain"
        | "preview:operate"
        | "source-control:write"
        | "filesystem:write" => "orchestration:operate",
        "terminal:read" => "terminal:operate",
        _ => return None,
    })
}

fn success(v: Value) -> Value {
    json!({"_tag": "Success", "value": v})
}

fn failure(cause: Value) -> Value {
    json!({"_tag": "Failure", "cause": [cause]})
}

fn exit_frame(id: &Value, exit: &Value) -> String {
    json!({"_tag": "Exit", "requestId": id, "exit": exit}).to_string()
}

/// A finished handler, reported back to the connection's pump.
pub(crate) struct Done {
    key: String,
    id: Value,
    /// `None`: a shadow computation that timed out or panicked.
    exit: Option<Value>,
}

struct Shadowed {
    tag: &'static str,
    /// Rust's encoding of its exit.
    rust: Option<String>,
    /// Node's `exit`, exactly as it appeared in Node's frame.
    node: Option<String>,
    cancel: CancellationToken,
    since: Instant,
}

/// Shadow entries whose Exit never arrives from Node are dropped after this.
const SHADOW_TTL: Duration = Duration::from_secs(600);

/// An s2c message, borrowing `exit` as Node's exact bytes.
#[derive(Deserialize)]
struct NodeMsg<'a> {
    #[serde(rename = "_tag")]
    tag: Option<&'a str>,
    #[serde(rename = "requestId", borrow)]
    request_id: Option<&'a RawValue>,
    #[serde(borrow)]
    exit: Option<&'a RawValue>,
}

fn interrupted() -> Value {
    // Research section 4: one Interrupt entry (Node repeats it per fiber).
    failure(json!({"_tag": "Interrupt", "fiberId": 0}))
}

/// What to send upstream for a client frame.
pub(crate) enum Fwd {
    Original,
    Text(String),
    Nothing,
}

/// Per-connection routing state. Keys are the request id's JSON text.
pub(crate) struct Conn {
    seam: Arc<Seam>,
    session: WsSession,
    owned: HashMap<String, CancellationToken>,
    shadow: HashMap<String, Shadowed>,
    done: UnboundedSender<Done>,
    limit: ShadowLimit,
}

impl Drop for Conn {
    fn drop(&mut self) {
        let shadowed = self.shadow.values().map(|s| &s.cancel);
        self.owned.values().chain(shadowed).for_each(|c| c.cancel());
    }
}

impl Conn {
    pub(crate) fn new(
        seam: Arc<Seam>,
        session: WsSession,
        done: UnboundedSender<Done>,
        limit: ShadowLimit,
    ) -> Self {
        Conn {
            seam,
            session,
            owned: HashMap::new(),
            shadow: HashMap::new(),
            done,
            limit,
        }
    }

    /// Routes a client text frame: what goes upstream, and frames Rust answers right away.
    pub(crate) fn c2s(&mut self, text: &str) -> (Fwd, Vec<String>) {
        let mut out = Vec::new();
        if self.seam.is_empty() {
            return (Fwd::Original, out);
        }
        let fwd = match serde_json::from_str::<Value>(text) {
            Err(_) => Fwd::Original,
            Ok(Value::Array(items)) => {
                let n = items.len();
                let rest: Vec<_> = items
                    .into_iter()
                    .filter(|m| !self.take(m, &mut out))
                    .collect();
                match rest.len() {
                    0 => Fwd::Nothing,
                    k if k == n => Fwd::Original,
                    // The one re-serialization: the unclaimed remainder of a split array.
                    _ => Fwd::Text(Value::Array(rest).to_string()),
                }
            }
            Ok(m) if self.take(&m, &mut out) => Fwd::Nothing,
            Ok(_) => Fwd::Original,
        };
        (fwd, out)
    }

    /// Handles `m` if Rust owns it; `false` means forward it.
    fn take(&mut self, m: &Value, out: &mut Vec<String>) -> bool {
        let key = m.get("requestId").map(Value::to_string);
        match m.get("_tag").and_then(Value::as_str) {
            Some("Request") => self.request(m, out),
            Some("Ack") => key.is_some_and(|k| self.owned.contains_key(&k)),
            Some("Interrupt") => {
                let Some(k) = key else { return false };
                if let Some(s) = self.shadow.remove(&k) {
                    s.cancel.cancel(); // Node answers the Interrupt; nothing to compare.
                    return false;
                }
                let Some(cancel) = self.owned.remove(&k) else {
                    return false;
                };
                cancel.cancel();
                out.push(exit_frame(&m["requestId"], &interrupted()));
                true
            }
            _ => false,
        }
    }

    fn request(&mut self, m: &Value, out: &mut Vec<String>) -> bool {
        let (Some(id), Some(tag)) = (m.get("id"), m.get("tag").and_then(Value::as_str)) else {
            return false;
        };
        let Some((h, mode)) = self.seam.find(tag) else {
            return false;
        };
        let h = h.clone();
        let session = match &self.session {
            WsSession::Deferred => {
                tracing::info!(
                    tag,
                    outcome = "deferred_unverifiable_credential",
                    "rust rpc"
                );
                return false;
            }
            // `RpcAuthorization.layer`: `scopes.includes(requiredScope)` on the token's scopes.
            WsSession::Verified(s) if s.scopes.iter().any(|x| x == h.required_scope()) => {
                Some(s.clone())
            }
            WsSession::Verified(_) | WsSession::Unverified => None,
        };
        let denied =
            || failure(json!({"_tag": "Fail", "error": authorization_error(h.required_scope())}));
        let key = id.to_string();
        let cancel = CancellationToken::new();
        let payload = m.get("payload").cloned().unwrap_or(Value::Null);
        match mode {
            // RpcServer `handleRequest`: an id already running is dropped, unanswered.
            Mode::Serve if self.owned.contains_key(&key) => true,
            Mode::Shadow if self.shadow.contains_key(&key) => false,
            Mode::Serve => {
                let Some(s) = session else {
                    out.push(exit_frame(id, &denied()));
                    return true;
                };
                self.owned.insert(key.clone(), cancel.clone());
                let task = tokio::spawn(self.run(h, payload, s, cancel));
                let done = self.done.clone();
                let id = id.clone();
                tokio::spawn(async move {
                    // What Node sends for a defect, so the client's request still ends.
                    let die = || failure(json!({"_tag": "Die", "defect": "rust handler panicked"}));
                    let exit = Some(task.await.unwrap_or_else(|_| die()));
                    let _ = done.send(Done { key, id, exit });
                });
                true
            }
            Mode::Shadow => {
                self.shadow.retain(|_, s| {
                    let live = s.since.elapsed() < SHADOW_TTL;
                    if !live {
                        s.cancel.cancel();
                    }
                    live
                });
                let mut entry = Shadowed {
                    tag: h.tag(),
                    rust: None,
                    node: None,
                    cancel: cancel.clone(),
                    since: Instant::now(),
                };
                match session {
                    None => entry.rust = Some(denied().to_string()),
                    Some(s) => {
                        let run = self.run(h, payload, s, cancel);
                        let Some(task) =
                            self.limit.spawn(entry.tag, async move { Some(run.await) })
                        else {
                            return false;
                        };
                        let (done, key, id) = (self.done.clone(), key.clone(), id.clone());
                        tokio::spawn(async move {
                            let exit = task.await.ok().flatten();
                            let _ = done.send(Done { key, id, exit });
                        });
                    }
                }
                self.shadow.insert(key, entry);
                false
            }
            Mode::Off => false,
        }
    }

    /// The handler's Exit for one request.
    fn run(
        &self,
        h: Arc<dyn UnaryHandler>,
        payload: Value,
        session: VerifiedSession,
        cancel: CancellationToken,
    ) -> impl Future<Output = Value> + Send + 'static {
        let ctx = HandlerCtx {
            session: Some(session),
            cancel: cancel.clone(),
            ..self.seam.ctx.clone()
        };
        async move {
            // Cancellation drops the handler even if it never looks at the token.
            tokio::select! {
                biased;
                _ = cancel.cancelled() => interrupted(),
                r = h.handle(payload, &ctx) => match r {
                    Ok(v) => success(v),
                    Err(e) => failure(json!({"_tag": "Fail", "error": e})),
                },
            }
        }
    }

    /// A handler finished: the frame to write for a served request, if it is still owned.
    pub(crate) fn done(&mut self, d: Done) -> Option<String> {
        if self.owned.remove(&d.key).is_some() {
            return d.exit.map(|e| exit_frame(&d.id, &e));
        }
        match d.exit {
            None => drop(self.shadow.remove(&d.key)),
            Some(exit) => {
                if let Some(s) = self.shadow.get_mut(&d.key) {
                    s.rust = Some(exit.to_string());
                    self.settle(d.key);
                }
            }
        }
        None
    }

    /// Watches Node's frames for the Exits of shadowed requests.
    pub(crate) fn s2c(&mut self, text: &str) {
        if self.shadow.is_empty() || !text.contains("\"Exit\"") {
            return;
        }
        let msgs = if text.trim_start().starts_with('[') {
            serde_json::from_str::<Vec<NodeMsg>>(text)
        } else {
            serde_json::from_str::<NodeMsg>(text).map(|m| vec![m])
        };
        for m in msgs.into_iter().flatten() {
            let (Some("Exit"), Some(id), Some(exit)) = (m.tag, m.request_id, m.exit) else {
                continue;
            };
            // Same key as the request's: the id's JSON as serde writes it.
            let Ok(id) = serde_json::from_str::<Value>(id.get()) else {
                continue;
            };
            let key = id.to_string();
            if let Some(s) = self.shadow.get_mut(&key) {
                s.node = Some(exit.get().to_owned());
                self.settle(key);
            }
        }
    }

    /// Compares Node's exact `exit` bytes with Rust's encoding once both are in; logs name the
    /// JSON path, never values.
    fn settle(&mut self, key: String) {
        let Some(Shadowed {
            rust: Some(rust),
            node: Some(node),
            tag,
            ..
        }) = self.shadow.get(&key)
        else {
            return;
        };
        if node == rust {
            tracing::info!(tag, outcome = "match", "rust shadow");
        } else {
            let path = json_path(node.as_bytes(), rust.as_bytes());
            tracing::warn!(tag, outcome = "mismatch", path, "rust shadow");
        }
        self.shadow.remove(&key);
    }
}
