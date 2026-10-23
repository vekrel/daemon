//! WS takeover for RPCs: per-tag Rust handlers in `shadow` (Node answers, Rust's Exit, or a
//! stream's first Chunk, is compared with Node's and logged) or `serve` (Rust answers, Node never
//! sees the request) mode.
//! Routing follows research section 4: frames Rust does not own are forwarded as the original
//! bytes, and the proxy's pump is the only writer to the client socket.
use crate::{
    auth::registry::{NodeStream, Registry},
    config::{Mode, RustConfig},
    handlers::{
        HandlerCtx, VerifiedSession,
        auth_session::{AuthSession, WsSession},
    },
    http_auth::DpopCtx,
    http_seam::{ShadowLimit, json_path},
};
use axum::http::HeaderMap;
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::BoxStream};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio_util::sync::CancellationToken;

/// A Rust answer for one RPC tag. Handlers must be read-only and idempotent: a served request
/// whose handler declines or panics is forwarded to Node, which then runs it again.
pub trait UnaryHandler: Send + Sync {
    fn tag(&self) -> &'static str;
    /// The mode without a `[rust.handlers]` entry: `shadow` until the handler is proven.
    fn default_mode(&self) -> Mode {
        Mode::Shadow
    }
    /// The scope `RpcAuthorization.ts` requires for this tag.
    fn required_scope(&self) -> &'static str;
    /// `Ok`: the Exit Success value; `Err`: the tagged error for Exit Failure `[{_tag:"Fail",error}]`;
    /// `None`: not mine, Node answers (serve forwards the request late; shadow skips the compare).
    fn handle<'a>(
        &'a self,
        payload: Value,
        ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Result<Value, Value>>>;
}

/// A stream's Chunks: each `Ok` is one Chunk's `values`; an `Err` ends the stream with Exit
/// Failure `[{_tag:"Fail",error}]`; the end of the stream is Exit Success `null`. An empty `Ok`
/// (`HANDOFF`) hands the request to Node: the seam forwards the original request under the same
/// id and stops owning it. Items are pulled only after the previous Chunk's Ack, so no Rust Chunk
/// is unacked at that point.
pub type Chunks = BoxStream<'static, Result<Vec<Value>, Value>>;

/// See `Chunks`.
pub const HANDOFF: Vec<Value> = Vec::new();

/// A Rust producer for one streaming RPC tag. Like Node, the seam sends a Chunk only after the
/// client acked the previous one, and drops the producer on Interrupt or socket close.
pub trait StreamHandler: Send + Sync {
    fn tag(&self) -> &'static str;
    fn default_mode(&self) -> Mode {
        Mode::Shadow
    }
    fn required_scope(&self) -> &'static str;
    /// `None`: not mine, Node answers (decline happens before the first Chunk or never).
    fn open<'a>(&'a self, payload: Value, ctx: &'a HandlerCtx) -> BoxFuture<'a, Option<Chunks>>;
}

#[derive(Clone)]
enum Handler {
    Unary(Arc<dyn UnaryHandler>),
    Stream(Arc<dyn StreamHandler>),
}

impl Handler {
    fn tag(&self) -> &'static str {
        match self {
            Handler::Unary(h) => h.tag(),
            Handler::Stream(h) => h.tag(),
        }
    }
    fn required_scope(&self) -> &'static str {
        match self {
            Handler::Unary(h) => h.required_scope(),
            Handler::Stream(h) => h.required_scope(),
        }
    }
}

#[derive(Default)]
pub struct Seam {
    handlers: Vec<(Handler, Mode)>,
    /// Every proxied socket by verified session (`connected`, close hook).
    registry: Arc<Registry>,
    pub ctx: HandlerCtx,
    /// Verifies the connection's session; without it every session is deferred to Node.
    auth: Option<Arc<AuthSession>>,
    /// `/ws` DPoP proofs (`"GET /ws dpop"`); `Mode::default()` is shadow.
    dpop: Mode,
}

impl std::fmt::Debug for Seam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let h: Vec<_> = self.handlers.iter().map(|(h, m)| (h.tag(), m)).collect();
        f.debug_struct("Seam").field("handlers", &h).finish()
    }
}

impl Seam {
    pub fn new(handlers: Vec<(Arc<dyn UnaryHandler>, Mode)>) -> Self {
        let handlers = handlers
            .into_iter()
            .filter(|h| h.1 != Mode::Off)
            .map(|(h, m)| (Handler::Unary(h), m))
            .collect();
        Seam {
            handlers,
            ..Seam::default()
        }
    }

    pub fn with_stream(mut self, mode: Mode, h: Arc<dyn StreamHandler>) -> Self {
        if mode != Mode::Off {
            self.handlers.push((Handler::Stream(h), mode));
        }
        self
    }

    /// Shares `registry` (the one stream handlers read `connected` from).
    pub fn with_registry(mut self, registry: Arc<Registry>) -> Self {
        self.registry = registry;
        self
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// Each handler in its `[rust.handlers]` mode, else its `default_mode`.
    pub fn from_config(handlers: Vec<Arc<dyn UnaryHandler>>, cfg: &RustConfig) -> Self {
        let handlers = handlers.into_iter().map(|h| {
            let mode = cfg.mode(h.tag(), h.default_mode());
            (h, mode)
        });
        Seam::new(handlers.collect())
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

    /// `/ws` DPoP proofs: `serve` consumes them (Node then gets a Rust ticket), `shadow` only
    /// checks them, `off` leaves them to Node.
    pub fn with_dpop_mode(mut self, mode: Mode) -> Self {
        self.dpop = mode;
        self
    }

    pub(crate) fn dpop_mode(&self) -> Mode {
        self.dpop
    }

    /// The connection's session from the upgrade request Node sees (`dctx`: the client's URL).
    pub(crate) async fn session(
        &self,
        h: &HeaderMap,
        query: Option<&str>,
        dctx: &DpopCtx,
    ) -> WsSession {
        match (&self.auth, self.is_empty()) {
            (Some(a), false) => a.ws_session(h, query, dctx).await,
            _ => WsSession::Deferred,
        }
    }

    /// A `wsTicket` for `sid`, so Node opens the socket of a DPoP proof Rust consumed.
    pub(crate) fn node_ticket(&self, sid: &str) -> Option<String> {
        let key = self.auth.as_ref()?.files().key()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        Some(crate::auth::ticket::issue(sid, now.as_millis() as i64, &key).0)
    }

    fn find(&self, tag: &str) -> Option<(&Handler, Mode)> {
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

/// A finished handler (or a stream's Chunk), reported back to the connection's pump.
pub(crate) struct Done {
    key: String,
    id: Value,
    /// `None`: the handler declined, or a shadow computation timed out or panicked. For a shadow
    /// stream: its first Chunk's `values` array (or its Exit).
    exit: Option<Value>,
    /// A served stream's Chunk `values`; `exit` is then unused.
    chunk: Option<Vec<Value>>,
}

impl Done {
    fn exit(key: String, id: Value, exit: Option<Value>) -> Done {
        Done {
            key,
            id,
            exit,
            chunk: None,
        }
    }
}

/// Where a finished handler's frame goes.
pub(crate) enum Out {
    Client(String),
    /// A served request the handler declined: the client's request, for Node to answer.
    Node(String),
}

struct Shadowed {
    tag: &'static str,
    /// A stream: Node's first Chunk `values` (or its Exit, if that comes first) is compared.
    stream: bool,
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
    #[serde(borrow)]
    values: Option<&'a RawValue>,
}

fn interrupted() -> Value {
    // Research section 4: one Interrupt entry (Node repeats it per fiber).
    failure(json!({"_tag": "Interrupt", "fiberId": 0}))
}

/// Whether a client frame might hold a Request, Ack or Interrupt, so it is worth parsing. Looks
/// for the quoted tag value, which no whitespace can split; any `\` escape (the tag could be
/// spelled with one) also parses. Pings and the like skip the parse.
fn may_route(text: &str) -> bool {
    text.contains('\\')
        || ["\"Request\"", "\"Ack\"", "\"Interrupt\""]
            .iter()
            .any(|t| text.contains(t))
}

/// What to send upstream for a client frame.
pub(crate) enum Fwd {
    Original,
    Text(String),
    Nothing,
}

/// The access stream's tag: whenever Node serves it for a socket, Rust's auth writes decline.
const ACCESS: &str = "subscribeAuthAccess";

/// A served request in flight.
struct Owned {
    cancel: CancellationToken,
    /// The request text, forwarded to Node on decline.
    raw: String,
    /// A stream's Ack signal: the producer waits for one per Chunk.
    ack: Option<UnboundedSender<()>>,
    /// Chunks sent and not yet acked; Acks beyond these are dropped.
    unacked: u32,
    tag: &'static str,
}

/// Per-connection routing state. Keys are the request id's JSON text.
pub(crate) struct Conn {
    seam: Arc<Seam>,
    session: WsSession,
    owned: HashMap<String, Owned>,
    shadow: HashMap<String, Shadowed>,
    done: UnboundedSender<Done>,
    limit: ShadowLimit,
    /// Set once Node serves this socket's `subscribeAuthAccess`; dropped with the socket.
    node_stream: Option<NodeStream>,
    /// `node_stream` was just taken: drain in-flight writers before the next frame to Node.
    drain: bool,
}

/// Longest wait for in-flight auth writers: Node's 5 s busy_timeout plus slack.
const DRAIN_LIMIT: Duration = Duration::from_secs(6);

impl Drop for Conn {
    fn drop(&mut self) {
        let shadowed = self.shadow.values().map(|s| &s.cancel);
        self.owned
            .values()
            .map(|o| &o.cancel)
            .chain(shadowed)
            .for_each(|c| c.cancel());
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
            node_stream: None,
            drain: false,
        }
    }

    /// Node serves this socket's `subscribeAuthAccess` (or may): see `NodeStream`.
    fn hold_node_stream(&mut self) {
        if self.node_stream.is_none() {
            self.node_stream = Some(self.seam.registry.node_stream());
            self.drain = true;
        }
    }

    /// Awaited before every frame to Node: Node reads its access snapshot when the subscribe
    /// arrives, so writers that passed their bypass check must commit first. Later writers see
    /// `node_stream` and decline. On timeout the frame goes anyway.
    pub(crate) async fn drained(&mut self) {
        if std::mem::take(&mut self.drain) && !self.seam.registry.drain(DRAIN_LIMIT).await {
            tracing::warn!(
                limit_ms = DRAIN_LIMIT.as_millis() as u64,
                "auth write drain timed out; forwarding"
            );
        }
    }

    /// Node's decoder reads binary frames as JSON too: any one may be a subscribe Node serves.
    pub(crate) fn c2s_binary(&mut self) {
        if !self.seam.is_empty() {
            self.hold_node_stream();
        }
    }

    /// Routes a client text frame: what goes upstream, and frames Rust answers right away.
    pub(crate) fn c2s(&mut self, text: &str) -> (Fwd, Vec<String>) {
        let mut out = Vec::new();
        if self.seam.is_empty() || !may_route(text) {
            return (Fwd::Original, out);
        }
        let fwd = match serde_json::from_str::<Value>(text) {
            // JSON.parse may still read it (lone surrogates, deep nesting), maybe as a subscribe
            // whose tag is spelled with escapes.
            Err(_) => {
                if text.contains('\\') || text.contains(ACCESS) {
                    self.hold_node_stream();
                }
                Fwd::Original
            }
            Ok(Value::Array(items)) => {
                let n = items.len();
                let rest: Vec<_> = items
                    .into_iter()
                    .filter(|m| !self.take(m, None, &mut out))
                    .collect();
                match rest.len() {
                    0 => Fwd::Nothing,
                    k if k == n => Fwd::Original,
                    // The one re-serialization: the unclaimed remainder of a split array.
                    _ => Fwd::Text(Value::Array(rest).to_string()),
                }
            }
            Ok(m) if self.take(&m, Some(text), &mut out) => Fwd::Nothing,
            Ok(_) => Fwd::Original,
        };
        (fwd, out)
    }

    /// Handles `m` (whose frame text is `raw` unless it came from an array) if Rust owns it;
    /// `false` means forward it.
    fn take(&mut self, m: &Value, raw: Option<&str>, out: &mut Vec<String>) -> bool {
        let key = m.get("requestId").map(Value::to_string);
        match m.get("_tag").and_then(Value::as_str) {
            Some("Request") => {
                let taken = self.request(m, raw, out);
                // Deferred session, shadow, limiter skip, mode off: Node serves it.
                if !taken && m.get("tag").and_then(Value::as_str) == Some(ACCESS) {
                    self.hold_node_stream();
                }
                taken
            }
            Some("Ack") => {
                let Some(o) = key.and_then(|k| self.owned.get_mut(&k)) else {
                    return false;
                };
                if let Some(a) = &o.ack
                    && o.unacked > 0
                {
                    o.unacked -= 1;
                    let _ = a.send(());
                }
                true
            }
            Some("Interrupt") => {
                let Some(k) = key else { return false };
                if let Some(s) = self.shadow.remove(&k) {
                    s.cancel.cancel(); // Node answers the Interrupt; nothing to compare.
                    return false;
                }
                let Some(o) = self.owned.remove(&k) else {
                    return false;
                };
                o.cancel.cancel();
                out.push(exit_frame(&m["requestId"], &interrupted()));
                true
            }
            _ => false,
        }
    }

    fn request(&mut self, m: &Value, raw: Option<&str>, out: &mut Vec<String>) -> bool {
        let (Some(id), Some(tag)) = (m.get("id"), m.get("tag").and_then(Value::as_str)) else {
            return false;
        };
        let Some((h, mode)) = self.seam.find(tag) else {
            return false;
        };
        let h = h.clone();
        let session = match &self.session {
            // Rejected: Node accepted a ticket Rust would refuse, so Rust is wrong; Node answers.
            WsSession::Deferred | WsSession::Rejected(_) => {
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
            WsSession::Verified(_) => None,
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
                // An array element is re-encoded, like the remainder of a split array frame.
                let raw = raw.map_or_else(|| m.to_string(), str::to_owned);
                let (done, id, tag) = (self.done.clone(), id.clone(), h.tag());
                let ack = match h {
                    Handler::Unary(h) => {
                        let task = tokio::spawn(self.run(h, payload, s, cancel.clone(), "serve"));
                        let key = key.clone();
                        tokio::spawn(async move {
                            // A panic declines: Node answers (handlers are read-only, so rerunning is safe).
                            let exit = task.await.ok().flatten();
                            let _ = done.send(Done::exit(key, id, exit));
                        });
                        None
                    }
                    Handler::Stream(h) => {
                        let (ack, acks) = unbounded_channel();
                        let ctx = self.ctx(s, cancel.clone());
                        tokio::spawn(produce(h, payload, ctx, acks, key.clone(), id, done));
                        Some(ack)
                    }
                };
                let o = Owned {
                    cancel,
                    raw,
                    ack,
                    unacked: 0,
                    tag,
                };
                self.owned.insert(key, o);
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
                    stream: matches!(h, Handler::Stream(_)),
                    rust: None,
                    node: None,
                    cancel: cancel.clone(),
                    since: Instant::now(),
                };
                match session {
                    None => entry.rust = Some(denied().to_string()),
                    Some(s) => {
                        let run = match h {
                            Handler::Unary(h) => self.run(h, payload, s, cancel, "shadow").boxed(),
                            Handler::Stream(h) => {
                                first_chunk(h, payload, self.ctx(s, cancel)).boxed()
                            }
                        };
                        let Some(task) = self.limit.spawn(entry.tag, run) else {
                            return false;
                        };
                        let (done, key, id) = (self.done.clone(), key.clone(), id.clone());
                        tokio::spawn(async move {
                            let exit = task.await.ok().flatten();
                            let _ = done.send(Done::exit(key, id, exit));
                        });
                    }
                }
                self.shadow.insert(key, entry);
                false
            }
            Mode::Off => false,
        }
    }

    fn ctx(&self, session: VerifiedSession, cancel: CancellationToken) -> HandlerCtx {
        HandlerCtx {
            session: Some(session),
            cancel,
            ..self.seam.ctx.clone()
        }
    }

    /// The handler's Exit for one request; `None` if it declined.
    fn run(
        &self,
        h: Arc<dyn UnaryHandler>,
        payload: Value,
        session: VerifiedSession,
        cancel: CancellationToken,
        mode: &'static str,
    ) -> impl Future<Output = Option<Value>> + Send + 'static {
        let ctx = self.ctx(session, cancel.clone());
        async move {
            // Cancellation drops the handler even if it never looks at the token.
            let r = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Some(interrupted()),
                r = h.handle(payload, &ctx) => r,
            };
            let Some(r) = r else {
                tracing::info!(
                    tag = h.tag(),
                    mode,
                    outcome = "declined",
                    "rust handler declined"
                );
                return None;
            };
            Some(match r {
                Ok(v) => success(v),
                Err(e) => failure(json!({"_tag": "Fail", "error": e})),
            })
        }
    }

    /// A handler finished: for a served request still owned, its Exit, or the request for Node.
    pub(crate) fn done(&mut self, d: Done) -> Option<Out> {
        if let Some(values) = d.chunk {
            // Dropped once the request is no longer owned (interrupted).
            let o = self.owned.get_mut(&d.key)?;
            o.unacked += 1;
            let c = json!({"_tag": "Chunk", "requestId": d.id, "values": values});
            return Some(Out::Client(c.to_string()));
        }
        if let Some(o) = self.owned.remove(&d.key) {
            return Some(match d.exit {
                Some(e) => Out::Client(exit_frame(&d.id, &e)),
                None => {
                    // Declined, handed off, or panicked before its first Chunk.
                    if o.tag == ACCESS {
                        self.hold_node_stream();
                    }
                    Out::Node(o.raw)
                }
            });
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
        if self.shadow.is_empty() {
            return;
        }
        let chunk = text.contains("\"Chunk\"") && self.shadow.values().any(|s| s.stream);
        if !chunk && !text.contains("\"Exit\"") {
            return;
        }
        let msgs = if text.trim_start().starts_with('[') {
            serde_json::from_str::<Vec<NodeMsg>>(text)
        } else {
            serde_json::from_str::<NodeMsg>(text).map(|m| vec![m])
        };
        for m in msgs.into_iter().flatten() {
            let (Some(tag), Some(id)) = (m.tag, m.request_id) else {
                continue;
            };
            let (stream, raw) = match (tag, m.exit, m.values) {
                ("Exit", Some(exit), _) => (false, exit),
                ("Chunk", _, Some(values)) => (true, values),
                _ => continue,
            };
            // Same key as the request's: the id's JSON as serde writes it.
            let Ok(id) = serde_json::from_str::<Value>(id.get()) else {
                continue;
            };
            let key = id.to_string();
            if let Some(s) = self.shadow.get_mut(&key)
                && (s.stream || !stream)
                && s.node.is_none()
            {
                s.node = Some(raw.get().to_owned());
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

/// Runs a served stream: one Chunk, then wait for its Ack, until the end, an error, an Interrupt
/// or the socket closing (`ctx.cancel`). A decline or a panic before the first Chunk forwards the
/// request to Node; a panic later ends the stream as interrupted.
async fn produce(
    h: Arc<dyn StreamHandler>,
    payload: Value,
    ctx: HandlerCtx,
    mut acks: tokio::sync::mpsc::UnboundedReceiver<()>,
    key: String,
    id: Value,
    done: UnboundedSender<Done>,
) {
    let cancel = ctx.cancel.clone();
    let sent = Arc::new(AtomicBool::new(false));
    let (tx, flag) = (done.clone(), sent.clone());
    let (k, i) = (key.clone(), id.clone());
    let task = tokio::spawn(async move {
        let chunks = tokio::select! {
            biased;
            _ = cancel.cancelled() => return None,
            c = h.open(payload, &ctx) => c,
        };
        let Some(mut chunks) = chunks else {
            tracing::info!(
                tag = h.tag(),
                mode = "serve",
                outcome = "declined",
                "rust handler declined"
            );
            return Some(None);
        };
        loop {
            let item = tokio::select! {
                biased;
                _ = cancel.cancelled() => return None,
                i = chunks.next() => i,
            };
            match item {
                // Handoff: forwarded to Node like a decline.
                Some(Ok(values)) if values.is_empty() => return Some(None),
                Some(Ok(values)) => {
                    let d = Done {
                        key: k.clone(),
                        id: i.clone(),
                        exit: None,
                        chunk: Some(values),
                    };
                    flag.store(true, Ordering::SeqCst);
                    if tx.send(d).is_err() {
                        return None;
                    }
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => return None,
                        a = acks.recv() => { a?; }
                    }
                }
                Some(Err(e)) => return Some(Some(failure(json!({"_tag": "Fail", "error": e})))),
                None => return Some(Some(success(Value::Null))),
            }
        }
    });
    let exit = match task.await {
        Ok(None) => return, // interrupted or closed: the pump already answered
        Ok(Some(exit)) => exit,
        Err(_) if sent.load(Ordering::SeqCst) => Some(interrupted()),
        Err(_) => None,
    };
    let _ = done.send(Done::exit(key, id, exit));
}

/// Shadow: the stream's first Chunk `values` (or its Exit), then the producer is dropped.
async fn first_chunk(h: Arc<dyn StreamHandler>, payload: Value, ctx: HandlerCtx) -> Option<Value> {
    let cancel = ctx.cancel.clone();
    tokio::select! {
        biased;
        _ = cancel.cancelled() => None,
        v = async {
            let Some(mut chunks) = h.open(payload, &ctx).await else {
                tracing::info!(tag = h.tag(), mode = "shadow", outcome = "declined", "rust handler declined");
                return None;
            };
            Some(match chunks.next().await {
                Some(Ok(values)) => Value::Array(values),
                Some(Err(e)) => failure(json!({"_tag": "Fail", "error": e})),
                None => success(Value::Null),
            })
        } => v,
    }
}

#[cfg(test)]
mod tests {
    use super::may_route;

    #[test]
    fn pre_check_skips_only_frames_that_cannot_be_routed() {
        for f in [
            r#"{"_tag":"Request","id":1}"#,
            r#"{ "_tag" : "Ack" , "requestId" : 1 }"#,
            r#"[{"_tag":"Ping"},{"_tag":"Interrupt","requestId":1}]"#,
            r#"{"_tag":"Requ\u0065st"}"#,
        ] {
            assert!(may_route(f), "{f}");
        }
        for f in [r#"{"_tag":"Ping"}"#, r#"{"_tag":"Eof"}"#, "not json"] {
            assert!(!may_route(f), "{f}");
        }
    }
}
