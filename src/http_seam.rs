//! HTTP takeover: per-route Rust handlers in `shadow` (Node answers, Rust's answer is compared and
//! logged) or `serve` (Rust answers, Node never sees the request) mode. See `config::Mode`.
use crate::{config::Mode, handlers::HandlerCtx};
use axum::{
    body::{Body, Bytes, HttpBody},
    http::{HeaderValue, Method, Response, header, request::Parts},
};
use futures_util::{Stream, future::BoxFuture};
use serde_json::Value;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinHandle,
};

/// Caps shadow computations across both seams: at most `permits` at once, each cut off after
/// `timeout`. When full, the comparison is skipped; the client is never affected.
#[derive(Clone, Debug)]
pub struct ShadowLimit {
    permits: Arc<Semaphore>,
    timeout: std::time::Duration,
}

impl Default for ShadowLimit {
    fn default() -> Self {
        ShadowLimit::new(64, std::time::Duration::from_secs(10))
    }
}

impl ShadowLimit {
    pub fn new(permits: usize, timeout: std::time::Duration) -> Self {
        ShadowLimit {
            permits: Arc::new(Semaphore::new(permits)),
            timeout,
        }
    }

    /// Spawns `fut` under a permit and the timeout (`None` on timeout); `None` without spawning,
    /// logged as `shadow_skipped_busy`, when every permit is taken. Never waits.
    pub fn spawn<T: Send + 'static>(
        &self,
        handler: &str,
        fut: impl Future<Output = Option<T>> + Send + 'static,
    ) -> Option<JoinHandle<Option<T>>> {
        let permit = self.acquire(handler)?;
        let fut = async move {
            let _permit = permit;
            fut.await
        };
        Some(self.run(handler, fut))
    }

    /// A permit, or `None` (logged as `shadow_skipped_busy`) when every permit is taken. The
    /// caller holds it for as long as the shadow work keeps memory (HTTP: through the compare).
    pub fn acquire(&self, handler: &str) -> Option<OwnedSemaphorePermit> {
        let p = self.permits.clone().try_acquire_owned().ok();
        if p.is_none() {
            tracing::info!(handler, outcome = "shadow_skipped_busy", "rust shadow");
        }
        p
    }

    /// Spawns `fut` under the timeout (`None` on timeout); the permit is the caller's.
    pub fn run<T: Send + 'static>(
        &self,
        handler: &str,
        fut: impl Future<Output = Option<T>> + Send + 'static,
    ) -> JoinHandle<Option<T>> {
        let (timeout, handler) = (self.timeout, handler.to_owned());
        tokio::spawn(async move {
            tokio::time::timeout(timeout, fut)
                .await
                .unwrap_or_else(|_| {
                    tracing::warn!(handler, outcome = "shadow_timeout", "rust shadow");
                    None
                })
        })
    }
}

pub trait RouteHandler: Send + Sync {
    fn method_path(&self) -> (Method, &'static str);
    /// The mode without a `[rust.handlers]` entry: `shadow` until the handler is proven.
    fn default_mode(&self) -> Mode {
        Mode::Shadow
    }
    /// Buffer the request body (up to `BODY_LIMIT`) into a `RequestBody` extension; a larger
    /// body goes straight to Node without calling the handler.
    fn wants_body(&self) -> bool {
        false
    }
    /// How shadow mode compares Node's answer with Rust's.
    fn compare(&self) -> Compare {
        Compare::DEFAULT
    }
    /// The handler writes in `serve`, so `shadow` is a dry run: its prediction (SELECTs only) must
    /// read the DB before Node writes it, and the proxy waits for it before forwarding.
    fn dry_run(&self) -> bool {
        false
    }
    /// `None` means "not mine": Node answers, in either mode.
    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>>;
}

/// On a dry run's predicted response: checks Node's real write against the prediction, given
/// Node's headers and body (blocking: it reads the DB). `None` when they agree, else what differs.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct DryRun(pub Arc<dyn Fn(&axum::http::HeaderMap, &[u8]) -> Option<String> + Send + Sync>);

/// The config key for a handler: `"GET /api/auth/session"`.
pub fn key(h: &dyn RouteHandler) -> String {
    let (m, p) = h.method_path();
    format!("{m} {p}")
}

/// Node bodies above this are passed through without comparison (`Compare::tee_limit`'s default).
pub const TEE_LIMIT: u64 = 1 << 20;

/// Request bodies above this are Node's.
pub const BODY_LIMIT: usize = 64 << 10;

/// The buffered request body, in `Parts::extensions` for handlers that `wants_body`.
#[derive(Clone, Debug)]
pub struct RequestBody(pub Bytes);

/// How long `buffer` waits for the whole body before handing it to Node.
pub const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Reads `body` whole if it fits `BODY_LIMIT` and arrives within `timeout`; otherwise `Err` with
/// a body that replays every byte already read, then the rest, so Node receives the original
/// bytes (and applies its own timeouts to a slow client). The outer `Err`: the client's body
/// broke mid-read, so nobody can answer it.
pub(crate) async fn buffer(
    body: Body,
    h: &axum::http::HeaderMap,
    timeout: std::time::Duration,
) -> Result<Result<Bytes, Body>, axum::Error> {
    use futures_util::StreamExt;
    let declared = h
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    if declared.is_some_and(|n| n > BODY_LIMIT as u64) {
        return Ok(Err(body));
    }
    let mut s = body.into_data_stream();
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, s.next()).await {
            Ok(None) => return Ok(Ok(buf.into())),
            Ok(Some(chunk)) => {
                buf.extend_from_slice(&chunk?);
                if buf.len() <= BODY_LIMIT {
                    continue;
                }
            }
            Err(_) => {}
        }
        // Too large or too slow.
        let head =
            futures_util::stream::once(std::future::ready(Ok::<_, axum::Error>(Bytes::from(buf))));
        return Ok(Err(Body::from_stream(head.chain(s))));
    }
}

/// The body text as Effect's `HttpApiBuilder.decodePayload` reads it for `media_type`; `None`
/// (Node answers: 415, Effect's 400, or a decoding Rust does not reproduce) otherwise.
fn body_text<'a>(req: &'a Parts, media_type: &str) -> Option<&'a str> {
    // No request decompression in the engine: Node would parse the coded bytes and fail.
    if req.headers.contains_key(header::CONTENT_ENCODING) {
        return None;
    }
    // `MediaType.normalize(headers["content-type"] ?? "application/json")`.
    let ct = match req.headers.get(header::CONTENT_TYPE) {
        Some(v) => v.to_str().ok()?.to_ascii_lowercase(),
        None => "application/json".into(),
    };
    if ct.split(';').next().unwrap_or("").trim() != media_type {
        return None;
    }
    // Node decodes lossily (U+FFFD); invalid UTF-8 is left to it. Its TextDecoder also drops a
    // leading BOM, which Rust does not reproduce.
    let text = std::str::from_utf8(&req.extensions.get::<RequestBody>()?.0).ok()?;
    (!text.starts_with('\u{feff}')).then_some(text)
}

/// `JSON.parse` of a JSON payload, before the endpoint's schema. An empty body is `None`
/// (Node decodes `undefined`, which a struct payload rejects).
pub fn json_body(req: &Parts) -> Option<Value> {
    let text = body_text(req, "application/json")?;
    // serde_json rejects everything JSON.parse rejects; duplicate keys keep the first position
    // and the last value, as in JS.
    (!text.is_empty()).then(|| serde_json::from_str(text).ok())?
}

/// `UrlParams.toRecord(new URLSearchParams(text))`: a key once is a string, repeated an array.
pub fn form_body(req: &Parts) -> Option<serde_json::Map<String, Value>> {
    let text = body_text(req, "application/x-www-form-urlencoded")?;
    // URLSearchParams drops a leading `?`; not reproduced.
    if text.starts_with('?') {
        return None;
    }
    let mut out = serde_json::Map::new();
    for pair in text.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (k, v) = (form_decode(k)?, Value::String(form_decode(v)?));
        match out.get_mut(&k) {
            None => {
                out.insert(k, v);
            }
            Some(Value::Array(a)) => a.push(v),
            Some(first) => *first = Value::Array(vec![first.take(), v]),
        }
    }
    Some(out)
}

/// WHATWG urlencoded value decoding: `+` is a space, `%XX` a byte, a stray `%` stays. `None` for
/// bytes that are not UTF-8 (URLSearchParams would substitute U+FFFD).
fn form_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16);
    let (mut out, mut i) = (Vec::with_capacity(b.len()), 0);
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() && hex(b[i + 1]).is_some() && hex(b[i + 2]).is_some() => {
                out.push((hex(b[i + 1])? * 16 + hex(b[i + 2])?) as u8);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// `x-t3-orchestration-protocol: 2`, which every `/api/orchestration/*` route requires
/// (`contracts/machineHttp.ts:81-85`). Without it Effect answers its own 400: handlers decline.
/// A repeated header reaches Node joined (`2, 2`) and fails too.
pub fn orchestration_protocol(req: &Parts) -> bool {
    let mut v = req.headers.get_all("x-t3-orchestration-protocol").iter();
    v.next().is_some_and(|v| v == "2") && v.next().is_none()
}

/// What shadow mode compares beyond status: JSON values everywhere except the listed paths
/// (`$.ticket`, `$[*].sessionId`; `$.traceId` always), ISO timestamps at `times` within ±2 s, and
/// the listed response headers by presence and bytes (`set-cookie` ignoring the token and with
/// `Expires` within ±2 s).
#[derive(Clone, Copy, Debug)]
pub struct Compare {
    pub ignore: &'static [&'static str],
    pub times: &'static [&'static str],
    pub headers: &'static [&'static str],
    /// Values Node's warm in-memory caches fill in where Rust answers the cold `null`. Still a
    /// mismatch; when nothing else differs its field is `ENRICHMENT`, and otherwise the first
    /// other differing path is reported, so enrichment never hides another difference.
    pub enrich: &'static [&'static str],
    /// Top-level keys holding the read's sequence: Node and Rust read at different moments, so
    /// a differing value is `SEQUENCE_SKEW` (a write landed between the reads), not a mismatch.
    pub skew: &'static [&'static str],
    /// Node bodies (decoded) above this are passed through without comparison.
    pub tee_limit: u64,
}

impl Compare {
    pub const DEFAULT: Compare = Compare {
        ignore: &[],
        times: &[],
        headers: &["content-type"],
        enrich: &[],
        skew: &[],
        tee_limit: TEE_LIMIT,
    };
    /// The headers auth routes must match: Node's credential and challenge headers.
    pub const AUTH_HEADERS: &'static [&'static str] = &[
        "content-type",
        "cache-control",
        "pragma",
        "www-authenticate",
        "set-cookie",
    ];
}

const SKEW_MS: i64 = 2000;

/// `diff`'s field when a `Compare::skew` key differs: the two reads saw different sequences.
pub const SEQUENCE_SKEW: &str = "sequence_skew";

/// `diff`'s field for a mismatch only at `Compare::enrich` paths (Node set, Rust `null`).
pub const ENRICHMENT: &str = "enrichment";

/// The first difference between Node's response and Rust's: (field, JSON path or header name).
pub fn diff(
    cmp: &Compare,
    status: axum::http::StatusCode,
    headers: &axum::http::HeaderMap,
    body: &[u8],
    rust: &Response<Bytes>,
) -> Option<(&'static str, String)> {
    if status != rust.status() {
        return Some(("status", "$".into()));
    }
    for &name in cmp.headers {
        let (n, r) = (headers.get_all(name), rust.headers().get_all(name));
        let same = n.iter().count() == r.iter().count()
            && n.iter().zip(r).all(|(a, b)| match name {
                "set-cookie" => same_cookie(a.as_bytes(), b.as_bytes()),
                _ => a == b,
            });
        if !same {
            return Some(("header", name.into()));
        }
    }
    diff_body(cmp, body, rust.body())
}

/// `diff` for two JSON bodies alone (Node's, Rust's): status and headers aside.
pub fn diff_body(cmp: &Compare, body: &[u8], rust: &[u8]) -> Option<(&'static str, String)> {
    if body == rust {
        return None;
    }
    let (Ok(mut a), Ok(mut b)) = (
        serde_json::from_slice::<Value>(body),
        serde_json::from_slice::<Value>(rust),
    ) else {
        return Some(("body", "$ (not json)".into()));
    };
    let canonical = |v: &Value, raw: &[u8]| serde_json::to_vec(v).is_ok_and(|c| c == raw);
    if !canonical(&a, body) || !canonical(&b, rust) {
        return Some(("body", "$ (formatting)".into()));
    }
    if cmp.skew.iter().any(|k| a.get(*k) != b.get(*k)) {
        return Some((SEQUENCE_SKEW, skew_path(cmp, &a, b)));
    }
    let raw = (!cmp.enrich.is_empty()).then(|| (a.clone(), b.clone()));
    let mut warm = false;
    mask(cmp, &mut a, &mut b, "$".into(), &mut warm);
    // Byte-exact: Value equality ignores key order, and Node's order follows its schema.
    if serde_json::to_vec(&a).ok() == serde_json::to_vec(&b).ok() {
        // Only enrichment differs: still a mismatch, at its first path, labelled for grepping.
        return warm.then(|| {
            let (a, b) = raw.expect("enrich paths");
            let path = first_diff(&a, &b, "$".into()).unwrap_or_else(|| "$".into());
            (ENRICHMENT, path)
        });
    }
    let path = if a == b {
        "$ (key order)".into()
    } else {
        first_diff(&a, &b, "$".into()).unwrap_or_else(|| "$ (formatting)".into())
    };
    Some(("body", path))
}

/// The first real difference under a skew: Rust's `skew` keys set to Node's, then compared
/// without `skew`; `""` when the sequences were the only difference.
pub fn skew_path(cmp: &Compare, node: &Value, mut rust: Value) -> String {
    for k in cmp.skew {
        if let (Some(v), Some(r)) = (node.get(*k), rust.get_mut(*k)) {
            *r = v.clone();
        }
    }
    let plain = Compare { skew: &[], ..*cmp };
    let (n, r) = (serde_json::to_vec(node), serde_json::to_vec(&rust));
    let (Ok(n), Ok(r)) = (n, r) else {
        return "$ (not json)".into();
    };
    diff_body(&plain, &n, &r).map_or_else(String::new, |(_, path)| path)
}

/// Nulls the ignored values on both sides and copies Rust's timestamp onto Node's when they are
/// within `SKEW_MS`, so `first_diff` only sees real differences. `path` uses `[*]` for indexes.
fn mask(cmp: &Compare, a: &mut Value, b: &mut Value, path: String, warm: &mut bool) {
    if path == "$.traceId" || cmp.ignore.contains(&path.as_str()) {
        (*a, *b) = (Value::Null, Value::Null);
    } else if cmp.enrich.contains(&path.as_str()) && b.is_null() && !a.is_null() {
        (*a, *warm) = (Value::Null, true);
    } else if cmp.times.contains(&path.as_str()) {
        let ms = |v: &Value| v.as_str().and_then(parse_iso);
        if let (Some(x), Some(y)) = (ms(a), ms(b))
            && (x - y).abs() <= SKEW_MS
        {
            *a = b.clone();
        }
    } else {
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                for (k, va) in x.iter_mut() {
                    if let Some(vb) = y.get_mut(k) {
                        mask(cmp, va, vb, format!("{path}.{k}"), warm);
                    }
                }
            }
            (Value::Array(x), Value::Array(y)) => {
                for (va, vb) in x.iter_mut().zip(y) {
                    mask(cmp, va, vb, format!("{path}[*]"), warm);
                }
            }
            _ => {}
        }
    }
}

/// `name=<token>; attrs` equal except the token, with `Expires` within `SKEW_MS`.
fn same_cookie(a: &[u8], b: &[u8]) -> bool {
    let split = |v: &[u8]| {
        let s = std::str::from_utf8(v).ok()?;
        let mut parts = s.split("; ");
        let name = parts.next()?.split_once('=')?.0.to_owned();
        let (mut attrs, mut expires) = (Vec::new(), None);
        for p in parts {
            match p.strip_prefix("Expires=") {
                Some(e) => expires = Some(parse_http_date(e)?),
                None => attrs.push(p.to_owned()),
            }
        }
        Some((name, attrs, expires))
    };
    match (split(a), split(b)) {
        (Some((na, aa, ea)), Some((nb, ab, eb))) => {
            na == nb
                && aa == ab
                && match (ea, eb) {
                    (Some(x), Some(y)) => (x - y).abs() <= SKEW_MS,
                    (x, y) => x == y,
                }
        }
        _ => a == b,
    }
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's days_from_civil).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// Epoch ms of `YYYY-MM-DDTHH:MM:SS.sssZ` (`toISOString`).
pub fn parse_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 24 || b[23] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let days = days_from_civil(n(0..4)?, n(5..7)?, n(8..10)?);
    Some(((days * 24 + n(11..13)?) * 60 + n(14..16)?) * 60_000 + n(17..19)? * 1000 + n(20..23)?)
}

/// Epoch ms of `Thu, 23 Oct 2026 08:00:00 GMT` (`toUTCString`).
fn parse_http_date(s: &str) -> Option<i64> {
    const MONTHS: &str = "JanFebMarAprMayJunJulAugSepOctNovDec";
    let mut f = s.split(' ');
    let (_, d, mon, y, t, gmt) = (
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
    );
    if gmt != "GMT" || mon.len() != 3 {
        return None;
    }
    let m = MONTHS.find(mon)? as i64 / 3 + 1;
    let days = days_from_civil(y.parse().ok()?, m, d.parse().ok()?);
    let mut hms = t.split(':').map(|x| x.parse::<i64>().ok());
    let (h, mi, sec) = (hms.next()??, hms.next()??, hms.next()??);
    Some(((days * 24 + h) * 60 + mi) * 60_000 + sec * 1000)
}

#[derive(Default)]
pub struct Seam {
    routes: Vec<(Mode, Arc<dyn RouteHandler>)>,
    pub ctx: HandlerCtx,
}

impl std::fmt::Debug for Seam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let routes: Vec<_> = self.routes.iter().map(|(m, h)| (m, key(&**h))).collect();
        f.debug_struct("Seam").field("routes", &routes).finish()
    }
}

impl Seam {
    pub fn new(ctx: HandlerCtx) -> Self {
        Seam {
            routes: Vec::new(),
            ctx,
        }
    }

    pub fn with(mut self, mode: Mode, h: Arc<dyn RouteHandler>) -> Self {
        if mode != Mode::Off {
            self.routes.push((mode, h));
        }
        self
    }

    pub(crate) fn find(&self, m: &Method, path: &str) -> Option<(Mode, Arc<dyn RouteHandler>)> {
        self.routes.iter().find_map(|(mode, h)| {
            let (hm, hp) = h.method_path();
            (hm == m && hp == path).then(|| (*mode, h.clone()))
        })
    }
}

pub(crate) fn served(r: Response<Bytes>) -> Response<Body> {
    let mut r = r.map(Body::from);
    r.headers_mut()
        .insert("x-vekrel-served-by", HeaderValue::from_static("rust"));
    r
}

/// Returns Node's response at once and streams its body through unchanged (errors included),
/// keeping a copy; once both the body and Rust's answer (`rust`, already running) are done, a
/// detached task compares and logs. Nothing here waits on Rust.
pub(crate) fn tee(
    node: Response<Body>,
    rust: JoinHandle<Option<Response<Bytes>>>,
    route: String,
    cmp: Compare,
    // Node rejects a DPoP proof only for the rewritten Host (see `dpop::node_htu_host_mismatch`).
    htu: bool,
    // Held until the compare is done: it bounds the bodies and JSON trees shadows keep in memory.
    permit: OwnedSemaphorePermit,
    // Rust's read once more, for a `sequence_skew` (`Compare::skew`); `None` keeps the skew.
    rerun: Option<BoxFuture<'static, Option<Response<Bytes>>>>,
) -> Response<Body> {
    let (parts, body) = node.into_parts();
    // shortcut: a body without a known length (chunked) is skipped too; Node sends lengths for JSON.
    if body.size_hint().upper().is_none_or(|n| n > cmp.tee_limit) {
        let (status, len) = (parts.status.as_u16(), body.size_hint().upper());
        tracing::info!(
            route,
            status,
            len,
            outcome = "shadow_skipped_large",
            "rust shadow"
        );
        return Response::from_parts(parts, body);
    }
    let (tx, rx) = oneshot::channel();
    let (status, headers) = (parts.status, parts.headers.clone());
    tokio::spawn(async move {
        let _permit = permit;
        // A handler that declines, panics, or a body that failed / was abandoned: nothing to compare.
        let (Ok(Some(rust)), Ok(bytes)) = (rust.await, rx.await) else {
            return;
        };
        // Node compresses bodies of 1 KiB and up when the client accepts it; compare the JSON.
        let enc = headers.get(header::CONTENT_ENCODING);
        let Some(bytes) = decoded_up_to(enc, bytes, cmp.tee_limit) else {
            tracing::info!(route, outcome = "skipped_encoding", "rust shadow");
            return;
        };
        // A multi-MB body (the shell) takes tens of ms to compare: off the async workers.
        let (h, b) = (headers.clone(), bytes.clone());
        let blocking = move || (diff(&cmp, status, &h, &b, &rust), rust);
        let Ok((mut d, rust)) = tokio::task::spawn_blocking(blocking).await else {
            return;
        };
        // A write landed between the two reads: Rust reads again now that Node's answer is in.
        if let (Some((SEQUENCE_SKEW, _)), Some(rerun)) = (&d, rerun)
            && let Some(again) = rerun.await
        {
            let (h, b) = (headers.clone(), bytes.clone());
            let blocking = move || diff(&cmp, status, &h, &b, &again);
            if let Ok(again) = tokio::task::spawn_blocking(blocking).await {
                d = again;
            }
        }
        if let Some(DryRun(check)) = rust.extensions().get::<DryRun>().cloned()
            && status == rust.status()
        {
            let (route, headers, bytes) = (route.clone(), headers.clone(), bytes.clone());
            match tokio::task::spawn_blocking(move || check(&headers, &bytes)).await {
                Ok(None) => tracing::info!(route, outcome = "match", "rust dry run"),
                Ok(Some(field)) => {
                    tracing::warn!(route, outcome = "mismatch", field, "rust dry run")
                }
                Err(_) => {}
            }
        }
        match d {
            None => tracing::info!(route, outcome = "match", "rust shadow"),
            Some((SEQUENCE_SKEW, path)) if path.is_empty() => {
                tracing::info!(route, outcome = SEQUENCE_SKEW, "rust shadow")
            }
            // Still skewed after the rerun: the first difference beyond the sequence is evidence.
            Some((SEQUENCE_SKEW, path)) => {
                tracing::info!(route, outcome = SEQUENCE_SKEW, path, "rust shadow")
            }
            // Expected while Node sits behind the proxy: not a Rust bug.
            Some((field, path)) if htu => {
                tracing::info!(
                    route,
                    outcome = "node_htu_host_mismatch",
                    field,
                    path,
                    "rust shadow"
                )
            }
            Some((field, path)) => {
                tracing::warn!(route, outcome = "mismatch", field, path, "rust shadow")
            }
        }
    });
    let tee = Tee {
        len: body.size_hint().exact(),
        inner: body.into_data_stream(),
        buf: Vec::new(),
        tx: Some(tx),
    };
    Response::from_parts(parts, Body::from_stream(tee))
}

/// Node's body with its `content-encoding` (Effect's `br`, `gzip`, `deflate`) undone, capped at
/// `TEE_LIMIT`; `None` for another coding or a corrupt body.
pub fn decoded(enc: Option<&HeaderValue>, body: Bytes) -> Option<Bytes> {
    decoded_up_to(enc, body, TEE_LIMIT)
}

/// `decoded` capped at `max` decoded bytes.
pub fn decoded_up_to(enc: Option<&HeaderValue>, body: Bytes, max: u64) -> Option<Bytes> {
    use std::io::Read;
    let mut out = Vec::new();
    let limit = max + 1;
    let r = match enc.map(|e| e.as_bytes()) {
        None | Some(b"identity") => return Some(body),
        Some(b"gzip") => flate2::read::GzDecoder::new(&body[..])
            .take(limit)
            .read_to_end(&mut out),
        Some(b"deflate") => flate2::read::ZlibDecoder::new(&body[..])
            .take(limit)
            .read_to_end(&mut out),
        Some(b"br") => brotli::Decompressor::new(&body[..], 4096)
            .take(limit)
            .read_to_end(&mut out),
        Some(_) => return None,
    };
    (r.is_ok() && out.len() as u64 <= max).then(|| out.into())
}

/// Passes `inner` through and sends a copy of the whole body on clean end.
struct Tee<S> {
    /// hyper stops polling once it has written content-length bytes, so the end may never be seen.
    len: Option<u64>,
    inner: S,
    buf: Vec<u8>,
    tx: Option<oneshot::Sender<Bytes>>,
}

impl<S> Tee<S> {
    fn finish(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(std::mem::take(&mut self.buf).into());
        }
    }
}

impl<S: Stream<Item = Result<Bytes, axum::Error>> + Unpin> Stream for Tee<S> {
    type Item = Result<Bytes, axum::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let p = Pin::new(&mut self.inner).poll_next(cx);
        match &p {
            Poll::Ready(Some(Ok(b))) => {
                self.buf.extend_from_slice(b);
                if self.len == Some(self.buf.len() as u64) {
                    self.finish();
                }
            }
            Poll::Ready(Some(Err(_))) => self.tx = None,
            Poll::Ready(None) => self.finish(),
            Poll::Pending => {}
        }
        p
    }
}

/// The first JSON path where `node` and `rust` differ (keys and indexes only, never values).
pub fn json_path(node: &[u8], rust: &[u8]) -> String {
    match (
        serde_json::from_slice::<Value>(node),
        serde_json::from_slice::<Value>(rust),
    ) {
        (Ok(a), Ok(b)) => first_diff(&a, &b, "$".into()).unwrap_or_else(|| "$ (formatting)".into()),
        _ => "$ (not json)".into(),
    }
}

fn first_diff(a: &Value, b: &Value, path: String) -> Option<String> {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for (i, (ka, kb)) in x.keys().zip(y.keys()).enumerate() {
                if ka != kb {
                    return Some(format!("{path} (key {i}: node {ka:?}, rust {kb:?})"));
                }
                if let Some(d) = first_diff(&x[ka], &y[kb], format!("{path}.{ka}")) {
                    return Some(d);
                }
            }
            (x.len() != y.len())
                .then(|| format!("{path} (node {} keys, rust {})", x.len(), y.len()))
        }
        (Value::Array(x), Value::Array(y)) => {
            for (i, (va, vb)) in x.iter().zip(y).enumerate() {
                if let Some(d) = first_diff(va, vb, format!("{path}[{i}]")) {
                    return Some(d);
                }
            }
            (x.len() != y.len())
                .then(|| format!("{path} (node {} items, rust {})", x.len(), y.len()))
        }
        _ => (a != b).then_some(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, Request, StatusCode};
    use std::time::Duration;

    async fn collect(b: Body) -> Vec<u8> {
        axum::body::to_bytes(b, usize::MAX).await.unwrap().to_vec()
    }

    #[tokio::test]
    async fn buffer_keeps_small_bodies_and_replays_large_ones() {
        let h = HeaderMap::new();
        let buffer = |b, h| buffer(b, h, BODY_TIMEOUT);
        let small = buffer(Body::from("abc"), &h).await.unwrap().unwrap();
        assert_eq!(&small[..], b"abc");
        // Exactly the limit still fits.
        let edge = vec![b'e'; BODY_LIMIT];
        assert_eq!(
            buffer(Body::from(edge.clone()), &h).await.unwrap().unwrap(),
            edge
        );
        // Streamed (no length) past the limit: every byte comes back, in order.
        let chunks: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 40 << 10]).collect();
        let whole = chunks.concat();
        let stream = futures_util::stream::iter(
            chunks
                .into_iter()
                .map(|c| Ok::<_, std::io::Error>(Bytes::from(c))),
        );
        let replay = buffer(Body::from_stream(stream), &h)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(collect(replay).await, whole);
        // A declared length over the limit is not read at all.
        let mut big = HeaderMap::new();
        big.insert(header::CONTENT_LENGTH, HeaderValue::from_static("65537"));
        let r = buffer(Body::from(vec![1u8; 65537]), &big)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(collect(r).await.len(), 65537);
    }

    #[tokio::test]
    async fn slow_bodies_go_to_node_with_the_bytes_read_so_far() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
        tx.send(Ok(Bytes::from_static(b"part1-"))).await.unwrap();
        let body = Body::from_stream(tokio_stream_from(rx));
        let replay = buffer(body, &HeaderMap::new(), Duration::from_millis(50))
            .await
            .unwrap()
            .unwrap_err();
        tx.send(Ok(Bytes::from_static(b"part2"))).await.unwrap();
        drop(tx);
        assert_eq!(collect(replay).await, b"part1-part2");
        // A body that breaks mid-read is the outer error.
        let broken = futures_util::stream::iter([
            Ok(Bytes::from_static(b"x")),
            Err(std::io::Error::other("reset")),
        ]);
        let r = buffer(Body::from_stream(broken), &HeaderMap::new(), BODY_TIMEOUT).await;
        assert!(r.is_err());
    }

    fn tokio_stream_from<T>(
        mut rx: tokio::sync::mpsc::Receiver<T>,
    ) -> impl futures_util::Stream<Item = T> {
        futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
    }

    fn with_body(ct: Option<&str>, body: &[u8]) -> Parts {
        let mut b = Request::post("/x");
        if let Some(ct) = ct {
            b = b.header("content-type", ct);
        }
        let (mut p, _) = b.body(()).unwrap().into_parts();
        p.extensions
            .insert(RequestBody(Bytes::copy_from_slice(body)));
        p
    }

    #[test]
    fn json_body_parses_like_json_parse_or_declines() {
        let j = |ct, b: &str| json_body(&with_body(ct, b.as_bytes()));
        assert_eq!(j(None, r#"{"a":1}"#), Some(serde_json::json!({"a":1})));
        assert_eq!(
            j(Some("Application/JSON; charset=utf-8"), " [1] "),
            Some(serde_json::json!([1]))
        );
        // Duplicate keys: first position, last value (JSON.parse).
        assert_eq!(
            j(None, r#"{"a":1,"b":2,"a":3}"#).unwrap().to_string(),
            r#"{"a":3,"b":2}"#
        );
        for bad in ["", "{", "{'a':1}", "[1,]", "{\"a\":1}x", "\u{feff}{}"] {
            assert_eq!(j(None, bad), None, "{bad:?}");
        }
        assert_eq!(j(Some("text/plain"), "{}"), None, "Node's 415");
        assert_eq!(
            json_body(&with_body(None, b"{\"a\":\"\xff\"}")),
            None,
            "not UTF-8"
        );
        let mut gz = with_body(None, b"{}");
        gz.headers
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert_eq!(json_body(&gz), None);
        let mut none = with_body(None, b"{}");
        none.extensions.clear();
        assert_eq!(json_body(&none), None, "not buffered");
    }

    #[test]
    fn form_body_decodes_like_url_search_params() {
        let f = |b: &str| {
            form_body(&with_body(
                Some("application/x-www-form-urlencoded"),
                b.as_bytes(),
            ))
            .map(|m| Value::Object(m).to_string())
        };
        // Pairs from Node's `[...new URLSearchParams(text)]`, folded by `UrlParams.toRecord`.
        assert_eq!(
            f("a=1&&b=%zz+x&a=%E2%82%AC&c&=d&a=%41").as_deref(),
            Some(r#"{"a":["1","€","A"],"b":"%zz x","c":"","":"d"}"#)
        );
        assert_eq!(f("").as_deref(), Some("{}"));
        // Node drops a leading `?` (URLSearchParams) and BOM (TextDecoder): Rust declines.
        assert_eq!(f("?a=1"), None);
        assert_eq!(f("\u{feff}a=1"), None);
        assert_eq!(f("a=?").as_deref(), Some(r#"{"a":"?"}"#));
        assert_eq!(f("e=%FF"), None, "Node substitutes U+FFFD");
        assert_eq!(f("e=%"), Some(r#"{"e":"%"}"#.into()));
        assert_eq!(
            form_body(&with_body(None, b"a=1")),
            None,
            "default type is JSON: 415"
        );
    }

    fn rust(status: u16, h: &[(&str, &str)], body: &str) -> Response<Bytes> {
        let mut b = Response::builder().status(status);
        for (k, v) in h {
            b = b.header(*k, *v);
        }
        b.body(Bytes::from(body.to_owned())).unwrap()
    }

    fn hm(h: &[(&str, &str)]) -> HeaderMap {
        h.iter()
            .map(|(k, v)| {
                (
                    header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    v.parse().unwrap(),
                )
            })
            .collect()
    }

    const CMP: Compare = Compare {
        ignore: &["$.ticket", "$[*].sessionId"],
        times: &["$.expiresAt", "$[*].issuedAt"],
        headers: Compare::AUTH_HEADERS,
        enrich: &[],
        ..Compare::DEFAULT
    };

    #[test]
    fn comparator_ignores_exactly_the_declared_paths() {
        let ct = ("content-type", "application/json");
        let d = |node: &str, r: &str| {
            diff(
                &CMP,
                StatusCode::OK,
                &hm(&[ct]),
                node.as_bytes(),
                &rust(200, &[ct], r),
            )
        };
        // Ignored values, traceId, and timestamps within 2 s.
        assert_eq!(
            d(
                r#"{"ticket":"a","expiresAt":"2026-10-23T08:00:00.000Z","traceId":"n"}"#,
                r#"{"ticket":"b","expiresAt":"2026-10-23T08:00:02.000Z","traceId":"r"}"#
            ),
            None
        );
        assert_eq!(
            d(
                r#"[{"sessionId":"a","issuedAt":"2026-10-23T23:59:59.500Z","x":1}]"#,
                r#"[{"sessionId":"b","issuedAt":"2026-10-24T00:00:01.000Z","x":1}]"#
            ),
            None
        );
        // Everything else is caught.
        let path = |n: &str, r: &str| d(n, r).map(|(f, p)| format!("{f} {p}"));
        assert_eq!(
            path(
                r#"{"expiresAt":"2026-10-23T08:00:00.000Z"}"#,
                r#"{"expiresAt":"2026-10-23T08:00:02.001Z"}"#
            )
            .as_deref(),
            Some("body $.expiresAt")
        );
        assert_eq!(
            path(
                r#"[{"sessionId":"a","x":1}]"#,
                r#"[{"sessionId":"a","x":2}]"#
            )
            .as_deref(),
            Some("body $[0].x")
        );
        assert_eq!(
            path(r#"{"ticket":"a","id":"1"}"#, r#"{"ticket":"a","id":"2"}"#).as_deref(),
            Some("body $.id")
        );
        assert_eq!(
            path(r#"{"ticket":"a","b":1}"#, r#"{"b":1,"ticket":"a"}"#).as_deref(),
            Some("body $ (key order)")
        );
        // Order-only difference deeper down, and an ignored field that differs alone.
        assert_eq!(
            path(
                r#"[{"sessionId":"a","x":1,"y":2}]"#,
                r#"[{"sessionId":"a","y":2,"x":1}]"#
            )
            .as_deref(),
            Some("body $ (key order)")
        );
        assert_eq!(
            path(r#"{"ticket":"a","b":1}"#, r#"{"ticket":"z","b":1}"#),
            None
        );
        assert_eq!(
            path(r#"{"ticket":"a"}"#, r#"{"ticket":"a","x":1}"#).as_deref(),
            Some("body $ (node 1 keys, rust 2)")
        );
        assert_eq!(
            path(r#"{"ticket":1}"#, r#"{ "ticket":2}"#).as_deref(),
            Some("body $ (formatting)")
        );
        // A timestamp path holding a non-timestamp is compared exactly.
        assert_eq!(
            path(r#"{"expiresAt":1}"#, r#"{"expiresAt":2}"#).as_deref(),
            Some("body $.expiresAt")
        );
        assert_eq!(
            diff(
                &CMP,
                StatusCode::OK,
                &hm(&[ct]),
                b"{}",
                &rust(401, &[ct], "{}")
            )
            .map(|x| x.0),
            Some("status")
        );
    }

    #[test]
    fn enrichment_is_a_labelled_mismatch_that_never_hides_another() {
        const E: Compare = Compare {
            enrich: &["$.projects[*].repositoryIdentity"],
            ..Compare::DEFAULT
        };
        let ct = ("content-type", "application/json");
        let d = |n: &str, r: &str| {
            diff(
                &E,
                StatusCode::OK,
                &hm(&[ct]),
                n.as_bytes(),
                &rust(200, &[ct], r),
            )
            .map(|(f, p)| format!("{f} {p}"))
        };
        let p =
            |id: &str, x: u8| format!(r#"{{"projects":[{{"repositoryIdentity":{id},"x":{x}}}]}}"#);
        assert_eq!(d(&p("null", 1), &p("null", 1)), None);
        assert_eq!(
            d(&p(r#"{"a":1}"#, 1), &p("null", 1)).as_deref(),
            Some("enrichment $.projects[0].repositoryIdentity")
        );
        // Anything else differing is still a mismatch, and Rust's value must equal Node's.
        assert_eq!(
            d(&p(r#"{"a":1}"#, 1), &p("null", 2)).as_deref(),
            Some("body $.projects[0].x")
        );
        assert_eq!(
            d(&p("null", 1), &p(r#"{"a":1}"#, 1)).as_deref(),
            Some("body $.projects[0].repositoryIdentity")
        );
    }

    #[test]
    fn a_differing_sequence_is_skew_not_a_mismatch() {
        const S: Compare = Compare {
            skew: &["snapshotSequence"],
            ..Compare::DEFAULT
        };
        let ct = ("content-type", "application/json");
        let d = |n: &str, r: &str| {
            diff(
                &S,
                StatusCode::OK,
                &hm(&[ct]),
                n.as_bytes(),
                &rust(200, &[ct], r),
            )
            .map(|(f, p)| format!("{f} {p}"))
        };
        assert_eq!(
            d(
                r#"{"snapshotSequence":3,"t":[1]}"#,
                r#"{"snapshotSequence":3,"t":[1]}"#
            ),
            None
        );
        assert_eq!(
            d(
                r#"{"snapshotSequence":3,"t":[1]}"#,
                r#"{"snapshotSequence":4,"t":[2]}"#
            )
            .as_deref(),
            Some("sequence_skew $.t[0]"),
            "the first difference beyond the sequence"
        );
        assert_eq!(
            d(
                r#"{"snapshotSequence":3,"t":[1]}"#,
                r#"{"snapshotSequence":4,"t":[1]}"#
            )
            .as_deref(),
            Some("sequence_skew "),
            "only the sequence differs: no path"
        );
        // Same sequence: every other difference is a mismatch.
        assert_eq!(
            d(
                r#"{"snapshotSequence":3,"t":[1]}"#,
                r#"{"snapshotSequence":3,"t":[2]}"#
            )
            .as_deref(),
            Some("body $.t[0]")
        );
        // Without `skew` a differing sequence is a mismatch.
        let plain = diff(
            &Compare::DEFAULT,
            StatusCode::OK,
            &hm(&[ct]),
            br#"{"snapshotSequence":3}"#,
            &rust(200, &[ct], r#"{"snapshotSequence":4}"#),
        );
        assert_eq!(plain.map(|(f, _)| f), Some("body"));
    }

    #[test]
    fn decoded_up_to_caps_the_decoded_size() {
        let big = vec![b' '; (TEE_LIMIT + 10) as usize];
        assert_eq!(
            decoded(None, big.clone().into()).map(|b| b.len()),
            Some(big.len())
        );
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &big).unwrap();
        let gz = gz.finish().unwrap();
        let enc = HeaderValue::from_static("gzip");
        assert_eq!(decoded(Some(&enc), gz.clone().into()), None);
        assert_eq!(
            decoded_up_to(Some(&enc), gz.into(), 64 << 20).map(|b| b.len()),
            Some(big.len())
        );
    }

    #[test]
    fn comparator_checks_declared_headers_and_masks_cookies() {
        let ct = ("content-type", "application/json");
        let ck = |tok: &str, exp: &str| {
            format!("vekrel_session_1_x={tok}; Path=/; Expires={exp}; HttpOnly; SameSite=Lax")
        };
        let d = |n: &[(&str, &str)], r: &[(&str, &str)]| {
            diff(&CMP, StatusCode::OK, &hm(n), b"{}", &rust(200, r, "{}"))
        };
        let (a, b) = (
            ck("tokA", "Fri, 23 Oct 2026 08:00:00 GMT"),
            ck("tokB", "Fri, 23 Oct 2026 08:00:02 GMT"),
        );
        let ns = [ct, ("cache-control", "no-store"), ("pragma", "no-cache")];
        assert_eq!(
            d(
                &[ns[0], ns[1], ns[2], ("set-cookie", &a)],
                &[ns[0], ns[1], ns[2], ("set-cookie", &b)]
            ),
            None
        );
        // Undeclared headers are not compared.
        assert_eq!(d(&[ct, ("vary", "x")], &[ct]), None);
        let hdr = |n: &[(&str, &str)], r: &[(&str, &str)]| d(n, r).map(|(f, p)| format!("{f} {p}"));
        assert_eq!(
            hdr(&ns, &[ct, ("cache-control", "no-store")]).as_deref(),
            Some("header pragma")
        );
        assert_eq!(
            hdr(&[ct], &[ct, ("www-authenticate", "DPoP")]).as_deref(),
            Some("header www-authenticate")
        );
        assert_eq!(
            hdr(&[("content-type", "text/plain")], &[ct]).as_deref(),
            Some("header content-type")
        );
        let late = ck("tokB", "Fri, 23 Oct 2026 08:00:03 GMT");
        assert_eq!(
            hdr(&[ct, ("set-cookie", &a)], &[ct, ("set-cookie", &late)]).as_deref(),
            Some("header set-cookie")
        );
        let secure = format!("{b}; Secure");
        assert_eq!(
            hdr(&[ct, ("set-cookie", &a)], &[ct, ("set-cookie", &secure)]).as_deref(),
            Some("header set-cookie")
        );
        let other = a.replace("vekrel_session_1_x", "vekrel_session_2_x");
        assert_eq!(
            hdr(&[ct, ("set-cookie", &a)], &[ct, ("set-cookie", &other)]).as_deref(),
            Some("header set-cookie")
        );
        assert_eq!(
            hdr(&[ct, ("set-cookie", &a)], &[ct]).as_deref(),
            Some("header set-cookie")
        );
    }

    #[test]
    fn date_parsers_agree_with_the_formatters() {
        use crate::{cookies::utc_string, handlers::auth_session::iso_millis};
        for ms in [0, 951_782_400_000, 1_792_742_400_123, 1_893_456_000_999] {
            assert_eq!(parse_iso(&iso_millis(ms)), Some(ms));
            assert_eq!(parse_http_date(&utc_string(ms)), Some(ms - ms % 1000));
        }
        assert_eq!(parse_iso("2026-10-23T08:00:00Z"), None);
    }

    /// Node's response whose body arrives only when `tx` sends (or closes), like a large or slow
    /// upstream body; `len` bytes declared.
    fn held_node(len: usize) -> (tokio::sync::mpsc::Sender<Bytes>, Response<Body>) {
        /// A body with a known length (as hyper gives Node's) whose bytes come from a channel.
        struct Held(tokio::sync::mpsc::Receiver<Bytes>, u64);
        impl HttpBody for Held {
            type Data = Bytes;
            type Error = std::io::Error;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>> {
                self.0
                    .poll_recv(cx)
                    .map(|b| b.map(|b| Ok(http_body::Frame::data(b))))
            }
            fn size_hint(&self) -> http_body::SizeHint {
                http_body::SizeHint::with_exact(self.1)
            }
        }
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(1);
        let r = Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::new(Held(rx, len as u64)))
            .unwrap();
        (tx, r)
    }

    #[tokio::test]
    async fn http_shadow_permits_cover_the_compare_and_never_delay_the_client() {
        let all = |b: Body| axum::body::to_bytes(b, usize::MAX);
        let l = ShadowLimit::new(2, Duration::from_secs(10));
        let ct = ("content-type", "application/json");
        let mut held = Vec::new();
        let mut skipped = 0;
        // 5 concurrent shadowed requests, 2 permits: Rust answers at once, Node's bodies are open.
        for _ in 0..5 {
            let Some(permit) = l.acquire("r") else {
                skipped += 1;
                continue;
            };
            let job = l.run("r", async move { Some(rust(200, &[ct], "[1]")) });
            let (tx, node) = held_node(3);
            held.push((
                tx,
                tee(node, job, "r".into(), Compare::DEFAULT, false, permit, None),
            ));
        }
        assert_eq!((held.len(), skipped), (2, 3));
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Rust's handlers are done; the compares still wait on Node's bodies and hold the permits.
        assert_eq!(l.permits.available_permits(), 0);
        for (tx, r) in held {
            tx.send(Bytes::from_static(b"[1]")).await.unwrap();
            drop(tx);
            assert_eq!(&all(r.into_body()).await.unwrap()[..], b"[1]");
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while l.permits.available_permits() < 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "compares never released"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Rust still computing: Node's body reaches the client at once.
        let permit = l.acquire("slow").unwrap();
        let job = l.run("slow", std::future::pending::<Option<Response<Bytes>>>());
        let (tx, node) = held_node(3);
        let r = tee(
            node,
            job,
            "slow".into(),
            Compare::DEFAULT,
            false,
            permit,
            None,
        );
        tx.send(Bytes::from_static(b"[2]")).await.unwrap();
        drop(tx);
        let body = tokio::time::timeout(Duration::from_secs(1), all(r.into_body()))
            .await
            .expect("not delayed by Rust");
        assert_eq!(&body.unwrap()[..], b"[2]");
        assert_eq!(
            l.permits.available_permits(),
            1,
            "held until Rust ends (its timeout)"
        );

        // Over the route's cap: passed through, compare skipped, the permit released at once.
        let permit = l.acquire("big").unwrap();
        let job = l.run("big", async move { Some(rust(200, &[ct], "[3]")) });
        let (tx, node) = held_node(11);
        let small = Compare {
            tee_limit: 10,
            ..Compare::DEFAULT
        };
        let r = tee(node, job, "big".into(), small, false, permit, None);
        assert_eq!(l.permits.available_permits(), 1);
        tx.send(Bytes::from_static(b"[333333333]")).await.unwrap();
        drop(tx);
        assert_eq!(all(r.into_body()).await.unwrap().len(), 11);
    }

    #[derive(Clone, Default)]
    struct Logs(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Logs {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_skew_reruns_rust_and_keeps_the_path_beyond_the_sequence() {
        let logs = Logs::default();
        let l = logs.clone();
        let sub = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || l.clone())
            .finish();
        let _g = tracing::subscriber::set_default(sub);
        let lim = ShadowLimit::default();
        let ct = ("content-type", "application/json");
        const S: Compare = Compare {
            skew: &["snapshotSequence"],
            ..Compare::DEFAULT
        };
        let node = r#"{"snapshotSequence":4,"t":[1]}"#;
        let cases = [
            // Rust read before Node's write; its rerun sees Node's sequence: compared, a match.
            ("a", r#"{"snapshotSequence":4,"t":[1]}"#, true),
            // No rerun: only the sequence differs, so no path.
            ("b", r#"{"snapshotSequence":4,"t":[1]}"#, false),
            // Still skewed after the rerun: the first real difference is logged.
            ("c", r#"{"snapshotSequence":5,"t":[2]}"#, true),
        ];
        for (route, again, rerun) in cases {
            let permit = lim.acquire(route).unwrap();
            let job = lim.run(route, async move {
                Some(rust(200, &[ct], r#"{"snapshotSequence":3,"t":[1]}"#))
            });
            let rerun = rerun.then(|| {
                let r: BoxFuture<'static, _> =
                    Box::pin(async move { Some(rust(200, &[ct], again)) });
                r
            });
            let (tx, resp) = held_node(node.len());
            let r = tee(resp, job, route.into(), S, false, permit, rerun);
            tx.send(Bytes::from_static(node.as_bytes())).await.unwrap();
            drop(tx);
            axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let lines = loop {
            let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
            let lines: Vec<String> = text
                .lines()
                .filter(|l| l.contains("rust shadow"))
                .map(String::from)
                .collect();
            if lines.len() >= 3 || tokio::time::Instant::now() > deadline {
                break lines;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let line = |r: &str| {
            let tag = format!("route=\"{r}\"");
            lines
                .iter()
                .find(|l| l.contains(&tag))
                .cloned()
                .unwrap_or_default()
        };
        assert!(line("a").contains("outcome=\"match\""), "{lines:?}");
        let b = line("b");
        assert!(
            b.contains("sequence_skew") && !b.contains("path"),
            "{lines:?}"
        );
        let c = line("c");
        assert!(
            c.contains("sequence_skew") && c.contains("path=\"$.t[0]\""),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn shadow_limit_skips_when_full_and_times_out() {
        let l = ShadowLimit::new(1, Duration::from_millis(50));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let slow = l
            .spawn("a", async move { rx.await.ok() })
            .expect("first gets the permit");
        assert!(l.spawn("b", async { Some(()) }).is_none(), "full: skipped");
        drop(tx);
        assert_eq!(slow.await.unwrap(), None);
        // The permit is back; a computation past the timeout yields None.
        let stuck = l.spawn("c", std::future::pending::<Option<()>>()).unwrap();
        assert_eq!(stuck.await.unwrap(), None);
        assert_eq!(
            l.spawn("d", async { Some(1) }).unwrap().await.unwrap(),
            Some(1)
        );
    }

    #[test]
    fn orchestration_protocol_header_must_be_exactly_2() {
        let p = |vals: &[&str]| {
            let mut b = Request::get("/api/orchestration/shell");
            for v in vals {
                b = b.header("x-t3-orchestration-protocol", *v);
            }
            orchestration_protocol(&b.body(()).unwrap().into_parts().0)
        };
        assert!(p(&["2"]));
        for bad in [
            &[][..],
            &["1"],
            &["3"],
            &["2 "],
            &["02"],
            &["2, 2"],
            &["2", "2"],
            &[""],
        ] {
            assert!(!p(bad), "{bad:?}");
        }
    }

    #[test]
    fn json_path_names_the_first_difference() {
        let p = |a: &str, b: &str| json_path(a.as_bytes(), b.as_bytes());
        assert_eq!(
            p(r#"{"a":{"b":[1,2]}}"#, r#"{"a":{"b":[1,3]}}"#),
            "$.a.b[1]"
        );
        assert_eq!(
            p(r#"{"a":1,"b":2}"#, r#"{"b":2,"a":1}"#),
            r#"$ (key 0: node "a", rust "b")"#
        );
        assert_eq!(
            p(r#"{"a":1,"b":2}"#, r#"{"a":1}"#),
            "$ (node 2 keys, rust 1)"
        );
        assert_eq!(p(r#"{"a":1}"#, r#"{ "a":1}"#), "$ (formatting)");
        assert_eq!(p("x", "{}"), "$ (not json)");
    }

    #[test]
    fn node_bodies_are_decoded_before_comparing() {
        use std::io::Write;
        let json = br#"{"a":1}"#;
        let enc = |v: &str| Some(axum::http::HeaderValue::from_str(v).unwrap());
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), Default::default());
        gz.write_all(json).unwrap();
        let mut zl = flate2::write::ZlibEncoder::new(Vec::new(), Default::default());
        zl.write_all(json).unwrap();
        // `br` of `{"a":1}` from Node's zlib.brotliCompressSync.
        let br: &[u8] = &[
            0x0b, 0x03, 0x80, 0x7b, 0x22, 0x61, 0x22, 0x3a, 0x31, 0x7d, 0x03,
        ];
        for (e, body) in [
            (None, json.to_vec()),
            (enc("identity"), json.to_vec()),
            (enc("gzip"), gz.finish().unwrap()),
            (enc("deflate"), zl.finish().unwrap()),
            (enc("br"), br.to_vec()),
        ] {
            assert_eq!(decoded(e.as_ref(), body.into()).as_deref(), Some(&json[..]));
        }
        assert_eq!(decoded(enc("zstd").as_ref(), json[..].into()), None);
        assert_eq!(
            decoded(enc("gzip").as_ref(), json[..].into()),
            None,
            "corrupt"
        );
    }
}
