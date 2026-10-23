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
    sync::{Semaphore, oneshot},
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
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            tracing::info!(handler, outcome = "shadow_skipped_busy", "rust shadow");
            return None;
        };
        let (timeout, handler) = (self.timeout, handler.to_owned());
        Some(tokio::spawn(async move {
            let _permit = permit;
            tokio::time::timeout(timeout, fut)
                .await
                .unwrap_or_else(|_| {
                    tracing::warn!(handler, outcome = "shadow_timeout", "rust shadow");
                    None
                })
        }))
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
    /// `None` means "not mine": Node answers, in either mode.
    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>>;
}

/// The config key for a handler: `"GET /api/auth/session"`.
pub fn key(h: &dyn RouteHandler) -> String {
    let (m, p) = h.method_path();
    format!("{m} {p}")
}

/// Node bodies above this are passed through without comparison.
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

/// What shadow mode compares beyond status: JSON values everywhere except the listed paths
/// (`$.ticket`, `$[*].sessionId`; `$.traceId` always), ISO timestamps at `times` within ±2 s, and
/// the listed response headers by presence and bytes (`set-cookie` ignoring the token and with
/// `Expires` within ±2 s).
#[derive(Clone, Copy, Debug)]
pub struct Compare {
    pub ignore: &'static [&'static str],
    pub times: &'static [&'static str],
    pub headers: &'static [&'static str],
}

impl Compare {
    pub const DEFAULT: Compare = Compare {
        ignore: &[],
        times: &[],
        headers: &["content-type"],
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
    if body == rust.body() {
        return None;
    }
    let (Ok(mut a), Ok(mut b)) = (
        serde_json::from_slice::<Value>(body),
        serde_json::from_slice::<Value>(rust.body()),
    ) else {
        return Some(("body", "$ (not json)".into()));
    };
    let canonical = |v: &Value, raw: &[u8]| serde_json::to_vec(v).is_ok_and(|c| c == raw);
    if !canonical(&a, body) || !canonical(&b, rust.body()) {
        return Some(("body", "$ (formatting)".into()));
    }
    mask(cmp, &mut a, &mut b, "$".into());
    // Byte-exact: Value equality ignores key order, and Node's order follows its schema.
    if serde_json::to_vec(&a).ok() == serde_json::to_vec(&b).ok() {
        return None;
    }
    let path = if a == b {
        "$ (key order)".into()
    } else {
        first_diff(&a, &b, "$".into()).unwrap_or_else(|| "$ (formatting)".into())
    };
    Some(("body", path))
}

/// Nulls the ignored values on both sides and copies Rust's timestamp onto Node's when they are
/// within `SKEW_MS`, so `first_diff` only sees real differences. `path` uses `[*]` for indexes.
fn mask(cmp: &Compare, a: &mut Value, b: &mut Value, path: String) {
    if path == "$.traceId" || cmp.ignore.contains(&path.as_str()) {
        (*a, *b) = (Value::Null, Value::Null);
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
                        mask(cmp, va, vb, format!("{path}.{k}"));
                    }
                }
            }
            (Value::Array(x), Value::Array(y)) => {
                for (va, vb) in x.iter_mut().zip(y) {
                    mask(cmp, va, vb, format!("{path}[*]"));
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
fn parse_iso(s: &str) -> Option<i64> {
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
) -> Response<Body> {
    let (parts, body) = node.into_parts();
    // shortcut: a body without a known length (chunked) is skipped too; Node sends lengths for JSON.
    if body.size_hint().upper().is_none_or(|n| n > TEE_LIMIT) {
        tracing::info!(route, outcome = "skipped_large", "rust shadow");
        return Response::from_parts(parts, body);
    }
    let (tx, rx) = oneshot::channel();
    let (status, headers) = (parts.status, parts.headers.clone());
    tokio::spawn(async move {
        // A handler that declines, panics, or a body that failed / was abandoned: nothing to compare.
        let (Ok(Some(rust)), Ok(bytes)) = (rust.await, rx.await) else {
            return;
        };
        // Node compresses bodies of 1 KiB and up when the client accepts it; compare the JSON.
        let enc = headers.get(header::CONTENT_ENCODING);
        let Some(bytes) = decoded(enc, bytes) else {
            tracing::info!(route, outcome = "skipped_encoding", "rust shadow");
            return;
        };
        match diff(&cmp, status, &headers, &bytes, &rust) {
            None => tracing::info!(route, outcome = "match", "rust shadow"),
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
fn decoded(enc: Option<&HeaderValue>, body: Bytes) -> Option<Bytes> {
    use std::io::Read;
    let mut out = Vec::new();
    let limit = TEE_LIMIT + 1;
    let r = match enc.map(|e| e.as_bytes()) {
        None | Some(b"identity") => return Some(body),
        Some(b"gzip") => flate2::read::GzDecoder::new(&body[..])
            .take(limit)
            .read_to_end(&mut out),
        Some(b"deflate") => flate2::read::ZlibDecoder::new(&body[..])
            .take(limit)
            .read_to_end(&mut out),
        Some(b"br") => brotli_decompressor::Decompressor::new(&body[..], 4096)
            .take(limit)
            .read_to_end(&mut out),
        Some(_) => return None,
    };
    (r.is_ok() && out.len() as u64 <= TEE_LIMIT).then(|| out.into())
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
    fn comparator_checks_declared_headers_and_masks_cookies() {
        let ct = ("content-type", "application/json");
        let ck = |tok: &str, exp: &str| {
            format!("t3_session_1_x={tok}; Path=/; Expires={exp}; HttpOnly; SameSite=Lax")
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
        let other = a.replace("t3_session_1_x", "t3_session_2_x");
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
