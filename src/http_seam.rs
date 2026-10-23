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
) -> Response<Body> {
    let (parts, body) = node.into_parts();
    // shortcut: a body without a known length (chunked) is skipped too; Node sends lengths for JSON.
    if body.size_hint().upper().is_none_or(|n| n > TEE_LIMIT) {
        tracing::info!(route, outcome = "skipped_large", "rust shadow");
        return Response::from_parts(parts, body);
    }
    let (tx, rx) = oneshot::channel();
    let (status, ct, enc) = (
        parts.status,
        parts.headers.get(header::CONTENT_TYPE).cloned(),
        parts.headers.get(header::CONTENT_ENCODING).cloned(),
    );
    tokio::spawn(async move {
        // A handler that declines, panics, or a body that failed / was abandoned: nothing to compare.
        let (Ok(Some(rust)), Ok(bytes)) = (rust.await, rx.await) else {
            return;
        };
        // Node compresses bodies of 1 KiB and up when the client accepts it; compare the JSON.
        let Some(bytes) = decoded(enc.as_ref(), bytes) else {
            tracing::info!(route, outcome = "skipped_encoding", "rust shadow");
            return;
        };
        let diff = if status != rust.status() {
            Some(("status", "$".to_owned()))
        } else if ct.as_ref() != rust.headers().get(header::CONTENT_TYPE) {
            Some(("content-type", "$".to_owned()))
        } else if bytes != rust.body() {
            Some(("body", json_path(&bytes, rust.body())))
        } else {
            None
        };
        match diff {
            None => tracing::info!(route, outcome = "match", "rust shadow"),
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
    use super::{ShadowLimit, decoded, json_path};
    use std::time::Duration;

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
