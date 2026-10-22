//! HTTP takeover: per-route Rust handlers in `shadow` (Node answers, Rust's answer is compared and
//! logged) or `serve` (Rust answers, Node never sees the request) mode. See `config::Mode`.
use crate::{config::Mode, handlers::HandlerCtx};
use axum::{
    body::{Body, Bytes, HttpBody},
    http::{HeaderValue, Method, Response, header, request::Parts},
};
use futures_util::future::BoxFuture;
use serde_json::Value;
use std::sync::Arc;

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

    pub(crate) fn find(&self, m: &Method, path: &str) -> Option<(Mode, &dyn RouteHandler)> {
        self.routes.iter().find_map(|(mode, h)| {
            let (hm, hp) = h.method_path();
            (hm == m && hp == path).then_some((*mode, &**h))
        })
    }
}

pub(crate) fn served(r: Response<Bytes>) -> Response<Body> {
    let mut r = r.map(Body::from);
    r.headers_mut()
        .insert("x-vekrel-served-by", HeaderValue::from_static("rust"));
    r
}

/// Buffers Node's response (if small enough), compares it with Rust's, logs, and returns Node's.
pub(crate) async fn tee(
    node: Response<Body>,
    rust: Response<Bytes>,
    route: &str,
) -> Response<Body> {
    let (parts, body) = node.into_parts();
    // shortcut: a body without a known length (chunked) is skipped too; Node sends lengths for JSON.
    if body.size_hint().upper().is_none_or(|n| n > TEE_LIMIT) {
        tracing::info!(route, outcome = "skipped_large", "rust shadow");
        return Response::from_parts(parts, body);
    }
    let bytes = match axum::body::to_bytes(body, TEE_LIMIT as usize).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("engine response failed: {e}");
            return crate::proxy_http::error(
                axum::http::StatusCode::BAD_GATEWAY,
                "engine_unreachable",
            );
        }
    };
    let ct = |h: &axum::http::HeaderMap| h.get(header::CONTENT_TYPE).cloned();
    let diff = if parts.status != rust.status() {
        Some(("status", "$".to_owned()))
    } else if ct(&parts.headers) != ct(rust.headers()) {
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
    Response::from_parts(parts, Body::from(bytes))
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
    use super::json_path;

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
}
