use crate::server::Upstream;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, Version, header},
    response::Response,
};
use std::time::Duration;

const HOP_BY_HOP: [&str; 6] = [
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
];

fn strip_hop_by_hop(h: &mut HeaderMap) {
    for name in HOP_BY_HOP {
        h.remove(name);
    }
    let proxy: Vec<_> = h
        .keys()
        .filter(|k| k.as_str().starts_with("proxy-"))
        .cloned()
        .collect();
    for name in proxy {
        h.remove(name);
    }
}

fn error(status: StatusCode, code: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"error":"{code}"}}"#)))
        .unwrap()
}

/// Streams any request not routed elsewhere to the engine and its response back.
pub async fn handler(State(upstream): State<Upstream>, mut req: Request<Body>) -> Response<Body> {
    let authority = format!("{}:{}", upstream.host, upstream.port);
    let path = req.uri().path_and_query().map_or("/", |p| p.as_str());
    *req.uri_mut() = format!("http://{authority}{path}")
        .parse()
        .expect("valid upstream uri");
    *req.version_mut() = Version::HTTP_11; // the pooled client speaks HTTP/1 only
    let h = req.headers_mut();
    strip_hop_by_hop(h);
    h.insert(
        header::HOST,
        HeaderValue::from_str(&authority).expect("valid host"),
    );
    h.insert("x-vekrel-proxy", HeaderValue::from_static("1"));

    match tokio::time::timeout(Duration::from_secs(30), upstream.client.request(req)).await {
        Err(_) => error(StatusCode::GATEWAY_TIMEOUT, "engine_timeout"),
        Ok(Err(e)) => {
            tracing::warn!("engine request failed: {e}");
            error(StatusCode::BAD_GATEWAY, "engine_unreachable")
        }
        Ok(Ok(res)) => {
            let (mut parts, body) = res.into_parts();
            strip_hop_by_hop(&mut parts.headers);
            Response::from_parts(parts, Body::new(body))
        }
    }
}
