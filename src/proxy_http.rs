use crate::{config::Mode, http_seam, server::Upstream};
use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, Version, header},
    response::Response,
};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

const HOP_BY_HOP: [&str; 6] = [
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
];

pub(crate) fn strip_hop_by_hop(h: &mut HeaderMap) {
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

/// Lets the engine's origin check trust a browser that reached it through this proxy.
pub(crate) fn add_forwarded(
    h: &mut HeaderMap,
    host: Option<HeaderValue>,
    public_port: u16,
    ip: Option<IpAddr>,
) {
    // Only a loopback authority on our port is vouched for; anything else (DNS rebinding)
    // gets no header, so the engine's own origin check decides.
    let host = host.filter(|v| {
        let v = v.to_str().unwrap_or("").to_ascii_lowercase();
        ["127.0.0.1", "localhost", "[::1]"]
            .iter()
            .any(|n| v == format!("{n}:{public_port}"))
    });
    h.insert("x-vekrel-proxy", HeaderValue::from_static("1"));
    h.insert("x-forwarded-proto", HeaderValue::from_static("http"));
    match host {
        Some(v) => h.insert("x-forwarded-host", v),
        None => h.remove("x-forwarded-host"),
    };
    // Replaced, never appended: a client-supplied first entry must not be trusted.
    match ip {
        Some(ip) => h.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&ip.to_string()).expect("ip"),
        ),
        None => h.remove("x-forwarded-for"),
    };
}

pub(crate) fn error(status: StatusCode, code: &str) -> Response {
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
    // `OPTIONS *` has no leading slash; spliced in, it corrupts the authority (port 80).
    if !path.starts_with('/') {
        return error(StatusCode::BAD_REQUEST, "bad_request_target");
    }
    *req.uri_mut() = format!("http://{authority}{path}")
        .parse()
        .expect("valid upstream uri");
    *req.version_mut() = Version::HTTP_11; // the pooled client speaks HTTP/1 only
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let h = req.headers_mut();
    let client_host = h.get(header::HOST).cloned();
    strip_hop_by_hop(h);
    h.insert(
        header::HOST,
        HeaderValue::from_str(&authority).expect("valid host"),
    );
    add_forwarded(h, client_host, upstream.public_port, ip);

    // Handlers see the request exactly as Node would (rewritten Host, X-Forwarded-*).
    let path = req.uri().path().to_owned();
    let Some((mode, h)) = upstream.seam.find(req.method(), &path) else {
        return forward(&upstream, req).await;
    };
    let (parts, body) = req.into_parts();
    if mode == Mode::Serve {
        return match h.handle(&parts, &upstream.seam.ctx).await {
            Some(r) => http_seam::served(r),
            None => forward(&upstream, Request::from_parts(parts, body)).await,
        };
    }
    // Shadow: Rust runs beside Node and never delays Node's answer.
    let (seam, rust_parts, route) = (upstream.seam.clone(), parts.clone(), http_seam::key(&*h));
    let rust = tokio::spawn(async move { h.handle(&rust_parts, &seam.ctx).await });
    let node = forward(&upstream, Request::from_parts(parts, body)).await;
    http_seam::tee(node, rust, route)
}

async fn forward(upstream: &Upstream, req: Request<Body>) -> Response<Body> {
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
