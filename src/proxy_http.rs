use crate::{auth::dpop, config::Mode, http_auth::DpopCtx, http_seam, server::Upstream};
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

/// `Host` is one of the daemon's own public origins: `127.0.0.1`, `localhost` or `[::1]` on
/// `public_port` (case-insensitive).
pub(crate) fn trusted_host(v: &HeaderValue, public_port: u16) -> bool {
    let v = v.to_str().unwrap_or("").to_ascii_lowercase();
    ["127.0.0.1", "localhost", "[::1]"]
        .iter()
        .any(|n| v == format!("{n}:{public_port}"))
}

/// The URL a client signs a DPoP `htu` for, but only on the daemon's own origins: another Host
/// (DNS rebinding, a forwarded name) is Node's to judge. `path` must be origin-form.
pub(crate) fn client_url(
    host: Option<&HeaderValue>,
    public_port: u16,
    path: &str,
) -> Option<String> {
    let host = host.filter(|h| trusted_host(h, public_port))?;
    crate::auth::dpop::request_url(Some(host.to_str().ok()?), path)
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
    let host = host.filter(|v| trusted_host(v, public_port));
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
    let (original_path, original_absolute) = (path.to_owned(), req.uri().authority().is_some());
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
    // The URL the client used, for DPoP `htu`; absolute-form targets are Node's.
    let client_url = (!original_absolute)
        .then(|| {
            client_url(
                req.headers().get(header::HOST),
                upstream.public_port,
                &original_path,
            )
        })
        .flatten();
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
    let (mut parts, body) = req.into_parts();
    let dctx = DpopCtx {
        url: client_url.clone(),
        serve: mode == Mode::Serve,
        ..DpopCtx::default()
    };
    parts.extensions.insert(dctx.clone());
    let body = if h.wants_body() {
        match http_seam::buffer(body, &parts.headers, http_seam::BODY_TIMEOUT).await {
            Ok(Ok(bytes)) => {
                parts
                    .extensions
                    .insert(http_seam::RequestBody(bytes.clone()));
                Body::from(bytes)
            }
            // Too large or too slow: Node's, with every byte replayed.
            Ok(Err(body)) => return forward(&upstream, Request::from_parts(parts, body)).await,
            // The client's body broke: Node's http server answers that with an empty
            // `400 Bad Request` + `Connection: close` (its default clientError), so do the same.
            Err(e) => {
                tracing::warn!("request body failed: {e}");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONNECTION, "close")
                    .body(Body::empty())
                    .expect("valid response");
            }
        }
    } else {
        body
    };
    if mode == Mode::Serve {
        return match h.handle(&parts, &upstream.seam.ctx).await {
            Some(r) => http_seam::served(r),
            None => {
                dctx.roll_back();
                forward(&upstream, Request::from_parts(parts, body)).await
            }
        };
    }
    let htu = match (parts.headers.get("dpop").map(|p| p.to_str()), &client_url) {
        (Some(Ok(p)), Some(c)) => {
            dpop::node_htu_host_mismatch(p, c, &format!("http://{authority}{original_path}"))
        }
        _ => false,
    };
    // Shadow: Rust runs beside Node and never delays Node's answer.
    let (seam, rust_parts, route, cmp) = (
        upstream.seam.clone(),
        parts.clone(),
        http_seam::key(&*h),
        h.compare(),
    );
    let rust = upstream.shadow.spawn(
        &route,
        async move { h.handle(&rust_parts, &seam.ctx).await },
    );
    let node = forward(&upstream, Request::from_parts(parts, body)).await;
    match rust {
        Some(rust) => http_seam::tee(node, rust, route, cmp, htu),
        None => node,
    }
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
