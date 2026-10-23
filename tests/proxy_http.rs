use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::any,
};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Mutex};
use vekrel::{server, supervisor::State};

async fn serve(app: Router) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    serve_on(l, app)
}

fn serve_on(l: TcpListener, app: Router) -> u16 {
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(
            l,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    port
}

/// Starts the proxy under test in front of `upstream_port`; returns its base URL.
async fn proxy(upstream_port: u16) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let app = server::build(
        Arc::new(State::default()),
        server::Upstream::loopback(upstream_port).with_public_port(port),
    );
    format!("http://127.0.0.1:{}", serve_on(l, app))
}

type Seen = Arc<Mutex<Option<(String, String, HeaderMap, String)>>>;

#[tokio::test]
async fn forwards_method_path_query_headers_and_body() {
    let seen: Seen = Default::default();
    let s = seen.clone();
    let up = serve(Router::new().fallback(any(move |req: Request| {
        let s = s.clone();
        async move {
            let (parts, body) = req.into_parts();
            let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
            *s.lock().await = Some((
                parts.method.to_string(),
                parts.uri.to_string(),
                parts.headers,
                String::from_utf8(body.to_vec()).unwrap(),
            ));
            Response::builder()
                .status(201)
                .header("x-up", "9")
                .body(Body::from("ok"))
                .unwrap()
        }
    })))
    .await;
    let base = proxy(up).await;
    let r = reqwest::Client::new()
        .post(format!("{base}/api/x?y=1"))
        .header("x-test", "7")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    assert_eq!(r.headers()["x-up"], "9");
    assert_eq!(r.text().await.unwrap(), "ok");
    let (method, uri, headers, body) = seen.lock().await.take().unwrap();
    assert_eq!(method, "POST");
    assert_eq!(uri, "/api/x?y=1");
    assert_eq!(headers["x-test"], "7");
    assert_eq!(body, "hello");
}

#[tokio::test]
async fn set_cookie_headers_pass_through_unmerged() {
    const A: &str = "a=1; Path=/; HttpOnly; SameSite=Lax";
    const B: &str = "b=2; Path=/; HttpOnly; SameSite=Lax";
    let up = serve(Router::new().fallback(any(|| async {
        Response::builder()
            .header("set-cookie", A)
            .header("set-cookie", B)
            .body(Body::empty())
            .unwrap()
    })))
    .await;
    let r = reqwest::get(format!("{}/", proxy(up).await)).await.unwrap();
    let cookies: Vec<_> = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(cookies, [A, B]);
}

#[tokio::test]
async fn streams_body_before_upstream_finishes() {
    let up = serve(Router::new().fallback(any(|| async {
        let chunks = futures_util::stream::unfold(0, |i| async move {
            match i {
                0 => Some((Ok::<_, std::io::Error>("a"), 1)),
                1 => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Some((Ok("b"), 2))
                }
                _ => None,
            }
        });
        Body::from_stream(chunks)
    })))
    .await;
    let mut r = reqwest::get(format!("{}/stream", proxy(up).await))
        .await
        .unwrap();
    let first = tokio::time::timeout(Duration::from_millis(500), r.chunk())
        .await
        .expect("first chunk within 500 ms");
    assert_eq!(first.unwrap().unwrap(), "a");
    assert_eq!(r.chunk().await.unwrap().unwrap(), "b");
}

#[tokio::test]
async fn head_has_no_body_and_keeps_content_length() {
    let up = serve(Router::new().fallback(any(|| async {
        Response::builder()
            .header("content-length", "5")
            .body(Body::empty())
            .unwrap()
    })))
    .await;
    let r = reqwest::Client::new()
        .head(format!("{}/f", proxy(up).await))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-length"], "5");
    assert!(r.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn hop_by_hop_headers_are_stripped_and_host_rewritten() {
    let seen: Arc<Mutex<Option<HeaderMap>>> = Default::default();
    let s = seen.clone();
    let up = serve(Router::new().fallback(any(move |headers: HeaderMap| {
        let s = s.clone();
        async move {
            *s.lock().await = Some(headers);
            Response::builder()
                .header("keep-alive", "timeout=5")
                .body(Body::empty())
                .unwrap()
        }
    })))
    .await;
    let r = reqwest::Client::new()
        .get(format!("{}/h", proxy(up).await))
        .header("connection", "keep-alive")
        .header("keep-alive", "timeout=5")
        .header("proxy-authorization", "x")
        .header("te", "trailers")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.headers().get("keep-alive").is_none(),
        "response hop-by-hop stripped"
    );
    let h = seen.lock().await.take().unwrap();
    assert_eq!(h["host"], format!("127.0.0.1:{up}"));
    assert_eq!(h["x-vekrel-proxy"], "1");
    for name in ["connection", "keep-alive", "proxy-authorization", "te"] {
        assert!(h.get(name).is_none(), "{name} forwarded");
    }
}

#[tokio::test]
async fn engine_down_returns_502_json() {
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let r = reqwest::get(format!("{}/x", proxy(dead).await))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(r.headers()["content-type"], "application/json");
    assert_eq!(r.text().await.unwrap(), r#"{"error":"engine_unreachable"}"#);
}

/// Upstream that records the request headers it sees.
async fn header_probe() -> (u16, Arc<Mutex<HeaderMap>>) {
    let seen: Arc<Mutex<HeaderMap>> = Default::default();
    let s = seen.clone();
    let up = serve(Router::new().fallback(any(move |h: HeaderMap| {
        let s = s.clone();
        async move {
            *s.lock().await = h;
            "ok"
        }
    })))
    .await;
    (up, seen)
}

#[tokio::test]
async fn forwarded_headers_reach_upstream() {
    let (up, seen) = header_probe().await;
    let base = proxy(up).await;
    reqwest::get(format!("{base}/x")).await.unwrap();
    let h = seen.lock().await;
    assert_eq!(h["x-forwarded-host"], base.trim_start_matches("http://"));
    assert_eq!(h["x-forwarded-proto"], "http");
    assert_eq!(h["x-forwarded-for"], "127.0.0.1");
    assert_eq!(h["x-vekrel-proxy"], "1");
}

#[tokio::test]
async fn client_supplied_forwarded_host_is_overwritten() {
    let (up, seen) = header_probe().await;
    let base = proxy(up).await;
    reqwest::Client::new()
        .get(format!("{base}/x"))
        .header("x-forwarded-host", "evil.example")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "10.0.0.9")
        .send()
        .await
        .unwrap();
    let h = seen.lock().await;
    assert_eq!(h["x-forwarded-host"], base.trim_start_matches("http://"));
    assert_eq!(h["x-forwarded-proto"], "http");
    assert_eq!(h["x-forwarded-for"], "127.0.0.1");
}

async fn forwarded_host_seen_with_client_host(host: impl Fn(&str) -> String) {
    let (up, seen) = header_probe().await;
    let base = proxy(up).await;
    let port = base.rsplit(':').next().unwrap();
    reqwest::Client::new()
        .get(format!("{base}/x"))
        .header("host", host(port))
        .header("x-forwarded-host", "127.0.0.1:1")
        .send()
        .await
        .unwrap();
    assert!(seen.lock().await.get("x-forwarded-host").is_none());
}

#[tokio::test]
async fn forwarded_host_omitted_for_non_loopback_host() {
    forwarded_host_seen_with_client_host(|p| format!("evil.example:{p}")).await;
}

#[tokio::test]
async fn forwarded_host_omitted_for_wrong_port() {
    forwarded_host_seen_with_client_host(|_| "127.0.0.1:1".into()).await;
}

/// Node signs a link proof only for a request that reached it unproxied (`linkChecks.ts`
/// `hasForwardedAuthorityHeaders`, `isAllowedEndpointOrigin` on the Host port), so the daemon
/// adds and rewrites nothing on that route; whatever the client sent is Node's to judge.
#[tokio::test]
async fn link_proof_passes_through_as_the_client_sent_it() {
    let (up, seen) = header_probe().await;
    let base = proxy(up).await;
    reqwest::Client::new()
        .post(format!("{base}/api/connect/link-proof?x=1"))
        .send()
        .await
        .unwrap();
    let h = seen.lock().await.clone();
    assert_eq!(h["host"], base.trim_start_matches("http://"));
    for name in [
        "x-vekrel-proxy",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-for",
    ] {
        assert!(h.get(name).is_none(), "{name} added");
    }
    // Client-sent ones stay, so Node refuses them exactly as it would directly.
    reqwest::Client::new()
        .post(format!("{base}/api/connect/link-proof"))
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "10.0.0.9")
        .send()
        .await
        .unwrap();
    let h = seen.lock().await.clone();
    assert_eq!(h["x-forwarded-proto"], "https");
    assert_eq!(h["x-forwarded-for"], "10.0.0.9");
    assert!(h.get("x-vekrel-proxy").is_none());
    // A client-sent `x-vekrel-proxy` never survives, on this route or any other.
    reqwest::Client::new()
        .post(format!("{base}/api/connect/link-proof"))
        .header("x-vekrel-proxy", "spoofed")
        .send()
        .await
        .unwrap();
    assert!(seen.lock().await.get("x-vekrel-proxy").is_none());
    // Neighbouring routes keep the usual rewrite.
    reqwest::Client::new()
        .post(format!("{base}/api/connect/relay-config"))
        .send()
        .await
        .unwrap();
    let h = seen.lock().await.clone();
    assert_eq!(h["host"], format!("127.0.0.1:{up}"));
    assert_eq!(h["x-vekrel-proxy"], "1");
    assert_eq!(h["x-forwarded-proto"], "http");
}

/// DNS rebinding: a foreign Host (or our host on another port) on the link-proof route gets 421
/// and never reaches Node.
#[tokio::test]
async fn link_proof_with_untrusted_host_never_reaches_node() {
    let (up, seen) = header_probe().await;
    let base = proxy(up).await;
    let port = base.rsplit(':').next().unwrap();
    for host in [format!("evil.example:{port}"), "127.0.0.1:1".into()] {
        let r = reqwest::Client::new()
            .post(format!("{base}/api/connect/link-proof"))
            .header("host", host)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(r.text().await.unwrap(), r#"{"error":"untrusted_host"}"#);
    }
    assert!(seen.lock().await.is_empty(), "reached Node");
}

#[tokio::test]
async fn client_supplied_vekrel_proxy_is_overwritten() {
    let (up, seen) = header_probe().await;
    let base = proxy(up).await;
    reqwest::Client::new()
        .get(format!("{base}/x"))
        .header("x-vekrel-proxy", "spoofed")
        .send()
        .await
        .unwrap();
    let h = seen.lock().await;
    assert_eq!(h.get_all("x-vekrel-proxy").iter().count(), 1);
    assert_eq!(h["x-vekrel-proxy"], "1");
}

#[tokio::test]
async fn asterisk_form_request_gets_400() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let base = proxy(1).await; // upstream never reached
    let mut s = tokio::net::TcpStream::connect(base.trim_start_matches("http://"))
        .await
        .unwrap();
    s.write_all(b"OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut out))
        .await
        .expect("response in time")
        .unwrap();
    assert!(out.starts_with("HTTP/1.1 400"), "{out:?}");
    assert!(
        out.ends_with(r#"{"error":"bad_request_target"}"#),
        "{out:?}"
    );
}
