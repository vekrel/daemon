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
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    port
}

/// Starts the proxy under test in front of `upstream_port`; returns its base URL.
async fn proxy(upstream_port: u16) -> String {
    let app = server::build(
        Arc::new(State::default()),
        server::Upstream::loopback(upstream_port),
    );
    format!("http://127.0.0.1:{}", serve(app).await)
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
