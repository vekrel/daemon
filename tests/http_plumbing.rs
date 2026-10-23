//! The HTTP seam's request-body buffering: a handler that `wants_body` sees the bytes; on a
//! decline or a body over 64 KiB Node receives the original bytes and headers.
use axum::{
    Router,
    body::{Body, Bytes},
    extract::Request,
    http::{Method, Response, request::Parts},
    routing::any,
};
use futures_util::{FutureExt, future::BoxFuture};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::TcpListener;
use vekrel::{
    config::Mode,
    handlers::HandlerCtx,
    http_seam::{self, RouteHandler, Seam},
    server,
    supervisor::State,
};

/// Answers `{"rust":<parsed body>}` for a JSON body and declines anything else; counts calls.
struct Echo(Arc<AtomicUsize>);

impl RouteHandler for Echo {
    fn default_mode(&self) -> Mode {
        Mode::Serve
    }
    fn wants_body(&self) -> bool {
        true
    }
    fn method_path(&self) -> (Method, &'static str) {
        (Method::POST, "/echo")
    }
    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        async move {
            let v = http_seam::json_body(req)?;
            Some(Response::new(Bytes::from(
                serde_json::json!({ "rust": v }).to_string(),
            )))
        }
        .boxed()
    }
}

/// Fake engine: echoes the request body, with `x-test` and `content-type` copied back.
async fn engine() -> u16 {
    let app = Router::new().fallback(any(|req: Request| async move {
        let h = req.headers().clone();
        let body = axum::body::to_bytes(req.into_body(), usize::MAX)
            .await
            .unwrap();
        let mut r = Response::builder();
        for k in ["x-test", "content-type"] {
            if let Some(v) = h.get(k) {
                r = r.header(k, v);
            }
        }
        r.body(Body::from(body)).unwrap()
    }));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    port
}

async fn proxy(up: u16, calls: Arc<AtomicUsize>) -> String {
    let seam = Seam::new(HandlerCtx::default()).with(Mode::Serve, Arc::new(Echo(calls)));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let app = server::build(
        Arc::new(State::default()),
        server::Upstream::loopback(up)
            .with_public_port(port)
            .with_seam(seam),
    );
    tokio::spawn(async move {
        axum::serve(
            l,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    format!("http://127.0.0.1:{port}/echo")
}

/// (served by Rust, x-test, content-type, body).
async fn post(url: &str, ct: &str, body: Vec<u8>) -> (bool, String, String, Vec<u8>) {
    let r = reqwest::Client::new()
        .post(url)
        .header("x-test", "kept")
        .header("content-type", ct)
        .body(body)
        .send()
        .await
        .unwrap();
    let h = r.headers().clone();
    let s = |k: &str| h.get(k).map_or("", |v| v.to_str().unwrap()).to_owned();
    (
        h.contains_key("x-vekrel-served-by"),
        s("x-test"),
        s("content-type"),
        r.bytes().await.unwrap().to_vec(),
    )
}

#[tokio::test]
async fn small_json_body_reaches_the_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let url = proxy(engine().await, calls.clone()).await;
    let (rust, _, _, body) = post(&url, "application/json", br#"{"a":[1]}"#.to_vec()).await;
    assert!(rust);
    assert_eq!(body, br#"{"rust":{"a":[1]}}"#);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn declines_reforward_the_original_bytes_and_headers() {
    let calls = Arc::new(AtomicUsize::new(0));
    let url = proxy(engine().await, calls.clone()).await;
    // Malformed JSON, a non-JSON type, invalid UTF-8: the handler declines, Node gets it all.
    for (ct, body) in [
        ("application/json", br#"{"a":"#.to_vec()),
        ("application/x-www-form-urlencoded", b"a=%FF".to_vec()),
        ("application/json", b"{\"a\":\"\xff\"}".to_vec()),
    ] {
        assert_eq!(
            post(&url, ct, body.clone()).await,
            (false, "kept".into(), ct.into(), body)
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn bodies_over_64_kib_go_to_node_untouched() {
    let calls = Arc::new(AtomicUsize::new(0));
    let url = proxy(engine().await, calls.clone()).await;
    let big: Vec<u8> = (0..(64 << 10) + 1).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        post(&url, "application/json", big.clone()).await,
        (false, "kept".into(), "application/json".into(), big)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "the handler never runs");
}

/// Sends a chunked request over a raw socket and returns the response bytes.
async fn raw_chunked(url: &str, chunks: &[&[u8]]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = url.trim_start_matches("http://").split('/').next().unwrap();
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "POST /echo HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\n\
         x-test: kept\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
    )
    .into_bytes();
    for c in chunks {
        req.extend(format!("{:x}\r\n", c.len()).bytes());
        req.extend_from_slice(c);
        req.extend(b"\r\n");
    }
    req.extend(b"0\r\n\r\n");
    s.write_all(&req).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    out
}

#[tokio::test]
async fn chunked_bodies_reach_node_byte_for_byte_on_decline() {
    let calls = Arc::new(AtomicUsize::new(0));
    let url = proxy(engine().await, calls.clone()).await;
    // Malformed JSON in three chunks (handler declines), then 3 x 30 KiB (over the limit mid-read).
    let small: [&[u8]; 3] = [b"{\"a\"", b":", b"[1,"];
    let big = vec![b'z'; 30 << 10];
    let large: [&[u8]; 3] = [&big, &big, &big];
    for (chunks, handler_runs) in [(&small[..], 1), (&large[..], 0)] {
        let before = calls.load(Ordering::SeqCst);
        let resp = raw_chunked(&url, chunks).await;
        let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let (head, body) = (
            String::from_utf8_lossy(&resp[..split]).to_lowercase(),
            &resp[split + 4..],
        );
        assert!(head.starts_with("http/1.1 200"), "{head}");
        assert!(
            head.contains("x-test: kept") && !head.contains("x-vekrel-served-by"),
            "{head}"
        );
        assert!(
            !head.contains("transfer-encoding: chunked"),
            "echo has a length: {head}"
        );
        assert_eq!(body, chunks.concat());
        assert_eq!(calls.load(Ordering::SeqCst) - before, handler_runs);
    }
}
