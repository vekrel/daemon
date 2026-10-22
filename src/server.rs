use crate::{
    proxy_http,
    proxy_ws::{self, FrameTap, NoTap},
    supervisor::State,
};
use axum::{Json, Router, body::Body, extract::State as AxState, routing::get};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::Ordering};

/// Where the Node engine listens (always loopback), plus a pooled client to reach it.
#[derive(Clone, Debug)]
pub struct Upstream {
    pub host: &'static str,
    pub port: u16,
    pub client: Client<HttpConnector, Body>,
}

impl Upstream {
    pub fn loopback(port: u16) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            host: "127.0.0.1",
            port,
            client,
        }
    }
}

pub fn build(state: Arc<State>, upstream: Upstream) -> Router {
    build_with_tap(state, upstream, Arc::new(NoTap))
}

pub fn build_with_tap(state: Arc<State>, upstream: Upstream, tap: Arc<dyn FrameTap>) -> Router {
    let ws = proxy_ws::Ctx {
        upstream: upstream.clone(),
        state: state.clone(),
        tap,
    };
    Router::new()
        .route("/healthz", get(healthz))
        .with_state(state)
        // Must precede the fallback, which strips `upgrade`.
        .route("/ws", get(proxy_ws::handler))
        .with_state(ws)
        .fallback(proxy_http::handler)
        .with_state(upstream)
}

async fn healthz(AxState(s): AxState<Arc<State>>) -> Json<Value> {
    let up = s.engine_up.load(Ordering::SeqCst);
    Json(json!({
        "engine": if up { "up" } else { "down" },
        "restarts": s.restarts.load(Ordering::SeqCst),
    }))
}
