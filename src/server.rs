use crate::{proxy_http, supervisor::State};
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
    Router::new()
        .route("/healthz", get(healthz))
        .with_state(state)
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
