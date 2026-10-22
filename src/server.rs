use crate::supervisor::State;
use axum::{Json, Router, extract::State as AxState, routing::get};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::Ordering};

/// Where the Node engine listens (always loopback).
#[derive(Clone, Debug)]
#[allow(dead_code)] // fields are read by the proxy routes added in later tasks
pub struct Upstream {
    pub host: &'static str,
    pub port: u16,
}

impl Upstream {
    pub fn loopback(port: u16) -> Self {
        Self { host: "127.0.0.1", port }
    }
}

pub fn build(state: Arc<State>, _upstream: Upstream) -> Router {
    Router::new().route("/healthz", get(healthz)).with_state(state)
}

async fn healthz(AxState(s): AxState<Arc<State>>) -> Json<Value> {
    let up = s.engine_up.load(Ordering::SeqCst);
    Json(json!({
        "engine": if up { "up" } else { "down" },
        "restarts": s.restarts.load(Ordering::SeqCst),
    }))
}
