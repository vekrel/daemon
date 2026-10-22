//! Test support: replays a `--record` file against a live socket and compares reply envelopes.
use crate::rpc_wire::parse_frame;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::{path::Path, time::Duration};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// `(_tag, request id)` of one envelope; frames that fail to parse become `("<unparsed>", None)`.
pub type Key = (String, Option<String>);

#[derive(Debug, Default)]
pub struct ReplayReport {
    pub matches: bool,
    /// Index into `recorded`/`seen` of the first differing s2c envelope.
    pub first_divergence: Option<usize>,
    pub recorded: Vec<Key>,
    pub seen: Vec<Key>,
}

#[derive(Deserialize)]
struct Line {
    dir: String,
    frame: String,
}

fn keys(frame: &str) -> Vec<Key> {
    match parse_frame(frame) {
        Ok(envs) => envs
            .iter()
            .map(|e| {
                let (tag, id) = e.key();
                (tag.to_owned(), id.map(str::to_owned))
            })
            .collect(),
        Err(_) => vec![("<unparsed>".into(), None)],
    }
}

/// Sends every c2s frame in recorded order; for each recorded s2c frame reads the next live
/// text frame (5 s timeout) and compares envelope keys, not payloads.
pub async fn replay<C>(recording: &Path, client: &mut C) -> ReplayReport
where
    C: StreamExt<Item = Result<Message, WsError>> + SinkExt<Message, Error = WsError> + Unpin,
{
    let text = std::fs::read_to_string(recording).expect("read recording");
    let mut r = ReplayReport::default();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let line: Line = serde_json::from_str(line).expect("recording line");
        if line.dir == "c2s" {
            if client.send(Message::text(line.frame)).await.is_err() {
                break;
            }
            continue;
        }
        r.recorded.extend(keys(&line.frame));
        if let Some(live) = next_text(client).await {
            r.seen.extend(keys(&live));
        }
    }
    r.first_divergence =
        (0..r.recorded.len().max(r.seen.len())).find(|&i| r.recorded.get(i) != r.seen.get(i));
    r.matches = r.first_divergence.is_none();
    r
}

async fn next_text<C>(client: &mut C) -> Option<String>
where
    C: StreamExt<Item = Result<Message, WsError>> + Unpin,
{
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), client.next()).await;
        match m.ok()?? {
            Ok(Message::Text(t)) => return Some(t.as_str().to_owned()),
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            _ => return None,
        }
    }
}
