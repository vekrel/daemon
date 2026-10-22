//! Test support: replays a `--record` file against a live socket and compares reply envelopes.
use crate::rpc_wire::parse_frame;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, time::Duration};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// `(conn, requestId as JSON text)`; `None` for envelopes without one (Pong, Defect...).
pub type Key = (u64, Option<String>);

/// One recording line: `{"t","conn","dir","frame"}`.
#[derive(Debug, Clone, Deserialize)]
pub struct Line {
    pub t: u64,
    /// Absent in recordings made before connection ids existed.
    #[serde(default)]
    pub conn: u64,
    pub dir: String,
    pub frame: String,
}

#[derive(Debug, Default)]
pub struct ReplayReport {
    pub matches: bool,
    /// Frames on either side that did not parse; any one fails the replay.
    pub unparsed: Vec<String>,
    /// Keys whose s2c `_tag` sequence differs.
    pub diverged: Vec<Key>,
    pub recorded: BTreeMap<Key, Vec<&'static str>>,
    pub seen: BTreeMap<Key, Vec<&'static str>>,
}

/// Groups s2c envelope tags per `(conn, requestId)`, in order; streams interleave freely, so
/// order only counts within one requestId. Every frame must parse, c2s included.
fn group(
    side: &str,
    lines: &[Line],
    unparsed: &mut Vec<String>,
) -> BTreeMap<Key, Vec<&'static str>> {
    let mut map: BTreeMap<Key, Vec<&'static str>> = BTreeMap::new();
    for (i, l) in lines.iter().enumerate() {
        match parse_frame(&l.frame) {
            Ok(envs) if l.dir == "s2c" => {
                for e in envs {
                    let (tag, id) = e.key();
                    let key = (l.conn, id.map(Value::to_string));
                    map.entry(key).or_default().push(tag);
                }
            }
            Ok(_) => {}
            Err(e) => unparsed.push(format!("{side}[{i}] conn {}: {e:?}", l.conn)),
        }
    }
    map
}

/// Compares envelope keys, not payloads.
pub fn compare(recorded: &[Line], live: &[Line]) -> ReplayReport {
    let mut unparsed = vec![];
    let rec = group("recorded", recorded, &mut unparsed);
    let seen = group("live", live, &mut unparsed);
    let mut keys: Vec<&Key> = rec.keys().chain(seen.keys()).collect();
    keys.sort();
    keys.dedup();
    let diverged: Vec<Key> = keys
        .into_iter()
        .filter(|k| rec.get(*k) != seen.get(*k))
        .cloned()
        .collect();
    ReplayReport {
        matches: unparsed.is_empty() && diverged.is_empty(),
        unparsed,
        diverged,
        recorded: rec,
        seen,
    }
}

/// Sends every c2s frame in recorded order; for each recorded s2c frame reads the next live
/// text frame (5 s timeout), then `compare`s.
/// shortcut: one live socket for every recorded conn; multi-connection recordings would need
/// one socket per conn (ids restart at 0 on each), add that when a test replays one.
pub async fn replay<C>(recording: &Path, client: &mut C) -> ReplayReport
where
    C: StreamExt<Item = Result<Message, WsError>> + SinkExt<Message, Error = WsError> + Unpin,
{
    let text = std::fs::read_to_string(recording).expect("read recording");
    let recorded: Vec<Line> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("recording line"))
        .collect();
    let mut live = vec![];
    for line in &recorded {
        if line.dir == "c2s" {
            if client
                .send(Message::text(line.frame.as_str()))
                .await
                .is_err()
            {
                break;
            }
            continue;
        }
        if let Some(frame) = next_text(client).await {
            live.push(Line {
                frame,
                ..line.clone()
            });
        }
    }
    compare(&recorded, &live)
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
