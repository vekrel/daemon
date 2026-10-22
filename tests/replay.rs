use axum::{
    Router,
    extract::{WebSocketUpgrade, ws::Message as AxMsg},
    routing::get,
};
use futures_util::StreamExt;
use std::path::PathBuf;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_tungstenite::connect_async;
use vekrel::replay::{Line, compare, replay};

struct Guard(JoinHandle<()>, PathBuf);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.abort();
        let _ = std::fs::remove_file(&self.1);
    }
}

const REQUEST: &str =
    r#"{"_tag":"Request","id":7,"tag":"subscribeServerConfig","payload":{},"headers":[]}"#;
const CHUNK: &str = r#"{"_tag":"Chunk","requestId":7,"values":[{"type":"snapshot"}]}"#;
const EXIT: &str = r#"{"_tag":"Exit","requestId":7,"exit":{"_tag":"Success","value":null}}"#;

/// Fake engine: Ping -> Pong, Request -> Chunk, Ack -> Exit.
async fn fake_engine() -> (u16, JoinHandle<()>) {
    let app = Router::new().route(
        "/ws",
        get(|ws: WebSocketUpgrade| async move {
            ws.on_upgrade(|mut s| async move {
                while let Some(Ok(AxMsg::Text(t))) = s.next().await {
                    let t = t.as_str();
                    let r = if t.contains("Ping") {
                        r#"{"_tag":"Pong"}"#
                    } else if t.contains("Request") {
                        CHUNK
                    } else {
                        EXIT
                    };
                    let _ = s.send(AxMsg::Text(r.into())).await;
                }
            })
        }),
    );
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    (
        port,
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() }),
    )
}

fn line(t: u64, dir: &str, frame: &str) -> String {
    serde_json::json!({"t": t, "conn": 0, "dir": dir, "frame": frame}).to_string()
}

async fn run(exit_frame: &str, name: &str) -> vekrel::replay::ReplayReport {
    let (port, h) = fake_engine().await;
    let path = std::env::temp_dir().join(format!(
        "vekrel-replay-{}-{name}.ndjson",
        std::process::id()
    ));
    let _g = Guard(h, path.clone());
    let rec = [
        line(1, "c2s", r#"{"_tag":"Ping"}"#),
        line(2, "s2c", r#"{"_tag":"Pong"}"#),
        line(3, "c2s", REQUEST),
        line(4, "s2c", CHUNK),
        line(5, "c2s", r#"{"_tag":"Ack","requestId":7}"#),
        line(6, "s2c", exit_frame),
    ];
    std::fs::write(&path, rec.join("\n") + "\n").unwrap();
    let (mut c, _) = connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .unwrap();
    replay(&path, &mut c).await
}

#[tokio::test]
async fn identical_engine_matches() {
    let r = run(EXIT, "same").await;
    assert!(r.matches, "{r:?}");
    assert_eq!(r.seen.values().map(Vec::len).sum::<usize>(), 3);
}

#[tokio::test]
async fn changed_tag_reports_divergence() {
    let r = run(CHUNK, "diff").await;
    assert!(!r.matches);
    assert_eq!(r.diverged, [(0, Some("7".to_owned()))], "{r:?}");
}

fn s2c(conn: u64, frame: &str) -> Line {
    Line {
        t: 0,
        conn,
        dir: "s2c".into(),
        frame: frame.into(),
    }
}

fn chunk(id: u64) -> String {
    format!(r#"{{"_tag":"Chunk","requestId":{id},"values":[]}}"#)
}

fn exit(id: u64) -> String {
    format!(r#"{{"_tag":"Exit","requestId":{id},"exit":{{"_tag":"Success","value":null}}}}"#)
}

#[test]
fn replay_fails_on_unparsable_frames() {
    // The old bug: both sides unparsable compared equal.
    let bad = [s2c(0, r#"{"_tag":"Chunk","requestId":"#)];
    let r = compare(&bad, &bad);
    assert!(!r.matches, "{r:?}");
    assert_eq!(r.unparsed.len(), 2, "{r:?}");
    // One side only is a failure too.
    let good = [s2c(0, &exit(1))];
    assert!(!compare(&good, &bad).matches);
    assert!(!compare(&bad, &good).matches);
    assert!(compare(&good, &good).matches);
}

#[test]
fn replay_matches_interleaved_streams_by_request_id() {
    let rec = [
        s2c(1, &chunk(0)),
        s2c(1, &chunk(1)),
        s2c(1, r#"{"_tag":"Pong"}"#),
        s2c(1, &chunk(0)),
        s2c(1, &exit(1)),
    ];
    let live = [
        s2c(1, &chunk(1)),
        s2c(1, &exit(1)),
        s2c(1, &chunk(0)),
        s2c(1, r#"{"_tag":"Pong"}"#),
        s2c(1, &chunk(0)),
    ];
    let r = compare(&rec, &live);
    assert!(r.matches, "{r:?}");

    // Order within one requestId still counts.
    let swapped = [
        s2c(1, &chunk(0)),
        s2c(1, &exit(1)),
        s2c(1, &chunk(1)),
        s2c(1, r#"{"_tag":"Pong"}"#),
        s2c(1, &chunk(0)),
    ];
    let r = compare(&rec, &swapped);
    assert_eq!(r.diverged, [(1, Some("1".to_owned()))], "{r:?}");

    // Same frames on another connection do not match.
    let other: Vec<Line> = rec.iter().map(|l| s2c(2, &l.frame)).collect();
    assert!(!compare(&rec, &other).matches);
}
