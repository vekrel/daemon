use axum::{
    Router,
    extract::{WebSocketUpgrade, ws::Message as AxMsg},
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use vekrel::{recorder::Recorder, server, supervisor::State};

struct Guard(JoinHandle<()>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn serve(app: Router) -> (u16, Guard) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let h = tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (port, Guard(h))
}

/// Odd spacing and an escape, to prove frames are stored byte-for-byte.
const PONG: &str = r#"{"_tag":"Pong"}"#;
const REPLY: &str = r#"[ {"_tag":"Pong"},{"_tag":"Exit","requestId":"1","exit":{"_tag":"Success","value":"café é"}} ]"#;
const ARRAY: &str = r#"[{"_tag":"Ping"}, {"_tag":"Ack","requestId":"1"}]"#;

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn records_every_text_frame_verbatim() {
    let up = Router::new().route(
        "/ws",
        get(|ws: WebSocketUpgrade| async move {
            ws.on_upgrade(|mut s| async move {
                while let Some(Ok(AxMsg::Text(t))) = s.next().await {
                    let r = if t.as_str() == r#"{"_tag":"Ping"}"# {
                        PONG
                    } else {
                        REPLY
                    };
                    let _ = s.send(AxMsg::Text(r.into())).await;
                }
            })
        }),
    );
    let (up, _g1) = serve(up).await;
    let dir = TempDir(std::env::temp_dir().join(format!("vekrel-rec-{}", std::process::id())));
    let rec = Arc::new(Recorder::create(&dir.0).unwrap());
    let path = rec.path().to_owned();
    assert!(path.starts_with(&dir.0) && path.extension().unwrap() == "ndjson");
    let app = server::build_with_tap(
        Arc::new(State::default()),
        server::Upstream::loopback(up),
        rec,
    );
    let (proxy, _g2) = serve(app).await;

    let (mut c, _) = connect_async(format!("ws://127.0.0.1:{proxy}/ws"))
        .await
        .unwrap();
    c.send(Message::text(r#"{"_tag":"Ping"}"#)).await.unwrap();
    assert_eq!(
        c.next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .as_str(),
        PONG
    );
    c.send(Message::text(ARRAY)).await.unwrap();
    assert_eq!(
        c.next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .as_str(),
        REPLY
    );

    // The writer runs off the forwarding path; wait for it.
    let mut lines = vec![];
    for _ in 0..100 {
        lines = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        if lines.len() >= 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(lines.len(), 4, "{lines:?}");
    let rows: Vec<Value> = lines
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let got: Vec<(&str, &str)> = rows
        .iter()
        .map(|r| (r["dir"].as_str().unwrap(), r["frame"].as_str().unwrap()))
        .collect();
    assert_eq!(
        got,
        [
            ("c2s", r#"{"_tag":"Ping"}"#),
            ("s2c", PONG),
            ("c2s", ARRAY),
            ("s2c", REPLY)
        ]
    );
    let ts: Vec<u64> = rows.iter().map(|r| r["t"].as_u64().unwrap()).collect();
    assert!(ts.windows(2).all(|w| w[0] <= w[1]), "{ts:?}");
}
