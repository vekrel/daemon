//! `orchestration.searchThreads` (`orchestration:read`): the engine's `ThreadSearch.search`
//! (`orchestration-v2/ThreadSearch.ts`) over the state DB, read-only.
//!
//! Rust answers only successes it reproduces exactly. `None` (Node answers): a payload
//! `OrchestrationSearchThreadsInput` rejects (Node's decode failure), any DB error or busy DB,
//! a row `SearchRow` would reject or alter on decode (Node fails, or trims an id), and a snippet
//! whose UTF-16 cut splits a surrogate pair (a `serde_json::Value` cannot carry it).
use crate::{
    db::read::StateDb,
    handlers::HandlerCtx,
    js_string::{collapse_space, index_of, slice, trim, units},
    rpc_seam::UnaryHandler,
};
use futures_util::{FutureExt, future::BoxFuture};
use rusqlite::types::ValueRef;
use serde_json::{Value, json};
use std::sync::{Arc, OnceLock};

#[derive(Default)]
pub struct SearchThreads {
    /// `<ctx.state_dir>/statev2.sqlite`, opened on the first request.
    db: OnceLock<Arc<StateDb>>,
}

impl UnaryHandler for SearchThreads {
    fn tag(&self) -> &'static str {
        "orchestration.searchThreads"
    }
    fn required_scope(&self) -> &'static str {
        "orchestration:read"
    }
    fn handle<'a>(
        &'a self,
        payload: Value,
        ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Result<Value, Value>>> {
        let db = self
            .db
            .get_or_init(|| Arc::new(StateDb::new(&ctx.state_dir)))
            .clone();
        async move {
            let r = tokio::task::spawn_blocking(move || search(&db, &payload)).await;
            r.ok().flatten().map(Ok)
        }
        .boxed()
    }
}

/// `OrchestrationSearchThreadsInput` decoded: `query` trimmed then 2..200 UTF-16 units, `limit` an
/// integer 1..50 (default 50). Extra keys are ignored, as Effect's struct decoding does.
fn decode(p: &Value) -> Option<(String, i64)> {
    let q = units(p.get("query")?.as_str()?);
    let q = trim(&q);
    if !(2..=200).contains(&q.len()) {
        return None;
    }
    let limit = match p.get("limit") {
        None => 50,
        Some(v) => {
            let f = v.as_f64()?;
            if f.fract() != 0.0 || !(1.0..=50.0).contains(&f) {
                return None;
            }
            f as i64
        }
    };
    Some((String::from_utf16(q).ok()?, limit))
}

/// `escapeLikePattern`.
fn escape_like(v: &str) -> String {
    v.replace('!', "!!").replace('%', "!%").replace('_', "!_")
}

/// The engine's statement, verbatim (`ThreadSearch.ts:78-128`), with `?1` / `?2` for its params.
const SQL: &str = r#"
      WITH candidate AS (
        SELECT
          threads.thread_id,
          threads.project_id,
          messages.role,
          json_extract(messages.payload_json, '$.text') AS match_text,
          messages.created_at AS message_created_at,
          messages.message_id,
          threads.updated_at AS thread_updated_at
        FROM orchestration_v2_projection_messages AS messages
        INNER JOIN orchestration_v2_projection_threads AS threads
          ON threads.thread_id = messages.thread_id
        INNER JOIN projection_projects AS projects
          ON projects.project_id = threads.project_id
        WHERE threads.deleted_at IS NULL
          AND threads.archived_at IS NULL
          AND projects.deleted_at IS NULL
          AND messages.streaming = 0
          AND messages.role IN ('user', 'assistant')
          AND json_extract(messages.payload_json, '$.text') LIKE ?1 ESCAPE '!'
      ),
      ranked AS (
        SELECT
          thread_id,
          project_id,
          role AS source,
          match_text,
          message_created_at,
          CASE role WHEN 'user' THEN 0 ELSE 1 END AS match_rank,
          thread_updated_at,
          ROW_NUMBER() OVER (
            PARTITION BY thread_id
            ORDER BY
              CASE role WHEN 'user' THEN 0 ELSE 1 END ASC,
              message_created_at DESC,
              message_id ASC
          ) AS thread_match_rank
        FROM candidate
      )
      SELECT
        thread_id AS "threadId",
        project_id AS "projectId",
        source,
        match_text AS "matchText",
        message_created_at AS "messageCreatedAt"
      FROM ranked
      WHERE thread_match_rank = 1
      ORDER BY match_rank ASC, thread_updated_at DESC, thread_id ASC
      LIMIT ?2
    "#;

/// A text column as JS reads it; `None` for any other type or invalid UTF-8 (Node would decode
/// replacement characters, or fail `Schema.String`).
fn text(v: ValueRef<'_>) -> Option<&str> {
    match v {
        ValueRef::Text(b) => std::str::from_utf8(b).ok(),
        _ => None,
    }
}

/// `ThreadId` / `ProjectId` (`TrimmedNonEmptyString`): Rust only passes ids decoding leaves as is.
fn entity_id(v: ValueRef<'_>) -> Option<&str> {
    text(v).filter(|s| !s.is_empty() && trim(&units(s)).len() == s.encode_utf16().count())
}

/// The `orchestration.searchThreads` Success value, or `None` (Node answers).
pub fn search(db: &StateDb, payload: &Value) -> Option<Value> {
    let (query, limit) = decode(payload)?;
    let pattern = format!("%{}%", escape_like(&query));
    let rows = db
        .read(|c| {
            let mut st = c.prepare(SQL)?;
            let mut rows = st.query(rusqlite::params![pattern, limit])?;
            let mut out = Vec::new();
            while let Some(r) = rows.next()? {
                let row = (|| {
                    let created = match r.get_ref(4).ok()? {
                        ValueRef::Null => Value::Null,
                        v => text(v)?.into(),
                    };
                    let source = text(r.get_ref(2).ok()?)?;
                    Some(json!({
                        "threadId": entity_id(r.get_ref(0).ok()?)?,
                        "projectId": entity_id(r.get_ref(1).ok()?)?,
                        "source": matches!(source, "user" | "assistant").then_some(source)?,
                        "snippet": snippet(text(r.get_ref(3).ok()?)?, &query)?,
                        "messageCreatedAt": created,
                    }))
                })();
                // One undecodable row fails Node's whole search.
                out.push(row);
            }
            Ok(out)
        })
        .inspect_err(|d| tracing::info!(reason = d.reason(), "searchThreads declined"))
        .ok()?;
    let matches: Option<Vec<Value>> = rows.into_iter().collect();
    Some(json!({ "matches": matches? }))
}

/// `foldAsciiCase`.
fn fold(s: &[u16]) -> Vec<u16> {
    s.iter()
        .map(|&u| {
            if (0x41..=0x5a).contains(&u) {
                u + 32
            } else {
                u
            }
        })
        .collect()
}

/// `buildSearchSnippet` (`ThreadSearch.ts:46-60`) on UTF-16 units; `None` if the cut splits a
/// surrogate pair.
fn snippet(text: &str, query: &str) -> Option<String> {
    let collapsed = collapse_space(&units(text));
    let t = trim(&collapsed);
    let len = t.len() as i64;
    if len <= 240 {
        return String::from_utf16(t).ok();
    }
    let q = fold(trim(&collapse_space(&units(query))));
    let at = index_of(&fold(t), &q);
    let start = (at - 72).max(0).min(len - 236);
    let end = len.min(start + 236);
    let mut out: Vec<u16> = Vec::with_capacity(240);
    if start > 0 {
        out.push(0x2026);
    }
    out.extend_from_slice(slice(t, start, end));
    if end < len {
        out.push(0x2026);
    }
    String::from_utf16(&out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::read::tests::fixture;

    const FIXTURE: &str = include_str!("../../tests/fixtures/thread_search.sql");
    /// Node's Exit for each payload over `FIXTURE` (written by the live test, see
    /// `thread_search_shadow_matches_node`); `rust` is `served` or `declined`.
    const GOLDEN: &str = include_str!("../../tests/golden/thread_search.json");

    fn db() -> (tempfile::TempDir, StateDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture(dir.path(), FIXTURE);
        (dir, db)
    }

    #[test]
    fn matches_node_golden_over_the_fixture() {
        let (_dir, db) = db();
        let cases: Vec<Value> = serde_json::from_str(GOLDEN).unwrap();
        assert!(cases.len() > 40, "{}", cases.len());
        let mut served = 0;
        for c in &cases {
            let got = search(&db, &c["payload"]);
            match c["rust"].as_str().unwrap() {
                "served" => {
                    let exit = json!({"_tag": "Success", "value": got.unwrap_or_else(|| panic!("{}", c["payload"]))});
                    assert_eq!(
                        exit.to_string(),
                        c["exit"].as_str().unwrap(),
                        "{}",
                        c["payload"]
                    );
                    served += 1;
                }
                _ => assert_eq!(got, None, "{}", c["payload"]),
            }
        }
        assert!(served > 25, "{served}");
    }

    fn ids(v: &Value) -> Vec<&str> {
        v["matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["threadId"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn orders_by_rank_then_recency_then_id_and_limits() {
        let (_dir, db) = db();
        let r = search(&db, &json!({"query": "foo"})).unwrap();
        // ts-a has a user match (rank 0); ts-b and ts-c tie on updated_at, so thread_id breaks it.
        assert_eq!(ids(&r), ["ts-a", "ts-b", "ts-c"]);
        assert_eq!(r["matches"][0]["source"], "user");
        let all = search(&db, &json!({"query": "bulk item"})).unwrap();
        assert_eq!(ids(&all).len(), 50, "default limit");
        let one = search(&db, &json!({"query": "bulk item", "limit": 1})).unwrap();
        assert_eq!(ids(&one), [ids(&all)[0]]);
        assert_eq!(
            ids(&search(&db, &json!({"query": "bulk item", "limit": 50.0})).unwrap()).len(),
            50
        );
        for bad in [
            json!(0),
            json!(51),
            json!(1.5),
            json!("2"),
            Value::Null,
            json!(-1),
        ] {
            assert_eq!(
                search(&db, &json!({"query": "bulk", "limit": bad})),
                None,
                "{bad}"
            );
        }
    }

    #[test]
    fn like_wildcards_are_literal_and_case_folds_ascii_only() {
        let (_dir, db) = db();
        let snip = |q: &str| {
            search(&db, &json!({ "query": q })).unwrap()["matches"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["snippet"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(snip("100%"), ["100% done_with! it"]);
        assert_eq!(snip("e_w"), ["100% done_with! it"]);
        assert_eq!(snip("h!"), ["100% done_with! it"]);
        assert_eq!(snip("%%"), Vec::<String>::new());
        assert_eq!(snip("HELLO world"), ["Hello World foo"]);
        assert_eq!(
            snip("ärger"),
            Vec::<String>::new(),
            "SQLite folds ASCII only"
        );
        assert_eq!(snip("Ärger"), ["Ärger über Öl 🎉"]);
    }

    #[test]
    fn query_is_trimmed_then_bounded_in_utf16_units() {
        let (_dir, db) = db();
        let ok = |p: Value| search(&db, &p).is_some();
        assert!(ok(json!({"query": " \u{a0}foo\u{feff} "})));
        assert!(ok(json!({"query": "🎉"})), "one emoji is 2 units");
        assert!(ok(json!({"query": "🎉".repeat(100)})));
        assert!(!ok(json!({"query": "🎉".repeat(101)})));
        assert!(ok(json!({"query": "b".repeat(200)})));
        assert!(!ok(json!({"query": "b".repeat(201)})));
        for bad in [
            json!({"query": ""}),
            json!({"query": " a "}),
            json!({"query": " \n "}),
            json!({"query": 5}),
            json!({}),
            json!("foo"),
            Value::Null,
        ] {
            assert!(!ok(bad.clone()), "{bad}");
        }
        assert!(ok(json!({"query": "foo", "extra": 1})));
    }

    #[test]
    fn snippet_cuts_on_utf16_units_like_js() {
        let long = |pre: usize, word: &str, post: usize| {
            format!("{}{word}{}", "a".repeat(pre), "b".repeat(post))
        };
        // Short text: whitespace collapsed and trimmed, no cut.
        assert_eq!(snippet(" x\u{a0}\u{2028}\ty ", "x"), Some("x y".into()));
        let exact = "c".repeat(240);
        assert_eq!(snippet(&exact, "cc"), Some(exact.clone()));
        // Match in the middle: 72 units of lead, 236 body, ellipses both sides.
        let s = snippet(&long(300, "needle", 300), "NEEDLE").unwrap();
        assert_eq!(s.encode_utf16().count(), 238);
        assert!(s.starts_with(&format!("…{}needle", "a".repeat(72))), "{s}");
        // Near the end: start pinned to len - 236, no trailing ellipsis.
        let s = snippet(&long(400, "needle", 0), "needle").unwrap();
        assert!(s.starts_with('…') && s.ends_with("needle"), "{s}");
        // Absent from the text (indexOf -1): from the start.
        let s = snippet(&long(300, "", 0), "zz").unwrap();
        assert!(s.ends_with('…') && !s.starts_with('…'));
        // A cut through a surrogate pair declines; an emoji inside the window is kept.
        let split = format!(
            "{}🎉{}needle{}",
            "x".repeat(99),
            "y".repeat(71),
            "z".repeat(200)
        );
        assert_eq!(snippet(&split, "needle"), None);
        let end = format!(
            "{}needle{}🎉{}",
            "x".repeat(100),
            "y".repeat(157),
            "z".repeat(100)
        );
        assert_eq!(
            snippet(&end, "needle"),
            None,
            "end cut after a high surrogate"
        );
        let inside = format!("{}needle🎉{}", "x".repeat(100), "z".repeat(200));
        assert!(snippet(&inside, "needle").unwrap().contains('🎉'));
    }

    #[test]
    fn rows_node_would_reject_or_trim_decline() {
        let (_dir, db) = db();
        assert_eq!(
            search(&db, &json!({"query": "paddedid"})),
            None,
            "id with a space"
        );
        assert_eq!(
            search(&db, &json!({"query": "345"})),
            None,
            "numeric $.text"
        );
        assert!(search(&db, &json!({"query": "emojicut"})).is_none());
        let empty = json!({"matches": []});
        for q in [
            "hiddenkey",
            "streamingonly",
            "systemonly",
            "archivedonly",
            "deletedonly",
            "goneproject",
        ] {
            assert_eq!(
                search(&db, &json!({ "query": q })),
                Some(empty.clone()),
                "{q}"
            );
        }
    }
}
