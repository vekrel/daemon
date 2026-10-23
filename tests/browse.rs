//! `filesystem.browse` (`handlers::browse`) against `WorkspaceEntries.browse`
//! (engine `workspace/WorkspaceEntries.ts:201-247`). `None` means Node answers.
//!
//! Expected orders were produced by Node 26 (ICU 78) `localeCompare`; the collation corpus is
//! synthetic (random names over the safe set, sorted by Node: byte order, then `localeCompare`).
use serde_json::{Value, json};
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};
use vekrel::{
    handlers::{
        HandlerCtx,
        browse::{self, Browse},
    },
    rpc_seam::UnaryHandler,
};

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp(name: &str) -> Tmp {
    // canonicalize: macOS /var is a symlink to /private/var, and Node resolves no symlinks either.
    let d = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("vekrel-browse-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Tmp(d)
}

fn dirs(root: &Path, names: &[&str]) {
    for n in names {
        std::fs::create_dir(root.join(n)).unwrap();
    }
}

async fn browse_with(h: &Browse, payload: Value) -> Option<String> {
    let out = h.handle(payload, &HandlerCtx::default()).await?;
    Some(out.expect("browse never fails in Rust").to_string())
}

async fn browse(home: &Path, payload: Value) -> Option<String> {
    browse_with(&Browse::new(home), payload).await
}

/// Node's result bytes: `{parentPath, entries:[{name, fullPath}]}`.
fn result(parent: &str, names: &[&str]) -> String {
    let entries: Vec<String> = names
        .iter()
        .map(|n| {
            let full = if parent == "/" {
                format!("/{n}")
            } else {
                format!("{parent}/{n}")
            };
            format!(r#"{{"name":{},"fullPath":{}}}"#, json!(n), json!(full))
        })
        .collect();
    format!(
        r#"{{"parentPath":{},"entries":[{}]}}"#,
        json!(parent),
        entries.join(",")
    )
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[tokio::test]
async fn trailing_separator_lists_the_dir_with_hidden_dirs_only() {
    let t = tmp("trailing");
    let d = &t.0;
    dirs(d, &["b", ".hidden", "A", "_x", "10", "2"]);
    std::fs::write(d.join("file.txt"), "").unwrap();
    std::fs::write(d.join(".hidden-file"), "").unwrap();
    symlink(d.join("b"), d.join("link-to-dir")).unwrap();
    let got = browse(d, json!({"partialPath": format!("{}/", s(d))})).await;
    // Node: ["_x",".hidden","10","2","A","b"]; files and the symlinked dir are excluded.
    assert_eq!(
        got.as_deref(),
        Some(result(s(d), &["_x", ".hidden", "10", "2", "A", "b"]).as_str())
    );
}

#[tokio::test]
async fn tilde_and_tilde_slash_expand_to_home() {
    let t = tmp("tilde");
    let d = &t.0;
    dirs(d, &["proj", ".cfg"]);
    let want = result(s(d), &[".cfg", "proj"]);
    for p in ["~", "~/"] {
        let got = browse(d, json!({"partialPath": p})).await;
        assert_eq!(got.as_deref(), Some(want.as_str()), "{p}");
    }
    // `~/pr` lists home filtered by the prefix, no hidden entries.
    let got = browse(d, json!({"partialPath": "~/pr"})).await;
    assert_eq!(got.as_deref(), Some(result(s(d), &["proj"]).as_str()));
}

#[tokio::test]
async fn prefix_filter_is_case_insensitive_like_to_lower_case() {
    let t = tmp("prefix");
    let d = &t.0;
    dirs(d, &["Bar", "bé", "b", "ab", ".b"]);
    let got = browse(d, json!({"partialPath": format!("{}/B", s(d))})).await;
    assert_eq!(
        got.as_deref(),
        Some(result(s(d), &["b", "Bar", "bé"]).as_str())
    );

    // `toLowerCase` is locale-independent full case mapping: İ -> i̇, final sigma, ß stays.
    let cases: &[(&str, &[&str], &str, &[&str])] = &[
        (
            "dot",
            &["İstanbul", "Ireland", "ab"],
            "i",
            &["Ireland", "İstanbul"],
        ),
        ("dot2", &["İstanbul", "Ireland"], "İ", &["İstanbul"]),
        ("sigma", &["ΟΔΟΣ"], "οδοσ", &[]),
        ("sigma2", &["ΟΔΟΣ"], "οδος", &["ΟΔΟΣ"]),
        ("sharp", &["Straße"], "STRASS", &[]),
        ("sharp2", &["Straße"], "straß", &["Straße"]),
        ("dz", &["ǅemal"], "ǆ", &["ǅemal"]),
    ];
    for (name, present, prefix, want) in cases {
        let t = tmp(name);
        dirs(&t.0, present);
        let got = browse(
            &t.0,
            json!({"partialPath": format!("{}/{prefix}", s(&t.0))}),
        )
        .await;
        assert_eq!(
            got.as_deref(),
            Some(result(s(&t.0), want).as_str()),
            "{name}"
        );
    }
}

#[tokio::test]
async fn hidden_entries_only_when_the_prefix_starts_with_a_dot() {
    let t = tmp("hidden");
    let d = &t.0;
    dirs(d, &[".git", ".Config", "visible"]);
    // `<dir>/.` resolves to `<dir>` itself (prefix = its name), so use `.c`.
    let got = browse(d, json!({"partialPath": format!("{}/.c", s(d))})).await;
    assert_eq!(got.as_deref(), Some(result(s(d), &[".Config"]).as_str()));
    let got = browse(d, json!({"partialPath": format!("{}/v", s(d))})).await;
    assert_eq!(got.as_deref(), Some(result(s(d), &["visible"]).as_str()));
}

#[tokio::test]
async fn unreadable_dir_lists_nothing() {
    let t = tmp("eacces");
    let locked = t.0.join("locked");
    dirs(&t.0, &["locked"]);
    dirs(&locked, &["inner"]);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let got = browse(&t.0, json!({"partialPath": format!("{}/", s(&locked))})).await;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(got.as_deref(), Some(result(s(&locked), &[]).as_str()));
}

#[tokio::test]
async fn node_answers_errors_and_inputs_rust_does_not_reproduce() {
    let t = tmp("errors");
    let d = &t.0;
    dirs(d, &["x"]);
    let home = d.as_path();
    let declined = [
        // Nonexistent parent / not a directory: Node's `read_directory_failed` error.
        json!({"partialPath": format!("{}/missing/", s(d))}),
        json!({"partialPath": format!("{}/missing/sub", s(d))}),
        // Windows path on darwin, relative without cwd: Node's other errors.
        json!({"partialPath": "C:\\Users"}),
        json!({"partialPath": "./x"}),
        // Resolved against Node's own process cwd.
        json!({"partialPath": "x"}),
        // Fails Node's input schema.
        json!({"partialPath": ""}),
        json!({"partialPath": " \u{3000} "}),
        json!({"partialPath": "/".repeat(513)}),
        json!({"partialPath": "/tmp", "cwd": 1}),
        json!({}),
    ];
    for p in declined {
        assert_eq!(browse(home, p.clone()).await, None, "{p}");
    }
    // The input schema trims (JS `trim`) before the length check.
    let padded = format!("\u{FEFF} {}/x/../\n", s(d));
    let got = browse(home, json!({"partialPath": padded, "extra": 1})).await;
    assert_eq!(got.as_deref(), Some(result(s(d), &["x"]).as_str()));
    let got = browse(
        home,
        json!({"partialPath": format!(" {}{}/ ", s(d), "/".repeat(511 - s(d).len()))}),
    )
    .await;
    assert_eq!(got.as_deref(), Some(result(s(d), &["x"]).as_str()));
    // `./` with a cwd resolves against it.
    let got = browse(home, json!({"partialPath": "./", "cwd": s(d)})).await;
    assert_eq!(got.as_deref(), Some(result(s(d), &["x"]).as_str()));
    let got = browse(
        home,
        json!({"partialPath": "../", "cwd": format!("{}/x", s(d))}),
    )
    .await;
    assert_eq!(got.as_deref(), Some(result(s(d), &["x"]).as_str()));
}

#[tokio::test]
async fn names_outside_the_safe_set_or_untrimmed_leave_the_dir_to_node() {
    for (name, present) in [
        ("han", &["不", "abc"][..]),
        // APFS refuses unassigned code points; newer-than-ICU4X ones are checked below.
        ("hebrew", &["שלום", "abc"][..]),
        ("space", &[" lead", "abc"][..]),
        ("nbsp", &["trail\u{A0}", "abc"][..]),
    ] {
        let t = tmp(name);
        dirs(&t.0, present);
        // Even with a prefix that would filter the odd name out.
        let got = browse(&t.0, json!({"partialPath": format!("{}/a", s(&t.0))})).await;
        assert_eq!(got, None, "{name}");
    }
    let t = tmp("ok");
    dirs(&t.0, &["Café", "🎉 party", "ünïcödé", "Ωmega", "Жук"]);
    let got = browse(&t.0, json!({"partialPath": format!("{}/", s(&t.0))})).await;
    // Node: ["🎉 party","Café","ünïcödé","Ωmega","Жук"]
    assert_eq!(
        got.as_deref(),
        Some(result(s(&t.0), &["🎉 party", "Café", "ünïcödé", "Ωmega", "Жук"]).as_str())
    );
}

#[test]
fn locale_gate_matches_icu_default_locale_selection() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |k: &str| pairs.iter().find(|p| p.0 == k).map(|p| p.1.to_owned())
    };
    assert!(browse::root_like_locale(env(&[])));
    assert!(browse::root_like_locale(env(&[("LANG", "C.UTF-8")])));
    assert!(browse::root_like_locale(env(&[("LANG", "en_GB.UTF-8")])));
    assert!(browse::root_like_locale(env(&[("LANG", "POSIX")])));
    // ICU reads LC_ALL, then LC_MESSAGES, then LANG (LC_COLLATE is ignored).
    assert!(!browse::root_like_locale(env(&[("LANG", "sv_SE.UTF-8")])));
    assert!(!browse::root_like_locale(env(&[
        ("LC_MESSAGES", "sv_SE.UTF-8"),
        ("LANG", "C")
    ])));
    assert!(!browse::root_like_locale(env(&[("LC_ALL", "de_DE.UTF-8")])));
    // BCP-47 extensions change collation (`en-u-kn-true` sorts numerically in Node).
    assert!(!browse::root_like_locale(env(&[(
        "LC_ALL",
        "en-u-kn-true"
    )])));
    assert!(!browse::root_like_locale(env(&[(
        "LANG",
        "en-US-u-co-emoji"
    )])));
    assert!(!browse::root_like_locale(env(&[("LANG", "en-t-de")])));
    assert!(!browse::root_like_locale(env(&[("LANG", "en-x-foo")])));
    assert!(!browse::root_like_locale(env(&[(
        "LANG",
        "en_US@collation=phonebook"
    )])));
    assert!(browse::root_like_locale(env(&[("LANG", "en-US")])));
    assert!(browse::root_like_locale(env(&[("LANG", "en-419")])));
    assert!(browse::root_like_locale(env(&[(
        "LC_COLLATE",
        "sv_SE.UTF-8"
    )])));
}

fn shuffle(v: &mut [String], mut seed: u64) {
    for i in (1..v.len()).rev() {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        v.swap(i, (seed >> 33) as usize % (i + 1));
    }
}

fn assert_sorts_like_node(want: &[String], seed: u64) {
    assert!(want.iter().all(|n| browse::in_safe_set(n)));
    assert!(!browse::in_safe_set("\u{1F6D9}") && !browse::in_safe_set("\u{20C1}"));
    let mut got = want.to_vec();
    shuffle(&mut got, seed);
    browse::sort_names(&mut got);
    let first = got.iter().zip(want).position(|(a, b)| a != b);
    assert_eq!(first, None, "first difference at index {first:?}");
}

#[test]
fn sort_matches_node_on_the_synthetic_corpus() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/collation-node.json");
    let cases: Vec<Vec<String>> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(cases.len(), 22);
    for (i, want) in cases.iter().enumerate() {
        assert_sorts_like_node(want, i as u64);
    }
}

#[test]
fn sort_matches_node_on_the_real_fixture() {
    let Some(dir) = std::env::var_os("VEKREL_FIXTURES_DIR") else {
        eprintln!("VEKREL_FIXTURES_DIR unset: skipping the real filesystem.browse replies");
        return;
    };
    let text =
        std::fs::read_to_string(Path::new(&dir).join("2026-10-22-boot-session.ndjson")).unwrap();
    let mut replies = 0;
    for line in text.lines() {
        let rec: Value = serde_json::from_str(line).unwrap();
        let Ok(f) = serde_json::from_str::<Value>(rec["frame"].as_str().unwrap()) else {
            continue;
        };
        let Some(entries) = f["exit"]["value"]["entries"].as_array() else {
            continue;
        };
        let names: Vec<String> = entries
            .iter()
            .map(|e| e["name"].as_str().unwrap().to_owned())
            .collect();
        assert_sorts_like_node(&names, replies);
        replies += 1;
    }
    assert_eq!(replies, 4, "filesystem.browse replies in the fixture");
}
