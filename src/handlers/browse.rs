//! `filesystem.browse` (`filesystem:read`): `WorkspaceEntries.browse` (engine
//! `workspace/WorkspaceEntries.ts:201-247`) on the host Node runs on (darwin/linux).
//!
//! Rust answers only what it reproduces exactly; everything else is `None` (Node answers):
//! every error Node raises (its `cause` is a defect Rust does not encode), relative paths Node
//! resolves against its own cwd, and directories with names outside [`in_safe_set`].
use crate::{handlers::HandlerCtx, rpc_seam::UnaryHandler};
use futures_util::{FutureExt, future::BoxFuture};
use icu_collator::{Collator, CollatorBorrowed, options::CollatorOptions};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::LazyLock};

pub struct Browse {
    /// `os.homedir()`: `$HOME` (libuv reads it first). `None`: Rust declines everything.
    home: Option<String>,
}

impl Browse {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        let home = home.into().into_os_string().into_string().ok();
        Browse { home }
    }

    /// Disabled (always `None`) unless Node's default collation locale sorts like root.
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok();
        let home = get("HOME").filter(|h| !h.is_empty() && root_like_locale(get));
        Browse { home }
    }
}

fn browse(home: Option<&str>, payload: &Value) -> Option<Value> {
    let home = home.filter(|h| h.starts_with('/'))?;
    // `FilesystemBrowseInput`: `TrimmedNonEmptyString` with max length 512, decoded trimmed.
    let field = |k| -> Option<Option<&str>> {
        match payload.get(k) {
            None => Some(None),
            Some(v) => {
                let s = js_trim(v.as_str()?);
                (!s.is_empty() && s.encode_utf16().count() <= 512).then_some(Some(s))
            }
        }
    };
    let partial = field("partialPath")??;
    let cwd = field("cwd")?;

    // resolveBrowseTarget
    let drive = partial.as_bytes();
    let windows = partial.starts_with("\\\\")
        || (drive.len() >= 2
            && drive[0].is_ascii_alphabetic()
            && drive[1] == b':'
            && matches!(drive.get(2), None | Some(b'/' | b'\\')));
    if windows {
        return None;
    }
    let resolved = if explicit_relative(partial) {
        let cwd = expand_home(cwd?, home);
        cwd.starts_with('/')
            .then(|| normalize(&format!("{cwd}/{partial}")))?
    } else {
        let p = expand_home(partial, home);
        // A relative path resolves against Node's process cwd.
        p.starts_with('/').then(|| normalize(&p))?
    };

    let ends_with_separator = partial.ends_with(['/', '\\']) || partial == "~";
    let (parent, prefix) = if ends_with_separator {
        (resolved.as_str(), "")
    } else {
        let i = resolved.rfind('/').expect("absolute");
        (
            if i == 0 { "/" } else { &resolved[..i] },
            &resolved[i + 1..],
        )
    };
    if js_trim(parent) != parent || !in_safe_set(prefix) {
        return None;
    }

    let dirents = match std::fs::read_dir(parent) {
        Ok(d) => d,
        Err(e) if matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
            return Some(json!({"parentPath": parent, "entries": []}));
        }
        Err(_) => return None,
    };
    let show_hidden = ends_with_separator || prefix.starts_with('.');
    let lower_prefix = prefix.to_lowercase();
    let mut names = Vec::new();
    for d in dirents {
        let d = d.ok()?;
        // `dirent.isDirectory()`: a symlink to a directory is not one.
        if !d.file_type().ok()?.is_dir() {
            continue;
        }
        let name = d.file_name().into_string().ok()?;
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        // Node would trim (or reject) such names on encode; leave the directory to Node.
        if !in_safe_set(&name) || js_trim(&name) != name {
            return None;
        }
        if name.to_lowercase().starts_with(&lower_prefix) {
            names.push(name);
        }
    }
    sort_names(&mut names);
    let sep = if parent == "/" { "" } else { "/" };
    // Field order of `FilesystemBrowseResult` / `FilesystemBrowseEntry`.
    let entries: Vec<Value> = names
        .into_iter()
        .map(|n| json!({"name": n, "fullPath": format!("{parent}{sep}{n}")}))
        .collect();
    Some(json!({"parentPath": parent, "entries": entries}))
}

impl UnaryHandler for Browse {
    fn default_mode(&self) -> crate::config::Mode {
        crate::config::Mode::Serve
    }
    fn tag(&self) -> &'static str {
        "filesystem.browse"
    }
    fn required_scope(&self) -> &'static str {
        "filesystem:read"
    }
    fn handle<'a>(
        &'a self,
        payload: Value,
        _ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Result<Value, Value>>> {
        let home = self.home.clone();
        async move {
            let r = tokio::task::spawn_blocking(move || browse(home.as_deref(), &payload)).await;
            r.ok().flatten().map(Ok)
        }
        .boxed()
    }
}

/// `isExplicitRelativePath` (`@vekrel/shared/path`).
fn explicit_relative(p: &str) -> bool {
    matches!(p, "." | "..")
        || ["./", "../", ".\\", "..\\"]
            .iter()
            .any(|s| p.starts_with(s))
}

/// `expandHomePath` (`provider-core/server/pathExpansion.ts`); `path.join` is applied by the
/// caller's `normalize`.
fn expand_home(v: &str, home: &str) -> String {
    match v {
        "~" => home.to_owned(),
        _ if v.starts_with("~/") || v.starts_with("~\\") => format!("{home}/{}", &v[2..]),
        _ => v.to_owned(),
    }
}

/// Node's posix `path.resolve` for an absolute path: drops `.`/empty segments, applies `..`,
/// no trailing slash.
fn normalize(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => drop(out.pop()),
            s => out.push(s),
        }
    }
    format!("/{}", out.join("/"))
}

/// `String.prototype.trim`.
fn js_trim(s: &str) -> &str {
    s.trim_matches(crate::machine::is_js_space)
}

/// Code points where ICU4X's root collation was checked to order exactly like Node 26 / ICU 78
/// `localeCompare` (every code point alone, prefixed, suffixed and doubled, plus 412k random
/// names mixing them). Outside it they disagree: Han (ICU 78 sorts by radical-stroke) and code
/// points newer than ICU4X's data (e.g. U+1F6D9, U+20C1, U+05C8). Controls are left out too.
pub fn in_safe_set(s: &str) -> bool {
    s.chars().all(|c| {
        matches!(c, '\u{20}'..='\u{7E}' | '\u{A0}'..='\u{4FF}' | '\u{1E00}'..='\u{1EFF}'
            | '\u{2000}'..='\u{206F}' | '\u{20A0}'..='\u{20C0}' | '\u{2100}'..='\u{214F}'
            | '\u{2190}'..='\u{21FF}' | '\u{2600}'..='\u{27BF}' | '\u{FE00}'..='\u{FE0F}'
            | '\u{1F300}'..='\u{1F64F}' | '\u{1F900}'..='\u{1F9FF}')
    })
}

/// V8's `localeCompare` default: root/en locale, tertiary strength, no numeric, case-first off,
/// punctuation not ignored — ICU4X's defaults.
static COLLATOR: LazyLock<CollatorBorrowed<'static>> = LazyLock::new(|| {
    Collator::try_new(Default::default(), CollatorOptions::default()).expect("compiled data")
});

/// `entries.toSorted((l, r) => l.name.localeCompare(r.name))` over `readdir`'s order, which
/// libuv's scandir sorts with `strcmp`: byte order first, then a stable collation sort.
pub fn sort_names(names: &mut [String]) {
    names.sort_unstable();
    names.sort_by(|a, b| COLLATOR.compare(a, b));
}

/// Whether Node's default locale collates like root. ICU takes it from `LC_ALL`, then
/// `LC_MESSAGES`, then `LANG` (not `LC_COLLATE`); unset, `C`, `POSIX` and `en*` all sort as root.
/// A BCP-47 value can carry collation keywords (`en-u-kn-true` sorts numerically), so any `-`
/// form other than plain `en-<region>` declines; so does any POSIX `@modifier`.
pub fn root_like_locale(get: impl Fn(&str) -> Option<String>) -> bool {
    let v = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|k| get(k).filter(|v| !v.is_empty()))
        .unwrap_or_default();
    if v.contains('@') {
        return false;
    }
    // The codeset (`.UTF-8`) may itself contain a `-`.
    let id = v.split('.').next().unwrap_or_default();
    if id.contains('-') {
        let mut parts = id.split('-');
        let (lang, region) = (parts.next(), parts.next());
        let region_ok = region.is_some_and(|r| {
            (r.len() == 2 && r.bytes().all(|b| b.is_ascii_alphabetic()))
                || (r.len() == 3 && r.bytes().all(|b| b.is_ascii_digit()))
        });
        return lang == Some("en") && region_ok && parts.next().is_none();
    }
    let lang = id.split('_').next().unwrap_or_default();
    matches!(lang, "" | "C" | "POSIX" | "en")
}
