//! `projects.readFile`, byte-compatible with the engine's `WorkspaceFileSystem.readFile`
//! (`WorkspaceFileSystem.ts` `resolveReadTarget`/`readFile`) and the `ProjectReadFileError`
//! mapping in `ws.ts` (`projectFileFailureContext`).
//!
//! shortcut: POSIX path semantics only (Node's `path.posix`); Windows needs `path.win32` rules.
use super::HandlerCtx;
use crate::rpc_seam::UnaryHandler;
use futures_util::{FutureExt, future::BoxFuture};
use serde_json::{Map, Value, json};
use std::{fs, io, io::Read};

const MAX_BYTES: u64 = 1024 * 1024;
const PATH_MAX_LENGTH: usize = 512;

pub struct ReadFile;

impl UnaryHandler for ReadFile {
    fn tag(&self) -> &'static str {
        "projects.readFile"
    }
    fn required_scope(&self) -> &'static str {
        "filesystem:read"
    }
    fn handle<'a>(
        &'a self,
        payload: Value,
        ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Result<Value, Value>>> {
        let proc_cwd = ctx.cwd.to_string_lossy().into_owned();
        // `os.homedir()`: `$HOME`, else the passwd entry.
        let home = std::env::var("HOME")
            .ok()
            .or_else(|| std::env::home_dir().map(|h| h.to_string_lossy().into_owned()))
            .unwrap_or_default();
        async move {
            let r =
                tokio::task::spawn_blocking(move || read_file(&payload, &proc_cwd, &home)).await;
            Some(r.expect("read_file does not panic"))
        }
        .boxed()
    }
}

/// The handler body. `proc_cwd` is the engine's `process.cwd()`, `home` its `os.homedir()`.
pub fn read_file(payload: &Value, proc_cwd: &str, home: &str) -> Result<Value, Value> {
    let input = decode(payload)?;
    let target = resolve_target(&input, proc_cwd, home).map_err(|f| error(&input, f))?;
    read_target(&input, target).map_err(|f| error(&input, f))
}

/// The decoded `ProjectReadFileInput` (strings trimmed, as `TrimmedNonEmptyString` decodes).
struct Input {
    cwd: String,
    rel: String,
    allow_missing: bool,
}

/// shortcut: Node answers an undecodable payload with a `Die` carrying the schema error text;
/// the seam can only send `Fail`, so this differs from Node for malformed clients only.
fn decode(p: &Value) -> Result<Input, Value> {
    let bad = |m: &str| json!({"_tag": "ProjectReadFileError", "message": m});
    let text = |k: &str| match p.get(k).and_then(Value::as_str).map(js_trim) {
        Some(s) if !s.is_empty() => Ok(s.to_owned()),
        _ => Err(bad(&format!("invalid {k}"))),
    };
    let (cwd, rel) = (text("cwd")?, text("relativePath")?);
    if rel.encode_utf16().count() > PATH_MAX_LENGTH {
        return Err(bad("invalid relativePath"));
    }
    let allow_missing = match p.get("allowMissing") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(bad("invalid allowMissing")),
    };
    Ok(Input {
        cwd,
        rel,
        allow_missing,
    })
}

/// A failure before the outer `ProjectReadFileError` wraps it.
enum Fail {
    OutsideRoot,
    Escape {
        root: String,
        resolved: String,
    },
    NotFile(String),
    Binary(String),
    Op {
        op: &'static str,
        resolved: String,
        at: String,
        /// The Node `SystemError` message.
        cause: String,
    },
}

/// `Some(real path)` to read; `None` for an absent optional file.
struct Target {
    rel: String,
    real: Option<String>,
}

fn resolve_target(i: &Input, proc_cwd: &str, home: &str) -> Result<Target, Fail> {
    let requested = &i.rel;
    let host = match requested.strip_prefix("~/") {
        Some(rest) => join(home, rest),
        None => requested.clone(),
    };
    // `isNetworkPath`: Windows would sign in to the host, so it gets the root check.
    let network = host
        .bytes()
        .take_while(|b| matches!(b, b'/' | b'\\'))
        .count()
        >= 2;
    if network {
        let rel = relative(proc_cwd, &i.cwd, &resolve(proc_cwd, &[&host]));
        if !(rel.is_empty() || (rel != ".." && !rel.starts_with("../") && !rel.starts_with('/'))) {
            return Err(Fail::OutsideRoot);
        }
    }
    if host.starts_with('/') {
        let abs = match network {
            true => resolve(proc_cwd, &[&host]),
            false => host,
        };
        let real = match realpath(&abs) {
            Ok(r) => Some(r),
            Err(e) if i.allow_missing && is_enoent(&e) => None,
            Err(e) => {
                return Err(op(
                    "realpath-target",
                    &abs,
                    &abs,
                    &e,
                    "realpath",
                    Some(&abs),
                ));
            }
        };
        return Ok(Target {
            rel: requested.clone(),
            real,
        });
    }

    // `resolveRelativePathWithinRoot`.
    let target_abs = resolve(proc_cwd, &[&i.cwd, requested]);
    let rel = relative(proc_cwd, &i.cwd, &target_abs);
    if rel.is_empty() || rel == "." || rel == ".." || rel.starts_with("../") || rel.starts_with('/')
    {
        return Err(Fail::OutsideRoot);
    }
    let root = resolve(proc_cwd, &[&i.cwd]);
    let real_root = realpath(&root).map_err(|e| {
        op(
            "realpath-workspace-root",
            &target_abs,
            &i.cwd,
            &e,
            "realpath",
            Some(&root),
        )
    })?;
    // Missing reads resolve the nearest existing ancestor; an existing entry that cannot
    // resolve (a dangling link) is an error, not absence.
    let mut candidate = target_abs.clone();
    let (real_target, exists) = loop {
        match realpath(&candidate) {
            Ok(r) => {
                let rest = relative(proc_cwd, &candidate, &target_abs);
                break (join(&r, &rest), candidate == target_abs);
            }
            Err(e) => {
                let fail = |e: &io::Error, sys, p: &str| {
                    op("realpath-target", &target_abs, &target_abs, e, sys, Some(p))
                };
                if !i.allow_missing || !is_enoent(&e) {
                    return Err(fail(&e, "realpath", &candidate));
                }
                let present = match fs::symlink_metadata(&candidate) {
                    Ok(_) => true,
                    Err(l) if is_enoent(&l) => false,
                    Err(l) => return Err(fail(&l, "lstat", &candidate)),
                };
                let parent = dirname(&candidate);
                if present || parent == candidate {
                    return Err(fail(&e, "realpath", &candidate));
                }
                candidate = parent;
            }
        }
    };
    // `isInsideRealRoot`.
    let inside = relative(proc_cwd, &real_root, &real_target);
    if inside == ".." || inside.starts_with("../") || inside.starts_with('/') {
        return Err(Fail::Escape {
            root: real_root,
            resolved: real_target,
        });
    }
    Ok(Target {
        rel,
        real: exists.then_some(real_target),
    })
}

fn read_target(i: &Input, t: Target) -> Result<Value, Fail> {
    let absent = || {
        json!({"relativePath": js_trim(&t.rel), "contents": "", "byteLength": 0,
               "truncated": false, "exists": false})
    };
    let Some(real) = t.real.clone() else {
        return Ok(absent());
    };
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    // Non-blocking so a FIFO cannot hang the open; the stat below rejects it.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, libc::O_NONBLOCK);
    let mut file = match opts.open(&real) {
        Ok(f) => f,
        Err(e) if i.allow_missing && is_enoent(&e) => return Ok(absent()),
        Err(e) => return Err(op("open", &real, &real, &e, "open", Some(&real))),
    };
    let meta = file
        .metadata()
        .map_err(|e| op("stat", &real, &real, &e, "fstat", None))?;
    if !meta.is_file() {
        return Err(Fail::NotFile(real));
    }
    let size = meta.len();
    let mut bytes = Vec::with_capacity(size.min(MAX_BYTES) as usize);
    (&mut file)
        .take(size.min(MAX_BYTES))
        .read_to_end(&mut bytes)
        .map_err(|e| op("read", &real, &real, &e, "read", None))?;
    if bytes.contains(&0) {
        return Err(Fail::Binary(real));
    }
    // `new TextDecoder("utf-8").decode`: U+FFFD per maximal invalid subpart, leading BOM dropped.
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(&text);
    Ok(
        json!({"relativePath": js_trim(&t.rel), "contents": text, "byteLength": size,
              "truncated": size > MAX_BYTES}),
    )
}

fn op(
    op: &'static str,
    resolved: &str,
    at: &str,
    e: &io::Error,
    syscall: &str,
    path: Option<&str>,
) -> Fail {
    let (code, desc) = errno(e);
    let cause = match path {
        Some(p) => format!("{code}: {desc}, {syscall} '{p}'"),
        None => format!("{code}: {desc}, {syscall}"),
    };
    Fail::Op {
        op,
        resolved: resolved.to_owned(),
        at: at.to_owned(),
        cause,
    }
}

/// The encoded `ProjectReadFileError` (schema field order; `cause` is a `Schema.Defect`, which
/// encodes an `Error` as `{name, message, cause?}`).
fn error(i: &Input, f: Fail) -> Value {
    let (cwd, rel) = (&i.cwd, &i.rel);
    let mut e = Map::new();
    let mut put = |k: &str, v: &str| e.insert(k.into(), Value::String(js_trim(v).into()));
    put("_tag", "ProjectReadFileError");
    put("cwd", cwd);
    put("relativePath", rel);
    let cause = match &f {
        Fail::OutsideRoot => {
            put("failure", "workspace_path_outside_root");
            defect(
                "WorkspacePathOutsideRootError",
                format!("Workspace file path must be relative to the project root: {rel}"),
            )
        }
        Fail::Escape { root, resolved } => {
            put("failure", "resolved_path_outside_root");
            put("resolvedPath", resolved);
            put("resolvedWorkspaceRoot", root);
            defect(
                "WorkspaceFilePathEscapeError",
                format!(
                    "Workspace file '{rel}' resolves outside workspace root '{cwd}': {resolved}"
                ),
            )
        }
        Fail::NotFile(resolved) => {
            put("failure", "path_not_file");
            put("resolvedPath", resolved);
            defect(
                "WorkspacePathNotFileError",
                format!("Workspace path '{rel}' in '{cwd}' is not a file: {resolved}"),
            )
        }
        Fail::Binary(resolved) => {
            put("failure", "binary_file");
            put("resolvedPath", resolved);
            defect(
                "WorkspaceBinaryFileError",
                format!(
                    "Workspace file '{rel}' in '{cwd}' is binary and cannot be previewed as text."
                ),
            )
        }
        Fail::Op {
            op,
            resolved,
            at,
            cause,
        } => {
            put("failure", "operation_failed");
            put("resolvedPath", resolved);
            put("operation", op);
            put("operationPath", at);
            let mut d = defect(
                "WorkspaceFileSystemOperationError",
                format!(
                    "Workspace file operation '{op}' failed at '{at}' for resolved path '{resolved}' (requested as '{rel}' in '{cwd}')."
                ),
            );
            d["cause"] = defect("Error", cause.clone());
            d
        }
    };
    put(
        "message",
        &format!("Failed to read workspace file '{rel}' in '{cwd}'."),
    );
    e.insert("cause".into(), cause);
    Value::Object(e)
}

fn defect(name: &str, message: String) -> Value {
    json!({"name": name, "message": message})
}

fn realpath(p: &str) -> io::Result<String> {
    fs::canonicalize(p).map(|r| r.to_string_lossy().into_owned())
}

fn is_enoent(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
}

/// libuv's code name and `uv_strerror` text, as in Node's `SystemError` message.
fn errno(e: &io::Error) -> (&'static str, &'static str) {
    #[cfg(unix)]
    if let Some(n) = e.raw_os_error() {
        let known = [
            (libc::ENOENT, "ENOENT", "no such file or directory"),
            (libc::ENOTDIR, "ENOTDIR", "not a directory"),
            (libc::EACCES, "EACCES", "permission denied"),
            (libc::EPERM, "EPERM", "operation not permitted"),
            (libc::ELOOP, "ELOOP", "too many symbolic links encountered"),
            (libc::ENAMETOOLONG, "ENAMETOOLONG", "name too long"),
            (libc::EISDIR, "EISDIR", "illegal operation on a directory"),
            (libc::EIO, "EIO", "i/o error"),
            (libc::EMFILE, "EMFILE", "too many open files"),
            (libc::ENFILE, "ENFILE", "file table overflow"),
            (libc::ENXIO, "ENXIO", "no such device or address"),
            (libc::EAGAIN, "EAGAIN", "resource temporarily unavailable"),
            (libc::EBADF, "EBADF", "bad file descriptor"),
            (libc::EINVAL, "EINVAL", "invalid argument"),
            (libc::ENODEV, "ENODEV", "no such device"),
            (
                libc::EOVERFLOW,
                "EOVERFLOW",
                "value too large for defined data type",
            ),
            (libc::EBUSY, "EBUSY", "resource busy or locked"),
            (libc::ENOMEM, "ENOMEM", "not enough memory"),
            (libc::ETIMEDOUT, "ETIMEDOUT", "connection timed out"),
        ];
        if let Some(&(_, c, d)) = known.iter().find(|k| k.0 == n) {
            return (c, d);
        }
    }
    // shortcut: errnos outside the table spell differently from Node; extend when one shows up.
    let _ = e;
    ("UNKNOWN", "unknown error")
}

/// `String.prototype.trim`: JS whitespace includes U+FEFF and excludes U+0085.
fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{FEFF}')
}

/// `path.posix.normalize`.
fn normalize(p: &str) -> String {
    let abs = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." if out.last().is_some_and(|s| *s != "..") => drop(out.pop()),
            ".." if abs => {}
            s => out.push(s),
        }
    }
    let mut s = out.join("/");
    if s.is_empty() && !abs {
        s.push('.');
    }
    if p.ends_with('/') && !(s.is_empty() && abs) {
        s.push('/');
    }
    if abs { format!("/{s}") } else { s }
}

/// `path.posix.resolve(...parts)` with `proc_cwd` as `process.cwd()`.
fn resolve(proc_cwd: &str, parts: &[&str]) -> String {
    let mut acc = String::new();
    for p in parts.iter().rev().copied().chain([proc_cwd]) {
        if p.is_empty() {
            continue;
        }
        acc = if acc.is_empty() {
            p.to_owned()
        } else {
            format!("{p}/{acc}")
        };
        if p.starts_with('/') {
            break;
        }
    }
    let n = normalize(&acc);
    match n.strip_suffix('/') {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => n,
    }
}

/// `path.posix.relative(from, to)`.
fn relative(proc_cwd: &str, from: &str, to: &str) -> String {
    let (f, t) = (resolve(proc_cwd, &[from]), resolve(proc_cwd, &[to]));
    let fs: Vec<_> = f.split('/').filter(|s| !s.is_empty()).collect();
    let ts: Vec<_> = t.split('/').filter(|s| !s.is_empty()).collect();
    let common = fs.iter().zip(&ts).take_while(|(a, b)| a == b).count();
    let mut out = vec![".."; fs.len() - common];
    out.extend(&ts[common..]);
    out.join("/")
}

/// `path.posix.join(a, b)`.
fn join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => ".".into(),
        (_, true) => normalize(a),
        (true, _) => normalize(b),
        _ => normalize(&format!("{a}/{b}")),
    }
}

/// `path.posix.dirname` of an absolute, normalized path.
fn dirname(p: &str) -> String {
    match p.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => p[..i].into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A temp tree: `<root>/ws` (the workspace) and `<root>/out`; removed on drop.
    struct Tmp {
        root: PathBuf,
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    impl Tmp {
        fn new(name: &str) -> Tmp {
            let root =
                std::env::temp_dir().join(format!("vekrel-rf-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("ws/sub")).unwrap();
            fs::create_dir_all(root.join("out")).unwrap();
            fs::write(root.join("ws/small.txt"), "hello\n").unwrap();
            fs::write(root.join("out/secret.txt"), "top secret\n").unwrap();
            Tmp { root }
        }
        fn p(&self, rel: &str) -> String {
            self.root.join(rel).to_string_lossy().into_owned()
        }
        /// The real path (temp dirs sit behind symlinks on macOS).
        fn real(&self, rel: &str) -> String {
            realpath(&self.p(rel)).unwrap()
        }
        fn write(&self, rel: &str, bytes: &[u8]) {
            fs::write(self.root.join(rel), bytes).unwrap();
        }
        fn read(&self, rel: &str, allow: Option<bool>) -> Result<String, String> {
            let mut p = json!({"cwd": self.p("ws"), "relativePath": rel});
            if let Some(a) = allow {
                p["allowMissing"] = json!(a);
            }
            self.read_payload(&p)
        }
        fn read_payload(&self, p: &Value) -> Result<String, String> {
            read_file(p, &self.p("ws"), &self.p("home"))
                .map(|v| v.to_string())
                .map_err(|v| v.to_string())
        }
    }

    #[test]
    fn missing_with_allow_missing_is_the_absent_shape() {
        let t = Tmp::new("absent");
        let absent = |r: &str| {
            format!(
                r#"{{"relativePath":"{r}","contents":"","byteLength":0,"truncated":false,"exists":false}}"#
            )
        };
        assert_eq!(t.read("t3.json", Some(true)).unwrap(), absent("t3.json"));
        assert_eq!(
            t.read("a/b/c.txt", Some(true)).unwrap(),
            absent("a/b/c.txt")
        );
        let abs = t.p("out/nope");
        assert_eq!(t.read(&abs, Some(true)).unwrap(), absent(&abs));
    }

    #[test]
    fn present_small_file_omits_exists() {
        let t = Tmp::new("small");
        let want =
            r#"{"relativePath":"small.txt","contents":"hello\n","byteLength":6,"truncated":false}"#;
        assert_eq!(t.read("small.txt", None).unwrap(), want);
        assert_eq!(t.read("small.txt", Some(true)).unwrap(), want);
        // Inputs decode trimmed; the result path is the normalized relative path.
        let p =
            json!({"cwd": format!(" {} ", t.p("ws")), "relativePath": "  ./sub/../small.txt  "});
        assert_eq!(t.read_payload(&p).unwrap(), want);
        // A relative cwd resolves against the engine's own cwd.
        let p = json!({"cwd": ".", "relativePath": "small.txt", "zzz": 1});
        assert_eq!(t.read_payload(&p).unwrap(), want);
    }

    fn contents(r: &str) -> (String, u64, bool) {
        let v: Value = serde_json::from_str(r).unwrap();
        let c = v["contents"].as_str().unwrap().to_owned();
        (c, v["byteLength"].as_u64().unwrap(), v["truncated"] == true)
    }

    #[test]
    fn large_files_truncate_to_the_first_mib_decoded_like_text_decoder() {
        let t = Tmp::new("big");
        let mib = MAX_BYTES as usize;
        // A 2-byte char split by the 1 MiB boundary decodes to one U+FFFD.
        let mut big = vec![b'a'; mib - 1];
        big.extend("é".as_bytes());
        big.extend(vec![b'b'; mib]);
        t.write("ws/big.txt", &big);
        let (c, n, trunc) = contents(&t.read("big.txt", None).unwrap());
        assert_eq!((n, trunc), (2 * MAX_BYTES + 1, true));
        assert_eq!(c, format!("{}\u{FFFD}", "a".repeat(mib - 1)));
        // So does a 4-byte char cut after two bytes.
        let mut big4 = vec![b'a'; mib - 2];
        big4.extend("😀".as_bytes());
        big4.extend(vec![b'z'; 100]);
        t.write("ws/big4.txt", &big4);
        let (c, n, trunc) = contents(&t.read("big4.txt", None).unwrap());
        assert_eq!((n, trunc), (MAX_BYTES + 102, true));
        assert_eq!(c, format!("{}\u{FFFD}", "a".repeat(mib - 2)));
        t.write("ws/exact.txt", &vec![b'c'; mib]);
        let (c, n, trunc) = contents(&t.read("exact.txt", None).unwrap());
        assert_eq!((c.len(), n, trunc), (mib, MAX_BYTES, false));
    }

    #[test]
    fn invalid_utf8_and_bom_decode_like_text_decoder() {
        let t = Tmp::new("utf8");
        t.write(
            "ws/invalid.txt",
            b"ok\xff\xfe\x80 \xc3\x28 \xe2\x82 \xf0\x9f\x98 end",
        );
        let (c, n, _) = contents(&t.read("invalid.txt", None).unwrap());
        // What Node returned for these bytes.
        assert_eq!(
            c,
            "ok\u{FFFD}\u{FFFD}\u{FFFD} \u{FFFD}( \u{FFFD} \u{FFFD} end"
        );
        assert_eq!(n, 19);
        t.write("ws/bom.txt", b"\xef\xbb\xbfhi");
        let want = r#"{"relativePath":"bom.txt","contents":"hi","byteLength":5,"truncated":false}"#;
        assert_eq!(t.read("bom.txt", None).unwrap(), want);
    }

    #[test]
    fn nul_byte_is_the_binary_file_error() {
        let t = Tmp::new("nul");
        t.write("ws/nul.bin", b"a\0b");
        let (ws, real) = (t.p("ws"), t.real("ws/nul.bin"));
        let want = format!(
            r#"{{"_tag":"ProjectReadFileError","cwd":"{ws}","relativePath":"nul.bin","failure":"binary_file","resolvedPath":"{real}","message":"Failed to read workspace file 'nul.bin' in '{ws}'.","cause":{{"name":"WorkspaceBinaryFileError","message":"Workspace file 'nul.bin' in '{ws}' is binary and cannot be previewed as text."}}}}"#
        );
        assert_eq!(t.read("nul.bin", None).unwrap_err(), want);
    }

    #[test]
    fn paths_leaving_the_root_are_outside_root_errors() {
        let t = Tmp::new("outside");
        let ws = t.p("ws");
        for rel in ["../out/secret.txt", ".", "sub/..", "//host/x"] {
            let want = format!(
                r#"{{"_tag":"ProjectReadFileError","cwd":"{ws}","relativePath":"{rel}","failure":"workspace_path_outside_root","message":"Failed to read workspace file '{rel}' in '{ws}'.","cause":{{"name":"WorkspacePathOutsideRootError","message":"Workspace file path must be relative to the project root: {rel}"}}}}"#
            );
            assert_eq!(t.read(rel, Some(true)).unwrap_err(), want, "{rel}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_out_of_the_root_are_escape_errors() {
        let t = Tmp::new("link");
        std::os::unix::fs::symlink("../out/secret.txt", t.root.join("ws/link")).unwrap();
        std::os::unix::fs::symlink("../out", t.root.join("ws/outdir")).unwrap();
        let (ws, rws) = (t.p("ws"), t.real("ws"));
        let escape = |rel: &str, resolved: &str| {
            format!(
                r#"{{"_tag":"ProjectReadFileError","cwd":"{ws}","relativePath":"{rel}","failure":"resolved_path_outside_root","resolvedPath":"{resolved}","resolvedWorkspaceRoot":"{rws}","message":"Failed to read workspace file '{rel}' in '{ws}'.","cause":{{"name":"WorkspaceFilePathEscapeError","message":"Workspace file '{rel}' resolves outside workspace root '{ws}': {resolved}"}}}}"#
            )
        };
        let secret = t.real("out/secret.txt");
        assert_eq!(t.read("link", None).unwrap_err(), escape("link", &secret));
        let nope = format!("{}/nope", t.real("out"));
        assert_eq!(
            t.read("outdir/nope", Some(true)).unwrap_err(),
            escape("outdir/nope", &nope)
        );
    }

    #[test]
    fn absolute_paths_read_anywhere_and_tilde_expands() {
        let t = Tmp::new("abs");
        let abs = t.p("out/secret.txt");
        let want = format!(
            r#"{{"relativePath":"{abs}","contents":"top secret\n","byteLength":11,"truncated":false}}"#
        );
        assert_eq!(t.read(&abs, None).unwrap(), want);
        fs::create_dir_all(t.root.join("home")).unwrap();
        t.write("home/x.txt", b"home file\n");
        let want = r#"{"relativePath":"~/x.txt","contents":"home file\n","byteLength":10,"truncated":false}"#;
        assert_eq!(t.read("~/x.txt", None).unwrap(), want);
    }

    fn op_error(ws: &str, rel: &str, op: &str, resolved: &str, at: &str, cause: &str) -> String {
        format!(
            r#"{{"_tag":"ProjectReadFileError","cwd":"{ws}","relativePath":"{rel}","failure":"operation_failed","resolvedPath":"{resolved}","operation":"{op}","operationPath":"{at}","message":"Failed to read workspace file '{rel}' in '{ws}'.","cause":{{"name":"WorkspaceFileSystemOperationError","message":"Workspace file operation '{op}' failed at '{at}' for resolved path '{resolved}' (requested as '{rel}' in '{ws}').","cause":{{"name":"Error","message":"{cause}"}}}}}}"#
        )
    }

    #[cfg(unix)]
    #[test]
    fn operation_failures_carry_node_system_error_messages() {
        let t = Tmp::new("ops");
        std::os::unix::fs::symlink("nowhere", t.root.join("ws/dangling")).unwrap();
        let ws = t.p("ws");
        let target = |r: &str| format!("{ws}/{r}");
        let realpath_err = |code: &str, p: &str| format!("{code}, realpath '{p}'");
        let enoent = "ENOENT: no such file or directory";
        for (rel, allow) in [
            ("t3.json", None),
            ("t3.json", Some(false)),
            ("dangling", Some(true)),
        ] {
            let p = target(rel);
            let want = op_error(
                &ws,
                rel,
                "realpath-target",
                &p,
                &p,
                &realpath_err(enoent, &p),
            );
            assert_eq!(t.read(rel, allow).unwrap_err(), want, "{rel}");
        }
        let p = target("small.txt/x");
        let cause = realpath_err("ENOTDIR: not a directory", &p);
        let want = op_error(&ws, "small.txt/x", "realpath-target", &p, &p, &cause);
        assert_eq!(t.read("small.txt/x", Some(true)).unwrap_err(), want);
        let abs = t.p("out/nope");
        let want = op_error(
            &ws,
            &abs,
            "realpath-target",
            &abs,
            &abs,
            &realpath_err(enoent, &abs),
        );
        assert_eq!(t.read(&abs, None).unwrap_err(), want);
        // A missing workspace root.
        let cwd = t.p("nope");
        let p = json!({"cwd": cwd, "relativePath": "x.txt"});
        let want = op_error(
            &cwd,
            "x.txt",
            "realpath-workspace-root",
            &format!("{cwd}/x.txt"),
            &cwd,
            &realpath_err(enoent, &cwd),
        );
        assert_eq!(t.read_payload(&p).unwrap_err(), want);
    }

    #[test]
    fn directories_are_not_files() {
        let t = Tmp::new("dir");
        let (ws, real) = (t.p("ws"), t.real("ws/sub"));
        let abs = t.p("ws/sub");
        for rel in ["sub", abs.as_str()] {
            let want = format!(
                r#"{{"_tag":"ProjectReadFileError","cwd":"{ws}","relativePath":"{rel}","failure":"path_not_file","resolvedPath":"{real}","message":"Failed to read workspace file '{rel}' in '{ws}'.","cause":{{"name":"WorkspacePathNotFileError","message":"Workspace path '{rel}' in '{ws}' is not a file: {real}"}}}}"#
            );
            assert_eq!(t.read(rel, None).unwrap_err(), want);
        }
    }

    #[test]
    fn node_path_helpers() {
        assert_eq!(resolve("/p", &["a/./b/../c/"]), "/p/a/c");
        assert_eq!(resolve("/p", &["/x", "../.."]), "/");
        assert_eq!(resolve("/p", &["//host/x"]), "/host/x");
        assert_eq!(relative("/p", "/a/b", "/a/c/d"), "../c/d");
        assert_eq!(relative("/p", "/a", "/a"), "");
        assert_eq!(join("/h", "d/"), "/h/d/");
        assert_eq!(join("/h", ""), "/h");
        assert_eq!(dirname("/a"), "/");
        assert_eq!(js_trim("\u{FEFF} a\u{85}"), "a\u{85}");
    }
}
