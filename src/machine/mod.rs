//! Host facts the engine's `ServerMachine` reports: label and machine kind.
pub mod kind;
pub mod label;

use std::{
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Runs `command args` and returns its stdout if it exits 0 within `timeout` (the engine's
/// `processRunner.run` with `timeoutBehavior: "timedOutResult"`). Injectable for tests.
pub type Run<'a> = &'a dyn Fn(&str, &[&str], Duration) -> Option<String>;
/// Reads a file as a string; `None` when missing or unreadable.
pub type ReadFile<'a> = &'a dyn Fn(&str) -> Option<String>;

/// JS WhiteSpace and LineTerminator (`trim`, `\s`): U+FEFF yes, U+0085 no, unlike `char::is_whitespace`.
pub fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{B}' | '\u{C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

/// JS `String.prototype.trim`, then non-empty.
pub fn normalize(s: &str) -> Option<&str> {
    let t = s.trim_matches(is_js_space);
    (!t.is_empty()).then_some(t)
}

/// The probe ran past its timeout (and was killed).
#[derive(Debug)]
pub struct TimedOut;

/// `Run` for real commands; `Err` on timeout so callers can tell it from a failure.
pub fn run_command(
    command: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Option<String>, TimedOut> {
    let Ok(mut child) = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return Ok(None);
    };
    let Some(mut out) = child.stdout.take() else {
        return Ok(None);
    };
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        out.read_to_end(&mut buf).map(|_| buf)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(_) => return Ok(None),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(TimedOut);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let Some(Ok(buf)) = reader.join().ok() else {
        return Ok(None);
    };
    Ok((status.code() == Some(0)).then(|| String::from_utf8_lossy(&buf).into_owned()))
}

pub fn read_file(path: &str) -> Option<String> {
    std::fs::read(path)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// `os.hostname()`.
#[cfg(unix)]
pub fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

// shortcut: no hostname off unix, so the label falls back to the cwd; port when Windows matters.
#[cfg(not(unix))]
pub fn hostname() -> Option<String> {
    None
}
