//! `resolveServerMachineLabel` (`ServerMachineLabel.ts`).
use super::{ReadFile, Run, normalize};
use std::time::Duration;

/// `processRunner`'s default timeout; the label probes set none.
const TIMEOUT: Duration = Duration::from_secs(60);

/// `os` is Node's `process.platform`.
pub fn resolve(
    os: &str,
    run: Run,
    read: ReadFile,
    hostname: Option<&str>,
    cwd_base_name: &str,
) -> String {
    friendly(os, run, read)
        .or_else(|| hostname.and_then(normalize).map(str::to_owned))
        .or_else(|| normalize(cwd_base_name).map(str::to_owned))
        .unwrap_or_else(|| "Vekrel machine".to_owned())
}

/// `resolveFriendlyHostLabel`.
fn friendly(os: &str, run: Run, read: ReadFile) -> Option<String> {
    let probe =
        |c: &str, a: &[&str]| run(c, a, TIMEOUT).and_then(|o| normalize(&o).map(str::to_owned));
    match os {
        "darwin" => probe("scutil", &["--get", "ComputerName"]),
        "linux" => read("/etc/machine-info")
            .and_then(|info| {
                normalize(&info).and_then(|i| machine_info_value(i, "PRETTY_HOSTNAME"))
            })
            .or_else(|| probe("hostnamectl", &["--pretty"])),
        _ => None,
    }
}

/// `parseMachineInfoValue`: the first `key=` line decides, quotes stripped.
fn machine_info_value(raw: &str, key: &str) -> Option<String> {
    let line = raw
        .lines()
        .map(|l| normalize(l).unwrap_or(""))
        .find(|l| !l.starts_with('#') && l.strip_prefix(key).is_some_and(|r| r.starts_with('=')))?;
    let v = normalize(&line[key.len() + 1..]).unwrap_or("");
    let quoted =
        (v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\''));
    let v = if quoted {
        v.get(1..v.len() - 1).unwrap_or("")
    } else {
        v
    };
    normalize(v).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn label(
        os: &str,
        cmds: &[(&str, Option<&str>)],
        machine_info: Option<&str>,
        host: Option<&str>,
        cwd: &str,
    ) -> (String, Vec<String>) {
        let calls = RefCell::new(Vec::new());
        let run = |c: &str, a: &[&str], _: Duration| {
            calls.borrow_mut().push(format!("{c} {}", a.join(" ")));
            cmds.iter()
                .find(|(k, _)| *k == c)
                .and_then(|(_, v)| v.map(str::to_owned))
        };
        let read = |p: &str| {
            assert_eq!(p, "/etc/machine-info");
            machine_info.map(str::to_owned)
        };
        let l = resolve(os, &run, &read, host, cwd);
        (l, calls.into_inner())
    }

    #[test]
    fn darwin_uses_computer_name_first() {
        let (l, calls) = label(
            "darwin",
            &[("scutil", Some("  Test Mac \n"))],
            None,
            Some("h"),
            "c",
        );
        assert_eq!(l, "Test Mac");
        assert_eq!(calls, ["scutil --get ComputerName"]);
    }

    #[test]
    fn darwin_falls_back_to_hostname_then_cwd_then_default() {
        // scutil fails (non-zero exit is `None`) or prints only whitespace.
        assert_eq!(
            label("darwin", &[("scutil", None)], None, Some(" host-1 "), "c").0,
            "host-1"
        );
        assert_eq!(
            label(
                "darwin",
                &[("scutil", Some(" \n"))],
                None,
                Some(""),
                " proj "
            )
            .0,
            "proj"
        );
        assert_eq!(label("darwin", &[], None, None, "  ").0, "Vekrel machine");
    }

    #[test]
    fn linux_prefers_pretty_hostname_from_machine_info() {
        let info = "# comment\nCHASSIS=laptop\nPRETTY_HOSTNAME=\"Test Box\"\n";
        let (l, calls) = label(
            "linux",
            &[("hostnamectl", Some("Other"))],
            Some(info),
            Some("h"),
            "c",
        );
        assert_eq!(l, "Test Box");
        assert!(calls.is_empty());
        let single = "PRETTY_HOSTNAME='Single'\r\n";
        assert_eq!(label("linux", &[], Some(single), None, "c").0, "Single");
        assert_eq!(
            label("linux", &[], Some("PRETTY_HOSTNAME= Bare \n"), None, "c").0,
            "Bare"
        );
    }

    #[test]
    fn linux_falls_back_to_hostnamectl_then_hostname() {
        let (l, calls) = label(
            "linux",
            &[("hostnamectl", Some("Pretty\n"))],
            Some("PRETTY_HOSTNAME=\"\"\n"),
            Some("h"),
            "c",
        );
        assert_eq!(l, "Pretty");
        assert_eq!(calls, ["hostnamectl --pretty"]);
        assert_eq!(
            label("linux", &[("hostnamectl", Some(""))], None, Some("h"), "c").0,
            "h"
        );
    }

    #[test]
    fn other_platforms_skip_probes() {
        let (l, calls) = label(
            "win32",
            &[("scutil", Some("x"))],
            Some("PRETTY_HOSTNAME=x"),
            Some("win-host"),
            "c",
        );
        assert_eq!(l, "win-host");
        assert!(calls.is_empty());
    }
}
