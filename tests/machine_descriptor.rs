//! `GET /.well-known/vekrel/machine`: bytes and key order against a golden copied from a real
//! engine reply (fixture line 2 `config.machine`, personal values replaced), the per-request
//! `agentActivityPublishing` secret read, and which engine configs Rust declines.
use axum::http::Request;
use std::path::{Path, PathBuf};
use vekrel::{
    config::EngineConfig,
    handlers::{
        HandlerCtx,
        machine_descriptor::{
            Facts, MachineDescriptor, agent_activity_publishing, descriptor_json, engine_version,
        },
    },
    http_seam::RouteHandler,
};

const GOLDEN: &str = include_str!("golden/machine_descriptor.json");

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vk-md-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn facts() -> Facts {
    Facts {
        label: "Test machine".into(),
        os: "darwin",
        arch: "arm64",
        machine: Some("laptop"),
    }
}

#[test]
fn descriptor_matches_golden_bytes_and_key_order() {
    let got = descriptor_json(
        "00000000-0000-4000-8000-000000000000",
        &facts(),
        "0.0.0-test",
        false,
    );
    assert_eq!(String::from_utf8(got).unwrap(), GOLDEN.trim_end());
}

#[test]
fn unknown_machine_kind_omits_the_key_and_publishing_flips_in_place() {
    let f = Facts {
        machine: None,
        ..facts()
    };
    let got = String::from_utf8(descriptor_json("id", &f, "1", true)).unwrap();
    assert!(got.contains(r#""platform":{"os":"darwin","arch":"arm64"},"#));
    assert!(got.contains(r#""pullRequestStackActions":true,"agentActivityPublishing":true,"projectCloneTracking":true"#));
}

#[test]
fn publishing_needs_true_flag_url_and_credential() {
    let d = tmp("secrets");
    let put = |n: &str, v: &[u8]| std::fs::write(d.join(format!("{n}.bin")), v).unwrap();
    assert!(!agent_activity_publishing(&d), "missing files");
    put("cloud-publish-agent-activity", b"true");
    put("cloud-relay-url", b"wss://relay.test");
    assert!(!agent_activity_publishing(&d), "no credential");
    put("cloud-relay-machine-credential", b"");
    assert!(!agent_activity_publishing(&d), "empty credential");
    put("cloud-relay-machine-credential", b"cred");
    assert!(agent_activity_publishing(&d));
    // TextDecoder drops a leading BOM; anything else than exactly "true" is off.
    put("cloud-publish-agent-activity", b"\xef\xbb\xbftrue");
    assert!(agent_activity_publishing(&d));
    put("cloud-publish-agent-activity", b"true\n");
    assert!(!agent_activity_publishing(&d));
    put("cloud-publish-agent-activity", b"true");
    // A read error other than NotFound turns the whole check false (`orElseSucceed`).
    std::fs::remove_file(d.join("cloud-relay-url.bin")).unwrap();
    std::fs::create_dir(d.join("cloud-relay-url.bin")).unwrap();
    assert!(!agent_activity_publishing(&d));
    std::fs::remove_dir_all(&d).unwrap();
}

fn engine(command: &str, args: &[&str]) -> EngineConfig {
    EngineConfig {
        command: command.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        port: None,
        record: false,
    }
}

fn fake_engine(root: &Path, rel: &str) -> PathBuf {
    let bin = root.join(rel);
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    std::fs::write(&bin, "").unwrap();
    std::fs::write(
        bin.parent().unwrap().parent().unwrap().join("package.json"),
        r#"{"name":"t3","version":"9.8.7"}"#,
    )
    .unwrap();
    bin
}

#[test]
fn engine_version_reads_package_json_next_to_the_bundle() {
    let d = tmp("engine");
    let bin = fake_engine(&d, "apps/server/dist/bin.mjs");
    let none = |_: &str| None;
    let v = engine_version(&engine("node", &[bin.to_str().unwrap()]), &d, none);
    assert_eq!(v.unwrap(), "9.8.7");
    // Relative to the engine's cwd, and via an absolute node path.
    let v = engine_version(
        &engine("/usr/local/bin/node", &["apps/server/dist/bin.mjs"]),
        &d,
        none,
    );
    assert_eq!(v.unwrap(), "9.8.7");
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn engine_version_declines_what_rust_cannot_reproduce() {
    let d = tmp("decline");
    let bin = fake_engine(&d, "apps/server/dist/bin.mjs");
    let bin = bin.to_str().unwrap();
    let none = |_: &str| None;
    let err = |c: &str, a: &[&str], env: &dyn Fn(&str) -> Option<String>| {
        engine_version(&engine(c, a), &d, env).unwrap_err()
    };
    assert!(err("bun", &[bin], &none).contains("node"));
    assert!(err("node", &["--inspect", bin], &none).contains("script"));
    assert!(err("node", &[bin, "--mode", "desktop"], &none).contains("--mode"));
    assert!(err("node", &["missing.mjs"], &none).contains("missing.mjs"));
    let launcher = |k: &str| (k == "VEKREL_NPM_LAUNCHER_PATH").then(|| "/x/bin/t3.mjs".to_owned());
    assert!(err("node", &[bin], &launcher).contains("VEKREL_NPM_LAUNCHER_PATH"));
    // Installs where Node reports `serverInstallation`.
    for rel in [
        "prefix/lib/node_modules/t3/dist/bin.mjs",
        "cache/_npx/abc/node_modules/t3/dist/bin.mjs",
        "cache/pnpm/dlx/abc/dist/bin.mjs",
        "home/.bun/install/cache/t3/dist/bin.mjs",
    ] {
        let b = fake_engine(&d, rel);
        assert!(
            err("node", &[b.to_str().unwrap()], &none).contains("serverInstallation"),
            "{rel}"
        );
    }
    std::fs::remove_dir_all(&d).unwrap();
}

#[tokio::test]
async fn handler_reads_machine_id_once_and_publishing_per_request() {
    let d = tmp("handler");
    let state = d.join("userdata");
    std::fs::create_dir_all(state.join("secrets")).unwrap();
    let ctx = HandlerCtx {
        cwd: d.clone(),
        state_dir: state.clone(),
        engine_port: 1,
        ..HandlerCtx::default()
    };
    let h = MachineDescriptor::new("9.8.7".into());
    let (parts, ()) = Request::get("/.well-known/vekrel/machine")
        .body(())
        .unwrap()
        .into_parts();
    // No machine-id yet: Node is still creating it, so Node answers.
    assert!(h.handle(&parts, &ctx).await.is_none());
    std::fs::write(
        state.join("machine-id"),
        " 11111111-2222-4333-8444-555555555555\n",
    )
    .unwrap();
    let r = h.handle(&parts, &ctx).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "application/json");
    let v: serde_json::Value = serde_json::from_slice(r.body()).unwrap();
    assert_eq!(v["machineId"], "11111111-2222-4333-8444-555555555555");
    assert_eq!(v["serverVersion"], "9.8.7");
    assert_eq!(v["capabilities"]["agentActivityPublishing"], false);
    // Node caches the id; the secret is re-read.
    std::fs::write(state.join("machine-id"), "changed\n").unwrap();
    for (n, val) in [
        ("cloud-publish-agent-activity", "true"),
        ("cloud-relay-url", "wss://relay.test"),
        ("cloud-relay-machine-credential", "cred"),
    ] {
        std::fs::write(state.join(format!("secrets/{n}.bin")), val).unwrap();
    }
    let v: serde_json::Value =
        serde_json::from_slice(h.handle(&parts, &ctx).await.unwrap().body()).unwrap();
    assert_eq!(v["machineId"], "11111111-2222-4333-8444-555555555555");
    assert_eq!(v["capabilities"]["agentActivityPublishing"], true);
    std::fs::remove_dir_all(&d).unwrap();
}
