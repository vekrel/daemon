//! `GET /.well-known/vekrel/machine`: bytes and key order against a golden copied from a real
//! engine reply (fixture line 2 `config.machine`, personal values replaced), the per-request
//! `agentActivityPublishing` secret read, the per-generation cache filled from Node's own
//! descriptor, and which engine configs Rust declines.
use axum::{
    Router,
    http::{Request, request::Parts},
    routing::get,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::TcpListener;
use vekrel::{
    config::EngineConfig,
    handlers::{
        HandlerCtx,
        machine_descriptor::{
            Facts, Machine, MachineDescriptor, Probe, agent_activity_publishing, descriptor_json,
            supported_engine,
        },
    },
    http_seam::RouteHandler,
    supervisor::State,
};

const GOLDEN: &str = include_str!("golden/machine_descriptor.json");

/// The guard removes the dir on drop, including on panic.
fn tmp(name: &str) -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::Builder::new()
        .prefix(&format!("vk-md-{name}-"))
        .tempdir()
        .unwrap();
    let d = t.path().to_path_buf();
    (t, d)
}

fn machine() -> Machine {
    Machine {
        machine_id: "00000000-0000-4000-8000-000000000000".into(),
        label: "Test machine".into(),
        os: "darwin".into(),
        arch: "arm64".into(),
        machine: Some("laptop"),
        server_version: "0.0.0-test".into(),
    }
}

#[test]
fn descriptor_matches_golden_bytes_and_key_order() {
    let got = descriptor_json(&machine(), false);
    assert_eq!(String::from_utf8(got).unwrap(), GOLDEN.trim_end());
}

#[test]
fn unknown_machine_kind_omits_the_key_and_publishing_flips_in_place() {
    let m = Machine {
        machine: None,
        ..machine()
    };
    let got = String::from_utf8(descriptor_json(&m, true)).unwrap();
    assert!(got.contains(r#""platform":{"os":"darwin","arch":"arm64"},"#));
    assert!(got.contains(
        r#""pullRequestStackActions":true,"agentActivityPublishing":true,"projectCloneTracking":true"#
    ));
}

#[test]
fn publishing_needs_true_flag_url_and_credential() {
    let (_t, d) = tmp("secrets");
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
    bin
}

#[test]
fn supported_engine_declines_what_rust_cannot_reproduce() {
    let (_t, d) = tmp("decline");
    let bin = fake_engine(&d, "apps/server/dist/bin.mjs");
    let bin = bin.to_str().unwrap();
    let none = |_: &str| None;
    assert_eq!(supported_engine(&engine("node", &[bin]), &d, none), Ok(()));
    let rel = supported_engine(
        &engine("/usr/local/bin/node", &["apps/server/dist/bin.mjs"]),
        &d,
        none,
    );
    assert_eq!(rel, Ok(()));
    let err = |c: &str, a: &[&str], env: &dyn Fn(&str) -> Option<String>| {
        supported_engine(&engine(c, a), &d, env).unwrap_err()
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
}

/// A fake engine whose descriptor reply can change between "restarts".
async fn fake_node(reply: Arc<Mutex<String>>) -> u16 {
    let app = Router::new().route(
        "/.well-known/vekrel/machine",
        get(move || {
            let r = reply.lock().unwrap().clone();
            async move { r }
        }),
    );
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    port
}

fn node_reply(version: &str) -> String {
    format!(
        r#"{{"machineId":"x","label":"x","platform":{{"os":"linux","arch":"x64"}},"serverVersion":"{version}"}}"#
    )
}

struct Rig {
    _t: tempfile::TempDir,
    state: Arc<State>,
    ctx: HandlerCtx,
    reply: Arc<Mutex<String>>,
    probes: Arc<AtomicUsize>,
    h: MachineDescriptor,
    parts: Parts,
}

async fn rig(name: &str, probe_ok: bool) -> Rig {
    let (t, d) = tmp(name);
    let state_dir = d.join("userdata");
    std::fs::create_dir_all(state_dir.join("secrets")).unwrap();
    std::fs::write(
        state_dir.join("machine-id"),
        " 11111111-2222-4333-8444-555555555555\n",
    )
    .unwrap();
    let reply = Arc::new(Mutex::new(node_reply("1.0.0")));
    let ctx = HandlerCtx {
        cwd: d.clone(),
        state_dir,
        engine_port: fake_node(reply.clone()).await,
        ..HandlerCtx::default()
    };
    let state = Arc::new(State::default());
    let probes = Arc::new(AtomicUsize::new(0));
    let n = probes.clone();
    // `None`: a probe timed out.
    let probe: Probe = Arc::new(move |platform: &str, _: &Path| {
        assert_eq!(platform, "linux", "probes follow Node's platform");
        n.fetch_add(1, Ordering::SeqCst);
        probe_ok.then(|| Facts {
            label: "Probed".into(),
            machine: Some("laptop"),
        })
    });
    let h = MachineDescriptor::start(state.clone(), ctx.clone(), probe);
    let (parts, ()) = Request::get("/.well-known/vekrel/machine")
        .body(())
        .unwrap()
        .into_parts();
    Rig {
        _t: t,
        state,
        ctx,
        reply,
        probes,
        h,
        parts,
    }
}

impl Rig {
    async fn get(&self) -> Option<serde_json::Value> {
        let r = self.h.handle(&self.parts, &self.ctx).await?;
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["content-type"], "application/json");
        Some(serde_json::from_slice(r.body()).unwrap())
    }

    async fn wait(&self) -> serde_json::Value {
        for _ in 0..100 {
            if let Some(v) = self.get().await {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("handler never answered");
    }
}

#[tokio::test]
async fn none_until_nodes_descriptor_is_fetched_then_follows_each_generation() {
    let r = rig("gen", true).await;
    // Engine not ready yet: Node answers.
    assert!(r.get().await.is_none());
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(r.get().await.is_none());
    assert_eq!(r.probes.load(Ordering::SeqCst), 0);

    r.state.engine_up.store(true, Ordering::SeqCst);
    let v = r.wait().await;
    assert_eq!(v["machineId"], "11111111-2222-4333-8444-555555555555");
    assert_eq!(v["label"], "Probed");
    assert_eq!(
        v["platform"],
        serde_json::json!({"os":"linux","arch":"x64","machine":"laptop"})
    );
    assert_eq!(v["serverVersion"], "1.0.0");
    assert_eq!(v["capabilities"]["agentActivityPublishing"], false);

    // Warmed: requests never probe. The publishing secret is still re-read per request.
    for (n, val) in [
        ("cloud-publish-agent-activity", "true"),
        ("cloud-relay-url", "wss://relay.test"),
        ("cloud-relay-machine-credential", "cred"),
    ] {
        std::fs::write(r.ctx.state_dir.join(format!("secrets/{n}.bin")), val).unwrap();
    }
    for _ in 0..3 {
        let v = r.get().await.unwrap();
        assert_eq!(v["capabilities"]["agentActivityPublishing"], true);
    }
    assert_eq!(r.probes.load(Ordering::SeqCst), 1);

    // Restart: the supervisor drops engine_up, then bumps the generation.
    r.state.engine_up.store(false, Ordering::SeqCst);
    *r.reply.lock().unwrap() = node_reply("9.9.9");
    std::fs::write(
        r.ctx.state_dir.join("machine-id"),
        "22222222-2222-4333-8444-555555555555\n",
    )
    .unwrap();
    r.state.bump_generation();
    assert!(
        r.get().await.is_none(),
        "old generation's cache is not served"
    );
    r.state.engine_up.store(true, Ordering::SeqCst);
    let v = r.wait().await;
    assert_eq!(v["serverVersion"], "9.9.9");
    assert_eq!(v["machineId"], "22222222-2222-4333-8444-555555555555");
    assert_eq!(r.probes.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn probe_timeout_leaves_the_generation_to_node() {
    let r = rig("timeout", false).await;
    r.state.engine_up.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(r.probes.load(Ordering::SeqCst) >= 1);
    assert!(r.get().await.is_none());
}
