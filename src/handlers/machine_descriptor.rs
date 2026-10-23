//! `GET /.well-known/vekrel/machine`, byte-compatible with the engine's `ServerMachine`.
use super::HandlerCtx;
use crate::{config::EngineConfig, http_seam::RouteHandler, supervisor::State};
use axum::{
    body::{Body, Bytes},
    http::{Method, Request, Response, header, request::Parts},
};
use futures_util::{FutureExt, future::BoxFuture};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};

/// The host probes Rust runs itself (`resolveServerMachineLabel`, `detectServerMachineKind`).
#[derive(Debug, Clone)]
pub struct Facts {
    pub label: String,
    pub machine: Option<&'static str>,
}

/// Runs the host probes for Node's `process.platform` in the engine's cwd. `None`: a probe timed
/// out, so Node may have seen a different answer.
pub type Probe = Arc<dyn Fn(&str, &Path) -> Option<Facts> + Send + Sync>;

/// Everything in the descriptor except `agentActivityPublishing`.
#[derive(Debug, Clone)]
pub struct Machine {
    pub machine_id: String,
    pub label: String,
    /// Copied from Node's own descriptor: `process.platform`/`arch` of the node binary.
    pub os: String,
    pub arch: String,
    pub machine: Option<&'static str>,
    /// Copied from Node's own descriptor: the version inlined into the bundle at build time.
    pub server_version: String,
}

/// The descriptor bytes as Node encodes them (`ExecutionMachineDescriptor` schema order), for an
/// engine whose launcher mode adds no optional capabilities.
pub fn descriptor_json(m: &Machine, agent_activity_publishing: bool) -> Vec<u8> {
    let mut capabilities = Map::new();
    for &k in CAPABILITIES {
        let v = match k {
            "fileAttachments" => json!({ "maxUploadBytes": PROVIDER_SEND_TURN_MAX_FILE_BYTES }),
            "agentActivityPublishing" => Value::Bool(agent_activity_publishing),
            _ => Value::Bool(true),
        };
        capabilities.insert(k.to_owned(), v);
    }
    serde_json::to_vec(&Descriptor {
        machine_id: &m.machine_id,
        label: &m.label,
        platform: Platform {
            os: &m.os,
            arch: &m.arch,
            machine: m.machine,
        },
        server_version: &m.server_version,
        orchestration_protocol_version: 2,
        capabilities,
    })
    .expect("serializable")
}

/// `contracts/chatAttachment.ts`.
const PROVIDER_SEND_TURN_MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;

/// The capabilities `ServerMachine.ts` sets, in `ExecutionMachineCapabilities` schema order
/// (`contracts/machine.ts`), not object-literal order. Absent: the launcher-mode keys
/// (`serverSelfUpdate`, `serverInstallation`, `serverSelfUpdateProgress`, `desktopAppUpdate`),
/// which `engine_version` guarantees Node leaves out, and `serverUpdateThreadContinuation`.
const CAPABILITIES: &[&str] = &[
    "repositoryIdentity",
    "connectionProbe",
    "attachmentUploads",
    "questionAttachments",
    "fileAttachments",
    "pullRequests",
    "pullRequestChecks",
    "inlineMessageContext",
    "requiredWorktreeBootstrap",
    "threadSettlement",
    "threadAutoSettlement",
    "storageCleanup",
    "storageCleanupRun",
    "databaseStorage",
    "otlpEndpointCheck",
    "projectWorktreeCleanup",
    "settledWorktreeCleanup",
    "worktreesDirectory",
    "threadAutoSettlementScope",
    "threadRestartContinuation",
    "projectSettingsOverrides",
    "projectProviderInstanceOverrides",
    "threadSnooze",
    "machineThemes",
    "usageLimitSources",
    "usagePriceOverrides",
    "usageModelAliases",
    "threadPinning",
    "threadPinReorder",
    "threadActiveReorder",
    "threadAutoSettleOptOut",
    "threadTitleRegeneration",
    "threadVisitedTracking",
    "threadPullRequestLinking",
    "serverResolvedCommandContext",
    "threadStop",
    "threadPullRequests",
    "threadPullRequestWatch",
    "pullRequestStackActions",
    "agentActivityPublishing",
    "projectCloneTracking",
    "ignoredFileListing",
    "machineIcon",
    "commandOutputStreaming",
    "serverBrowser",
];

/// `ExecutionMachineDescriptor`, fields in schema order.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor<'a> {
    machine_id: &'a str,
    label: &'a str,
    platform: Platform<'a>,
    server_version: &'a str,
    orchestration_protocol_version: u32,
    capabilities: Map<String, Value>,
}

#[derive(Serialize)]
struct Platform<'a> {
    os: &'a str,
    arch: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine: Option<&'static str>,
}

/// `readAgentActivityPublishingActive` (`cloud/config.ts`) against `<stateDir>/secrets`.
pub fn agent_activity_publishing(secrets_dir: &Path) -> bool {
    // `secrets.get`: NotFound is None; any other error fails the whole read, which gives false.
    let read = |name: &str| match std::fs::read(secrets_dir.join(format!("{name}.bin"))) {
        Ok(b) => Ok(Some(text_decode(&b))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    };
    let set = |v: Option<String>| v.is_some_and(|s| !s.is_empty());
    match (
        read("cloud-publish-agent-activity"),
        read("cloud-relay-url"),
        read("cloud-relay-machine-credential"),
    ) {
        (Ok(enabled), Ok(url), Ok(cred)) => {
            enabled.as_deref() == Some("true") && set(url) && set(cred)
        }
        _ => false,
    }
}

/// `new TextDecoder().decode(bytes)`: lossy UTF-8 with a leading BOM dropped.
fn text_decode(b: &[u8]) -> String {
    String::from_utf8_lossy(b.strip_prefix(b"\xef\xbb\xbf").unwrap_or(b)).into_owned()
}

/// Why Rust cannot reproduce this engine's descriptor, if it cannot.
pub fn supported_engine(
    cfg: &EngineConfig,
    cwd: &Path,
    env: impl Fn(&str) -> Option<String>,
) -> Result<(), String> {
    if let Some(why) = super::auth_session::unsupported_engine(&cfg.args, &env) {
        return Err(why);
    }
    // `argv[1]` below is Node's; other runtimes may differ.
    if Path::new(&cfg.command)
        .file_name()
        .is_none_or(|n| n != "node")
    {
        return Err("engine command is not node".into());
    }
    let script = match cfg.args.first() {
        Some(s) if !s.starts_with('-') => s,
        _ => return Err("first engine arg is not the script".into()),
    };
    // `resolveEntryPath` would use the launcher, which Rust does not inspect.
    if env("VEKREL_NPM_LAUNCHER_PATH").is_some_and(|v| !v.trim().is_empty()) {
        return Err("VEKREL_NPM_LAUNCHER_PATH is set".into());
    }
    let entry = std::fs::canonicalize(cwd.join(script)).map_err(|e| format!("{script}: {e}"))?;
    // `resolveServerInstallation`: these entries can make Node report `serverInstallation`.
    let e = entry.to_string_lossy().replace('\\', "/");
    if e.ends_with("/lib/node_modules/vekrel/dist/bin.mjs")
        || e.ends_with("/lib/node_modules/vekrel/bin/vekrel.mjs")
        || [
            "/_npx/",
            "/pnpm/dlx/",
            "/.pnpm/dlx/",
            "/pnpm-cache/dlx/",
            "/.bun/install/cache/",
            "/bunx-",
        ]
        .iter()
        .any(|p| e.contains(p))
    {
        return Err(format!("{e} may report serverInstallation"));
    }
    Ok(())
}

/// The generation a `Machine` was loaded for, and the `Machine`.
type Cache = Arc<Mutex<Option<(u64, Arc<Machine>)>>>;

/// Node fixes the descriptor at startup, so Rust's copy is per supervisor generation: once the
/// engine is ready, a warmer fetches Node's own descriptor (version, os/arch), re-reads the machine
/// id and runs the host probes. Until that succeeds for the current generation, Node answers.
pub struct MachineDescriptor {
    state: Arc<State>,
    cache: Cache,
}

impl MachineDescriptor {
    /// Spawns the warmer; needs a Tokio runtime.
    pub fn start(state: Arc<State>, ctx: HandlerCtx, probe: Probe) -> Self {
        let cache = Arc::new(Mutex::new(None));
        tokio::spawn(warm(state.clone(), ctx, probe, cache.clone()));
        MachineDescriptor { state, cache }
    }
}

async fn warm(state: Arc<State>, ctx: HandlerCtx, probe: Probe, cache: Cache) {
    let mut generation = state.generation_tx.subscribe();
    loop {
        let g = *generation.borrow_and_update();
        if let Some(m) = load(&state, g, &ctx, &probe).await {
            *cache.lock().unwrap() = Some((g, Arc::new(m)));
        }
        if generation.changed().await.is_err() {
            return;
        }
    }
}

/// `None` once generation `g` is over, or if a probe timed out.
async fn load(state: &State, g: u64, ctx: &HandlerCtx, probe: &Probe) -> Option<Machine> {
    let client = Client::builder(TokioExecutor::new()).build_http::<Body>();
    loop {
        if state.generation.load(Ordering::SeqCst) != g {
            return None;
        }
        if state.engine_up.load(Ordering::SeqCst)
            && let Some((server_version, os, arch)) = fetch(&client, ctx.engine_port).await
        {
            // Node created the id before it started listening.
            let id = std::fs::read_to_string(ctx.state_dir.join("machine-id")).ok();
            if let Some(machine_id) = id.as_deref().and_then(crate::machine::normalize) {
                let platform = if os == "windows" {
                    "win32".into()
                } else {
                    os.clone()
                };
                let (probe, cwd) = (probe.clone(), ctx.cwd.clone());
                let facts = tokio::task::spawn_blocking(move || probe(&platform, &cwd))
                    .await
                    .ok()??;
                return Some(Machine {
                    machine_id: machine_id.to_owned(),
                    label: facts.label,
                    os,
                    arch,
                    machine: facts.machine,
                    server_version,
                });
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Node's own descriptor over loopback (not through the seam): `(serverVersion, os, arch)`.
async fn fetch(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    port: u16,
) -> Option<(String, String, String)> {
    let req = Request::get(format!(
        "http://127.0.0.1:{port}/.well-known/vekrel/machine"
    ))
    .body(Body::empty())
    .ok()?;
    let attempt = async {
        let r = client.request(req).await.ok()?;
        if !r.status().is_success() {
            return None;
        }
        axum::body::to_bytes(Body::new(r.into_body()), 1 << 20)
            .await
            .ok()
    };
    let body = tokio::time::timeout(Duration::from_secs(5), attempt)
        .await
        .ok()??;
    let v: Value = serde_json::from_slice(&body).ok()?;
    let s = |v: &Value| v.as_str().map(str::to_owned);
    Some((
        s(&v["serverVersion"])?,
        s(&v["platform"]["os"])?,
        s(&v["platform"]["arch"])?,
    ))
}

/// The production `Probe`: the host's label and kind probes, as `ServerMachine.make` runs them.
pub fn probe_host(platform: &str, cwd: &Path) -> Option<Facts> {
    use crate::machine::{hostname, kind, label, read_file, run_command};
    let timed_out = std::cell::Cell::new(false);
    let run = |c: &str, a: &[&str], t: Duration| {
        run_command(c, a, t).unwrap_or_else(|_| {
            timed_out.set(true);
            None
        })
    };
    let cwd_base = cwd
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let facts = Facts {
        label: label::resolve(platform, &run, &read_file, hostname().as_deref(), &cwd_base),
        machine: kind::detect(platform, &run, &read_file),
    };
    (!timed_out.get()).then_some(facts)
}

impl RouteHandler for MachineDescriptor {
    fn default_mode(&self) -> crate::config::Mode {
        crate::config::Mode::Serve
    }
    fn method_path(&self) -> (Method, &'static str) {
        (Method::GET, "/.well-known/vekrel/machine")
    }

    fn handle<'a>(
        &'a self,
        _req: &'a Parts,
        ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        let g = self.state.generation.load(Ordering::SeqCst);
        let m = match &*self.cache.lock().unwrap() {
            Some((cg, m)) if *cg == g => m.clone(),
            _ => {
                // Logged like every handler's decline, so each request has an outcome line.
                tracing::info!(
                    route = "GET /.well-known/vekrel/machine",
                    why = "descriptor_not_loaded",
                    outcome = "declined",
                    "rust machine descriptor"
                );
                return async { None }.boxed();
            }
        };
        let secrets = ctx.state_dir.join("secrets");
        async move {
            let publishing =
                tokio::task::spawn_blocking(move || agent_activity_publishing(&secrets))
                    .await
                    .ok()?;
            Some(
                Response::builder()
                    .status(200)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::VARY, "Accept-Encoding")
                    .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                    .body(Bytes::from(descriptor_json(&m, publishing)))
                    .expect("valid response"),
            )
        }
        .boxed()
    }
}
