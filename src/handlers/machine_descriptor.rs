//! `GET /.well-known/vekrel/machine`, byte-compatible with the engine's `ServerMachine`.
use super::HandlerCtx;
use crate::{config::EngineConfig, http_seam::RouteHandler};
use axum::{
    body::Bytes,
    http::{Method, Response, header, request::Parts},
};
use futures_util::{FutureExt, future::BoxFuture};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::{
    path::Path,
    sync::{Arc, OnceLock},
};

/// What the engine probes once at startup (`ServerMachine.make`).
#[derive(Debug, Clone)]
pub struct Facts {
    pub label: String,
    /// `platformOs(process.platform)`.
    pub os: &'static str,
    /// `platformArch(process.arch)`.
    pub arch: &'static str,
    pub machine: Option<&'static str>,
}

/// The descriptor bytes as Node encodes them (`ExecutionMachineDescriptor` schema order), for an
/// engine whose launcher mode adds no optional capabilities.
pub fn descriptor_json(
    machine_id: &str,
    facts: &Facts,
    server_version: &str,
    agent_activity_publishing: bool,
) -> Vec<u8> {
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
        machine_id,
        label: &facts.label,
        platform: Platform {
            os: facts.os,
            arch: facts.arch,
            machine: facts.machine,
        },
        server_version,
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
    platform: Platform,
    server_version: &'a str,
    orchestration_protocol_version: u32,
    capabilities: Map<String, Value>,
}

#[derive(Serialize)]
struct Platform {
    os: &'static str,
    arch: &'static str,
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

/// The engine's `packageJson.version`, or why Rust cannot reproduce this engine's descriptor.
pub fn engine_version(
    cfg: &EngineConfig,
    cwd: &Path,
    env: impl Fn(&str) -> Option<String>,
) -> Result<String, String> {
    if let Some(why) = super::auth_session::unsupported_engine(&cfg.args, &env) {
        return Err(why);
    }
    // `process.platform`/`arch` and `argv[1]` below are Node's; other runtimes may differ.
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
    if e.ends_with("/lib/node_modules/t3/dist/bin.mjs")
        || e.ends_with("/lib/node_modules/t3/bin/t3.mjs")
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
    // Node bundles `apps/server/package.json`; the bundle sits in `apps/server/dist/`.
    let pkg = entry
        .parent()
        .and_then(Path::parent)
        .map(|d| d.join("package.json"))
        .ok_or("no package.json above the engine script")?;
    let text = std::fs::read_to_string(&pkg).map_err(|e| format!("{}: {e}", pkg.display()))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", pkg.display()))?;
    match v["version"].as_str() {
        Some(s) if !s.is_empty() && s.trim() == s => Ok(s.to_owned()),
        _ => Err(format!("{}: no usable version", pkg.display())),
    }
}

pub struct MachineDescriptor {
    inner: Arc<Inner>,
}

struct Inner {
    server_version: String,
    /// Node reads it once at startup.
    machine_id: OnceLock<String>,
    /// Node probes once at startup.
    facts: OnceLock<Facts>,
}

impl MachineDescriptor {
    pub fn new(server_version: String) -> Self {
        MachineDescriptor {
            inner: Arc::new(Inner {
                server_version,
                machine_id: OnceLock::new(),
                facts: OnceLock::new(),
            }),
        }
    }
}

impl Inner {
    fn answer(&self, ctx: &HandlerCtx) -> Option<Response<Bytes>> {
        let machine_id = match self.machine_id.get() {
            Some(id) => id,
            None => {
                // Missing or empty: Node creates it during its startup, so let Node answer.
                let raw = std::fs::read_to_string(ctx.state_dir.join("machine-id")).ok()?;
                let id = crate::machine::normalize(&raw)?.to_owned();
                self.machine_id.get_or_init(|| id)
            }
        };
        let facts = self.facts.get_or_init(|| probe(&ctx.cwd));
        let body = descriptor_json(
            machine_id,
            facts,
            &self.server_version,
            agent_activity_publishing(&ctx.state_dir.join("secrets")),
        );
        Some(
            Response::builder()
                .status(200)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::VARY, "Accept-Encoding")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Bytes::from(body))
                .expect("valid response"),
        )
    }
}

/// The startup half of `ServerMachine.make`, on this host.
fn probe(cwd: &Path) -> Facts {
    use crate::machine::{hostname, kind, label, read_file, run_command};
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        os => os,
    };
    let cwd_base = cwd
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    Facts {
        label: label::resolve(
            platform,
            &run_command,
            &read_file,
            hostname().as_deref(),
            &cwd_base,
        ),
        os: match platform {
            "darwin" => "darwin",
            "linux" => "linux",
            "win32" => "windows",
            _ => "unknown",
        },
        arch: match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "x64",
            _ => "other",
        },
        machine: kind::detect(platform, &run_command, &read_file),
    }
}

impl RouteHandler for MachineDescriptor {
    fn method_path(&self) -> (Method, &'static str) {
        (Method::GET, "/.well-known/vekrel/machine")
    }

    fn handle<'a>(
        &'a self,
        _req: &'a Parts,
        ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        let (inner, ctx) = (self.inner.clone(), ctx.clone());
        async move {
            tokio::task::spawn_blocking(move || inner.answer(&ctx))
                .await
                .ok()?
        }
        .boxed()
    }
}
