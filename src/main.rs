use clap::{Parser, Subcommand};
use std::{path::PathBuf, sync::Arc, time::Duration};
use vekrel::{
    auth::{self, shadow::AuthFiles},
    config,
    handlers::{HandlerCtx, auth_session, browse, machine_descriptor, read_file},
    http_seam::{self, RouteHandler, Seam},
    proxy_ws::{FrameTap, NoTap},
    recorder::Recorder,
    rpc_seam::{self, UnaryHandler},
    server, supervisor,
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Serve {
        #[arg(long)]
        config: PathBuf,
        /// Record WS frames to <state>/recordings (contains session tokens).
        #[arg(long)]
        record: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let Cmd::Serve { config, record } = Cli::parse().cmd;
    let mut cfg = config::load(&config)?;
    cfg.engine.record |= record;
    let engine_port = cfg.engine_port()?;
    let recorder = match cfg.engine.record {
        true => Some(Arc::new(Recorder::create(
            &state_dir()?.join("recordings"),
        )?)),
        false => None,
    };
    let tap: Arc<dyn FrameTap> = match &recorder {
        Some(r) => r.clone(),
        None => Arc::new(NoTap),
    };
    // Same layout as the engine's config.ts: <base>/userdata/{statev2.sqlite,secrets/}.
    let auth_files = match state_dir() {
        Ok(base) => {
            let userdata = base.join("userdata");
            let files = Arc::new(AuthFiles::new(
                userdata.join("secrets/server-signing-key.bin"),
                userdata.join("statev2.sqlite"),
            ));
            Some((userdata, files))
        }
        Err(e) => {
            tracing::warn!("shadow auth and Rust handlers disabled: {e}");
            None
        }
    };
    let state = Arc::new(supervisor::State::default());
    let mut seam = Seam::default();
    // Each tag's mode comes from `[rust.handlers]`, else the handler's `default_mode`.
    let ws_handlers: Vec<Arc<dyn UnaryHandler>> = vec![
        Arc::new(read_file::ReadFile),
        Arc::new(browse::Browse::from_env()),
    ];
    let mut rpc = rpc_seam::Seam::from_config(ws_handlers, &cfg.rust);
    if let Some((userdata, files)) = &auth_files {
        let ctx = HandlerCtx {
            cwd: std::env::current_dir()?,
            state_dir: userdata.clone(),
            engine_port,
            ..HandlerCtx::default()
        };
        seam = Seam::new(ctx.clone());
        rpc = rpc.with_ctx(ctx);
        let unsupported =
            auth_session::unsupported_engine(&cfg.engine.args, |k| std::env::var(k).ok());
        match (unsupported, userdata.to_str()) {
            (Some(why), _) => tracing::warn!("GET /api/auth/session handler disabled: {why}"),
            (None, None) => {
                tracing::warn!("GET /api/auth/session handler disabled: non-UTF-8 state dir")
            }
            (None, Some(dir)) => {
                // The supervisor pins the engine to VEKREL_HOST=127.0.0.1, so no machine id is needed.
                let desc = auth_session::Descriptor::web("127.0.0.1", engine_port, dir, "");
                let auth = Arc::new(auth_session::AuthSession::new(desc, files.clone()));
                let h: Arc<dyn RouteHandler> = auth.clone();
                let mode = cfg.rust.mode(&http_seam::key(&*h), h.default_mode());
                seam = seam.with(mode, h);
                // Without it (unsupported engine config) WS sessions are unverified: serve denies.
                rpc = rpc.with_auth(auth);
            }
        }
        let cwd = seam.ctx.cwd.clone();
        match machine_descriptor::supported_engine(&cfg.engine, &cwd, |k| std::env::var(k).ok()) {
            Err(why) => {
                tracing::warn!("GET /.well-known/vekrel/machine handler disabled: {why}")
            }
            // Off: no warmer either, so no probes run.
            Ok(())
                if cfg.rust.handlers.get("GET /.well-known/vekrel/machine")
                    == Some(&config::Mode::Off) => {}
            Ok(()) => {
                let h: Arc<dyn RouteHandler> =
                    Arc::new(machine_descriptor::MachineDescriptor::start(
                        state.clone(),
                        seam.ctx.clone(),
                        Arc::new(machine_descriptor::probe_host),
                    ));
                let mode = cfg.rust.mode(&http_seam::key(&*h), h.default_mode());
                seam = seam.with(mode, h);
            }
        }
    }
    let engine = tokio::spawn(supervisor::run(cfg.engine, engine_port, state.clone()));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", cfg.server.port)).await?;
    let mut app = server::build_with_tap(
        state.clone(),
        server::Upstream::loopback(engine_port)
            .with_public_port(cfg.server.port)
            .with_seam(seam)
            .with_rpc_seam(rpc),
        tap,
    );
    if let Some((_, files)) = auth_files {
        app = auth::shadow::apply_shared(app, files);
    }
    tokio::select! {
        r = axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()) => r?,
        _ = shutdown_signal() => tracing::info!("shutting down"),
    }
    // Sockets get 1001; the supervisor SIGTERMs the engine and SIGKILLs it after its grace.
    state.shutdown();
    // Backstop only: if this times out, dropping the runtime drops the child (kill_on_drop).
    let _ = tokio::time::timeout(supervisor::GRACE + Duration::from_secs(1), engine).await;
    if let Some(r) = recorder {
        tokio::task::spawn_blocking(move || r.close(Duration::from_secs(1))).await?;
    }
    Ok(())
}

/// The engine's `resolveBaseDir` (`os-jank.ts`): trimmed `$VEKREL_HOME` with `~` expanded, made
/// absolute and normalized like `path.resolve`, else `~/.vekrel`. The exact string matters: the
/// session cookie name hashes it.
fn state_dir() -> Result<PathBuf, &'static str> {
    let home = || {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .ok_or("neither VEKREL_HOME nor HOME is set")
    };
    let raw = match std::env::var_os("VEKREL_HOME") {
        Some(v) => v.into_string().map_err(|_| "VEKREL_HOME is not UTF-8")?,
        None => String::new(),
    };
    let raw = raw.trim();
    let p = if raw.is_empty() {
        home()?.join(".vekrel")
    } else if raw == "~" {
        home()?
    } else if let Some(rest) = raw.strip_prefix("~/").or(raw.strip_prefix("~\\")) {
        home()?.join(rest)
    } else {
        PathBuf::from(raw)
    };
    let abs = std::env::current_dir().map_or(p.clone(), |c| c.join(&p));
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            c => out.push(c),
        }
    }
    Ok(out)
}

#[cfg(unix)]
async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
