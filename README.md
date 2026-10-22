<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/brand/logo-horizontal-on-dark.png">
    <img src=".github/brand/logo-horizontal-on-light.png" alt="Vekrel" width="360">
  </picture>
</p>

# Vekrel-Daemon

The Rust daemon that runs on each machine. `vekrel serve` supervises the Vekrel engine (Node) on a loopback port and fronts it on one public port.

The engine restarts with exponential backoff (1s doubling, 30s cap, reset after 60s up) if it crashes; a clean exit is not restarted. `GET /healthz` on the public port returns `{"engine":"up"|"down","restarts":N}`. The engine child gets `VEKREL_PORT`, `VEKREL_HOST=127.0.0.1`, `VEKREL_NO_BROWSER=1`.

## Config

```toml
[server]
port = 3773        # public port
[engine]
command = "node"
args = ["/abs/path/apps/server/dist/bin.mjs"]
# port = 3783      # loopback only; defaults to server.port + 10
```

## Run

```bash
cargo run -- serve --config vekrel.toml [--record]
```

## Running with the reference engine

Build the engine bundle and a web UI, then smoke the front door:

```bash
(cd ../Vekrel-Engine && pnpm --filter vekrel-engine build:bundle)
(cd ../Vekrel-Web && pnpm --filter @vekrel/web build)
scripts/smoke.sh ../Vekrel-Engine ../Vekrel-Web   # or ENGINE_DIR=... WEB_DIR=... PORT=3779
```

The script copies `Vekrel-Web/apps/web/dist` into the engine, starts `vekrel serve --record` with a temporary `VEKREL_HOME`, checks `/healthz` and `/.well-known/vekrel/machine` through the public port, then stops the daemon and deletes the temporary state.

For a browser session, run `vekrel serve` yourself with a config like the one in the script. The engine logs a pairing URL with its own loopback port (`public + 10`). Replace that port with the public port before you open it so the browser goes through the proxy. With `--record`, frames are written to `$VEKREL_HOME/recordings/`. Those files contain session tokens, so never commit them.

## Shadow auth

Every request, including the `/ws` upgrade, goes through an observe-only check of the engine's session credential: any `t3_session*` cookie or an `Authorization: Bearer|DPoP` token. The daemon verifies the HMAC with `<VEKREL_HOME>/userdata/secrets/server-signing-key.bin`, then checks expiry and the `auth_sessions` row in `<VEKREL_HOME>/userdata/statev2.sqlite`, opened read-only. The DPoP proof itself is not checked. The outcome goes into a request extension, and anything other than `Verified` or `NoCredential` is logged as a `shadow auth` warning with the path (never the token). It never blocks or changes a request; the engine still decides.
