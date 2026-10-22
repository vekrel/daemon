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
