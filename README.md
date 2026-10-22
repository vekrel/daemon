# Vekrel-Daemon

The Rust daemon that runs on each machine, supervises the Vekrel engine, and will own pairing, triggers, and the relay connection.

Today `vekreld` starts the engine, restarts it with exponential backoff (1s doubling, 30s cap, reset after 60s up) if it crashes, and exposes `GET /healthz` returning `{"engine":"up"|"down","restarts":N}`. A clean engine exit is not restarted. The engine gets its port via `VEKREL_PORT`.

## Config

```toml
[engine]
command = "node"
args = ["/abs/path/apps/server/dist/bin.mjs"]
port = 3773
[daemon]
health_port = 3774
```

## Run

```bash
cargo run -- serve --config vekreld.toml
```
