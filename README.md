<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/brand/logo-horizontal-on-dark.png">
    <img src=".github/brand/logo-horizontal-on-light.png" alt="Vekrel" width="360">
  </picture>
</p>

# Vekrel-Daemon

The Rust daemon that runs on each machine. `vekrel serve` supervises the Vekrel engine (Node) on a loopback port and fronts it on one public port.

The engine restarts with exponential backoff (1s doubling, 30s cap, reset after 60s up) if it crashes; a clean exit is not restarted. `GET /healthz` on the public port returns `{"engine":"up"|"down","restarts":N}`. The engine child gets `VEKREL_PORT`, `VEKREL_HOST=127.0.0.1`, `VEKREL_NO_BROWSER=1`, `VEKREL_ADVERTISED_ORIGIN=http://127.0.0.1:<public port>` (so printed URLs and the QR point at the daemon).

## Config

```toml
[server]
port = 3773        # public port
[engine]
command = "node"
args = ["/abs/path/apps/server/dist/bin.mjs"]
# port = 3783      # loopback only; defaults to server.port + 10
[rust.handlers]    # optional; every handler in the table below defaults to "serve"
"GET /api/auth/session" = "serve"   # off | shadow | serve
"subscribeAuthAccess" = "serve"
"GET /ws dpop" = "serve"
```

The auth writes (`POST /api/auth/pairing-token`, `/api/auth/pairing-links/revoke`, `/api/auth/browser-session`, `/oauth/token`, `/api/auth/clients/revoke`, `/api/auth/clients/revoke-others`) only `serve` while `subscribeAuthAccess` serves: Node's stream never sees Rust's writes. A write configured `serve` with the stream in `shadow` or `off` runs in `shadow`, and the daemon logs a warning at startup.

Rust handlers: in `shadow` the engine answers, and the daemon compares its own answer (status, `content-type`, body bytes after undoing the engine's `br`/`gzip`/`deflate` encoding; bodies over 1 MiB are skipped) and logs `rust shadow` with `outcome="match"` or `outcome="mismatch"` plus the first differing JSON path (never values). In `serve` the daemon answers with `x-vekrel-served-by: rust` and the engine never sees the request. Requests a handler cannot answer exactly (legacy cookie, a DPoP proof it cannot judge, unreadable key or DB, a missing `machine-id`) always go to the engine. The machine handler is disabled at startup unless the engine runs as `node <script>` from a plain checkout (no npm/npx/pnpm/bun install, no `VEKREL_NPM_LAUNCHER_PATH`), because Node adds install capabilities otherwise.

WS RPC handlers are keyed by tag (e.g. `"projects.readFile"`). In `serve` the daemon answers the `Request` itself and checks the tag's scope against the token scopes of the session on the `/ws` upgrade (cookie or Bearer). Only a session the daemon verified and found lacking the scope gets `MachineAuthorizationError`. Any session it cannot verify goes to the engine, which accepted the socket and decides (logged `deferred_unverifiable_credential`): a `wsTicket` or DPoP upgrade it declines (see the table below), a credential the daemon cannot read or verify, an unreadable signing key or DB, and every connection when the engine runs with a config the daemon cannot reproduce (dev auth, dev URL, `--mode`/`--host`/`--base-dir`/`--bootstrap-fd`, a non-UTF-8 or unresolvable state dir). A handler that panics in `serve` declines too, so the engine answers. In `shadow` the engine answers, and the daemon compares its `Exit` with the engine's. Every other frame is forwarded byte for byte. At most 64 shadow computations (HTTP and WS together) run at once, each with a 10 s limit. When the limit is full, the comparison is skipped and logged as `shadow_skipped_busy`. A handler may decline a request it cannot answer exactly: `serve` then forwards the client's request to the engine, and both log `rust handler declined` with `mode` and `outcome="declined"`. `filesystem.browse` declines every engine error, paths relative to the engine's cwd, and directories with names outside the code points where its ICU4X collation was checked against Node's `localeCompare` (e.g. Han). It is disabled when `LC_ALL`/`LC_MESSAGES`/`LANG` selects a non-English locale, a BCP-47 form other than plain `en-<region>` (extensions such as `en-u-kn-true` change Node's sort), or a POSIX `@modifier`.

### What Rust answers today

| Route / tag | Default | When it declines to Node |
|---|---|---|
| `GET /.well-known/vekrel/machine` | `serve` | Handler disabled at startup when the engine is not `node <script>` from a plain checkout (npm/npx/pnpm/bun install, `VEKREL_NPM_LAUNCHER_PATH`, `--mode`/`--host`/`--base-dir`/dev settings, unreadable `package.json`). Per request: `<VEKREL_HOME>/userdata/machine-id` missing or empty. |
| `GET /api/auth/session` | `serve` | Legacy `t3_session` cookie, a DPoP proof it cannot judge, signing key or DB unreadable, `%` in the token, non-ASCII header values, an `Origin` it cannot parse exactly. Disabled for engine configs it cannot reproduce (as above). |
| `POST /api/auth/websocket-ticket` | `serve` | Callers the auth middleware cannot verify (legacy cookie, a DPoP proof it cannot judge), `dev-auth-` sessions, an unreadable signing key. Rust signs the 5 min ticket with the engine's key, so Node's `/ws` accepts it. |
| `/ws` upgrades (`?wsTicket=`, DPoP), key `GET /ws dpop` | `serve` | A percent-encoded or repeated `wsTicket`, a DPoP proof it cannot judge (unknown `alg`, no trusted client URL, absolute-form target), a token whose claims differ from its row, `dev-auth-` sids. A ticket becomes a verified session with the session's scopes. A DPoP upgrade Rust accepts writes the replay marker and reaches Node with a Rust-issued `wsTicket` (Node behind the proxy would reject the proof's `htu`). |
| `POST /api/auth/browser-session`, `POST /oauth/token` | `serve` | In `serve`, any `subscribeAuthAccess` bypass (`auth::bypass::active`: Tailscale Serve, a cloud link, unreadable secrets, an unverified `/ws`, or an open `/ws` whose `subscribeAuthAccess` went to Node, until that socket closes), so Node writes and its own stream publishes the change. A credential with no `auth_pairing_links` row (desktop bootstrap, the dev token) or a non-`one-time-token` row, a body Effect's schema rejects, the legacy cookie, a repeated `dpop` header, a DPoP proof it cannot judge or without a trusted client URL, an unreadable key, DB or secrets dir. Every decline is decided before any write. `serve` consumes the link with Node's exact conditional UPDATE (scope and `jkt` checks in the WHERE), inserts the session and revokes the replaced cookie session in one `BEGIN IMMEDIATE` transaction, and writes the DPoP replay marker first (`/oauth/token`). `shadow` is a dry run: the same WHERE as SELECTs before Node's write (the proxy waits for it), then a `rust dry run` log line compares Node's new row, token claims and consume against the prediction. Rust stores the client's own address in `client_ip_address`; Node behind the proxy stores `127.0.0.1`. |
| `projects.readFile` | `serve` | Payloads Node rejects with a `Die` (blank or missing `cwd`/`relativePath`, over 512 UTF-16 units, wrong types), errors with an errno outside its table or no OS code (e.g. a NUL in the path). A verified session without `filesystem:read` gets `MachineAuthorizationError` from Rust; an unverifiable one goes to Node. |
| `subscribeAuthAccess` (stream) | `serve` | Tailscale Serve configured (`--tailscale-serve*`, `VEKREL_TAILSCALE_SERVE`), a cloud link (`secrets/cloud-relay-url.bin`, `cloud-relay-machine-credential.bin`, `cloud-endpoint-runtime-config.bin`) or any open `/ws` whose session Rust could not verify, because `connected` then needs sockets the daemon cannot see (re-checked on every poll: mid-stream, once the client has acked the last Rust Chunk, the original request goes to Node under the same id and Node's snapshot replaces the client's state); a non-object payload; a snapshot read error (e.g. a busy DB); a row Node could not decode. Once a socket's stream goes to Node (declined or handed off), the auth writes and the clients list go to Node until that socket closes, since Node's stream never sees Rust's writes. Before such a socket's first frame reaches Node, the proxy waits until every Rust auth write already past its bypass check has committed (at most 6 s, then it forwards and logs `auth write drain timed out`), so Node's snapshot includes them; not covered: a cloud link or Tailscale Serve appearing mid-write. Snapshot from SQL plus the daemon's socket registry, then events from re-reading both lists when `PRAGMA data_version` or the registry changes (polled every 250 ms), one Chunk per Ack. `shadow` compares only the first Chunk. |
| `POST /api/auth/pairing-token`, `GET /api/auth/pairing-links`, `POST /api/auth/pairing-links/revoke` | `serve` | Callers the auth middleware cannot verify, `dev-auth-` sessions, a body Effect would reject (non-object, `null`/blank/non-string `label` or `id`, `scopes` not an array of grant scopes), a DB error or a link row Node could not decode; in `serve`, create and revoke also go to Node (before any write) while a socket may bypass the daemon or an open socket's `subscribeAuthAccess` went to Node (the same `auth::bypass::active` check), since Node's own stream only sees Node's writes. `serve` writes `auth_pairing_links` in one statement (12-char code, 5 min, as Node); `shadow` predicts without writing. |
| `GET /api/auth/clients`, `POST /api/auth/clients/revoke`, `POST /api/auth/clients/revoke-others` | `serve` | Callers the auth middleware cannot verify, `dev-auth-` sessions, a body Effect would reject, a DB error or a row Node could not decode; the list also whenever a socket may bypass the daemon (only Node's in-memory map then knows `connected`) or an open socket's `subscribeAuthAccess` went to Node (`auth::bypass::active`, like the writes); in `serve`, the revokes too (before any write), and when the route is not configured `serve`. The list is Node's (`connected` from the socket registry, expired-but-connected rows kept, `bySessionPriority` order). `serve` revokes with Node's one `UPDATE … RETURNING` (revoke-others: every unrevoked row but the caller's, expired and MCP ones included), then closes both legs of each revoked session's proxied sockets with Node's 1000 close; Node's `markDisconnected` publishes `clientRemoved`, and sockets that reach Node directly close on its 5 s row re-check. `shadow` predicts without writing. |
| `GET /api/projects` | `shadow` (cannot serve: a configured `serve` is downgraded to `shadow` with a startup warning, because Rust answers Node's cold enrichment cache, `repositoryIdentity: null` and the row's `faviconPath`, and cannot see when Node's warm cache has values; until Rust owns that cache) | Callers the auth middleware cannot verify, `dev-auth-` sessions, a DB that fails the schema gate, is busy or errors, and any live row whose decode and re-encode Rust does not reproduce exactly (text Effect would trim or reject, a legacy `provider` model selection or options object, a legacy lucide monogram, a non-ASCII monogram, unknown keys or kinds, an `auto_pull` other than 0/1). A verified session without `orchestration:read` gets Node's 403. Rows are `projection_projects` without deleted ones, in `created_at, project_id` order. `shadow` allows `updatedAt` within 2 s; a difference only where Node has enrichment and Rust `null` is a `mismatch` with `field="enrichment"` (any other difference is reported at its own path). |
| `filesystem.browse` | `serve` | Every engine error (missing parent, `ENOTDIR`, Windows or cwd-relative paths), non-UTF-8 names or names with JS-trimmable edge whitespace, any name outside the collation-checked code points (e.g. Han), `$HOME` unset, non-root locale (see above). Same scope rule as `readFile`. |
| `orchestration.searchThreads` | `shadow` | Payloads Node rejects with a `Die` (`query` trimmed outside 2..200 UTF-16 units or not a string, `limit` not an integer 1..50), a busy DB (100 ms) or any SQL error, the schema gate, a result row Node would fail or change on decode (non-text `$.text`, ids with JS-trimmable edge whitespace, invalid UTF-8), and a snippet whose UTF-16 cut splits a surrogate pair. Node's SQL verbatim on a read-only connection; scope `orchestration:read`. |
| `orchestration.getArchivedShellSnapshot` | `shadow` (cannot serve, like `GET /api/projects`: Node fills `projects[*].repositoryIdentity` from its warm enrichment cache; a configured `serve` is downgraded with a startup warning) | A payload that is not an object, a DB that fails the schema gate, is busy or errors, any shell builder decline (`payload_drift`, `decode_limit`, `item_kind_not_ported`, `not_ported` incl. `unordered_rows`), a project row Rust does not reproduce, a value serde would write unlike `JSON.stringify`. Projects, archived threads and `latestApplicationSequence` come from one read transaction. In `shadow` a differing `snapshotSequence` is `outcome="sequence_skew"` (a write landed between the reads), and an enrichment-only difference a `mismatch` with `field="enrichment"`. |

In `serve` Rust sends JSON uncompressed; the engine would brotli/gzip bodies of 1 KiB and up (the machine descriptor) when the client accepts it. Set a key to `shadow` to compare against the engine again, or `off` to leave it to Node.

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

The script copies `Vekrel-Web/apps/web/dist` into the engine, starts `vekrel serve --record` with a temporary `VEKREL_HOME`, checks `/healthz` and `/.well-known/vekrel/machine` through the public port, pairs with the engine's token and asserts that `/.well-known/vekrel/machine` and `/api/auth/session` (with the paired cookie) carry `x-vekrel-served-by: rust`, then stops the daemon and deletes the temporary state.

For a browser session, run `vekrel serve` yourself with a config like the one in the script. The daemon sets `VEKREL_ADVERTISED_ORIGIN` to its public origin, so the pairing URL and QR the engine prints already use the public port. Clients must reach the engine through the daemon: a direct engine-port connection is invisible to Rust (no Rust stream events, not `connected`, and a Rust revoke closes it only on Node's 5 s row re-check). With `--record`, frames are written to `$VEKREL_HOME/recordings/`. Those files contain session tokens, so never commit them.

## Shadow auth

Every request, including the `/ws` upgrade, goes through an observe-only check of the engine's session credential: any `t3_session*` cookie or an `Authorization: Bearer|DPoP` token. The daemon verifies the HMAC with `<VEKREL_HOME>/userdata/secrets/server-signing-key.bin`, then checks expiry and the `auth_sessions` row in `<VEKREL_HOME>/userdata/statev2.sqlite`, opened read-only. The DPoP proof itself is not checked. The outcome goes into a request extension, and anything other than `Verified` or `NoCredential` is logged as a `shadow auth` warning with the path (never the token). It never blocks or changes a request; the engine still decides.
