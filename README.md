[![Built with Claude Code](https://img.shields.io/badge/Built_with-Claude_Code-6B57FF?logo=claude&logoColor=white)](https://claude.ai/code)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# dockhand-mcp

FastMCP Python MCP server wrapping the [Dockhand](https://github.com/Finsys/dockhand) REST API.

Gives an AI agent structured access to Docker container and stack management on a Dockhand-managed host: list containers and stacks, perform lifecycle actions, check for image updates, pull and recreate containers, and run CVE scans.

## Tool Reference

| Tool | Description |
|------|-------------|
| `get_health` | Dockhand health status and timestamp |
| `list_containers` | All containers: name, image, status, environment |
| `list_stacks` | All Compose stacks: name, status, container count |
| `list_images` | All images: id, tags, size, created |
| `list_volumes` | All volumes: name, driver, mountpoint, labels |
| `list_networks` | All networks: name, driver, scope, attached containers |
| `get_host_info` | Docker host: hostname, IP, CPU, memory, uptime |
| `inspect_container` | Full container config — **secret-shaped env vars redacted**, see [Secrets](#secrets-in-inspect_container) |
| `get_container_logs` | Combined stdout/stderr, `tail` bounded to 100 by default |
| `get_container_stats` | One-shot CPU / memory / network / block-IO snapshot |
| `get_stack_compose` | A stack's compose content and resolved compose/env paths |
| `get_pending_updates` | Containers with an image update available, from the last check |
| `container_action` | start / stop / restart / pause / unpause / remove a container |
| `stack_action` | start / stop / restart / deploy a stack |
| `check_updates` | Run an image update check across all containers (synchronous) |
| `update_container` | Re-pull a container's image and recreate it in place |
| `scan_image` | Trivy/Grype CVE scan by image name |
| `get_activity` | Recent Dockhand operations log |

All tools except `get_health` and `get_activity` accept an optional `environment_id`.
Dockhand exposes 257 routes; this server wraps the read and lifecycle subset above.
Write operations beyond the lifecycle actions — `exec`, `prune`, volume clone, image
delete, batch — are deliberately not wrapped.

## Container Actions

`container_action` dispatches to these Dockhand endpoints:

| Action | HTTP | Path |
|--------|------|------|
| `start` | POST | `/api/containers/{id}/start` |
| `stop` | POST | `/api/containers/{id}/stop` |
| `restart` | POST | `/api/containers/{id}/restart` |
| `pause` | POST | `/api/containers/{id}/pause` |
| `unpause` | POST | `/api/containers/{id}/unpause` |
| `remove` | DELETE | `/api/containers/{id}` |

## Stack Actions

`stack_action` dispatches to these paths:

| Action | HTTP | Path |
|--------|------|------|
| `start` | POST | `/api/stacks/{name}/start` |
| `stop` | POST | `/api/stacks/{name}/stop` |
| `restart` | POST | `/api/stacks/{name}/restart` |
| `deploy` | POST | `/api/stacks/{name}/deploy` |

`deploy` sends a JSON body `{"pull": …, "build": …, "forceRecreate": …}`; the other stack
actions send no body at all.

Those three are exposed as arguments, defaulting to `pull=True`, `build=False`,
`force_recreate=False` — the values the tool previously hardcoded:

```python
stack_action("searxng", "deploy")  # compose up -d --pull always
stack_action("searxng", "deploy", pull=False)  # compose up -d
```

`pull=True` becomes `--pull always`, which re-resolves every image and can recreate
services you did not intend to touch. `pull=False` gives a plain `docker compose up -d`,
which recreates only services whose resolved config actually changed.

Passing any of the three to `start`/`stop`/`restart` is an error rather than a silent
no-op — those routes send no body, so Dockhand would never receive the flag.

## Environments

Every Dockhand REST endpoint resolves the target environment from a `?env=<int>` query
parameter (parsed with `parseInt`). List endpoints **silently return an empty array** (HTTP
200, no error) when it is absent, and action jobs fail asynchronously with
`No environment specified`. To avoid that failure mode, every list and action tool resolves
the environment as:

```
explicit environment_id argument  →  DOCKHAND_DEFAULT_ENV  →  clear DockhandConfigError
```

Every tool except `get_health` and `get_activity` accepts an optional `environment_id`.
`get_pending_updates` is the one route where Dockhand documents `env` as **required**
rather than optional. In practice set
`DOCKHAND_DEFAULT_ENV` once (see [Getting the Environment ID](#getting-the-environment-id))
and omit the argument.

## Asynchronous Actions

Only some Dockhand routes are asynchronous, and the split is not the intuitive one. Derived
from the v1.0.46 OpenAPI spec, `jobId` is documented on exactly six routes; of the ones this
server calls, only **`stack_action` with `start` or `stop`** returns one.

Those poll `GET /api/jobs/{jobId}` to completion and return the terminal result:

```json
{ "jobId": "…", "success": true,  "output": " Container searxng Started \n" }
{ "jobId": "…", "success": false, "error":  "Failed to restart compose stack" }
```

So a returned `success: false` is a real failure, not a queued job you have to chase down.

Everything else answers directly and is **not** polled — including `stack_action("…",
"deploy")`, `update_container`, and `check_updates`. `check_updates` in particular returns
its final result rather than a job handle, because the route offers a `text/event-stream`
feed *"or, with `Accept: application/json`, the final result as plain JSON"*, and this
client sets that header on every request. Expect it to be slow: it contacts a registry per
image.

## Update Workflow

To update a container to its latest image:

```
1. check_updates()
   → contacts a registry per image and returns {total, updatesFound, results}

2. get_pending_updates()
   → reads the result back later without re-running the check

3. scan_image("nginx:latest")
   → review CVE count before pulling

4. update_container(container_id)
   → re-pulls the image and recreates the container in place
```

`update_container` posts to `/api/containers/batch-update`, which inspects the container
server-side, pulls its image and recreates it with full Config/HostConfig passthrough. It
does **not** run `docker compose`; a compose-managed container is recreated through the
Docker API directly. Verified against Dockhand v1.0.46: this does not orphan a container
from its compose project — the compose labels and config-hash survive intact, and a
subsequent `docker compose up -d --dry-run` reports no wanted change.

Two return shapes are worth handling:

```json
{ "success": true, "containerId": "…", "containerName": "nginx" }
{ "success": true, "skipped": true, "reason": "Skipped - dockhand.update=false label" }
```

A container labelled `dockhand.update=false` is reported as a **skip**, not a plain
success. The returned `containerId` on a real update is the **new** container's id, since
the container is destroyed and recreated.

For a **digest-pinned** image — which forge uses widely — this re-pulls the same digest and
recreates. That is a recreate, not an upgrade: change the pin first if you want a new
version.

## Known Limitations

Three things this server cannot do, none of which are fixable in this repo.

**Stacks whose `env_file` lives outside `~/docker` cannot be deployed through Dockhand at
all.** The Dockhand container has no mount for such paths — `/home/ted/.secrets` being the
common case — so it cannot resolve the file. No code change here helps; it needs a mount on
the Dockhand container. Use `docker compose up -d` directly for those stacks.

**`deploy` is whole-stack — there is no per-service scoping.** `POST /api/stacks/{name}/deploy`
accepts only `{build, forceRecreate, pull}` and has no service parameter. Dockhand's compose
runner threads a service name internally, but the route never passes one, so this is an
upstream feature request rather than a local gap. When you need single-service scope, run
`docker compose up -d <service>` directly.

**`inspect_container` output is sensitive even after redaction.** See below.

## Secrets in `inspect_container`

`inspect_container` calls `GET /api/containers/{id}`, never `GET /api/containers/{id}/inspect`.
The latter returns the raw Docker inspect payload and is deliberately never wrapped; a test
asserts it stays unreachable.

Dockhand documents the former as masking a compose project's secret variables to `KEY=***`.
**Do not rely on that.** Measured against a live v1.0.46 host, 322 of 322 secret-shaped
environment variables across 123 containers came back unmasked — Dockhand masks variables it
knows as a project's registered secrets, and stacks that supply environment from `env_file`
paths Dockhand cannot read have none registered.

So this server does its own redaction before returning anything: environment variables whose
**name** looks like a credential (`*_TOKEN`, `*_PASSWORD`, `*_SECRET`, `*_KEY`, `*API_KEY*`
and similar) are replaced with `***REDACTED***`, and credentials embedded in URL **values**
(`postgres://user:pass@host`) are stripped separately, since a bland `*_URL` key defeats any
name-based test.

It covers `Config.Env` and `Config.Labels`. It does **not** cover `Config.Cmd`, `Entrypoint`
or `Args` — a credential passed on a command line is still returned in the clear. Treat the
output as sensitive regardless.

`GET /api/stacks/{name}/env` and `/env/raw` return stack secrets with no masking and are not
wrapped by any tool.

`get_container_logs` carries the ordinary risk that logs contain secrets; no redaction can
find a secret in a log line, since there is no key to match on. This is the same exposure as
`docker logs`.

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `DOCKHAND_ENDPOINT` | yes | — | Base URL, e.g. `http://localhost:7777` |
| `DOCKHAND_API_TOKEN` | yes | — | Bearer token from Dockhand UI (Settings → API Tokens) |
| `DOCKHAND_DEFAULT_ENV` | **effectively yes** | — | Default Dockhand environment ID (e.g. `1`). Used by every list and action tool as the `?env=` query param when the caller doesn't pass one. Without it (and no explicit `environment_id`), those tools return a clear config error. See [Environments](#environments) |
| `MCP_TRANSPORT` | no | `stdio` | `stdio` for local dev; `http` for the long-lived PM2 service. See [Deployment](#deployment-forge-pm2) |
| `DOCKHAND_MCP_HTTP_HOST` | no | `127.0.0.1` | Bind host in `http` mode. Loopback-only — startup refuses a non-loopback host |
| `DOCKHAND_MCP_HTTP_PORT` | no | `8505` | Bind port in `http` mode |
| `DOCKHAND_MCP_HTTP_PATH` | no | `/mcp` | MCP endpoint path in `http` mode |
| `DOCKHAND_MCP_BEARER` | **yes in `http` mode** | — | Bearer token the HTTP endpoint requires (≥ 16 chars). scoped-mcp presents it as `Authorization: Bearer`. Startup refuses `http` mode without it |
| `LOG_LEVEL` | no | `INFO` | structlog verbosity |
| `LOG_FILE` | no | `/opt/appdata/dockhand-mcp/logs/dockhand-mcp.log` | Single JSON log sink. When this path is writable it is the **only** sink — stderr is not also written. If it is unwritable (or set to empty) logging falls back to stderr-only. Set it to `''` to let PM2 own the files |
| `INFLUXDB_URL` | no | — | Enables InfluxDB telemetry when set |
| `INFLUXDB_TOKEN` | no | — | InfluxDB auth token |
| `INFLUXDB_BUCKET` | no | `dockhand-mcp` | InfluxDB bucket name |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | — | Enables OTEL traces when set |
| `NATS_URL` | no | — | Enables NATS event publishing when set |
| `NATS_SUBJECT_PREFIX` | no | `dockhand` | NATS subject prefix |

## Deployment (forge, PM2)

dockhand-mcp runs as a **single long-lived HTTP service** under PM2, bound to
`127.0.0.1:8505/mcp` and fronted by scoped-mcp via `url:` (the memsearch-mcp pattern).
Running it as a persistent process — rather than a per-turn stdio subprocess — is what lets
its OTel/InfluxDB/NATS telemetry actually flush and centralizes logs under `pm2 logs`.

```bash
# Clone
cd ~/repos/personal
git clone <repo-url> dockhand-mcp

# Install
cd dockhand-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Secrets in ~/.secrets/forge.env (injected via --env-file, never in the repo):
#   DOCKHAND_API_TOKEN   — Dockhand API token (UI: Settings → API Tokens)
#   DOCKHAND_MCP_BEARER  — token scoped-mcp presents to THIS endpoint (>= 16 chars).
#                          Generate: python3 -c "import secrets; print(secrets.token_hex(32))"
#   OTEL_EXPORTER_OTLP_ENDPOINT / INFLUXDB_URL / INFLUXDB_TOKEN / NATS_URL — telemetry (optional)

# Start (ecosystem.config.js sets MCP_TRANSPORT=http and binds 127.0.0.1:8505)
pm2 start ecosystem.config.js --env-file ~/.secrets/forge.env
pm2 save

# Verify: listening loopback-only, unauth rejected, bearer accepted
ss -tlnp | grep 127.0.0.1:8505
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8505/mcp   # 401
```

**scoped-mcp cutover** (sysadmin) — point the manifest at the HTTP service instead of spawning
a subprocess:

```yaml
dockhand-mcp:
  type: mcp_proxy
  config:
    url: http://localhost:8505/mcp
    headers:
      Authorization: "Bearer ${DOCKHAND_MCP_BEARER}"
```

HITL gating on `container_action` / `stack_action` / `update_container` is applied by scoped-mcp
by tool name and is unaffected by the transport change.

### Local development (stdio)

Leave `MCP_TRANSPORT` unset (defaults to `stdio`) to run the historical per-turn subprocess mode
directly under an MCP client — no bearer or port needed.

## Getting the Environment ID

```bash
curl -s http://localhost:7777/api/environments \
  -H "Authorization: Bearer <token>" | python3 -m json.tool
```

The forge environment has `"id": 1`. Set `DOCKHAND_DEFAULT_ENV=1` in forge.env.

## Development

```bash
pip install -e ".[dev]"
pytest
pytest --cov=dockhand_mcp
```

## Observability

| Feature | Default | Enable with |
|---------|---------|-------------|
| Structured JSON logging | **ON** | `LOG_LEVEL`, `LOG_FILE` |
| InfluxDB telemetry | off | `INFLUXDB_URL` |
| OTEL traces | off | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| NATS publishing | off | `NATS_URL` |

`httpx`, `httpcore`, `mcp` and `nats` are pinned to `WARNING` regardless of `LOG_LEVEL`, so
raising `LOG_LEVEL` to `DEBUG` gets you this service's own detail rather than its
dependencies' wire trace.

**A backend that is configured but failing warns once and is then disabled** for the life of
the process (`influx_init_failed` / `nats_init_failed`), rather than being retried on every
tool call. A backend whose env var is simply *unset* is disabled silently — that is the
intended "off" path. The warning carries the exception class only, never the URL or token:
a NATS URL embeds its own credentials.

Telemetry is best-effort and must never slow a tool down. NATS is connected with
`allow_reconnect=False` and a single retry under an overall deadline, and nats-py's default
error callback — which logs at ERROR, once per reconnect attempt — is replaced with a
warn-once one. Ten `emit_metric()` calls against two dead backends complete in ~0.1 s and
produce three log lines. `INFLUXDB_URL` is worth double-checking after any change: the
InfluxDB client constructs lazily, so a wrong URL is only reported when the first write
fails (`influx_write_failed`), not at startup.

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, every tool call is wrapped in a span named
`dockhand.tool.<name>` (via a FastMCP middleware) and exported to the collector; spans and NATS
events flush on the long-lived HTTP process and are drained cleanly on shutdown. Under the old
per-turn stdio subprocess the batch exporters were torn down before flushing, so telemetry never
arrived — running as a PM2 HTTP service is what makes it observable.

## Verified API Paths

All endpoint paths were verified against the live Dockhand instance (v1.0.27) before implementation.
Path discovery method: SvelteKit manifest extraction from the running container.
