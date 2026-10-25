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
| `list_stacks` | Compose stacks, **compact by default**: status, health, counts, and each container's name/service/state. `detail=true` or `names=[...]` for full rows |
| `list_images` | All images: id, tags, size, created |
| `list_volumes` | All volumes: name, driver, mountpoint, labels |
| `list_networks` | All networks: name, driver, scope, attached containers |
| `get_host_info` | Docker host: hostname, IP, CPU, memory, uptime |
| `inspect_container` | Full container config — **secret-shaped env vars redacted**, see [Secrets](#secrets-in-inspect_container) |
| `get_container_logs` | Combined stdout/stderr, `tail` bounded to 100 by default. **Env-file dumps masked**, see [Env-File Dumps](#env-file-dumps-in-dockhands-log) |
| `get_container_stats` | One-shot CPU / memory / network / block-IO snapshot |
| `get_stack_compose` | A stack's compose content and resolved compose/env paths. Inline secret-shaped values redacted |
| `get_pending_updates` | Containers with an image update available, from the last check. Rows older than 7 days are flagged `stale` |
| `container_action` | start / stop / restart / pause / unpause / remove a container |
| `stack_action` | start / stop / restart / deploy a stack. **Requires `acknowledge_env_log=true`**, see [Stack Actions](#stack-actions) |
| `check_updates` | Run an image update check across all containers (synchronous). **Returns only rows needing attention** unless `include_all=true`. Pinned rows carry a `pin_assessment` — see [Digest-Pinned Images](#digest-pinned-images-pin_assessment) |
| `update_container` | Re-pull a container's image and recreate it in place. Accepts a name or an id |
| `scan_image` | Trivy/Grype CVE scan by image name |
| `get_activity` | Recent Dockhand operations log, filterable by container, action and date |
| `get_activity_stats` | Event totals, today's count, and counts by action (restart loops show here) |
| `get_stack_stats` | CPU / memory / network / block-IO snapshot per stack |
| `get_disk_usage` | `docker system df` totals and the ten largest images and volumes |
| `get_vulnerability_summary` | Stored scan totals by severity, plus one filtered page of findings |
| `list_stack_deploys` | A stack's deploy history: when, who, options, what changed |
| `get_stack_deploy_log` | One deploy run's compose output, masked like `get_container_logs` |
| `validate_stack` | Lint a stack's compose file (or an edit of it) with Dockhand's preflight validator |
| `get_version_notes` | Upstream release notes for the versions an update would cross |
| `list_schedules` | Dockhand's schedules: auto-updates, start/stop, git syncs, prune, backups |
| `get_schedule_executions` | Schedule run history, logs masked |
| `get_scheduled_actions` | A container's scheduled start/stop times (read only) |
| `get_auto_update_policy` | A container's auto-update setting (read only) |

Every tool except `get_health` accepts an optional `environment_id`, as an integer or a
string. Dockhand 1.0.55 exposes 285 routes; this server wraps the read and lifecycle subset
above. See [Excluded Routes](#excluded-routes) for what is deliberately not wrapped.

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

**Every action requires `acknowledge_env_log=true`.** Dockhand prints the stack's whole
`.env` file to its own stdout on all four actions (measured on 1.0.55 with a canary stack),
so every secret in it lands in `docker logs dockhand`, and in any log pipeline that ships
that container. Without the flag the call is refused before any request is made, with an
error naming the alternative: run `docker compose` for the stack directly. The flag also
puts the choice into the arguments a HITL approval prompt shows.

```python
stack_action("searxng", "deploy", acknowledge_env_log=True)  # compose up -d
stack_action("searxng", "deploy", acknowledge_env_log=True, pull=True)  # --pull always
```

`deploy`'s three body flags default to `pull=False`, `build=False`, `force_recreate=False`
(`pull` defaulted to `True` before 0.8.0). `pull=False` gives a plain `docker compose up -d`,
which recreates only services whose resolved config changed, and still pulls a digest pin
that is not present locally. `pull=True` becomes `--pull always`, which re-resolves every
image and can recreate services you did not intend to touch.

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

Every tool except `get_health` accepts an optional `environment_id`.
`get_pending_updates` is the one route where Dockhand documents `env` as **required**
rather than optional. In practice set
`DOCKHAND_DEFAULT_ENV` once (see [Getting the Environment ID](#getting-the-environment-id))
and omit the argument. A few routes treat the environment as an optional *filter*
(`get_activity`, `get_activity_stats`, `list_schedules`, `get_schedule_executions`,
`scan_image`); there, no `environment_id` means every environment.

### Pinning an instance: `DOCKHAND_ALLOWED_ENVS`

Set `DOCKHAND_ALLOWED_ENVS` to a comma-separated list of environment ids to confine an
instance to them, for example a second instance for an agent that should only reach one
remote host:

- an environment outside the list is refused before any request;
- with more than one id listed, `environment_id` is required and the default is not applied;
- the optional-filter routes above are always filtered to the pin, and schedules or
  executions from other environments (including Dockhand's own system schedules) are dropped;
- a deploy log is read only after its run's environment is checked.

Unset, behaviour is unchanged.

**This is a dockhand-mcp-side pin, not a Dockhand permission.** The Dockhand API token is
valid for every environment, so the pin is only as strong as the pinned instance's own
configuration and the isolation of its port. Run it with its own bearer on its own port,
and give the confined agent no route to the unpinned instance.

## Asynchronous Actions

Only some Dockhand routes are asynchronous, and the split is not the intuitive one. Of the
routes this server calls, only **`stack_action` with `start` or `stop`** returns a `jobId`
(the 1.0.55 spec marks it required on both). `restart` and `deploy` are documented as
Server-Sent Events streams, and with `Accept: application/json` they answer
`{success, output|error}` directly; measured on 1.0.55.

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

4. update_container("nginx")
   → re-pulls the image and recreates the container in place
```

`update_container` takes a container name, a short id or a full id. batch-update matches
full ids only, so the name is resolved with a read first; a name that does not resolve is
an error and nothing is updated. (Before 0.8.0 a name failed *after* the HITL approval.)

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

## Digest-Pinned Images: `pin_assessment`

Dockhand cannot detect updates for a digest pin. It resolves `repo@sha256:X` to `X`, so a
pinned container **always** reads `hasUpdate: false`, whether or not its tag has moved. For a
pinned row that means *Dockhand cannot tell*, not *current*. Pinned images also never show up
in `get_pending_updates`, because Dockhand only lists rows it has flagged.

The answer comes from a separate scheduled digest-pin checker, which compares each pin against
the registry (index vs platform-manifest aware) and writes a JSON report to disk. This server
reads that report and **never** contacts a registry or runs the checker itself. It only
overlays the report onto Dockhand's response:

- Every row whose image ref contains `@sha256:` gets
  `pin_assessment: {status, detail, report_generated, report_state}`.
- Floating-tag rows get no `pin_assessment` key at all.
- Dockhand's own fields (`hasUpdate`, `hasImageUpdate`, `updatesFound`, …) are passed through
  unchanged, so `updatesFound` still excludes pins.
- The top level gains
  `digest_pins: {report_state, report_generated, report_age_hours, report_reason, pinned, by_status}`.
  Every pinned row is counted in exactly one `by_status` bucket.

`status` is the report's status **verbatim**: `current`, `update`, `exempt`,
`exempt-expired`, `unresolvable`, `error`, `known-stale`, `known-stale-expired`, `drift`
(the running image differs from its compose declaration) or `undeclared`. An unrecognised
status is passed through rather than rejected. The one status this server adds is
**`not_assessed`**. It means *unknown*, never *current*, and it is used when:

| `report_state` | Why every pinned row is `not_assessed` |
|---|---|
| `missing` | No report at the configured path |
| `unreadable` | Not JSON, not an object, no `containers` list, or `generated` is missing, naive, unparseable or in the future |
| `schema_mismatch` | `schema_version` is anything other than `1` |
| `stale` | `generated` is older than `DIGEST_PIN_MAX_AGE_H` (default 30 h: a daily run plus slack). The checker deliberately leaves the old report in place when it cannot reach docker or the registry, so age is the staleness signal |

With `report_state: ok`, a single row is still `not_assessed` when the container is not in
the report, when it runs a different image from the one the report assessed (it was recreated
on one side of the report run), or when it is matched only by image ref and that ref maps to
conflicting statuses. Rows are joined by container name first and fall back to the exact
image ref.

A report problem never fails the tool. The Dockhand data always comes back.

**Schema versions.** This server reads report schema **1** only, and fails closed on any
other version. A checker change that bumps the schema (for example, a new status for a pin
whose digest no longer exists in the registry) will turn every pinned row `not_assessed` until
this reader is updated for the new version.

## Known Limitations

Four things this server cannot do, none of which are fixable in this repo.

**Dockhand logs a stack's `.env` on every stack action.** `parseEnvFileContent()` prints the
whole file, and then a "Skipped lines" summary that repeats commented-out lines and the
continuation lines of multi-line values. This happens for any stack with a `.env`, whatever
starts the action: this server, the UI or Dockhand's scheduler. This server masks it in what
it returns (see [Env-File Dumps](#env-file-dumps-in-dockhands-log)) and makes `stack_action`
require an acknowledgement, but it cannot stop Dockhand writing it. For a stack with
secrets, run `docker compose` directly.

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

So this server does its own redaction before returning anything. Matching on key names alone
proved insufficient — a security audit found `POSTGRES_PWD` and `DFLY_requirepass` returning
real passwords in the clear, and a follow-up scan of all 123 containers found four more. A
name list can only ever be current up to the last time someone tried to defeat it, so the
redaction is layered:

| Rule | Effect |
|---|---|
| Credential-shaped **key** (`*PASS*`, `*PWD*`, `*TOKEN*`, `*SECRET*`, `*_KEY*`, `*AUTH*`, …) | Redacted, unless the value cannot be a secret at all — a flag, a number, or empty |
| Any **value** that is a long opaque token | Redacted whatever the key is called — this is what catches an unpredicted name |
| Credentials in URL values (`postgres://user:pass@host`) and query strings (`?access_token=…`) | Stripped |

Values that cannot encode a credential stay readable, so config flags, ports, paths and plain
URLs remain legible. Measured against 1679 live environment variables: 443 redacted, 1236
visible, every known secret caught.

One deliberate cost: a path *to* a key, such as `TEMPORAL_TLS_KEY=/etc/temporal/tls.key`, is
redacted too. Letting the path rule run ahead of the key rule is exactly what leaked a
`WEBHOOK_SECRET` whose value was a URL.

It covers `Config.Env` and `Config.Labels`. It does **not** cover `Config.Cmd`, `Entrypoint`
or `Args` — a credential passed on a command line is still returned in the clear. Treat the
output as sensitive regardless.

`GET /api/stacks/{name}/env` and `/env/raw` return stack secrets with no masking and are not
wrapped by any tool.

## Env-File Dumps in Dockhand's Log

`get_container_logs`, `get_stack_deploy_log` and `get_schedule_executions` mask what Dockhand
prints when it parses a stack's `.env`, for **every** container, not only one named
`dockhand`. The mask keys on the text, which a container's name cannot change.

| Layer | What it catches |
|---|---|
| Block | Everything between `[Git] Raw content:` and `[Git] Total lines: N` becomes `[env file content masked by dockhand-mcp]`. This is what catches a multi-line value's continuation lines, which have no key to match on |
| Fail closed, end missing | A block whose end marker was cut off by `tail` is masked to the end of the text |
| Fail closed, start missing | An end marker with no start (the head was cut off) masks the `N` lines before it |
| Fail closed, frame changed | An unexpected line between the header and `Raw content:` starts the mask early |
| Skipped-lines summary | `[Git] Skipped lines (N): ...` is masked whole |
| Env-shaped lines | Anything else shaped `KEY=`, `# KEY=`, `export KEY=` (dot and dash keys included) gets the value-shape redaction above. A quoted value that never closes is masked to the end |

`masked_lines` in the response counts what was removed. A secret in free text, with no
`KEY=` in front of it, has nothing to match on and is returned as-is. Treat log output as
sensitive.

`get_stack_compose` applies the value-shape redaction to values written inline in the
compose file (`- KEY=value`, `KEY: value`) and reports `redacted_values`; a bare `${NAME}`
reference stays readable.

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `DOCKHAND_ENDPOINT` | yes | — | Base URL, e.g. `http://localhost:7777` |
| `DOCKHAND_API_TOKEN` | yes | — | Bearer token from Dockhand UI (Settings → API Tokens) |
| `DOCKHAND_ALLOWED_ENVS` | no | — | Comma-separated environment ids this instance may reach. See [Pinning an instance](#pinning-an-instance-dockhand_allowed_envs) |
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
| `DIGEST_PIN_REPORT` | no | `~/.local/state/digest-pin-check/report.json` | Digest-pin report to overlay. Env only; deliberately not a tool argument. See [Digest-Pinned Images](#digest-pinned-images-pin_assessment) |
| `DIGEST_PIN_MAX_AGE_H` | no | `30` | Report age, in hours, beyond which every pinned row is `not_assessed` (`stale`). Invalid or non-positive values fall back to 30 |

## Deployment (forge, PM2)

dockhand-mcp runs as a **single long-lived HTTP service** under PM2, bound to
`127.0.0.1:8505/mcp` and fronted by scoped-mcp via `url:` (the memsearch-mcp pattern).
Running it as a persistent process — rather than a per-turn stdio subprocess — is what lets
its OTel/InfluxDB/NATS telemetry actually flush and centralizes logs under `pm2 logs`.

```bash
# Clone
cd ~/repos/personal
git clone <repo-url> dockhand-mcp

# Install (the package is under src/ since 0.8.0; re-run this after any pull that
# moves files, because an editable install records paths)
cd dockhand-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[influxdb,otel,nats]"

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
uv sync --frozen --extra dev     # exactly the committed uv.lock, as CI installs it
uv run --frozen pytest --cov     # coverage floor is in pyproject.toml
uv run --frozen ruff check src tests
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

## Excluded Routes

Not wrapped, deliberately, and guarded by a test that fails if a call to one appears:

- `containers/{id}/exec`, `exec/run`, and every `files/*` route: a shell in, and writes to,
  a container's filesystem;
- `system/files`, which lists Dockhand's own filesystem;
- `stacks/{name}/env`, `stacks/{name}/env/raw` and `git/stacks/{id}/env-files`, which
  return env values with no masking;
- Hawser tokens, backups and restore, secret providers, and registry credentials;
- every schedule, auto-update, scheduled-action, report or tag **mutation**: the
  corresponding tools here are read only;
- the activity and deploy-history DELETEs, prune, and the Server-Sent Events streams.

A second test pins the set of tools that make a POST or DELETE at all. A new one needs a
HITL line in every scoped-mcp manifest that loads this server before it is deployed.

## Verified API Paths

All endpoint paths were verified against the live Dockhand instance (v1.0.27) before implementation.
Path discovery method: SvelteKit manifest extraction from the running container. The 0.8.0
routes were written against the Dockhand 1.0.55 OpenAPI spec and checked against a live
1.0.55 instance on 2026-10-25.
