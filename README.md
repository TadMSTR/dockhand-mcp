# dockhand-mcp

FastMCP Python MCP server wrapping the [Dockhand](https://github.com/Finsys/dockhand) REST API.

Gives an AI agent structured access to Docker container and stack management on a Dockhand-managed host: list containers and stacks, perform lifecycle actions, check for image updates, pull and recreate containers, and run CVE scans.

## Tool Reference

| Tool | Description |
|------|-------------|
| `get_health` | Dockhand health status and timestamp |
| `list_containers` | All containers: name, image, status, environment |
| `list_stacks` | All Compose stacks: name, status, container count |
| `container_action` | start / stop / restart / pause / unpause / remove a container |
| `stack_action` | start / stop / restart / deploy a stack |
| `check_updates` | Queue an image update check for all containers (async job) |
| `update_container` | Pull latest image and recreate a specific container |
| `scan_image` | Trivy/Grype CVE scan by image name |
| `get_activity` | Recent Dockhand operations log |

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

`deploy` pulls new images and recreates the stack (equivalent to `docker compose up -d --pull`).
`deploy` sends a JSON body `{"pull": true, "build": false, "forceRecreate": false}`; the other
stack actions send no body.

## Environments

Every Dockhand REST endpoint resolves the target environment from a `?env=<int>` query
parameter (parsed with `parseInt`). List endpoints **silently return an empty array** (HTTP
200, no error) when it is absent, and action jobs fail asynchronously with
`No environment specified`. To avoid that failure mode, every list and action tool resolves
the environment as:

```
explicit environment_id argument  →  DOCKHAND_DEFAULT_ENV  →  clear DockhandConfigError
```

`list_containers`, `list_stacks`, `container_action`, `stack_action`, `check_updates`, and
`update_container` all accept an optional `environment_id`. In practice set
`DOCKHAND_DEFAULT_ENV` once (see [Getting the Environment ID](#getting-the-environment-id))
and omit the argument.

## Asynchronous actions

Stack actions (`start`/`stop`/`restart`/`deploy`) and `update_container` run **asynchronously**
in Dockhand: the endpoint returns `{"jobId": ...}` immediately and the work completes in the
background. These tools **wait for the job to finish** — polling `GET /api/jobs/{jobId}` — and
return the terminal result:

```json
{ "jobId": "…", "success": true,  "output": " Container searxng Started \n" }
{ "jobId": "…", "success": false, "error":  "Failed to restart compose stack" }
```

So a returned `success: false` is a real failure, not a queued job you have to chase down.
`check_updates` is fire-and-forget: it returns the `jobId`; use `get_activity` / `list_containers`
to observe completion.

## Update Workflow

To update a container to its latest image:

```
1. check_updates()
   → queues async job; get_activity() to see when it completes

2. list_containers()
   → check which containers show update available

3. scan_image("nginx:latest")
   → review CVE count before pulling

4. update_container(container_id)
   → pulls latest image and recreates the container
```

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `DOCKHAND_ENDPOINT` | yes | — | Base URL, e.g. `http://localhost:7777` |
| `DOCKHAND_API_TOKEN` | yes | — | Bearer token from Dockhand UI (Settings → API Tokens) |
| `DOCKHAND_DEFAULT_ENV` | **effectively yes** | — | Default Dockhand environment ID (e.g. `1`). Used by every list and action tool as the `?env=` query param when the caller doesn't pass one. Without it (and no explicit `environment_id`), those tools return a clear config error. See [Environments](#environments) |
| `LOG_LEVEL` | no | `INFO` | structlog verbosity |
| `LOG_FILE` | no | — | Log to file path; stdout if unset |
| `INFLUXDB_URL` | no | — | Enables InfluxDB telemetry when set |
| `INFLUXDB_TOKEN` | no | — | InfluxDB auth token |
| `INFLUXDB_BUCKET` | no | `dockhand-mcp` | InfluxDB bucket name |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | — | Enables OTEL traces when set |
| `NATS_URL` | no | — | Enables NATS event publishing when set |
| `NATS_SUBJECT_PREFIX` | no | `dockhand` | NATS subject prefix |

## Deployment (forge, PM2)

```bash
# Clone
cd ~/repos/personal
git clone <repo-url> dockhand-mcp

# Install
cd dockhand-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Create API token in Dockhand UI: Settings → API Tokens
# Add DOCKHAND_API_TOKEN to ~/.secrets/forge.env

# Start (secrets injected via --env-file)
pm2 start ecosystem.config.js --env-file ~/.secrets/forge.env
pm2 save
```

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

## Verified API Paths

All endpoint paths were verified against the live Dockhand instance (v1.0.27) before implementation.
Path discovery method: SvelteKit manifest extraction from the running container.
