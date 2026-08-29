# dockhand-mcp

FastMCP server wrapping the Dockhand REST API for Docker container and stack management.

## What it does

Provides MCP tools to inspect, control, and update Docker containers and stacks via the Dockhand service running on forge.

## Tools

- `get_health` — Dockhand service health check.
- `list_containers` — All containers with status.
- `list_stacks` — All Compose stacks.
- `container_action(id, action, environment_id=None)` — start / stop / restart / pause / unpause / remove.
- `stack_action(name, action, environment_id=None)` — start / stop / restart / deploy (async; waits for the job).
- `check_updates(environment_id=None)` — Check for available image updates.
- `update_container(id, environment_id=None)` — Pull and recreate a container with a newer image (async; waits for the job).
- `scan_image(image)` — Security scan an image.
- `get_activity` — Recent Dockhand activity log.

## Structure

```
dockhand_mcp/
  server.py          FastMCP server — 9 tools
  client.py          DockhandClient — async httpx wrapper, get_client() factory
  observability.py   configure_logging() (structlog JSON), emit_metric() (InfluxDB)
tests/               pytest with respx mocks
pyproject.toml
```

## Dependencies

| Package   | Role                         |
|-----------|------------------------------|
| fastmcp   | MCP server framework         |
| httpx     | Async HTTP client            |
| pydantic  | Transitive, via fastmcp — no direct use |
| structlog | JSON structured logging      |

## Configuration

| Env var                | Required | Purpose                                                        |
|------------------------|----------|----------------------------------------------------------------|
| `DOCKHAND_ENDPOINT`    | Yes      | Dockhand base URL (e.g. `http://localhost:7777`)               |
| `DOCKHAND_API_TOKEN`   | Yes      | Bearer auth token (Dockhand UI → Settings → API Tokens)        |
| `DOCKHAND_DEFAULT_ENV` | Effectively yes | Default environment id for the `?env=` query param      |
| `LOG_LEVEL`            | No       | Logging verbosity (default: INFO)                              |
| `LOG_FILE`             | No       | Single log sink; stderr only if unwritable or empty            |
| `INFLUXDB_URL`         | No       | InfluxDB endpoint for metrics                                 |

## Key architecture decisions

- **Input validation before API calls** — container and stack IDs are validated against `_SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$")` before being sent to Dockhand. Do not relax this regex.
- **`DockhandError` / `DockhandConfigError`** — `client.py` raises these typed exceptions. Tool handlers catch them and return structured error responses rather than letting exceptions propagate.
- **Environment resolution** — every Dockhand endpoint reads the environment from a `?env=<int>` query param and silently returns `[]` (or fails the async job) when it is missing. `DockhandClient.resolve_env(environment_id)` centralises the `arg → DOCKHAND_DEFAULT_ENV → DockhandConfigError` precedence; all list/action tools call it and pass `params={"env": ...}`. Never send env in a JSON body — the handlers ignore it there.
- **Async job polling** — stack actions and `update_container` return `{"jobId": ...}` and run in the background. `DockhandClient.poll_job()` polls `GET /api/jobs/{jobId}` to a terminal state and returns `{success, output|error}`; `server._finalize_job()` wires this into the tools so callers get a real verdict, not an opaque handle. `deploy` additionally requires a JSON body (`{pull, build, forceRecreate}`) or the handler 500s.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

Tests use respx to mock httpx calls — no live Dockhand instance required.

## Git workflow

Branch before editing — do not commit directly to `main`.
