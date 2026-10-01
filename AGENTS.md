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
  pin_report.py      Digest-pin report reader + pin_assessment overlay (file read only)
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
| `DIGEST_PIN_REPORT`    | No       | Digest-pin report path (default `~/.local/state/digest-pin-check/report.json`) |
| `DIGEST_PIN_MAX_AGE_H` | No       | Report staleness limit in hours (default 30)                   |

## Key architecture decisions

- **Input validation before API calls** — container and stack IDs are validated against `_SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$")` before being sent to Dockhand. Do not relax this regex.
- **`DockhandError` / `DockhandConfigError`** — `client.py` raises these typed exceptions. Tool handlers catch them and return structured error responses rather than letting exceptions propagate.
- **Environment resolution** — every Dockhand endpoint reads the environment from a `?env=<int>` query param and silently returns `[]` (or fails the async job) when it is missing. `DockhandClient.resolve_env(environment_id)` centralises the `arg → DOCKHAND_DEFAULT_ENV → DockhandConfigError` precedence; all list/action tools call it and pass `params={"env": ...}`. Never send env in a JSON body — the handlers ignore it there.
- **Async job polling** — stack actions and `update_container` return `{"jobId": ...}` and run in the background. `DockhandClient.poll_job()` polls `GET /api/jobs/{jobId}` to a terminal state and returns `{success, output|error}`; `server._finalize_job()` wires this into the tools so callers get a real verdict, not an opaque handle. `deploy` additionally requires a JSON body (`{pull, build, forceRecreate}`) or the handler 500s.

- **Digest-pin overlay fails closed** — `check_updates` / `get_pending_updates` attach `pin_assessment` to rows whose image ref contains `@sha256:`, taken from a report written by a separate scheduled checker. A missing, stale, unreadable or non-v1 report makes every pinned row `not_assessed`; never default a pin to `current`, and never modify Dockhand's own fields. The report path is env-only — do not add it as a tool argument. Do not add registry access here; the checker owns that logic. Test fixtures in `tests/fixtures/` are frozen real data — do not hand-write shapes.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

Tests use respx to mock httpx calls — no live Dockhand instance required.

## Git workflow

Branch before editing — do not commit directly to `main`.
