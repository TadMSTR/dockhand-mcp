# dockhand-mcp

FastMCP server wrapping the Dockhand REST API for Docker container and stack management.

## What it does

Provides MCP tools to inspect, control, and update Docker containers and stacks via the Dockhand service running on forge.

## Tools

- `get_health` — Dockhand service health check.
- `list_containers` — All containers with status.
- `list_stacks` — All Compose stacks.
- `container_action(id, action)` — start / stop / restart / pause / unpause / remove.
- `stack_action(id, action)` — start / stop / restart / deploy.
- `check_updates` — Check for available image updates.
- `update_container(id)` — Pull and recreate a container with a newer image.
- `scan_image(image)` — Security scan an image.
- `get_activity` — Recent Dockhand activity log.

## Structure

```
dockhand_mcp/
  server.py          FastMCP server — 9 tools
  client.py          DockhandClient — async httpx wrapper, get_client() factory
  models.py          Pydantic models for API responses
  observability.py   configure_logging() (structlog JSON), emit_metric() (InfluxDB)
tests/               pytest with respx mocks
pyproject.toml
```

## Dependencies

| Package   | Role                         |
|-----------|------------------------------|
| fastmcp   | MCP server framework         |
| httpx     | Async HTTP client            |
| pydantic  | Response models              |
| structlog | JSON structured logging      |

## Configuration

| Env var          | Required | Purpose                              |
|------------------|----------|--------------------------------------|
| `DOCKHAND_URL`   | Yes      | Dockhand base URL                    |
| `DOCKHAND_TOKEN` | No       | Basic or Bearer auth token           |
| `LOG_LEVEL`      | No       | Logging verbosity (default: INFO)    |
| `LOG_FILE`       | No       | Log file path (default: stderr only) |
| `INFLUXDB_URL`   | No       | InfluxDB endpoint for metrics        |

## Key architecture decisions

- **Input validation before API calls** — container and stack IDs are validated against `_SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$")` before being sent to Dockhand. Do not relax this regex.
- **`DockhandError` / `DockhandConfigError`** — `client.py` raises these typed exceptions. Tool handlers catch them and return structured error responses rather than letting exceptions propagate.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

Tests use respx to mock httpx calls — no live Dockhand instance required.

## Git workflow

Branch before editing — do not commit directly to `main`.
