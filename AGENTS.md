# dockhand-mcp

FastMCP server wrapping the Dockhand REST API for Docker container and stack management.

## What it does

Provides MCP tools to inspect, control, and update Docker containers and stacks via the Dockhand service running on forge.

## Tools

30 tools. The README's Tool Reference table is the list, and a test keeps the two in step.
The lifecycle tools are `container_action`, `stack_action` and `update_container` (HITL-gated
in scoped-mcp); everything else is read only.

## Structure

```
src/dockhand_mcp/
  server.py          FastMCP server — 30 tools
  client.py          DockhandClient — async httpx wrapper, env resolution + pin, get_client()
  redaction.py       Value-shape redaction, env-dump masking, compose redaction
  pin_report.py      Digest-pin report reader + pin_assessment overlay (file read only)
  observability.py   configure_logging() (structlog JSON), emit_metric() (InfluxDB)
tests/               pytest with respx mocks
pyproject.toml
uv.lock              the tested and audited dependency tree
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
- **`DockhandError` / `DockhandConfigError`** — `client.py` raises these typed exceptions, including for a transport failure or a non-JSON body (`status_code` 0). Tool handlers catch them and return structured error responses rather than letting exceptions propagate. Decode with `json_body(resp)`, never `resp.json()`.
- **`stack_action` requires `acknowledge_env_log=true`** on every action, refused with zero requests otherwise: Dockhand logs the stack's `.env` on all four. Do not relax it to a subset of actions or to a truthy value.
- **Every text a tool returns from Dockhand's logs goes through `mask_env_dump`** (container logs, deploy logs, schedule-execution logs). Mask before truncating, never after. Never reduce the redaction in `redaction.py` to a key-name list.
- **`DOCKHAND_ALLOWED_ENVS`** is enforced in `resolve_env` and `env_filter`. A new tool resolves its env through one of them, and a route with no env parameter must check the env of what it reads (see `get_stack_deploy_log`).
- **No new POST/DELETE without a HITL line.** `test_contract.py` pins the set of tools that mutate; exec, files and the other excluded routes in the README stay unwrapped.
- **Environment resolution** — every Dockhand endpoint reads the environment from a `?env=<int>` query param and silently returns `[]` (or fails the async job) when it is missing. `DockhandClient.resolve_env(environment_id)` centralises the `arg → DOCKHAND_DEFAULT_ENV → DockhandConfigError` precedence; all list/action tools call it and pass `params={"env": ...}`. Never send env in a JSON body — the handlers ignore it there.
- **Async job polling** — stack actions and `update_container` return `{"jobId": ...}` and run in the background. `DockhandClient.poll_job()` polls `GET /api/jobs/{jobId}` to a terminal state and returns `{success, output|error}`; `server._finalize_job()` wires this into the tools so callers get a real verdict, not an opaque handle. `deploy` additionally requires a JSON body (`{pull, build, forceRecreate}`) or the handler 500s.

- **Digest-pin overlay fails closed** — `check_updates` / `get_pending_updates` attach `pin_assessment` to rows whose image ref contains `@sha256:`, taken from a report written by a separate scheduled checker. A missing, stale, unreadable or non-v1 report makes every pinned row `not_assessed`; never default a pin to `current`, and never modify Dockhand's own fields. The report path is env-only — do not add it as a tool argument. Do not add registry access here; the checker owns that logic. Test fixtures in `tests/fixtures/` are frozen real data — do not hand-write shapes.

## Testing

```bash
uv sync --frozen --extra dev
uv run --frozen pytest --cov
```

Tests use respx to mock httpx calls — no live Dockhand instance required. `test_protocol.py` goes through `fastmcp.Client`, so schemas and argument validation are covered too.

## Git workflow

Branch before editing — do not commit directly to `main`.
