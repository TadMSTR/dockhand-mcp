# Changelog

## [0.2.0] — 2026-07-25

### Fixed

- **Environment parameter — list/action tools were non-functional.** Every Dockhand
  endpoint resolves the environment from the `?env=<int>` query param and silently
  returns an empty array (HTTP 200, no error) when it is absent. The server sent
  `?environmentId=` (ignored) and only when a caller passed one — which agents never
  did — so `list_stacks`/`list_containers` always returned empty and action jobs failed
  with "No environment specified". All list and action tools now resolve the environment
  (`argument → DOCKHAND_DEFAULT_ENV → DockhandConfigError`) and send `?env=`.
  (Fixes the root cause behind four "stacks not registered" reports.)
- **`stack_action(deploy)` returned HTTP 500.** The deploy handler calls
  `request.json()` and threw `Unexpected end of JSON input` on the empty body the MCP
  sent. `deploy` now sends `{"pull": true, "build": false, "forceRecreate": false}`.
- **`update_container` sent env in the wrong place.** It posted
  `{"environmentId": …}` in the body; the handler reads `?env=` from the query and
  expects a `{repullImage, startAfterUpdate}` body. Corrected both.
- **Silent empty results masked the config error.** When no environment resolves, list
  tools now return a clear `DockhandConfigError` message instead of `{total: 0}`.
- **File logging could crash startup.** `configure_logging()` now falls back to
  stderr-only if the log directory is unwritable (e.g. CI runners, restricted perms)
  instead of raising at import.

### Changed

- Stack actions and `update_container` are asynchronous in Dockhand (they return a
  `jobId`). These tools now **poll `GET /api/jobs/{jobId}` to completion** and return the
  terminal result — `{jobId, success, output}` or `{jobId, success: false, error}` —
  instead of an opaque job handle, so a failure is reported as a failure.
- `container_action`, `stack_action`, `check_updates`, and `update_container` gained an
  optional `environment_id` argument (defaults to `DOCKHAND_DEFAULT_ENV`).

### Added

- GitHub Actions CI (`.github/workflows/ci.yml`): ruff lint + pytest + coverage on
  Python 3.11–3.13.
- Ruff configuration (`[tool.ruff]`) pinning pyflakes + isort + essential pycodestyle.
- Tool-level tests (`tests/test_tools.py`) that exercise the `@mcp.tool` functions against
  a mocked Dockhand — asserting the `?env=` contract, the deploy body, and job polling —
  plus `resolve_env` and `poll_job` unit tests. These cover the gap that let the
  env-param bug ship green (the old suite mocked only the HTTP client).

### Security

- Resolves the prior query-param-injection finding (env sent via f-string): env is now
  `int()`-cast in `resolve_env()` and passed via httpx's typed `params={"env": …}`.
- `poll_job()` validates the Dockhand-sourced `jobId` against `^[A-Za-z0-9][A-Za-z0-9_.-]*$`
  before interpolating it into the `/api/jobs/{id}` path (defense-in-depth; audit IV-15).
- Error passthrough to the calling agent (OE-02) reviewed and accepted for this loopback-only
  service with trusted agent callers — see `accepted-risks.md` in the build report.

### Notes

- Runtime on forge stays broken until `DOCKHAND_DEFAULT_ENV="1"` is added to the
  dockhand-mcp env block in the sysadmin manifests (separate follow-on).
- The plan anticipated Server-Sent-Event responses for stack actions; the live Dockhand
  (v1.0.27) instead returns `{jobId}` JSON and exposes results via `GET /api/jobs/{id}`.
  Implemented to the verified live contract (job polling), not SSE.

## [0.1.1] — 2026-05-27

### Fixed

- **Observability: stderr routing** — `configure_logging()` was using
  `structlog.PrintLoggerFactory()` which routes to `sys.stdout`. Switched to
  `structlog.stdlib.LoggerFactory()` with an explicit `sys.stderr` stream handler.
- **Observability: default log path** — `LOG_FILE` was opt-in (defaulted to `""`).
  Now baked in: `/opt/appdata/dockhand-mcp/logs/dockhand-mcp.log`.
- **Observability: bare LOG_FILE guard** — added `if log_dir:` guard before
  `os.makedirs` to prevent `FileNotFoundError` on bare filenames.

### Added

- OTEL tracing support (opt-in via `OTEL_EXPORTER_OTLP_ENDPOINT`) with silent failure
  when `opentelemetry` packages are absent.
- `[otel]` optional dep group: `opentelemetry-sdk>=1.20`,
  `opentelemetry-exporter-otlp-proto-grpc>=1.20`.

## [0.1.0] — 2026-05-25

### Added

- Initial release of `dockhand-mcp` — FastMCP Python MCP server wrapping the Dockhand REST API
- 9 tools covering the full Dockhand management surface:
  - `get_health` — Dockhand health status and timestamp
  - `list_containers` — All containers with name, image, status, environment
  - `list_stacks` — All Compose stacks with name, status, container count
  - `container_action` — start / stop / restart / pause / unpause / remove a container
  - `stack_action` — start / stop / restart / deploy a stack
  - `check_updates` — Queue async image update check for all containers
  - `update_container` — Pull latest image and recreate a specific container
  - `scan_image` — Trivy/Grype CVE scan by image name
  - `get_activity` — Recent Dockhand operations log with pagination
- Bearer token auth via `DOCKHAND_API_TOKEN` (injected via PM2 `--env-file`, never hardcoded)
- `DockhandError` (HTTP error) and `DockhandConfigError` (missing env var) exception hierarchy
- `httpx.AsyncClient` with `trust_env=False` — prevents ALL_PROXY/SOCKS interference
- Structured JSON logging via structlog; optional InfluxDB and NATS telemetry
- PM2 ecosystem config (`ecosystem.config.js`) for forge deployment
- Input validation: `container_id` and `stack_name` validated against safe ID pattern before URL construction
- Query parameters encoded via httpx `params=` dict (not f-string interpolation)
- 10 unit tests covering auth injection, error handling, action routing, and request body content
