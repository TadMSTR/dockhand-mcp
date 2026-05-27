# Changelog

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
