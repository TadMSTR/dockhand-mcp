# Changelog

## [0.4.0] — 2026-08-29

Observability and error-handling hardening. Everything below was a *runtime* defect that
CI and a code read both passed — the repo was clean at `9231f01` while the deployed service
had been failing silently for 35 days.

### Fixed

- **A configured-but-failing telemetry backend is now visible, and is not retried per call.**
  `_get_influx()` and `_get_nats()` caught `Exception` and `pass`ed, leaving the client global
  at `None`. Two consequences: no log line ever (35 days of logs contained zero lines
  mentioning influx), and *every* `emit_metric()` call re-entered the connect path — for NATS
  each attempt spawned another `allow_reconnect=True` background loop that was never closed,
  which is how one stale env var produced **2,867** `Authorization Violation` lines. Both now
  log one warning and set a negative-cache sentinel. A backend whose env var is simply *unset*
  stays silent, as before — that is the intended disabled path. The warning carries the
  exception class only, never the URL or token; a NATS URL embeds its own credentials.
  (vikunja#574 P1, #575)
- **NATS is now connected with fail-fast options, and nats-py's default error callback is
  replaced.** The sentinel above fixes the per-call re-entry, but that was only half the
  flood — measured against a refused port, a *single* default `nats.connect()` blocks the
  calling tool for ~120 s and reports ~60 times before it ever raises, because
  `_select_next_server()` loops on `max_reconnect_attempts=60` / `reconnect_time_wait=2` and
  invokes `error_cb` on every attempt. nats-py's default callback logs
  `nats: encountered error` at **ERROR** on the `nats.aio.client` logger, so demoting that
  logger to WARNING (below) does not silence it either. Now: `allow_reconnect=False`,
  `max_reconnect_attempts=1`, `reconnect_time_wait=0`, `connect_timeout=2`, an overall
  `asyncio.wait_for` deadline, and a warn-once `error_cb` of our own. Measured after the fix:
  ten `emit_metric()` calls against two dead backends complete in **0.1 s** and produce
  **three** log lines, against ~120 s and an unbounded flood before.
  Note `max_reconnect_attempts=0` is a trap, not "no retries" — the discard check is
  `> 0`, so 0 retries forever.
- **A broken InfluxDB URL is now visible at all.** `InfluxDBClient3` constructs lazily and
  does not contact the host, so `_get_influx()` succeeds against an unreachable URL and its
  init sentinel never fires — verified against `http://127.0.0.1:9/nope`. The warn-once on
  the *write* path is therefore what actually surfaces a broken InfluxDB; without it this
  half of the ticket would still be entirely silent.
- **Missing `DOCKHAND_ENDPOINT`/`DOCKHAND_API_TOKEN` no longer escapes as an unhandled
  exception.** `DockhandClient.__init__` raised `RuntimeError`, which is not in the
  `(DockhandError, DockhandConfigError)` tuple the tools catch — and `client = get_client()`
  sat on the line *before* `try:` in all nine tools, so it was outside the block as well. The
  error escaped the tool and was never logged, because `_tool_error()` is what logs and it
  never ran. Now raises `DockhandConfigError` (matching `resolve_env()`, which was
  deliberately given that type for this reason) and the call moved inside the `try` in all
  nine tools. (vikunja#576, and the real mechanism behind #126)
- **`stack_action` and `update_container` reported `duration_s` three orders of magnitude
  too low.** The timer closed after the initial POST, while `_finalize_job()` then polled the
  async job for up to 120 s. SigNoz spans measured 121–135 s for calls whose metric field
  said ~0.1 s — the span and the metric disagreed about the same call. The timer now closes
  after `_finalize_job()`; the initial-POST latency is retained under the new
  `post_duration_s` field rather than being dropped. (vikunja#574 P5)

### Changed

- **Third-party loggers are pinned to `WARNING`.** `configure_logging()` set the root logger
  to `LOG_LEVEL` and never demoted libraries, so `httpx`, `httpcore`, `mcp` and `nats` all
  logged at INFO into the file (measured: 76 `ListToolsRequest`, 58 `CallToolRequest`, 11
  httpx request lines, plus the NATS flood). The app's own logger still honours `LOG_LEVEL`.
  Same fix as scoped-mcp (#554) and task-dispatcher (#552). (vikunja#574 P3)
- **One log sink, not two.** A stderr `StreamHandler` and a `FileHandler` were both attached,
  so under PM2 every line was written to `error_file` *and* to `LOG_FILE` — two near-identical
  files, neither rotating. The file handler now wins when `LOG_FILE` is writable; stderr
  remains the fallback when it is not, which is what keeps CI and restricted-perms runners
  alive. (vikunja#574 P4)
- **`get_health` and `get_activity` now emit metrics** like the other seven tools. Metric
  coverage was 7 of 9 with no stated reason. (vikunja#574 P6)
- **A write/publish failure inside `emit_metric()` warns once per process** instead of being
  swallowed. Unlike an init failure it does not disable the backend — a rejected write is
  often a transient collector restart — but it is no longer silent. This goes beyond the
  literal text of the build plan's phase 1, which scoped the fix to `_get_influx()`/
  `_get_nats()`; see the InfluxDB note above for why that scope was not sufficient.
- `ecosystem.config.js` and `README.md` corrected: both described the stderr+file
  double-write as intended, and the ecosystem comment claimed rotation "with the
  pm2-logrotate module" which was never installed. Rotation is now real, via
  `/etc/logrotate.d/forge-logs` (daily, rotate 14, copytruncate), installed 2026-08-29.

### Security

- **`nats_shutdown_failed` no longer logs a rendered traceback.** Post-audit remediation
  (2026-08-29, LOW-1): the site carried `exc_info=True`, which is a looser disclosure surface
  than the five new warnings this release added, in the one file it hardened against exactly
  that. NATS is the credential-bearing backend — a NATS URL is `nats://user:password@host` —
  so it now follows the same class-only discipline.
  The two OTel sites (`otel_init_failed`, `otel_shutdown_failed`) keep `exc_info` **by
  decision, now documented in-code**: `OTEL_EXPORTER_OTLP_ENDPOINT` carries no credential, and
  their `try` block spans five imports plus an exporter build, so the traceback answers a
  question `error_class` alone cannot. A test pins that exemption set at exactly two sites,
  both `otel_*`, so neither a new `exc_info` on a credential-bearing site nor a silent removal
  of the exemption can land unnoticed.
- Filed the long-missing `accepted-risks.md` row for dockhand-mcp's OE-02 disposition
  (accepted 2026-07-25, recommended by that audit, never written; re-flagged 2026-08-29), and
  a row accepting the venv's 23 pre-existing transitive CVEs.

### Removed

- `dockhand_mcp/models.py`. 41 statements, 0% coverage, imported nowhere — the tools return
  raw dicts and the Pydantic aliases were never applied. Wiring it into the tool return types
  is a larger change and belongs in its own build.

### Testing

- Coverage **60% → 87%**, and `--cov-fail-under=85` now gates CI. The floor was measured in a
  venv installed with `.[dev]` only — what CI actually installs — because the optional
  influx/nats/otel extras are absent there.
- New `tests/test_observability.py` (the telemetry layer was at 38%) and
  `tests/test_tool_errors_and_metrics.py`. The optional backends are faked via `sys.modules`
  rather than imported, so the tests run identically in CI where those extras are absent.
- The failure-path tests assert both that a warning fired *and* that its payload contains no
  credential — "no secret in the log" passes trivially against a path that logs nothing.

### Previously unreleased

Three commits landed after the 0.3.0 entry and were never tagged or logged:

- `a1254e1` — stop wiring `NATS_URL` until a dockhand NATS user is provisioned (PR #4).
  **The commit alone did not resolve the NATS flood.** The removal never reached the running
  process: PM2 had the variable baked into `dump.pm2`, and `pm2 restart --update-env` can add
  or overwrite a variable but cannot delete one. It took a `pm2 delete` + `pm2 start` +
  `pm2 save` (done 2026-08-29) to clear it. A future reader looking at `a1254e1` and the log
  dates will otherwise conclude the fix simply didn't work.
- `dd0c99e` — add the Release workflow (tag push → GitHub Release) (PR #5).
- `9231f01` — fix the `LOG_FILE` default and heading style in the README.

## [0.3.0] — 2026-07-25

### Added

- **HTTP transport for a long-lived PM2 service.** `MCP_TRANSPORT=http` runs the server as a
  persistent HTTP service on `127.0.0.1:8505/mcp` (configurable via
  `DOCKHAND_MCP_HTTP_HOST`/`_PORT`/`_PATH`), fronted by scoped-mcp via `url:`. `stdio` remains the
  default for local dev. This is the change that makes telemetry observable — a per-turn stdio
  subprocess tore down the OTel `BatchSpanProcessor` and NATS connection before they could flush.
- **Bearer auth on the HTTP endpoint.** In `http` mode a `DOCKHAND_MCP_BEARER` token
  (`StaticTokenVerifier`) is required; unauthenticated requests are rejected (401). Startup
  fails closed if the transport is `http` and the token is missing, shorter than 16 chars, or the
  bind host is non-loopback.
- **Per-tool OTel spans.** A FastMCP middleware wraps every tool call in a
  `dockhand.tool.<name>` span (no-op unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set). Previously
  `get_tracer()` built the exporter but nothing ever emitted a span, so SigNoz stayed empty.
- **Graceful telemetry shutdown.** A server lifespan flushes the tracer provider, drains the NATS
  connection, and closes the httpx client on stop.

### Changed

- **`ecosystem.config.js` rewritten to the working HTTP form.** Runs the venv interpreter with
  `MCP_TRANSPORT=http`, binds `127.0.0.1:8505`, sets `LOG_FILE`/rotation-friendly PM2 log paths,
  and documents the secrets/telemetry endpoints supplied via `--env-file ~/.secrets/forge.env`.
  The previous file launched the stdio server under PM2 with no client on stdin — it would
  restart-loop.

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
