"""
dockhand-mcp — FastMCP server wrapping the Dockhand REST API.

Tool surface:
  get_health          — Dockhand status and version
  list_containers     — All containers across environments
  list_stacks         — All compose stacks
  container_action    — start / stop / restart / pause / unpause / remove
  stack_action        — start / stop / restart / deploy
  check_updates       — Queue an image update check (async job)
  update_container    — Pull latest image and recreate a container
  scan_image          — Trivy/Grype CVE scan by image name
  get_activity        — Recent Dockhand operations log
"""

from __future__ import annotations

import os
import re
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

import structlog
from fastmcp import FastMCP
from fastmcp.server.auth import StaticTokenVerifier

from .client import (
    DockhandClient,
    DockhandConfigError,
    DockhandError,
    close_client,
    get_client,
)
from .observability import (
    ToolTracingMiddleware,
    configure_logging,
    emit_metric,
    get_tracer,
    shutdown_observability,
)

configure_logging()
log = structlog.get_logger(__name__)


@asynccontextmanager
async def _lifespan(app):
    # Build the tracer eagerly so the OTLP exporter is ready before the first
    # tool call (and a misconfigured endpoint surfaces at startup, not mid-call).
    get_tracer()
    log.info("dockhand_mcp_started", transport=_TRANSPORT)
    try:
        yield
    finally:
        await shutdown_observability()
        await close_client()
        log.info("dockhand_mcp_stopped")

# --- Transport / endpoint auth configuration ------------------------------
# stdio (default) keeps the historical per-turn subprocess mode for local dev.
# http runs the long-lived PM2 service on a loopback port fronted by scoped-mcp.
_TRANSPORT = os.environ.get("MCP_TRANSPORT", "stdio")
_HTTP_HOST = os.environ.get("DOCKHAND_MCP_HTTP_HOST", "127.0.0.1")
_HTTP_PORT = int(os.environ.get("DOCKHAND_MCP_HTTP_PORT", "8505"))
_HTTP_PATH = os.environ.get("DOCKHAND_MCP_HTTP_PATH", "/mcp")
_BEARER = os.environ.get("DOCKHAND_MCP_BEARER", "")

# Hosts treated as loopback for the fail-closed non-loopback guard in main().
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
# A short bearer on a reachable port is trivially brute-forceable and would show
# up in cleartext in any log that isn't length-gated. Require a real token; a
# generated secrets.token_hex(32) is 64 chars, well clear of this floor.
_MIN_BEARER_LENGTH = 16

# Auth is gated on DOCKHAND_MCP_BEARER being set, independent of transport —
# stdio mode has no HTTP surface so this only takes effect when MCP_TRANSPORT=http.
_auth = None
if _BEARER:
    _auth = StaticTokenVerifier(
        tokens={_BEARER: {"sub": "scoped-mcp", "client_id": "cli"}}
    )

mcp = FastMCP(
    name="dockhand",
    instructions=(
        "Dockhand MCP server. Provides Docker container and stack management on forge "
        "via the Dockhand REST API. Use list_containers and list_stacks to inspect state. "
        "Use container_action and stack_action for lifecycle operations. "
        "Use check_updates to queue an image freshness check, then list_containers to see "
        "which containers have updates. Use scan_image for CVE scanning before pulling "
        "a new image. Use update_container to pull and recreate a specific container."
    ),
    auth=_auth,
    lifespan=_lifespan,
)

# Emit an OTel span per tool call (no-op until OTEL_EXPORTER_OTLP_ENDPOINT is set).
mcp.add_middleware(ToolTracingMiddleware())

_CONTAINER_ACTIONS = {"start", "stop", "restart", "pause", "unpause", "remove"}
_STACK_ACTIONS = {"start", "stop", "restart", "deploy"}
_SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$")


def _tool_error(tool: str, err: Exception) -> dict:
    # SECURITY[accepted]: OE-02 — returns Dockhand's own error text to the calling
    # agent. Loopback-only service, trusted forge-agent callers, no secrets or
    # stack traces in the message. Accepted 2026-07-25 (audit
    # dockhand-mcp-env-param-fix; same class as memsearch-mcp / nextcloud-mcp).
    log.error("tool_error", tool=tool, error=str(err))
    return {"error": str(err)}


async def _timed_get(client: DockhandClient, path: str, **kwargs: Any):
    t0 = time.perf_counter()
    resp = await client.get(path, **kwargs)
    return resp, time.perf_counter() - t0


async def _timed_post(client: DockhandClient, path: str, **kwargs: Any):
    t0 = time.perf_counter()
    resp = await client.post(path, **kwargs)
    return resp, time.perf_counter() - t0


async def _finalize_job(client: DockhandClient, data: dict) -> dict:
    """If ``data`` carries a Dockhand ``jobId``, poll the job to completion and
    return its terminal result merged with the job id; otherwise return ``data``.

    Dockhand runs stack/container actions asynchronously and returns only a job
    handle. Polling here means the tool returns a real ``{success, output|error}``
    verdict instead of an opaque id the caller cannot interpret — the silent
    "job queued but failed" gap that masked the missing-env bug.
    """
    job_id = data.get("jobId") if isinstance(data, dict) else None
    if not job_id:
        return data
    result = await client.poll_job(job_id)
    return {"jobId": job_id, **result}


def _ids_match(returned: str, requested: str) -> bool:
    """True when two Docker container ids refer to the same container.

    Dockhand may echo the full 64-char id for a request that carried the 12-char
    form, so an equality test would miss. Only useful on the paths where the id
    survives — see _unwrap_batch_update.
    """
    if not returned or not requested:
        return False
    return returned.startswith(requested) or requested.startswith(returned)


def _shape_batch_result(result: dict) -> dict:
    """Re-shape one batch-update result so a skip cannot read as an update.

    Dockhand reports a container it declined to touch as a **successful** result
    carrying an ``error`` string ("Skipped - dockhand.update=false label"). A skip
    that is indistinguishable from a completed update is how an agent concludes it
    deployed something it did not.

    The ``error`` key is dropped in that case: callers treat its presence as a
    failure signal, and a skip is not a failure. A genuine failure keeps it.
    """
    out = dict(result)
    reason = out.get("error")
    if out.get("success") and reason:
        out["skipped"] = True
        out["reason"] = reason
        out.pop("error", None)
    return out


def _unwrap_batch_update(data: dict, container_id: str) -> dict:
    """Reduce a batch-update envelope to the one container this tool asked about.

    ``POST /api/containers/batch-update`` answers with
    ``{success, results: [...], summary}`` because it is built for many
    containers. update_container's contract is one, so returning the envelope
    would make every caller index into it.

    **The returned id is not always the requested id.** Measured against
    Dockhand v1.0.46 on 2026-09-07:

    - a successful update returns the **new** container's id, because the
      container was destroyed and recreated (requested ``a978d6d4…`` came back
      as ``ea2167c1…``);
    - a skip or a failure returns the id unchanged, because nothing was
      recreated.

    So matching on the id fails on exactly the path that succeeds. Since this
    tool always sends exactly one id, a single result is unambiguously that
    container and is taken as-is. Id matching is only a disambiguator for a
    multi-result response, which this tool cannot currently provoke.
    """
    if not isinstance(data, dict):
        return data
    results = data.get("results")
    if not isinstance(results, list):
        return data
    if not results:
        return {
            "success": False,
            "error": (
                f"Dockhand returned no batch-update result for container {container_id!r}"
            ),
        }
    if len(results) == 1 and isinstance(results[0], dict):
        return _shape_batch_result(results[0])

    # More results than ids sent: identify ours rather than guessing at [0].
    match = next(
        (
            r
            for r in results
            if isinstance(r, dict) and _ids_match(str(r.get("containerId", "")), container_id)
        ),
        None,
    )
    return _shape_batch_result(match) if match is not None else data


# ---------------------------------------------------------------------------
# Read tools
# ---------------------------------------------------------------------------

@mcp.tool
async def get_health() -> dict:
    """Get Dockhand health status and timestamp.

    Returns status 'ok' when Dockhand is running normally.
    """
    try:
        client = get_client()
        resp, duration = await _timed_get(client, "/api/health")
        data = resp.json()
        log.info("get_health", status=data.get("status"), duration_s=round(duration, 3))
        await emit_metric(
            "dockhand_tool",
            {"tool": "get_health"},
            {"duration_s": duration, "status": str(data.get("status", ""))},
        )
        return data
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("get_health", e)


@mcp.tool
async def list_containers(environment_id: Optional[str] = None) -> dict:
    """List all Docker containers managed by Dockhand.

    Returns container name, image, status, and environment for each container.

    Args:
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        resp, duration = await _timed_get(client, "/api/containers", params={"env": env})
        data = resp.json()
        containers = data if isinstance(data, list) else data.get("containers", [])
        total = len(containers)
        running = sum(1 for c in containers if (c.get("state") or c.get("status") or "").lower() == "running")
        log.info("list_containers", total=total, running=running, duration_s=round(duration, 3))
        await emit_metric(
            "dockhand_tool",
            {"tool": "list_containers"},
            {"duration_s": duration, "total": total, "running": running},
        )
        return {"containers": containers, "summary": {"total": total, "running": running}}
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("list_containers", e)


@mcp.tool
async def list_stacks(environment_id: Optional[str] = None) -> dict:
    """List all Docker Compose stacks managed by Dockhand.

    Returns stack name, status, and container count for each stack.

    Args:
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        resp, duration = await _timed_get(client, "/api/stacks", params={"env": env})
        data = resp.json()
        stacks = data if isinstance(data, list) else data.get("stacks", [])
        log.info("list_stacks", total=len(stacks), duration_s=round(duration, 3))
        await emit_metric(
            "dockhand_tool",
            {"tool": "list_stacks"},
            {"duration_s": duration, "total": len(stacks)},
        )
        return {"stacks": stacks, "total": len(stacks)}
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("list_stacks", e)


@mcp.tool
async def get_activity(limit: int = 20, offset: int = 0) -> dict:
    """Get recent Dockhand activity log — container start/stop/update events.

    Args:
        limit: Number of events to return (default 20, max 100).
        offset: Pagination offset (default 0).
    """
    try:
        client = get_client()
        resp, duration = await _timed_get(
            client, f"/api/activity?limit={min(limit, 100)}&offset={offset}"
        )
        data = resp.json()
        events = data.get("events", data) if isinstance(data, dict) else data
        total = data.get("total", len(events)) if isinstance(data, dict) else len(events)
        log.info("get_activity", returned=len(events), total=total, duration_s=round(duration, 3))
        await emit_metric(
            "dockhand_tool",
            {"tool": "get_activity"},
            {"duration_s": duration, "returned": len(events), "total": total},
        )
        return data
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("get_activity", e)


# ---------------------------------------------------------------------------
# Read tools — environment redaction
# ---------------------------------------------------------------------------

# SECURITY: this is the ONLY thing standing between inspect_container's caller and
# every secret on the host. It was designed as a second layer behind Dockhand's own
# masking; measurement on 2026-09-07 showed that masking does not fire here at all.
#
# GET /api/containers/{id} is documented as masking a compose project's secret
# variables to KEY=***, and GET /api/containers/{id}/inspect is documented as not
# masking anything. Against forge's live Dockhand v1.0.46, both returned 322 of 322
# secret-shaped env vars UNMASKED across 123 containers — the string "***" appeared
# nowhere in either response. Dockhand masks variables it knows as a project's
# secrets, and forge's stacks supply env from env_file paths Dockhand's container
# cannot read (vikunja#542/#410). So the masking is real code that never fires here.
#
# Consequence: do not weaken this pass on the grounds that Dockhand also masks.
# It does not.
_SECRET_KEY = re.compile(
    r"PASSWORD|PASSWD|PASSPHRASE|TOKEN|SECRET|CREDENTIAL|APIKEY|API_KEY"
    r"|ACCESS_KEY|PRIVATE_KEY|_KEY|KEY_|KEYS|SALT|BEARER|DSN",
    re.IGNORECASE,
)

# Credentials embedded in a URL value (postgres://user:pass@host) are invisible to
# a key-name test — the key is usually a bland *_URL or *_DSN.
_URL_CREDENTIALS = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s/@]+@")

_REDACTED = "***REDACTED***"


def _redact_env_entry(entry: str) -> str:
    """Redact one ``KEY=value`` string from a Docker ``Config.Env`` array."""
    if not isinstance(entry, str):
        return entry
    key, sep, value = entry.partition("=")
    if not sep:
        return entry
    if _SECRET_KEY.search(key):
        return f"{key}={_REDACTED}"
    # Not a secret-shaped key, but the value may still carry credentials.
    return key + sep + _URL_CREDENTIALS.sub(rf"\g<scheme>{_REDACTED}@", value)


def _redact_container_env(payload: Any) -> Any:
    """Return ``payload`` with secret-shaped values in Config.Env/Labels redacted.

    Scope, stated plainly because a redaction pass that overstates its reach is
    worse than none: this covers ``Config.Env`` and ``Config.Labels``. It does
    **not** inspect ``Config.Cmd``, ``Entrypoint`` or ``Args``, so a container
    started with a credential on its command line is still returned in the clear.
    inspect_container's docstring says so, and its output is to be treated as
    sensitive regardless.
    """
    if not isinstance(payload, dict):
        return payload
    out = dict(payload)
    config = out.get("Config")
    if isinstance(config, dict):
        config = dict(config)
        env = config.get("Env")
        if isinstance(env, list):
            config["Env"] = [_redact_env_entry(e) for e in env]
        labels = config.get("Labels")
        if isinstance(labels, dict):
            config["Labels"] = {
                k: (_REDACTED if _SECRET_KEY.search(str(k)) else v)
                for k, v in labels.items()
            }
        out["Config"] = config
    return out


# ---------------------------------------------------------------------------
# Read tools — inventory and diagnostics
# ---------------------------------------------------------------------------

@mcp.tool
async def inspect_container(container_id: str, environment_id: Optional[str] = None) -> dict:
    """Inspect a container's full Docker configuration — image, env, mounts, network.

    **Treat the output as sensitive.** Environment variables whose name looks like
    a credential (``*_TOKEN``, ``*_PASSWORD``, ``*_SECRET``, ``*_KEY``, ``*API_KEY*``
    and similar) are replaced with ``***REDACTED***`` by this server before the
    payload is returned, as are credentials embedded in URL values. That redaction
    is the only protection there is: Dockhand documents masking on this route, but
    it resolves a compose project's registered secrets and forge supplies env from
    env_file paths Dockhand cannot read, so in practice nothing is masked upstream.

    The redaction covers Config.Env and Config.Labels. It does **not** cover
    Config.Cmd, Entrypoint or Args — a credential passed on a command line is
    still returned in the clear.

    Args:
        container_id: Container ID from list_containers.
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    if not _SAFE_ID.match(container_id):
        return {"error": f"Invalid container_id: {container_id!r}"}
    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        # NOT /api/containers/{id}/inspect. That route additionally returns raw
        # drift data and has no masking pass of any kind upstream. Wrapping it
        # would hand every caller the complete environment of every container.
        resp, duration = await _timed_get(
            client, f"/api/containers/{container_id}", params={"env": env}
        )
        data = _redact_container_env(resp.json())
        log.info(
            "inspect_container", container_id=container_id[:12], duration_s=round(duration, 3)
        )
        await emit_metric(
            "dockhand_tool",
            {"tool": "inspect_container"},
            {"duration_s": duration, "container_id": container_id[:12]},
        )
        return data
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("inspect_container", e)


@mcp.tool
async def get_container_logs(
    container_id: str,
    tail: int = 100,
    since: Optional[str] = None,
    until: Optional[str] = None,
    environment_id: Optional[str] = None,
) -> dict:
    """Get a container's combined stdout/stderr logs.

    ``tail`` is bounded to 100 lines by default and capped at 5000 — an unbounded
    default would pull a whole log history into the caller's context.

    Logs may contain secrets that no redaction here can find, since a secret in a
    log line has no key to match on. This is the same exposure as ``docker logs``.

    Args:
        container_id: Container ID from list_containers.
        tail: Number of lines from the end of the log (default 100, max 5000).
        since: Only logs after this timestamp, e.g. '2026-09-07T12:00:00Z'.
        until: Only logs before this timestamp.
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    if not _SAFE_ID.match(container_id):
        return {"error": f"Invalid container_id: {container_id!r}"}
    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        params: dict[str, Any] = {"env": env, "tail": max(1, min(int(tail), 5000))}
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        resp, duration = await _timed_get(
            client, f"/api/containers/{container_id}/logs", params=params
        )
        data = resp.json() if resp.content else {}
        if not isinstance(data, dict):
            data = {"logs": data}
        log.info(
            "get_container_logs",
            container_id=container_id[:12],
            tail=params["tail"],
            duration_s=round(duration, 3),
        )
        await emit_metric(
            "dockhand_tool",
            {"tool": "get_container_logs"},
            {"duration_s": duration, "container_id": container_id[:12]},
        )
        return data
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("get_container_logs", e)


@mcp.tool
async def get_container_stats(container_id: str, environment_id: Optional[str] = None) -> dict:
    """Get a one-shot CPU, memory, network and block-IO snapshot for a container.

    This is a single sample, not a stream — call it again for a second reading.

    Args:
        container_id: Container ID from list_containers.
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    if not _SAFE_ID.match(container_id):
        return {"error": f"Invalid container_id: {container_id!r}"}
    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        resp, duration = await _timed_get(
            client, f"/api/containers/{container_id}/stats", params={"env": env}
        )
        data = resp.json()
        log.info(
            "get_container_stats", container_id=container_id[:12], duration_s=round(duration, 3)
        )
        await emit_metric(
            "dockhand_tool",
            {"tool": "get_container_stats"},
            {"duration_s": duration, "container_id": container_id[:12]},
        )
        return data if isinstance(data, dict) else {"stats": data}
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("get_container_stats", e)


@mcp.tool
async def get_stack_compose(stack_name: str, environment_id: Optional[str] = None) -> dict:
    """Get a stack's docker-compose file content and its resolved compose/env paths.

    Returns the compose definition only. Stack environment *values* are not
    exposed by this server at all — Dockhand's stack env routes have no masking
    and are deliberately not wrapped.

    Args:
        stack_name: Stack name from list_stacks.
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    if not _SAFE_ID.match(stack_name):
        return {"error": f"Invalid stack_name: {stack_name!r}"}
    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        resp, duration = await _timed_get(
            client, f"/api/stacks/{stack_name}/compose", params={"env": env}
        )
        data = resp.json()
        log.info("get_stack_compose", stack=stack_name, duration_s=round(duration, 3))
        await emit_metric(
            "dockhand_tool",
            {"tool": "get_stack_compose"},
            {"duration_s": duration, "stack": stack_name},
        )
        return data if isinstance(data, dict) else {"compose": data}
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("get_stack_compose", e)


async def _listing_tool(tool: str, path: str, key: str, environment_id: Optional[str]) -> dict:
    """Shared body for the flat inventory listings (images, volumes, networks).

    All three answer ``[]`` rather than an error when ``env`` is absent, which is
    the silent-empty failure mode resolve_env() exists to prevent — so the env is
    resolved (and raises) before the request is made.
    """
    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        resp, duration = await _timed_get(client, path, params={"env": env})
        data = resp.json()
        items = data if isinstance(data, list) else data.get(key, [])
        log.info(tool, total=len(items), duration_s=round(duration, 3))
        await emit_metric(
            "dockhand_tool", {"tool": tool}, {"duration_s": duration, "total": len(items)}
        )
        return {key: items, "total": len(items)}
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error(tool, e)


@mcp.tool
async def list_images(environment_id: Optional[str] = None) -> dict:
    """List Docker images — id, tags, size and creation time.

    Args:
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    return await _listing_tool("list_images", "/api/images", "images", environment_id)


@mcp.tool
async def list_volumes(environment_id: Optional[str] = None) -> dict:
    """List Docker volumes — name, driver, mountpoint and labels.

    Args:
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    return await _listing_tool("list_volumes", "/api/volumes", "volumes", environment_id)


@mcp.tool
async def list_networks(environment_id: Optional[str] = None) -> dict:
    """List Docker networks — name, driver, scope and attached containers.

    Args:
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    return await _listing_tool("list_networks", "/api/networks", "networks", environment_id)


@mcp.tool
async def get_pending_updates(environment_id: Optional[str] = None) -> dict:
    """List containers with an image update available.

    Reports what a previous check_updates run found; it does not run a new check.

    Args:
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
            Required on this route — unlike the other listings, Dockhand documents
            ``env`` as mandatory here.
    """
    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        resp, duration = await _timed_get(
            client, "/api/containers/pending-updates", params={"env": env}
        )
        data = resp.json()
        # The key is "pendingUpdates", not "updates". Reading the wrong one
        # returned total=0 against a host that had 27 — a zero indistinguishable
        # from a real "nothing pending", which is the whole failure mode this
        # tool exists to avoid. Verified against the live response, not guessed.
        updates = data if isinstance(data, list) else data.get("pendingUpdates", [])
        available = sum(1 for u in updates if isinstance(u, dict) and u.get("hasImageUpdate"))
        log.info(
            "get_pending_updates",
            total=len(updates),
            available=available,
            duration_s=round(duration, 3),
        )
        await emit_metric(
            "dockhand_tool",
            {"tool": "get_pending_updates"},
            {"duration_s": duration, "total": len(updates)},
        )
        return {
            "pendingUpdates": updates,
            "total": len(updates),
            "withUpdateAvailable": available,
        }
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("get_pending_updates", e)


@mcp.tool
async def get_host_info(environment_id: Optional[str] = None) -> dict:
    """Get Docker host information — hostname, CPU, memory, uptime, container counts.

    Args:
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        resp, duration = await _timed_get(client, "/api/host", params={"env": env})
        data = resp.json()
        log.info("get_host_info", duration_s=round(duration, 3))
        await emit_metric("dockhand_tool", {"tool": "get_host_info"}, {"duration_s": duration})
        return data if isinstance(data, dict) else {"host": data}
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("get_host_info", e)


# ---------------------------------------------------------------------------
# Action tools
# ---------------------------------------------------------------------------

@mcp.tool
async def container_action(
    container_id: str, action: str, environment_id: Optional[str] = None
) -> dict:
    """Perform a lifecycle action on a Docker container.

    Actions: start, stop, restart, pause, unpause, remove.
    Use list_containers to get container IDs.

    Note: 'remove' permanently deletes the container. Use with care.

    Args:
        container_id: Container ID from list_containers.
        action: One of: start, stop, restart, pause, unpause, remove.
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    if action not in _CONTAINER_ACTIONS:
        return {"error": f"action must be one of: {', '.join(sorted(_CONTAINER_ACTIONS))}"}
    if not _SAFE_ID.match(container_id):
        return {"error": f"Invalid container_id: {container_id!r}"}

    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        t0 = time.perf_counter()
        if action == "remove":
            resp = await client.delete(
                f"/api/containers/{container_id}", params={"env": env}
            )
        else:
            resp = await client.post(
                f"/api/containers/{container_id}/{action}", params={"env": env}
            )
        duration = time.perf_counter() - t0

        data = resp.json() if resp.content else {"status": "ok"}
        log.info(
            "container_action",
            container_id=container_id[:12],
            action=action,
            duration_s=round(duration, 3),
        )
        await emit_metric(
            "dockhand_tool",
            {"tool": "container_action", "action": action},
            {"duration_s": duration, "container_id": container_id[:12]},
        )
        return data
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("container_action", e)


@mcp.tool
async def stack_action(
    stack_name: str,
    action: str,
    environment_id: Optional[str] = None,
    pull: Optional[bool] = None,
    build: Optional[bool] = None,
    force_recreate: Optional[bool] = None,
) -> dict:
    """Perform a lifecycle action on a Docker Compose stack.

    Actions: start, stop, restart, deploy.
    Use list_stacks to see available stack names.

    **deploy is whole-stack.** Dockhand's REST API has no per-service parameter —
    its compose runner threads a service name internally, but the route never
    accepts one. When you need single-service scope, run
    ``docker compose up -d <service>`` via system-ops instead.

    ``pull`` defaults to True, which makes Dockhand run ``compose up -d --pull
    always``. That re-resolves every image and can recreate services you did not
    intend to touch (vikunja#671). ``pull=False`` gives a plain
    ``docker compose up -d``, which recreates only services whose resolved
    config actually changed.

    Job behaviour differs by action, per the v1.0.46 spec: ``start`` and ``stop``
    return a jobId and are polled to completion here, returning
    {jobId, success, output} or {jobId, success: false, error}. ``deploy`` and
    ``restart`` return their result directly and are not polled.

    Args:
        stack_name: Stack name from list_stacks.
        action: One of: start, stop, restart, deploy.
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
        pull: deploy only. Re-pull images first. Defaults to True.
        build: deploy only. Build images before starting. Defaults to False.
        force_recreate: deploy only. Recreate containers even when config is
            unchanged. Defaults to False.
    """
    if action not in _STACK_ACTIONS:
        return {"error": f"action must be one of: {', '.join(sorted(_STACK_ACTIONS))}"}
    if not _SAFE_ID.match(stack_name):
        return {"error": f"Invalid stack_name: {stack_name!r}"}

    # These three are rejected rather than ignored on the bodyless actions.
    # Accepting pull=False on a restart and dropping it would report a flag as
    # honoured that Dockhand never received — the same class of defect as a skip
    # that reads as a completed update. Defaults are None, not the real defaults,
    # so "explicitly asked for" is distinguishable from "left alone".
    if action != "deploy":
        supplied = [
            name
            for name, value in (
                ("pull", pull),
                ("build", build),
                ("force_recreate", force_recreate),
            )
            if value is not None
        ]
        if supplied:
            return {
                "error": (
                    f"{', '.join(supplied)} applies only to action='deploy'; "
                    f"{action!r} sends no body and Dockhand would ignore it."
                )
            }

    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        # deploy's handler calls request.json() and 500s on an empty body;
        # start/stop/restart take no body. Unset flags resolve to the historical
        # hardcoded values so existing callers see no behaviour change.
        body = (
            {
                "pull": True if pull is None else pull,
                "build": False if build is None else build,
                "forceRecreate": False if force_recreate is None else force_recreate,
            }
            if action == "deploy"
            else None
        )
        # duration_s must span _finalize_job's poll, not just the initial POST.
        # Dockhand runs the action asynchronously, so timing only the POST
        # reported ~0.1 s for calls the OTel span measured at 121-135 s — the
        # span and the metric disagreed about the same call (vikunja#574 P5).
        t0 = time.perf_counter()
        resp, post_duration = await _timed_post(
            client, f"/api/stacks/{stack_name}/{action}", params={"env": env}, json=body
        )
        data = resp.json() if resp.content else {"status": "ok"}
        data = await _finalize_job(client, data)
        duration = time.perf_counter() - t0
        log.info(
            "stack_action",
            stack=stack_name,
            action=action,
            success=data.get("success"),
            duration_s=round(duration, 3),
            post_duration_s=round(post_duration, 3),
        )
        await emit_metric(
            "dockhand_tool",
            {"tool": "stack_action", "action": action},
            {
                "duration_s": duration,
                "post_duration_s": post_duration,
                "stack": stack_name,
            },
        )
        return data
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("stack_action", e)


@mcp.tool
async def check_updates(environment_id: Optional[str] = None) -> dict:
    """Check every container for a newer image, and wait for the answer.

    Not queued, despite the name: Dockhand documents this route as a
    text/event-stream job feed "or, with Accept: application/json, the final
    result as plain JSON" — and client.py sets that header on every request. So
    it returns the completed result directly, as {total, updatesFound, results}.

    Returns no job ID. The old docstring said it did and told callers to poll
    get_activity; jobId is documented on six routes and this is not one of them,
    and every real call in this service's logs recorded an empty job id.

    Expect this to take a while — it contacts a registry per image. Use
    get_pending_updates afterwards to read the result back without re-running it.

    Args:
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
            Without it Dockhand fails with 'No environment specified'.
    """
    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        resp, duration = await _timed_post(
            client, "/api/containers/check-updates", params={"env": env}
        )
        data = resp.json()
        # Not job_id: this route returns {total, updatesFound, results} directly
        # and every real call logged an empty job id for the life of the service.
        log.info(
            "check_updates",
            checked=data.get("total"),
            updates_found=data.get("updatesFound"),
            duration_s=round(duration, 3),
        )
        await emit_metric(
            "dockhand_tool",
            {"tool": "check_updates"},
            {"duration_s": duration},
        )
        return data
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("check_updates", e)


@mcp.tool
async def update_container(container_id: str, environment_id: Optional[str] = None) -> dict:
    """Re-pull a container's image and recreate the container in place.

    Recreates the container through Dockhand's batch-update endpoint, which
    inspects the running container server-side, pulls its image and recreates it
    with full Config/HostConfig passthrough — every setting is preserved and no
    configuration is reconstructed by this tool.

    This does **not** run ``docker compose``. A compose-managed container is
    recreated through the Docker API directly.

    Responds synchronously: there is no job to poll and no job ID to track.

    For a **digest-pinned** image — which forge uses widely — this re-pulls the
    same digest and recreates the container. That is a recreate, not an upgrade;
    change the pin first if you want a new version.

    Returns ``{success, containerId, containerName}``, or
    ``{success: true, skipped: true, reason: ...}`` when the container carries the
    ``dockhand.update=false`` label and Dockhand declined to touch it.

    Args:
        container_id: Container ID from list_containers.
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    if not _SAFE_ID.match(container_id):
        return {"error": f"Invalid container_id: {container_id!r}"}

    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        # Do NOT route this at POST /api/containers/{id}/update. That handler
        # destructures the body as {startAfterUpdate, repullImage, ...options} and
        # then calls pullImage(options.image), so a body carrying only the two
        # control flags leaves options.image undefined and Dockhand throws
        # "Cannot read properties of undefined (reading 'includes')". Every call
        # this service ever made to that route failed that way, from v0.1.0 until
        # 2026-09-07 — zero successes (vikunja#702).
        #
        # batch-update requires {containerIds} and nothing else, and does the
        # inspect-pull-recreate cycle itself. The alternative — GET the container
        # and echo its create-options back into /update — reimplements config
        # passthrough in Python and loses fields.
        #
        # See stack_action: the timer must close after _finalize_job (vikunja#574 P5).
        # batch-update is synchronous and returns no jobId, so the poll is a no-op
        # here; it stays in the path in case upstream makes the route async.
        t0 = time.perf_counter()
        resp, post_duration = await _timed_post(
            client,
            "/api/containers/batch-update",
            params={"env": env},
            json={"containerIds": [container_id]},
        )
        data = resp.json() if resp.content else {"status": "ok"}
        data = await _finalize_job(client, data)
        data = _unwrap_batch_update(data, container_id)
        duration = time.perf_counter() - t0
        log.info(
            "update_container",
            container_id=container_id[:12],
            env_id=env,
            success=data.get("success"),
            # A skip is logged distinctly: "success=True" alone would record a
            # container Dockhand never touched as an update that happened.
            skipped=bool(data.get("skipped")),
            duration_s=round(duration, 3),
            post_duration_s=round(post_duration, 3),
        )
        await emit_metric(
            "dockhand_tool",
            {"tool": "update_container"},
            {
                "duration_s": duration,
                "post_duration_s": post_duration,
                "container_id": container_id[:12],
            },
        )
        return data
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("update_container", e)


@mcp.tool
async def scan_image(image_name: str) -> dict:
    """Run a Trivy/Grype CVE vulnerability scan on a Docker image.

    Scans the image for known CVEs. Returns vulnerability counts by severity
    (critical, high, medium, low) and a list of findings.

    Use this before pulling a new image to check for known vulnerabilities.

    Args:
        image_name: Full image name with tag, e.g. 'nginx:latest', 'postgres:16-alpine'.
    """
    try:
        client = get_client()
        resp, duration = await _timed_post(
            client,
            "/api/images/scan",
            json={"imageName": image_name},
        )
        data = resp.json()
        log.info(
            "scan_image",
            image=image_name,
            duration_s=round(duration, 3),
        )
        await emit_metric(
            "dockhand_tool",
            {"tool": "scan_image"},
            {"duration_s": duration, "image": image_name},
        )
        return data
    except (DockhandError, DockhandConfigError) as e:
        return _tool_error("scan_image", e)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if _TRANSPORT == "http":
        if _HTTP_HOST not in _LOOPBACK_HOSTS:
            raise RuntimeError(
                f"Refusing to bind dockhand-mcp HTTP transport to non-loopback host "
                f"{_HTTP_HOST!r}. This service is loopback-only by design; front it "
                f"with scoped-mcp, do not expose the port."
            )
        if not _BEARER:
            raise RuntimeError(
                "Refusing to start dockhand-mcp HTTP transport without DOCKHAND_MCP_BEARER "
                "set. HTTP mode must not run with an unauthenticated, reachable port."
            )
        if len(_BEARER) < _MIN_BEARER_LENGTH:
            raise RuntimeError(
                f"DOCKHAND_MCP_BEARER is too short ({len(_BEARER)} chars, need "
                f">= {_MIN_BEARER_LENGTH}). Generate one with: "
                'python3 -c "import secrets; print(secrets.token_hex(32))"'
            )
        log.info(
            "dockhand_mcp_http_start",
            host=_HTTP_HOST,
            port=_HTTP_PORT,
            path=_HTTP_PATH,
        )
        mcp.run(transport="http", host=_HTTP_HOST, port=_HTTP_PORT, path=_HTTP_PATH)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
