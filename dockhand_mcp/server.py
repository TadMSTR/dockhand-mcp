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
    stack_name: str, action: str, environment_id: Optional[str] = None
) -> dict:
    """Perform a lifecycle action on a Docker Compose stack.

    Actions: start, stop, restart, deploy.
    'deploy' pulls new images and recreates the stack (equivalent to docker compose up -d --pull).
    Use list_stacks to see available stack names.

    Dockhand runs the action asynchronously; this tool waits for the job to
    finish and returns its result: {jobId, success, output} on success or
    {jobId, success: false, error} on failure.

    Args:
        stack_name: Stack name from list_stacks.
        action: One of: start, stop, restart, deploy.
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    if action not in _STACK_ACTIONS:
        return {"error": f"action must be one of: {', '.join(sorted(_STACK_ACTIONS))}"}
    if not _SAFE_ID.match(stack_name):
        return {"error": f"Invalid stack_name: {stack_name!r}"}

    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        # deploy's handler calls request.json() and 500s on an empty body;
        # start/stop/restart take no body.
        body = (
            {"pull": True, "build": False, "forceRecreate": False}
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
    """Queue an image update check for all containers.

    Dockhand checks whether newer image tags are available for running containers.
    Returns a job ID — use get_activity to see when it completes.
    After completion, list_containers will show which containers have updates available.

    Args:
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
            Without it the queued job resolves to 'No environment specified'.
    """
    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        resp, duration = await _timed_post(
            client, "/api/containers/check-updates", params={"env": env}
        )
        data = resp.json()
        job_id = data.get("jobId", "")
        log.info("check_updates", job_id=job_id, duration_s=round(duration, 3))
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
    """Pull the latest image and recreate a specific container.

    Equivalent to pulling the new image and running docker compose up -d for
    that container. Returns a job ID — use get_activity to track progress.

    Args:
        container_id: Container ID from list_containers.
        environment_id: Dockhand environment ID. Defaults to DOCKHAND_DEFAULT_ENV.
    """
    if not _SAFE_ID.match(container_id):
        return {"error": f"Invalid container_id: {container_id!r}"}

    try:
        client = get_client()
        env = client.resolve_env(environment_id)
        # env is a query param (?env=); the handler also requires a JSON body
        # ({repullImage, startAfterUpdate}) and 500s on an empty body.
        # See stack_action: the timer must close after _finalize_job, which polls
        # the async job for up to 120 s (vikunja#574 P5).
        t0 = time.perf_counter()
        resp, post_duration = await _timed_post(
            client,
            f"/api/containers/{container_id}/update",
            params={"env": env},
            json={"repullImage": True, "startAfterUpdate": True},
        )
        data = resp.json() if resp.content else {"status": "ok"}
        data = await _finalize_job(client, data)
        duration = time.perf_counter() - t0
        log.info(
            "update_container",
            container_id=container_id[:12],
            env_id=env,
            success=data.get("success"),
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
