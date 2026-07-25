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

import re
import time
from typing import Any, Optional

import structlog
from fastmcp import FastMCP

from .client import DockhandClient, DockhandConfigError, DockhandError, get_client
from .observability import configure_logging, emit_metric

configure_logging()
log = structlog.get_logger(__name__)

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
)

_CONTAINER_ACTIONS = {"start", "stop", "restart", "pause", "unpause", "remove"}
_STACK_ACTIONS = {"start", "stop", "restart", "deploy"}
_SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$")


def _tool_error(tool: str, err: Exception) -> dict:
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
    client = get_client()
    try:
        resp, duration = await _timed_get(client, "/api/health")
        data = resp.json()
        log.info("get_health", status=data.get("status"), duration_s=round(duration, 3))
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
    client = get_client()
    try:
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
    client = get_client()
    try:
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
    client = get_client()
    try:
        resp, duration = await _timed_get(
            client, f"/api/activity?limit={min(limit, 100)}&offset={offset}"
        )
        data = resp.json()
        events = data.get("events", data) if isinstance(data, dict) else data
        total = data.get("total", len(events)) if isinstance(data, dict) else len(events)
        log.info("get_activity", returned=len(events), total=total, duration_s=round(duration, 3))
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

    client = get_client()
    try:
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

    client = get_client()
    try:
        env = client.resolve_env(environment_id)
        # deploy's handler calls request.json() and 500s on an empty body;
        # start/stop/restart take no body.
        body = (
            {"pull": True, "build": False, "forceRecreate": False}
            if action == "deploy"
            else None
        )
        resp, duration = await _timed_post(
            client, f"/api/stacks/{stack_name}/{action}", params={"env": env}, json=body
        )
        data = resp.json() if resp.content else {"status": "ok"}
        data = await _finalize_job(client, data)
        log.info(
            "stack_action",
            stack=stack_name,
            action=action,
            success=data.get("success"),
            duration_s=round(duration, 3),
        )
        await emit_metric(
            "dockhand_tool",
            {"tool": "stack_action", "action": action},
            {"duration_s": duration, "stack": stack_name},
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
    client = get_client()
    try:
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

    client = get_client()
    try:
        env = client.resolve_env(environment_id)
        # env is a query param (?env=); the handler also requires a JSON body
        # ({repullImage, startAfterUpdate}) and 500s on an empty body.
        resp, duration = await _timed_post(
            client,
            f"/api/containers/{container_id}/update",
            params={"env": env},
            json={"repullImage": True, "startAfterUpdate": True},
        )
        data = resp.json() if resp.content else {"status": "ok"}
        data = await _finalize_job(client, data)
        log.info(
            "update_container",
            container_id=container_id[:12],
            env_id=env,
            success=data.get("success"),
            duration_s=round(duration, 3),
        )
        await emit_metric(
            "dockhand_tool",
            {"tool": "update_container"},
            {"duration_s": duration, "container_id": container_id[:12]},
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
    client = get_client()
    try:
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
    mcp.run()


if __name__ == "__main__":
    main()
