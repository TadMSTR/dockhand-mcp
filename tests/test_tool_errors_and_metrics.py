"""
Tool-level error handling and metric-emission tests (vikunja#574 P5/P6, #576).

Two defects these cover, both invisible to the existing suite because it only
ever exercised the happy path with a fully-configured environment:

* A missing ``DOCKHAND_ENDPOINT``/``DOCKHAND_API_TOKEN`` raised ``RuntimeError``
  from ``DockhandClient.__init__``, on the line *before* ``try:``. It was outside
  the caught ``(DockhandError, DockhandConfigError)`` tuple *and* outside the
  block, so it escaped the tool as an unhandled exception and was never logged —
  ``_tool_error()`` is what logs, and it never ran.
* ``stack_action``/``update_container`` timed only the initial POST, so the
  emitted ``duration_s`` excluded the entire async job. SigNoz spans said
  121-135 s for calls whose metric said ~0.1 s.
"""

import asyncio

import httpx
import pytest
import respx

from dockhand_mcp import client as client_module
from dockhand_mcp import server

from .conftest import (
    BATCH_UPDATE_SUCCESS,
    ENDPOINT,
    JOB_DONE_SUCCESS,
    JOB_QUEUED,
    STACKS_RESPONSE,
)

# Every tool, with the arguments needed to reach get_client(). The action tools
# validate their arguments before building a client, so the values must be valid
# or the tool short-circuits and the test proves nothing.
ALL_TOOLS = [
    ("get_health", {}),
    ("list_containers", {}),
    ("list_stacks", {}),
    ("get_activity", {}),
    ("container_action", {"container_id": "abc123", "action": "start"}),
    ("stack_action", {"stack_name": "searxng", "action": "restart"}),
    ("check_updates", {}),
    ("update_container", {"container_id": "abc123"}),
    ("scan_image", {"image_name": "nginx:latest"}),
    # Phase 6 read-only surface.
    ("inspect_container", {"container_id": "abc123"}),
    ("get_container_logs", {"container_id": "abc123"}),
    ("get_container_stats", {"container_id": "abc123"}),
    ("get_stack_compose", {"stack_name": "searxng"}),
    ("list_images", {}),
    ("list_volumes", {}),
    ("list_networks", {}),
    ("get_pending_updates", {}),
    ("get_host_info", {}),
]


@pytest.fixture
def no_dockhand_config(monkeypatch):
    monkeypatch.delenv("DOCKHAND_ENDPOINT", raising=False)
    monkeypatch.setenv("DOCKHAND_API_TOKEN", "test-token-abc123")
    monkeypatch.setenv("DOCKHAND_DEFAULT_ENV", "1")


@pytest.fixture
def collect_metrics(monkeypatch):
    """Capture emit_metric calls as ``(measurement, tags, fields)``."""
    emitted = []

    async def _emit(measurement, tags, fields):
        emitted.append((measurement, tags, fields))

    monkeypatch.setattr(server, "emit_metric", _emit)
    return emitted


# ---------------------------------------------------------------------------
# Phase 6 — a config error is returned, never raised
# ---------------------------------------------------------------------------


def test_every_tool_is_covered_by_the_config_error_test():
    """Guards the roster. A tool added without a row in ALL_TOOLS would otherwise
    reintroduce the bug in the one place nothing checks.

    Deliberately not asserted against a hardcoded count — a number in the test
    name goes stale the moment the surface grows, and updating it is the step
    that gets skipped.
    """
    registered = {
        name
        for name, obj in vars(server).items()
        if callable(obj)
        and getattr(obj, "__module__", "") == server.__name__
        and not name.startswith("_")
        and asyncio.iscoroutinefunction(obj)
        and name not in {"main"}
    }
    assert registered == {name for name, _ in ALL_TOOLS}


@pytest.mark.parametrize("tool_name,kwargs", ALL_TOOLS)
@pytest.mark.asyncio
async def test_missing_endpoint_returns_error_dict(tool_name, kwargs, no_dockhand_config):
    """With DOCKHAND_ENDPOINT unset every tool returns {"error": ...}.

    Before the fix this raised RuntimeError straight out of the tool.
    """
    tool = getattr(server, tool_name)

    result = await tool(**kwargs)

    assert isinstance(result, dict), f"{tool_name} did not return a dict"
    assert "error" in result, f"{tool_name} returned {result!r}"
    assert "DOCKHAND_ENDPOINT" in result["error"]


@pytest.mark.asyncio
async def test_missing_token_returns_error_dict(monkeypatch):
    monkeypatch.setenv("DOCKHAND_ENDPOINT", ENDPOINT)
    monkeypatch.delenv("DOCKHAND_API_TOKEN", raising=False)

    result = await server.list_stacks()

    assert "error" in result
    assert "DOCKHAND_API_TOKEN" in result["error"]


def test_client_raises_config_error_not_runtime_error(monkeypatch):
    """The exception type is the fix — the tools catch DockhandConfigError, and a
    RuntimeError would sail straight past even from inside the try."""
    monkeypatch.delenv("DOCKHAND_ENDPOINT", raising=False)

    with pytest.raises(client_module.DockhandConfigError):
        client_module.DockhandClient()

    monkeypatch.setenv("DOCKHAND_ENDPOINT", ENDPOINT)
    monkeypatch.delenv("DOCKHAND_API_TOKEN", raising=False)

    with pytest.raises(client_module.DockhandConfigError):
        client_module.DockhandClient()


@pytest.mark.asyncio
async def test_config_error_is_logged(no_dockhand_config, monkeypatch):
    """_tool_error() is the only thing that logs. The old escape path meant a
    misconfigured service produced no log line at all."""
    logged = []
    monkeypatch.setattr(server.log, "error", lambda event, **kw: logged.append((event, kw)))

    await server.list_stacks()

    assert [e for e, _ in logged] == ["tool_error"]
    assert logged[0][1]["tool"] == "list_stacks"


# ---------------------------------------------------------------------------
# Phase 4 — duration_s spans the async job, not just the POST
# ---------------------------------------------------------------------------

POLL_DELAY = 0.15


@pytest.fixture
def slow_job(monkeypatch):
    """Make _finalize_job's poll take a measurable amount of time.

    respx answers instantly, so without this both timers read ~0 and the
    assertion below could not distinguish the fixed code from the broken code.
    """

    async def _slow_poll(self, job_id, **kwargs):
        await asyncio.sleep(POLL_DELAY)
        return JOB_DONE_SUCCESS["result"]

    monkeypatch.setattr(client_module.DockhandClient, "poll_job", _slow_poll)


@pytest.mark.asyncio
async def test_stack_action_duration_includes_the_job_poll(mock_env, slow_job, collect_metrics):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/stacks/searxng/restart").mock(
            return_value=httpx.Response(200, json=JOB_QUEUED)
        )

        await server.stack_action(stack_name="searxng", action="restart")

    assert len(collect_metrics) == 1
    _, tags, fields = collect_metrics[0]
    assert tags == {"tool": "stack_action", "action": "restart"}
    # The fix: the total spans the poll the caller actually waited through.
    assert fields["duration_s"] >= POLL_DELAY
    # The old value is kept, correctly labelled, so initial-POST latency is still
    # available and nothing silently changed meaning.
    assert fields["post_duration_s"] < POLL_DELAY
    assert fields["post_duration_s"] < fields["duration_s"]


@pytest.mark.asyncio
async def test_update_container_does_not_poll_a_job(mock_env, collect_metrics):
    """Retargeted from the old job-poll timing test (vikunja#574 P5).

    update_container used to post to /api/containers/{id}/update and poll the
    jobId it returned. It now posts to batch-update, which is synchronous and
    documents no jobId — so the property worth pinning is the inverse: no job is
    polled, and duration_s therefore collapses onto post_duration_s. The
    poll-spanning invariant itself is still covered, by
    test_stack_action_duration_includes_the_job_poll above, on a route that
    genuinely returns one.
    """
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        mock.post("/api/containers/batch-update").mock(
            return_value=httpx.Response(200, json=BATCH_UPDATE_SUCCESS)
        )
        jobs = mock.get(f"/api/jobs/{JOB_QUEUED['jobId']}").mock(
            return_value=httpx.Response(200, json=JOB_DONE_SUCCESS)
        )

        await server.update_container(container_id="abc123def456")

    assert jobs.call_count == 0
    assert len(collect_metrics) == 1
    _, tags, fields = collect_metrics[0]
    assert tags == {"tool": "update_container"}
    assert fields["duration_s"] >= fields["post_duration_s"]


# ---------------------------------------------------------------------------
# Phase 5 — get_health and get_activity emit a metric like the other seven
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_health_emits_a_metric(mock_env, collect_metrics):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/health").mock(return_value=httpx.Response(200, json={"status": "ok"}))

        await server.get_health()

    assert len(collect_metrics) == 1
    measurement, tags, fields = collect_metrics[0]
    assert measurement == "dockhand_tool"
    assert tags == {"tool": "get_health"}
    assert fields["status"] == "ok"
    assert "duration_s" in fields


@pytest.mark.asyncio
async def test_get_activity_emits_a_metric(mock_env, collect_metrics):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.route(method="GET", path="/api/activity").mock(
            return_value=httpx.Response(200, json={"events": [{"id": 1}], "total": 7})
        )

        await server.get_activity()

    assert len(collect_metrics) == 1
    _, tags, fields = collect_metrics[0]
    assert tags == {"tool": "get_activity"}
    assert fields["returned"] == 1
    assert fields["total"] == 7


@pytest.mark.asyncio
async def test_every_tool_emits_exactly_one_metric(mock_env, collect_metrics):
    """Phase 5's real assertion: metric coverage is now the whole tool surface,
    not seven of nine. A new tool that forgets emit_metric fails here."""
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        mock.get("/api/health").mock(return_value=httpx.Response(200, json={"status": "ok"}))
        mock.get("/api/containers").mock(return_value=httpx.Response(200, json=[]))
        mock.get("/api/stacks").mock(return_value=httpx.Response(200, json=STACKS_RESPONSE))
        mock.route(method="GET", path="/api/activity").mock(
            return_value=httpx.Response(200, json={"events": [], "total": 0})
        )
        mock.post("/api/containers/abc123/start").mock(
            return_value=httpx.Response(200, json={"success": True})
        )
        mock.post("/api/stacks/searxng/restart").mock(
            return_value=httpx.Response(200, json=JOB_QUEUED)
        )
        mock.post("/api/containers/check-updates").mock(
            return_value=httpx.Response(200, json=JOB_QUEUED)
        )
        mock.post("/api/containers/batch-update").mock(
            return_value=httpx.Response(200, json=BATCH_UPDATE_SUCCESS)
        )
        mock.post("/api/images/scan").mock(
            return_value=httpx.Response(200, json={"imageName": "nginx:latest"})
        )
        # Phase 6 read-only surface.
        mock.get("/api/containers/abc123").mock(
            return_value=httpx.Response(200, json={"Id": "abc123", "Config": {"Env": []}})
        )
        mock.get("/api/containers/abc123/logs").mock(
            return_value=httpx.Response(200, json={"logs": ""})
        )
        mock.get("/api/containers/abc123/stats").mock(
            return_value=httpx.Response(200, json={"cpu": 0.0})
        )
        mock.get("/api/stacks/searxng/compose").mock(
            return_value=httpx.Response(200, json={"content": "services: {}"})
        )
        mock.get("/api/images").mock(return_value=httpx.Response(200, json=[]))
        mock.get("/api/volumes").mock(return_value=httpx.Response(200, json=[]))
        mock.get("/api/networks").mock(return_value=httpx.Response(200, json=[]))
        mock.get("/api/containers/pending-updates").mock(return_value=httpx.Response(200, json=[]))
        mock.get("/api/host").mock(return_value=httpx.Response(200, json={"hostname": "forge"}))
        mock.get(f"/api/jobs/{JOB_QUEUED['jobId']}").mock(
            return_value=httpx.Response(200, json=JOB_DONE_SUCCESS)
        )

        for tool_name, kwargs in ALL_TOOLS:
            await getattr(server, tool_name)(**kwargs)

    emitted_tools = [tags["tool"] for _, tags, _ in collect_metrics]
    assert sorted(emitted_tools) == sorted(name for name, _ in ALL_TOOLS)
