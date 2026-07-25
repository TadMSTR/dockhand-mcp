"""
Tool-level tests — exercise the @mcp.tool functions end to end against a mocked
Dockhand, asserting the real ``?env=`` contract, the deploy body, and async job
polling. These are the tests that would have caught the shipped env-param bug:
the previous suite mocked only the HTTP client and never checked what the tools
actually sent.
"""

import json

import httpx
import pytest
import respx

from dockhand_mcp import server

from .conftest import (
    CONTAINERS_RESPONSE,
    ENDPOINT,
    JOB_DONE_FAILURE,
    JOB_DONE_SUCCESS,
    JOB_QUEUED,
    STACKS_RESPONSE,
)


def _env_of(route):
    """Return the int value of the ?env= query param on a route's first call."""
    return route.calls[0].request.url.params.get("env")


# ---------------------------------------------------------------------------
# Read tools default the env and send ?env=
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_stacks_sends_default_env(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/stacks").mock(
            return_value=httpx.Response(200, json=STACKS_RESPONSE)
        )

        result = await server.list_stacks()

        assert _env_of(route) == "1"  # DOCKHAND_DEFAULT_ENV
        assert result["total"] == 2
        assert result["stacks"][0]["name"] == "searxng"


@pytest.mark.asyncio
async def test_list_stacks_arg_overrides_env(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/stacks").mock(
            return_value=httpx.Response(200, json=STACKS_RESPONSE)
        )

        await server.list_stacks(environment_id="2")

        assert _env_of(route) == "2"


@pytest.mark.asyncio
async def test_list_containers_sends_env_and_counts_running(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/containers").mock(
            return_value=httpx.Response(200, json=CONTAINERS_RESPONSE)
        )

        result = await server.list_containers()

        assert _env_of(route) == "1"
        assert result["summary"]["total"] == 3
        assert result["summary"]["running"] == 2  # two running, one exited


@pytest.mark.asyncio
async def test_list_stacks_no_env_returns_error_and_makes_no_call(monkeypatch):
    """With no arg and no DOCKHAND_DEFAULT_ENV, the tool returns a clear error and
    never hits Dockhand — instead of silently returning an empty list."""
    monkeypatch.setenv("DOCKHAND_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("DOCKHAND_API_TOKEN", "test-token-abc123")
    monkeypatch.delenv("DOCKHAND_DEFAULT_ENV", raising=False)

    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = mock.get("/api/stacks").mock(
            return_value=httpx.Response(200, json=STACKS_RESPONSE)
        )

        result = await server.list_stacks()

        assert route.call_count == 0
        assert "error" in result
        assert "DOCKHAND_DEFAULT_ENV" in result["error"]


# ---------------------------------------------------------------------------
# stack_action: env, deploy body, async job polling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stack_action_deploy_sends_body_env_and_polls_result(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        deploy = mock.post("/api/stacks/searxng/deploy").mock(
            return_value=httpx.Response(200, json=JOB_QUEUED)
        )
        mock.get(f"/api/jobs/{JOB_QUEUED['jobId']}").mock(
            return_value=httpx.Response(200, json=JOB_DONE_SUCCESS)
        )

        result = await server.stack_action(stack_name="searxng", action="deploy")

        # env in query
        assert _env_of(deploy) == "1"
        # deploy body fixes the empty-body 500
        body = json.loads(deploy.calls[0].request.content)
        assert body == {"pull": True, "build": False, "forceRecreate": False}
        # polled job result is surfaced, not the opaque jobId
        assert result["jobId"] == JOB_QUEUED["jobId"]
        assert result["success"] is True
        assert "Started" in result["output"]


@pytest.mark.asyncio
async def test_stack_action_restart_sends_no_body(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        restart = mock.post("/api/stacks/searxng/restart").mock(
            return_value=httpx.Response(200, json=JOB_QUEUED)
        )
        mock.get(f"/api/jobs/{JOB_QUEUED['jobId']}").mock(
            return_value=httpx.Response(200, json=JOB_DONE_SUCCESS)
        )

        result = await server.stack_action(stack_name="searxng", action="restart")

        assert _env_of(restart) == "1"
        assert restart.calls[0].request.content == b""  # no JSON body
        assert result["success"] is True


@pytest.mark.asyncio
async def test_stack_action_surfaces_job_failure(mock_env):
    """A job that finishes with success=false is reported as a failure, not a
    false success — this is the silent-failure gap that hid the missing env."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/stacks/searxng/restart").mock(
            return_value=httpx.Response(200, json=JOB_QUEUED)
        )
        mock.get(f"/api/jobs/{JOB_QUEUED['jobId']}").mock(
            return_value=httpx.Response(200, json=JOB_DONE_FAILURE)
        )

        result = await server.stack_action(stack_name="searxng", action="restart")

        assert result["success"] is False
        assert "Failed to restart" in result["error"]


@pytest.mark.asyncio
async def test_stack_action_rejects_unknown_action(mock_env):
    result = await server.stack_action(stack_name="searxng", action="explode")
    assert "action must be one of" in result["error"]


# ---------------------------------------------------------------------------
# container_action: env in query, remove uses DELETE
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_container_action_start_sends_env(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.post("/api/containers/abc123/start").mock(
            return_value=httpx.Response(200, json={"success": True})
        )

        result = await server.container_action(container_id="abc123", action="start")

        assert _env_of(route) == "1"
        assert result["success"] is True


@pytest.mark.asyncio
async def test_container_action_remove_uses_delete_with_env(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.delete("/api/containers/abc123").mock(
            return_value=httpx.Response(200, json={"success": True})
        )

        await server.container_action(container_id="abc123", action="remove")

        assert route.call_count == 1
        assert _env_of(route) == "1"


# ---------------------------------------------------------------------------
# check_updates + update_container: env location and body
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_check_updates_sends_env(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.post("/api/containers/check-updates").mock(
            return_value=httpx.Response(200, json=JOB_QUEUED)
        )

        result = await server.check_updates()

        assert _env_of(route) == "1"
        assert result["jobId"] == JOB_QUEUED["jobId"]


@pytest.mark.asyncio
async def test_update_container_sends_env_in_query_and_body(mock_env):
    """update_container puts env in the query (not the body) and sends the
    required {repullImage, startAfterUpdate} body — the old code sent
    {'environmentId': ...} in the body, which the handler ignored."""
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.post("/api/containers/abc123/update").mock(
            return_value=httpx.Response(200, json=JOB_QUEUED)
        )
        mock.get(f"/api/jobs/{JOB_QUEUED['jobId']}").mock(
            return_value=httpx.Response(200, json=JOB_DONE_SUCCESS)
        )

        result = await server.update_container(container_id="abc123")

        assert _env_of(route) == "1"
        body = json.loads(route.calls[0].request.content)
        assert body == {"repullImage": True, "startAfterUpdate": True}
        assert "environmentId" not in body
        assert result["success"] is True
