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
    BATCH_UPDATE_FAILED,
    BATCH_UPDATE_MULTI,
    BATCH_UPDATE_SKIPPED,
    BATCH_UPDATE_SUCCESS,
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


# vikunja#671: deploy hardcoded pull=True, which becomes `compose up -d --pull
# always` and re-resolves every image — the likely cause of the unexpected
# librechat recreates. These assert the flags reach the body verbatim.

@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({}, {"pull": True, "build": False, "forceRecreate": False}),
        ({"pull": False}, {"pull": False, "build": False, "forceRecreate": False}),
        ({"build": True}, {"pull": True, "build": True, "forceRecreate": False}),
        (
            {"force_recreate": True},
            {"pull": True, "build": False, "forceRecreate": True},
        ),
        (
            {"pull": False, "build": True, "force_recreate": True},
            {"pull": False, "build": True, "forceRecreate": True},
        ),
    ],
)
@pytest.mark.asyncio
async def test_stack_action_deploy_flags_reach_the_body(mock_env, kwargs, expected):
    with respx.mock(base_url=ENDPOINT) as mock:
        deploy = mock.post("/api/stacks/searxng/deploy").mock(
            return_value=httpx.Response(200, json={"success": True, "output": "ok"})
        )

        await server.stack_action(stack_name="searxng", action="deploy", **kwargs)

        assert json.loads(deploy.calls[0].request.content) == expected


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
@pytest.mark.parametrize("flag", ["pull", "build", "force_recreate"])
@pytest.mark.asyncio
async def test_stack_action_rejects_deploy_flags_on_bodyless_actions(
    mock_env, action, flag
):
    """Silently dropping the flag would report it as honoured when Dockhand
    never received it — the route sends no body at all."""
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = mock.post(f"/api/stacks/searxng/{action}").mock(
            return_value=httpx.Response(200, json=JOB_QUEUED)
        )

        result = await server.stack_action(
            stack_name="searxng", action=action, **{flag: False}
        )

        assert flag in result["error"]
        assert "deploy" in result["error"]
        # Rejected before the request, not after.
        assert route.call_count == 0


@pytest.mark.asyncio
async def test_stack_action_deploy_is_not_polled(mock_env):
    """Per the v1.0.46 spec, jobId is documented on start/stop/down — not deploy.
    Nothing should be polled when the route answers directly."""
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        mock.post("/api/stacks/searxng/deploy").mock(
            return_value=httpx.Response(200, json={"success": True, "output": "ok"})
        )
        jobs = mock.get(f"/api/jobs/{JOB_QUEUED['jobId']}").mock(
            return_value=httpx.Response(200, json=JOB_DONE_SUCCESS)
        )

        result = await server.stack_action(
            stack_name="searxng", action="deploy", pull=False
        )

        assert jobs.call_count == 0
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
async def test_check_updates_sends_env_and_returns_the_final_result(mock_env):
    """This route is synchronous for us and returns no jobId.

    It documents a text/event-stream job feed "or, with Accept: application/json,
    the final result as plain JSON", and client.py sets that header on every
    request. The previous version of this test mocked a {"jobId": ...} response
    and asserted the tool surfaced it — a shape Dockhand never sends here, and
    every real call in the service's logs recorded an empty job id.
    """
    final_result = {"total": 124, "updatesFound": 27, "results": []}
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = mock.post("/api/containers/check-updates").mock(
            return_value=httpx.Response(200, json=final_result)
        )
        jobs = mock.get(f"/api/jobs/{JOB_QUEUED['jobId']}").mock(
            return_value=httpx.Response(200, json=JOB_DONE_SUCCESS)
        )

        result = await server.check_updates()

        assert _env_of(route) == "1"
        assert result["updatesFound"] == 27
        assert "jobId" not in result
        assert jobs.call_count == 0


# update_container previously posted {"repullImage", "startAfterUpdate"} to
# /api/containers/{id}/update, and the test here asserted that exact body. The
# route destructures {startAfterUpdate, repullImage, ...options} and then calls
# pullImage(options.image), so every call 500'd on
# "Cannot read properties of undefined (reading 'includes')" — the tool never
# once succeeded, and the test pinned the defect in place (vikunja#702).
#
# These replacements are written against openapi-v1.0.46.json's contract for
# POST /api/containers/batch-update, not against what the code does.

@pytest.mark.asyncio
async def test_update_container_posts_batch_update(mock_env):
    """The body is {containerIds: [id]} and env stays in the query string."""
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.post("/api/containers/batch-update").mock(
            return_value=httpx.Response(200, json=BATCH_UPDATE_SUCCESS)
        )

        result = await server.update_container(container_id="abc123def456")

        assert _env_of(route) == "1"
        body = json.loads(route.calls[0].request.content)
        assert body == {"containerIds": ["abc123def456"]}

        # Unwrapped to the single container, not the batch envelope.
        assert result["success"] is True
        assert result["containerName"] == "nginx"
        assert "results" not in result
        assert "summary" not in result


@pytest.mark.asyncio
async def test_update_container_never_calls_the_update_route(mock_env):
    """Regression guard for vikunja#702.

    The old route is registered here purely so a call to it would be recorded
    rather than raising as an unmocked request — the assertion is that it is
    never reached.
    """
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        broken = mock.post("/api/containers/abc123def456/update").mock(
            return_value=httpx.Response(200, json=JOB_QUEUED)
        )
        fixed = mock.post("/api/containers/batch-update").mock(
            return_value=httpx.Response(200, json=BATCH_UPDATE_SUCCESS)
        )

        await server.update_container(container_id="abc123def456")

        assert broken.call_count == 0
        # Without this the test passes just as well when the tool makes no
        # request at all — an early return would look like a fixed route.
        assert fixed.call_count == 1


@pytest.mark.asyncio
async def test_update_container_surfaces_a_skip_distinctly(mock_env):
    """dockhand.update=false comes back as success+error; it must not read as an
    update that happened."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/containers/batch-update").mock(
            return_value=httpx.Response(200, json=BATCH_UPDATE_SKIPPED)
        )

        result = await server.update_container(container_id="abc123def456")

        assert result["skipped"] is True
        assert "dockhand.update=false" in result["reason"]
        # Callers read a bare `error` key as a tool failure; a skip is not one.
        assert "error" not in result


@pytest.mark.asyncio
async def test_update_container_reports_a_real_failure(mock_env):
    """A genuine per-container failure keeps success=False and its error text."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/containers/batch-update").mock(
            return_value=httpx.Response(200, json=BATCH_UPDATE_FAILED)
        )

        result = await server.update_container(container_id="abc123def456")

        assert result["success"] is False
        assert "Failed to pull image" in result["error"]
        assert "skipped" not in result


@pytest.mark.asyncio
async def test_update_container_returns_the_recreated_id(mock_env):
    """A successful update returns the NEW container id, not the requested one.

    Measured live on Dockhand v1.0.46: the container is destroyed and recreated,
    so matching the result on the requested id fails on exactly the path that
    worked. The single-result case must therefore not depend on an id match.
    """
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/containers/batch-update").mock(
            return_value=httpx.Response(200, json=BATCH_UPDATE_SUCCESS)
        )

        result = await server.update_container(container_id="abc123def456")

        assert result["success"] is True
        assert result["containerId"] == "f00dcafe9999"
        assert result["containerId"] != "abc123def456"


@pytest.mark.asyncio
async def test_update_container_picks_our_result_from_several(mock_env):
    """With more results than ids sent, the right one is identified by id —
    tolerating the full 64-char form echoed for a 12-char request."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/containers/batch-update").mock(
            return_value=httpx.Response(200, json=BATCH_UPDATE_MULTI)
        )

        result = await server.update_container(container_id="abc123def456")

        assert result["containerName"] == "nginx"


@pytest.mark.asyncio
async def test_update_container_flags_an_empty_result_set(mock_env):
    """An empty results array must not read as a successful update."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/containers/batch-update").mock(
            return_value=httpx.Response(
                200,
                json={"success": True, "results": [], "summary": {"total": 0, "success": 0, "failed": 0}},
            )
        )

        result = await server.update_container(container_id="abc123def456")

        assert result["success"] is False
        assert "no batch-update result" in result["error"]
