"""
Tests for DockhandClient — auth injection, error handling, env resolution,
and async job polling.
"""

import httpx
import pytest
import respx

from dockhand_mcp.client import DockhandClient, DockhandConfigError, DockhandError

from .conftest import (
    API_TOKEN,
    ENDPOINT,
    HEALTH_RESPONSE,
    JOB_DONE_FAILURE,
    JOB_DONE_SUCCESS,
)

# ---------------------------------------------------------------------------
# Auth injection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bearer_token_sent_on_get(mock_env):
    """GET requests include Authorization: Bearer <token>."""
    with respx.mock(base_url=ENDPOINT) as mock:
        health = mock.get("/api/health").mock(
            return_value=httpx.Response(200, json=HEALTH_RESPONSE)
        )

        client = DockhandClient()
        await client.get("/api/health")

        req = health.calls[0].request
        assert req.headers.get("authorization") == f"Bearer {API_TOKEN}"
        await client.close()


@pytest.mark.asyncio
async def test_bearer_token_sent_on_post(mock_env):
    """POST requests include Authorization: Bearer <token>."""
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.post("/api/containers/check-updates").mock(
            return_value=httpx.Response(200, json={"jobId": "j1"})
        )

        client = DockhandClient()
        await client.post("/api/containers/check-updates")

        req = route.calls[0].request
        assert req.headers.get("authorization") == f"Bearer {API_TOKEN}"
        await client.close()


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_4xx_raises_dockhand_error(mock_env):
    """4xx responses raise DockhandError with the error message."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/containers/nonexistent/start").mock(
            return_value=httpx.Response(404, json={"error": "Container not found"})
        )

        client = DockhandClient()
        with pytest.raises(DockhandError) as exc_info:
            await client.post("/api/containers/nonexistent/start")

        assert exc_info.value.status_code == 404
        assert "Container not found" in str(exc_info.value)
        await client.close()


@pytest.mark.asyncio
async def test_5xx_raises_dockhand_error(mock_env):
    """5xx responses raise DockhandError."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers").mock(
            return_value=httpx.Response(500, json={"error": "Internal server error"})
        )

        client = DockhandClient()
        with pytest.raises(DockhandError) as exc_info:
            await client.get("/api/containers")

        assert exc_info.value.status_code == 500
        await client.close()


@pytest.mark.asyncio
async def test_error_with_message_field(mock_env):
    """Dockhand 500s use a 'message' field (e.g. the empty-body deploy error)."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/stacks/x/deploy").mock(
            return_value=httpx.Response(
                500, json={"message": "Unexpected end of JSON input", "code": "INTERNAL_ERROR"}
            )
        )

        client = DockhandClient()
        with pytest.raises(DockhandError) as exc_info:
            await client.post("/api/stacks/x/deploy")

        assert "Unexpected end of JSON input" in str(exc_info.value)
        await client.close()


# ---------------------------------------------------------------------------
# Environment resolution (arg -> DOCKHAND_DEFAULT_ENV -> error)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_env_uses_default(mock_env):
    """resolve_env falls back to DOCKHAND_DEFAULT_ENV and returns an int."""
    client = DockhandClient()
    assert client.resolve_env() == 1
    assert client.resolve_env(None) == 1
    await client.close()


@pytest.mark.asyncio
async def test_resolve_env_arg_overrides_default(mock_env):
    """An explicit environment_id argument wins over the default."""
    client = DockhandClient()
    assert client.resolve_env("2") == 2
    assert client.resolve_env(3) == 3
    await client.close()


@pytest.mark.asyncio
async def test_resolve_env_missing_raises_config_error(monkeypatch):
    """No arg and no DOCKHAND_DEFAULT_ENV raises DockhandConfigError."""
    monkeypatch.setenv("DOCKHAND_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("DOCKHAND_API_TOKEN", API_TOKEN)
    monkeypatch.delenv("DOCKHAND_DEFAULT_ENV", raising=False)

    client = DockhandClient()
    with pytest.raises(DockhandConfigError) as exc_info:
        client.resolve_env()
    assert "DOCKHAND_DEFAULT_ENV" in str(exc_info.value)
    await client.close()


@pytest.mark.asyncio
async def test_resolve_env_non_integer_raises_config_error(monkeypatch):
    """A non-integer environment id raises DockhandConfigError."""
    monkeypatch.setenv("DOCKHAND_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("DOCKHAND_API_TOKEN", API_TOKEN)
    monkeypatch.setenv("DOCKHAND_DEFAULT_ENV", "forge")  # not an int

    client = DockhandClient()
    with pytest.raises(DockhandConfigError) as exc_info:
        client.resolve_env()
    assert "integer" in str(exc_info.value)
    await client.close()


# ---------------------------------------------------------------------------
# Async job polling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_poll_job_returns_success_result(mock_env):
    """poll_job returns the terminal result dict for a done+success job."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get(f"/api/jobs/{JOB_DONE_SUCCESS['id']}").mock(
            return_value=httpx.Response(200, json=JOB_DONE_SUCCESS)
        )

        client = DockhandClient()
        result = await client.poll_job(JOB_DONE_SUCCESS["id"])

        assert result["success"] is True
        assert "Started" in result["output"]
        await client.close()


@pytest.mark.asyncio
async def test_poll_job_returns_failure_result(mock_env):
    """poll_job surfaces a done+failure job's error rather than a false success."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get(f"/api/jobs/{JOB_DONE_FAILURE['id']}").mock(
            return_value=httpx.Response(200, json=JOB_DONE_FAILURE)
        )

        client = DockhandClient()
        result = await client.poll_job(JOB_DONE_FAILURE["id"])

        assert result["success"] is False
        assert "Failed to restart" in result["error"]
        await client.close()


@pytest.mark.asyncio
async def test_poll_job_waits_for_done(mock_env):
    """poll_job keeps polling while status is running, then returns the result."""
    with respx.mock(base_url=ENDPOINT) as mock:
        running = {"id": JOB_DONE_SUCCESS["id"], "status": "running", "lines": []}
        mock.get(f"/api/jobs/{JOB_DONE_SUCCESS['id']}").mock(
            side_effect=[
                httpx.Response(200, json=running),
                httpx.Response(200, json=JOB_DONE_SUCCESS),
            ]
        )

        client = DockhandClient()
        result = await client.poll_job(JOB_DONE_SUCCESS["id"], interval=0.01)

        assert result["success"] is True
        await client.close()


@pytest.mark.asyncio
async def test_poll_job_rejects_malformed_job_id(mock_env):
    """A job id that isn't a plain identifier is refused before any request is
    made — it must not be interpolated into the /api/jobs/{id} URL path."""
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = mock.get(url__regex=r".*").mock(
            return_value=httpx.Response(200, json={"status": "done", "result": {}})
        )

        client = DockhandClient()
        result = await client.poll_job("../../secret")

        assert route.call_count == 0
        assert result["success"] is False
        assert "malformed job id" in result["error"]
        await client.close()


@pytest.mark.asyncio
async def test_poll_job_timeout_returns_failure(mock_env):
    """poll_job returns a synthetic failure (not a hang) if the job never finishes."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get(f"/api/jobs/{JOB_DONE_SUCCESS['id']}").mock(
            return_value=httpx.Response(200, json={"id": JOB_DONE_SUCCESS["id"], "status": "running"})
        )

        client = DockhandClient()
        result = await client.poll_job(
            JOB_DONE_SUCCESS["id"], timeout=0.0, interval=0.01
        )

        assert result["success"] is False
        assert "did not complete" in result["error"]
        await client.close()
