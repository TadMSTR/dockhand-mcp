"""
Tests for DockhandClient — auth injection, error handling, action routing.
"""

import pytest
import respx
import httpx

from dockhand_mcp.client import DockhandClient, DockhandError, DockhandConfigError

from .conftest import (
    ENDPOINT,
    API_TOKEN,
    HEALTH_RESPONSE,
    CONTAINERS_RESPONSE,
    JOB_RESPONSE,
    ACTIVITY_RESPONSE,
    SCAN_RESPONSE,
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
            return_value=httpx.Response(200, json=JOB_RESPONSE)
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
async def test_error_with_details_field(mock_env):
    """Error responses with 'details' field include details in the message."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/containers/abc/update").mock(
            return_value=httpx.Response(
                500,
                json={"error": "Failed to update container", "details": "No environment specified"},
            )
        )

        client = DockhandClient()
        with pytest.raises(DockhandError) as exc_info:
            await client.post("/api/containers/abc/update")

        assert "No environment specified" in str(exc_info.value)
        await client.close()


@pytest.mark.asyncio
async def test_missing_env_raises_config_error(monkeypatch):
    """Missing DOCKHAND_DEFAULT_ENV raises DockhandConfigError when accessed."""
    monkeypatch.setenv("DOCKHAND_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("DOCKHAND_API_TOKEN", API_TOKEN)
    monkeypatch.delenv("DOCKHAND_DEFAULT_ENV", raising=False)

    client = DockhandClient()
    with pytest.raises(DockhandConfigError) as exc_info:
        client.default_env_id()

    assert "DOCKHAND_DEFAULT_ENV" in str(exc_info.value)
    await client.close()


# ---------------------------------------------------------------------------
# Container action routing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_container_remove_uses_delete(mock_env):
    """container_action 'remove' uses DELETE, not POST."""
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        delete_route = mock.delete("/api/containers/abc123").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        post_route = mock.post("/api/containers/abc123/remove").mock(
            return_value=httpx.Response(200, json={})
        )

        client = DockhandClient()
        await client.delete("/api/containers/abc123")

        assert delete_route.call_count == 1
        assert post_route.call_count == 0
        await client.close()


@pytest.mark.asyncio
async def test_container_start_uses_post(mock_env):
    """container_action 'start' uses POST /api/containers/{id}/start."""
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.post("/api/containers/abc123/start").mock(
            return_value=httpx.Response(200, json=JOB_RESPONSE)
        )

        client = DockhandClient()
        resp = await client.post("/api/containers/abc123/start")

        assert route.call_count == 1
        assert resp.json() == JOB_RESPONSE
        await client.close()


# ---------------------------------------------------------------------------
# Scan and update body
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_sends_image_name(mock_env):
    """scan_image sends {'imageName': ...} in the request body."""
    import json

    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.post("/api/images/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE)
        )

        client = DockhandClient()
        await client.post("/api/images/scan", json={"imageName": "nginx:latest"})

        body = json.loads(route.calls[0].request.content)
        assert body["imageName"] == "nginx:latest"
        await client.close()


@pytest.mark.asyncio
async def test_update_container_sends_env_id(mock_env):
    """update_container sends environmentId in the request body."""
    import json

    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.post("/api/containers/abc123/update").mock(
            return_value=httpx.Response(200, json=JOB_RESPONSE)
        )

        client = DockhandClient()
        await client.post("/api/containers/abc123/update", json={"environmentId": 1})

        body = json.loads(route.calls[0].request.content)
        assert body["environmentId"] == 1
        await client.close()
