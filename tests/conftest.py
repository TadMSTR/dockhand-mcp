"""Shared fixtures for dockhand-mcp tests."""

import pytest
import dockhand_mcp.client as client_module

ENDPOINT = "http://localhost:7777"
API_TOKEN = "test-token-abc123"
DEFAULT_ENV = "1"

HEALTH_RESPONSE = {"status": "ok", "timestamp": "2026-05-25T12:00:00.000Z"}

CONTAINERS_RESPONSE = [
    {
        "id": "abc123def456",
        "name": "nginx",
        "image": "nginx:latest",
        "status": "running",
        "state": "running",
        "environmentId": 1,
        "environmentName": "forge",
    },
    {
        "id": "def456ghi789",
        "name": "postgres",
        "image": "postgres:16",
        "status": "running",
        "state": "running",
        "environmentId": 1,
        "environmentName": "forge",
    },
]

STACKS_RESPONSE = [
    {"name": "nginx-proxy", "status": "running", "containerCount": 3, "environmentId": 1},
    {"name": "monitoring", "status": "running", "containerCount": 5, "environmentId": 1},
]

JOB_RESPONSE = {"jobId": "job-xyz-789"}

ACTIVITY_RESPONSE = {
    "events": [
        {
            "id": 1,
            "containerId": "abc123def456",
            "containerName": "nginx",
            "image": "nginx:latest",
            "action": "start",
            "timestamp": "2026-05-25T11:00:00Z",
            "environmentName": "forge",
        }
    ],
    "total": 1,
    "limit": 20,
    "offset": 0,
}

SCAN_RESPONSE = {
    "imageName": "nginx:latest",
    "vulnerabilities": {
        "critical": 0,
        "high": 2,
        "medium": 5,
        "low": 10,
    },
    "findings": [],
}


@pytest.fixture(autouse=True)
def reset_client_singleton():
    client_module._client = None
    yield
    if client_module._client:
        import asyncio
        asyncio.get_event_loop().run_until_complete(client_module._client.close())
    client_module._client = None


@pytest.fixture
def mock_env(monkeypatch):
    monkeypatch.setenv("DOCKHAND_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("DOCKHAND_API_TOKEN", API_TOKEN)
    monkeypatch.setenv("DOCKHAND_DEFAULT_ENV", DEFAULT_ENV)
