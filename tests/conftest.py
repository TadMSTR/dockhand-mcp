"""Shared fixtures for dockhand-mcp tests.

Fixtures encode Dockhand's real REST contract: every endpoint resolves the
environment from the ``?env=<int>`` query param, and action endpoints run
asynchronously — returning ``{"jobId": ...}`` and exposing a terminal result via
``GET /api/jobs/{jobId}``.
"""

import pytest

import dockhand_mcp.client as client_module

ENDPOINT = "http://localhost:7777"
API_TOKEN = "test-token-abc123"
DEFAULT_ENV = "1"

HEALTH_RESPONSE = {"status": "ok", "timestamp": "2026-05-25T12:00:00.000Z"}

# Dockhand returns a bare array; the MCP counts running via state/status.
CONTAINERS_RESPONSE = [
    {"id": "abc123def456", "name": "nginx", "image": "nginx:latest", "state": "running"},
    {"id": "def456ghi789", "name": "postgres", "image": "postgres:16", "state": "running"},
    {"id": "ghi789jkl012", "name": "redis", "image": "redis:7", "state": "exited"},
]

STACKS_RESPONSE = [
    {"name": "searxng", "status": "running", "containers": ["a", "b", "c"]},
    {"name": "monitoring", "status": "running", "containers": ["d", "e"]},
]

# What an action endpoint returns synchronously — just the async job handle.
JOB_ID = "job-xyz-789"
JOB_QUEUED = {"jobId": JOB_ID}

# What GET /api/jobs/{jobId} returns once the async job finishes.
JOB_DONE_SUCCESS = {
    "id": JOB_ID,
    "status": "done",
    "lines": [
        {"event": "progress", "data": {"status": "Deploying stack..."}},
        {"event": "result", "data": {"success": True, "output": " Container x Started \n"}},
    ],
    "result": {"success": True, "output": " Container x Started \n"},
}
JOB_DONE_FAILURE = {
    "id": JOB_ID,
    "status": "done",
    "lines": [
        {"event": "result", "data": {"success": False, "error": "Failed to restart compose stack"}},
    ],
    "result": {"success": False, "error": "Failed to restart compose stack"},
}

# POST /api/containers/batch-update answers SYNCHRONOUSLY with a per-container
# result set and no jobId — shapes taken from openapi-v1.0.46.json, whose 200
# schema requires {success, results, summary} and, per result,
# {containerId, containerName, success} with an optional {error}.
#
# The returned containerId depends on what happened, measured live against
# Dockhand v1.0.46 on 2026-09-07:
#   success -> the NEW id, because the container was recreated
#   skip/failure -> the requested id, because nothing was recreated
# Fixtures below reproduce that asymmetry. A success fixture echoing the
# requested id back would be a shape Dockhand never actually produces.
REQUESTED_ID = "abc123def456"
RECREATED_ID = "f00dcafe9999"

BATCH_UPDATE_SUCCESS = {
    "success": True,
    "results": [
        {"containerId": RECREATED_ID, "containerName": "nginx", "success": True},
    ],
    "summary": {"total": 1, "success": 1, "failed": 0},
}

# A container labelled dockhand.update=false comes back as a SUCCESS carrying an
# error string. Kept as its own fixture rather than a flag on the one above:
# telling this apart from a real update is the whole point of the skip handling.
# The error text is the literal string Dockhand returned in the live check.
BATCH_UPDATE_SKIPPED = {
    "success": True,
    "results": [
        {
            "containerId": REQUESTED_ID,
            "containerName": "nginx",
            "success": True,
            "error": "Skipped - dockhand.update=false label",
        },
    ],
    "summary": {"total": 1, "success": 1, "failed": 0},
}

BATCH_UPDATE_FAILED = {
    "success": False,
    "results": [
        {
            "containerId": REQUESTED_ID,
            "containerName": "nginx",
            "success": False,
            "error": "Failed to pull image nginx:latest",
        },
    ],
    "summary": {"total": 1, "success": 0, "failed": 1},
}

# More results than ids sent — the only case where id matching decides the
# answer. Dockhand echoes the full 64-char id for a 12-char request, so the
# match has to tolerate the prefix.
BATCH_UPDATE_MULTI = {
    "success": True,
    "results": [
        {"containerId": "999888777666" + "0" * 52, "containerName": "other", "success": True},
        {"containerId": REQUESTED_ID + "0" * 52, "containerName": "nginx", "success": True},
    ],
    "summary": {"total": 2, "success": 2, "failed": 0},
}

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
    "vulnerabilities": {"critical": 0, "high": 2, "medium": 5, "low": 10},
    "findings": [],
}


@pytest.fixture(autouse=True)
async def reset_client_singleton():
    """Reset the module-level client between tests and close it in the test's own
    event loop to avoid leaking httpx connections across loops."""
    client_module._client = None
    yield
    c = client_module._client
    client_module._client = None
    if c is not None:
        await c.close()


@pytest.fixture
def mock_env(monkeypatch):
    monkeypatch.setenv("DOCKHAND_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("DOCKHAND_API_TOKEN", API_TOKEN)
    monkeypatch.setenv("DOCKHAND_DEFAULT_ENV", DEFAULT_ENV)
