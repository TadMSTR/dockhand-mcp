"""
Transport + endpoint-auth tests for the HTTP/PM2 migration.

``main()`` reads module-level config (``_TRANSPORT``, ``_HTTP_*``, ``_BEARER``)
evaluated at import time. These tests patch those globals directly and mock
``mcp.run`` — the same shape as githost-mcp's transport tests — so no live socket
is bound. The stdio path must stay a bare ``mcp.run()`` for local dev.
"""

from __future__ import annotations

import importlib

import pytest

from dockhand_mcp import server


@pytest.fixture
def patch_run(monkeypatch):
    """Replace mcp.run with a recorder so main() never binds a socket."""
    calls = {}

    def fake_run(*args, **kwargs):
        calls["args"] = args
        calls["kwargs"] = kwargs

    monkeypatch.setattr(server.mcp, "run", fake_run)
    return calls


# ---------------------------------------------------------------------------
# Transport switch
# ---------------------------------------------------------------------------

def test_stdio_is_the_default_and_calls_plain_run(patch_run, monkeypatch):
    monkeypatch.setattr(server, "_TRANSPORT", "stdio")
    server.main()
    assert patch_run["args"] == ()
    assert patch_run["kwargs"] == {}


def test_http_runs_with_loopback_host_port_path(patch_run, monkeypatch):
    monkeypatch.setattr(server, "_TRANSPORT", "http")
    monkeypatch.setattr(server, "_HTTP_HOST", "127.0.0.1")
    monkeypatch.setattr(server, "_HTTP_PORT", 8505)
    monkeypatch.setattr(server, "_HTTP_PATH", "/mcp")
    monkeypatch.setattr(server, "_BEARER", "0123456789abcdef0123")
    server.main()
    assert patch_run["kwargs"] == {
        "transport": "http",
        "host": "127.0.0.1",
        "port": 8505,
        "path": "/mcp",
    }


# ---------------------------------------------------------------------------
# HTTP fail-closed guards
# ---------------------------------------------------------------------------

def test_http_without_bearer_refuses_to_start(patch_run, monkeypatch):
    monkeypatch.setattr(server, "_TRANSPORT", "http")
    monkeypatch.setattr(server, "_BEARER", "")
    with pytest.raises(RuntimeError, match="without DOCKHAND_MCP_BEARER"):
        server.main()
    assert patch_run == {}  # run never reached


def test_http_short_bearer_refuses_to_start(patch_run, monkeypatch):
    monkeypatch.setattr(server, "_TRANSPORT", "http")
    monkeypatch.setattr(server, "_BEARER", "tooshort")
    with pytest.raises(RuntimeError, match="too short"):
        server.main()
    assert patch_run == {}


def test_http_nonloopback_host_refuses_to_start(patch_run, monkeypatch):
    monkeypatch.setattr(server, "_TRANSPORT", "http")
    monkeypatch.setattr(server, "_HTTP_HOST", "0.0.0.0")
    monkeypatch.setattr(server, "_BEARER", "0123456789abcdef0123")
    with pytest.raises(RuntimeError, match="non-loopback"):
        server.main()
    assert patch_run == {}


# ---------------------------------------------------------------------------
# Auth wiring (evaluated at import time)
# ---------------------------------------------------------------------------

def test_bearer_env_builds_static_token_verifier(monkeypatch):
    """With DOCKHAND_MCP_BEARER set, the FastMCP server is constructed with a
    StaticTokenVerifier so the HTTP endpoint rejects unauthenticated callers."""
    from fastmcp.server.auth import StaticTokenVerifier

    monkeypatch.setenv("DOCKHAND_MCP_BEARER", "0123456789abcdef0123")
    reloaded = importlib.reload(server)
    try:
        assert isinstance(reloaded._auth, StaticTokenVerifier)
    finally:
        # Restore the unauthenticated default so later tests see a clean module.
        monkeypatch.delenv("DOCKHAND_MCP_BEARER", raising=False)
        importlib.reload(server)


def test_no_bearer_means_no_auth(monkeypatch):
    monkeypatch.delenv("DOCKHAND_MCP_BEARER", raising=False)
    reloaded = importlib.reload(server)
    assert reloaded._auth is None


def test_tool_tracing_middleware_registered():
    assert any(
        type(m).__name__ == "ToolTracingMiddleware" for m in server.mcp.middleware
    )
