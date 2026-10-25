"""
Protocol-layer tests: the tools as an MCP client sees them, through
``fastmcp.Client(server.mcp)`` rather than as Python functions.

Every other module calls ``server.<tool>(...)`` directly, which skips the
argument validation fastmcp does from each tool's schema. That gap is how an
integer ``environment_id`` was rejected for every agent while 216 tests passed
(vikunja#1239 item 2).
"""

from __future__ import annotations

import importlib
import inspect

import httpx
import pytest
import respx
from fastmcp import Client

from dockhand_mcp import server

from .conftest import ENDPOINT, STACKS_RESPONSE
from .test_tool_errors_and_metrics import ALL_TOOLS


async def test_list_tools_is_exactly_the_tool_roster():
    async with Client(server.mcp) as client:
        tools = await client.list_tools()
    assert {t.name for t in tools} == {name for name, _ in ALL_TOOLS}


async def test_every_input_schema_matches_its_signature():
    """The schema an agent is shown is the signature, parameter for parameter,
    and the required set is exactly the parameters without a default."""
    async with Client(server.mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
    for name, tool in tools.items():
        fn = getattr(server, name)
        fn = getattr(fn, "fn", fn)
        params = inspect.signature(fn).parameters
        schema = tool.inputSchema
        assert set(schema.get("properties", {})) == set(params), name
        required = {p for p, v in params.items() if v.default is inspect.Parameter.empty}
        assert set(schema.get("required", [])) == required, name


def _accepts(schema: dict, json_type: str) -> bool:
    if schema.get("type") == json_type:
        return True
    return any(_accepts(s, json_type) for s in schema.get("anyOf", []))


async def test_environment_id_accepts_an_integer_and_a_string_everywhere():
    async with Client(server.mcp) as client:
        tools = await client.list_tools()
    with_env = [t for t in tools if "environment_id" in t.inputSchema.get("properties", {})]
    assert with_env, "no tool takes environment_id"
    for tool in with_env:
        prop = tool.inputSchema["properties"]["environment_id"]
        assert _accepts(prop, "integer"), tool.name
        assert _accepts(prop, "string"), tool.name


@pytest.mark.parametrize("env_arg", [2, "2"])
async def test_call_tool_with_an_integer_env_sends_it(mock_env, env_arg):
    """The reproduction from #1239: this failed pydantic validation at the MCP
    layer before any request was made."""
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/stacks").mock(return_value=httpx.Response(200, json=STACKS_RESPONSE))
        async with Client(server.mcp) as client:
            result = await client.call_tool("list_stacks", {"environment_id": env_arg})

    assert route.calls[0].request.url.params["env"] == "2"
    assert result.data["total"] == 2


async def test_stack_action_refusal_reaches_the_client_as_data(mock_env):
    """The guard's refusal is a normal result, not a protocol error, so the
    agent reads the reason and the remedy."""
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = mock.route(method="POST", path__startswith="/api/stacks/").mock(
            return_value=httpx.Response(200, json={"success": True})
        )
        async with Client(server.mcp) as client:
            result = await client.call_tool(
                "stack_action", {"stack_name": "searxng", "action": "deploy"}
            )

    assert route.call_count == 0
    assert result.data["acknowledge_env_log_required"] is True
    assert "system-ops" in result.data["error"]


@pytest.fixture
def authed_server(monkeypatch):
    """The server module rebuilt with a bearer, as PM2 runs it."""
    monkeypatch.setenv("DOCKHAND_MCP_BEARER", "right-bearer-0123456789abcdef")
    reloaded = importlib.reload(server)
    try:
        yield reloaded
    finally:
        monkeypatch.delenv("DOCKHAND_MCP_BEARER", raising=False)
        importlib.reload(server)


async def test_http_transport_rejects_a_wrong_bearer(authed_server):
    import httpx2

    app = authed_server.mcp.http_app(path="/mcp")
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    headers = {"Accept": "application/json, text/event-stream"}
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
    ) as http:
        wrong = await http.post(
            "/mcp", json=body, headers={**headers, "Authorization": "Bearer wrong-bearer"}
        )
        missing = await http.post("/mcp", json=body, headers=headers)

    assert wrong.status_code == 401
    assert missing.status_code == 401


async def test_http_transport_accepts_the_right_bearer(authed_server):
    from fastmcp.utilities.tests import asgi_client

    async with asgi_client(authed_server.mcp, auth="right-bearer-0123456789abcdef") as client:
        tools = await client.list_tools()
    assert "list_stacks" in {t.name for t in tools}
