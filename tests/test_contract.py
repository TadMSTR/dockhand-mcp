"""
The 0.8.0 contract (dockhand-2026-10 p2): every tool returns an error dict
whatever the transport does, stack_action refuses without acknowledge_env_log,
env-file dumps never come back unmasked, DOCKHAND_ALLOWED_ENVS holds, and the
destructive tools make no request on bad input.

"Zero requests" is asserted by registering a catch-all route and checking its
call count. A test that only checked the returned error would pass just as well
if the request had gone out first.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from dockhand_mcp import server
from dockhand_mcp.redaction import (
    ENV_DUMP_PLACEHOLDER,
    mask_env_dump,
    redact_compose,
    redact_value,
    scrub_strings,
)

from .conftest import (
    BATCH_UPDATE_SUCCESS,
    ENDPOINT,
    FULL_ID,
    INSPECT_FOR_RESOLVE,
    STACKS_RESPONSE,
)
from .test_tool_errors_and_metrics import ALL_TOOLS

CANARY = "dhcanary-5e1f00d5"
ML_CANARY = "dhcanaryml-0b5e55ed"


def _catch_all(mock, response=None, side_effect=None):
    route = mock.route()
    if side_effect is not None:
        return route.mock(side_effect=side_effect)
    return route.mock(return_value=response or httpx.Response(200, json={}))


# ---------------------------------------------------------------------------
# Transport: every tool x {ReadTimeout, ConnectError, HTML 200}
# ---------------------------------------------------------------------------

_FAILURES = {
    "read_timeout": {"side_effect": httpx.ReadTimeout("timed out")},
    "connect_error": {"side_effect": httpx.ConnectError("refused")},
    "html_200": {
        "response": httpx.Response(
            200, text="<html>login</html>", headers={"content-type": "text/html"}
        )
    },
}


@pytest.mark.parametrize("failure", sorted(_FAILURES))
@pytest.mark.parametrize("tool_name,kwargs", ALL_TOOLS)
async def test_every_tool_returns_an_error_dict_on_transport_failure(
    mock_env, monkeypatch, tool_name, kwargs, failure
):
    logged = []
    monkeypatch.setattr(server.log, "error", lambda event, **kw: logged.append((event, kw)))
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        _catch_all(mock, **_FAILURES[failure])
        result = await getattr(server, tool_name)(**kwargs)

    assert isinstance(result, dict), f"{tool_name} returned {result!r}"
    assert "error" in result, f"{tool_name} returned {result!r}"
    assert "Dockhand error 0" in result["error"]
    assert [e for e, _ in logged] == ["tool_error"]
    assert logged[0][1]["tool"] == tool_name
    assert logged[0][1]["status_code"] == 0


async def test_an_http_error_keeps_its_status(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/stacks").mock(return_value=httpx.Response(503, json={"error": "down"}))
        result = await server.list_stacks()
    assert result["error"] == "Dockhand error 503: down"


# ---------------------------------------------------------------------------
# stack_action guard (#1237)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["start", "stop", "restart", "deploy"])
@pytest.mark.parametrize("ack", [False, None, "true", 1])
async def test_stack_action_without_the_flag_makes_zero_requests(mock_env, action, ack):
    """Only a real boolean true acknowledges. A truthy string or int that slipped
    past validation must not."""
    kwargs = {} if ack is None else {"acknowledge_env_log": ack}
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = _catch_all(mock)
        result = await server.stack_action(stack_name="searxng", action=action, **kwargs)

    assert route.call_count == 0
    assert result["acknowledge_env_log_required"] is True
    assert ".env" in result["error"]
    assert "system-ops" in result["error"]
    assert "acknowledge_env_log=true" in result["error"]


@pytest.mark.parametrize("action", ["start", "stop", "restart", "deploy"])
async def test_stack_action_with_the_flag_sends_the_request(mock_env, action):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.post(f"/api/stacks/searxng/{action}").mock(
            return_value=httpx.Response(200, json={"success": True, "output": ""})
        )
        result = await server.stack_action(
            stack_name="searxng", action=action, acknowledge_env_log=True
        )

    assert route.call_count == 1
    assert result["success"] is True
    if action == "deploy":
        assert json.loads(route.calls[0].request.content)["pull"] is False


# ---------------------------------------------------------------------------
# Masking (audit F-02)
# ---------------------------------------------------------------------------

_TS = "2026-10-25T19:58:29.305804067Z 2026-10-25T19:58:29.305Z INFO  "


def _dump(*content: str, end: bool = True) -> str:
    lines = [
        f"{_TS}[Git] ----------------------------------------",
        f"{_TS}[Git] PARSE ENV FILE CONTENT",
        f"{_TS}[Git] ----------------------------------------",
        f"{_TS}[Git] Raw content length: 99 chars",
        f"{_TS}[Git] Raw content:",
        f"{_TS}{content[0]}",
        *[f"2026-10-25T19:58:29.305836799Z {c}" for c in content[1:]],
    ]
    if end:
        lines.append(f"{_TS}[Git] Total lines: {len(content)}")
        lines.append(f"{_TS}[Git] Parsed env var keys: A")
    return "\n".join(lines)


_SKIPPED = (
    f"{_TS}[Git] Skipped lines (3): Line 2: # OLD_TOKEN={CANARY}...; "
    f'Line 5 (no =): {ML_CANARY}; Line 6 (no =): last"'
)

MASK_CASES = {
    "single_line": _dump(f"DB_PASSWORD={CANARY}", "PLAIN=1"),
    "multi_line_quoted": _dump("A=1", 'CERT="-----BEGIN', ML_CANARY, '-----END"'),
    "commented": _dump(f"# OLD_TOKEN={CANARY}", "A=1"),
    "dot_key": _dump(f"my.app-key={CANARY}"),
    "truncated_no_end": _dump("A=1", f"B={CANARY}", 'C="x', ML_CANARY, end=False),
    # Dockhand's own tail cut the head off the block.
    "truncated_no_start": "\n".join(
        [
            f"2026-10-25T19:58:29.305836799Z {ML_CANARY}",
            '2026-10-25T19:58:29.305836799Z last"',
            f"{_TS}[Git] Total lines: 6",
            "after",
        ]
    ),
    "skipped_lines_summary": _dump("A=1") + "\n" + _SKIPPED,
    "stray_env_line": f"{_TS}SOME_SECRET={CANARY}",
    "stray_opaque_value": f"{_TS}BLAND=abcdefghijklmnopqrstuvwxyz0123{CANARY[-4:]}",
}


@pytest.mark.parametrize("case", sorted(MASK_CASES))
async def test_get_container_logs_masks_every_dump_shape(mock_env, case):
    text = MASK_CASES[case]
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/dockhand/logs").mock(
            return_value=httpx.Response(200, json={"logs": text})
        )
        result = await server.get_container_logs(container_id="dockhand")

    assert CANARY not in str(result)
    assert ML_CANARY not in str(result)
    assert "abcdefghijklmnopqrstuvwxyz" not in str(result)
    assert result["masked_lines"] > 0


@pytest.mark.parametrize("case", sorted(MASK_CASES))
async def test_get_stack_deploy_log_masks_every_dump_shape(mock_env, case):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/stacks/searxng/deploys/7").mock(
            return_value=httpx.Response(200, json={"id": 7, "environmentId": 1})
        )
        mock.get("/api/stacks/searxng/deploys/7/log").mock(
            return_value=httpx.Response(200, text=MASK_CASES[case])
        )
        result = await server.get_stack_deploy_log(stack_name="searxng", run_id=7)

    assert CANARY not in str(result)
    assert ML_CANARY not in str(result)
    assert result["masked_lines"] > 0


async def test_schedule_execution_logs_are_masked(mock_env):
    rows = [{"id": 1, "environmentId": 1, "logs": MASK_CASES["multi_line_quoted"]}]
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/schedules/executions").mock(
            return_value=httpx.Response(200, json={"executions": rows, "total": 1})
        )
        result = await server.get_schedule_executions()
    assert ML_CANARY not in str(result)
    assert result["masked_lines"] > 0


def test_the_mask_keeps_the_frame_and_ordinary_lines_readable():
    text = "\n".join(["before", _dump(f"A={CANARY}"), "level=info msg=started port=8080"])
    masked, _ = mask_env_dump(text)
    assert ENV_DUMP_PLACEHOLDER in masked
    assert "[Git] Total lines: 1" in masked
    assert "[Git] Parsed env var keys: A" in masked
    assert masked.startswith("before\n")
    assert masked.endswith("level=info msg=started port=8080")


def test_a_changed_frame_fails_closed():
    """A line between the header and "Raw content:" that is not a known frame line
    means upstream changed the format; content is masked from there."""
    text = "\n".join(
        [
            f"{_TS}[Git] PARSE ENV FILE CONTENT",
            f"{_TS}[Git] Raw env follows",
            f"{_TS}K={CANARY}",
            ML_CANARY,
        ]
    )
    masked, _ = mask_env_dump(text)
    assert CANARY not in masked
    assert ML_CANARY not in masked


def test_a_window_that_cuts_both_markers_still_masks_opaque_lines():
    """since/until can select the middle of a dump, with neither marker in view.
    A PEM body or a long continuation line is masked by shape alone."""
    pem_line = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ" + CANARY[-8:]
    text = "\n".join([f"2026-10-25T19:58:29.305836799Z {pem_line}", "Container x Started"])
    masked, n = mask_env_dump(text)
    assert pem_line not in masked
    assert "Container x Started" in masked
    assert n == 1


@pytest.mark.parametrize(
    "url",
    [
        "postgres://u:p/ss@db:5432/x",
        "postgres://u:p@ss@db/x",
        "postgres://u:p%40ss@db/x",
        "redis://:p?ss#x@cache:6379",
        "https://u:pw@host/path?q=1",
    ],
)
def test_url_userinfo_is_stripped_whatever_the_password_holds(url):
    out = redact_value("SOME_URL", url)
    assert "p/ss" not in out and "p@ss" not in out and "p%40ss" not in out
    assert "p?ss" not in out and ":pw@" not in out
    assert "***REDACTED***@" in out


def test_a_url_with_no_userinfo_is_unchanged():
    assert redact_value("FEED_URL", "https://example.com/a/b?page=2") == (
        "https://example.com/a/b?page=2"
    )


# Built from parts so the file holds no literal PEM header for a secret scanner
# to flag; the frame is synthetic and its body is the test canary.
_PEM = "PRIVATE " + "KEY"


def test_compose_block_scalars_are_redacted_line_by_line():
    text = "\n".join(
        [
            "services:",
            "  a:",
            "    environment:",
            "      TLS_KEY: |",
            f"        -----BEGIN {_PEM}-----",
            f"        MIIEvQIBADANBgkqhkiG9w0BAQEFAASC{CANARY}",
            f"        -----END {_PEM}-----",
            "    command: >",
            "      serve --port 8080",
            "    image: nginx:1",
        ]
    )
    out, n = redact_compose(text)
    assert CANARY not in out
    assert "      TLS_KEY: |" in out
    assert "      serve --port 8080" in out
    assert "    image: nginx:1" in out
    assert n == 3


def test_scrub_strings_reaches_nested_values():
    rows = [{"name": "sync", "details": {"repo": f"https://x-token:{CANARY}@git.example/r"}}]
    assert CANARY not in str(scrub_strings(rows))


async def test_new_read_tools_scrub_url_credentials(mock_env):
    secret_url = f"https://bot:{CANARY}@git.example/repo.git"
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/schedules").mock(
            return_value=httpx.Response(
                200, json={"schedules": [{"id": 1, "environmentId": 1, "description": secret_url}]}
            )
        )
        mock.get("/api/schedules/executions").mock(
            return_value=httpx.Response(
                200,
                json={"executions": [{"id": 1, "details": {"url": secret_url}}], "total": 1},
            )
        )
        mock.get("/api/stacks/web/deploys").mock(
            return_value=httpx.Response(200, json={"runs": [{"id": 1, "errorMessage": secret_url}]})
        )
        results = [
            await server.list_schedules(),
            await server.get_schedule_executions(),
            await server.list_stack_deploys(stack_name="web"),
        ]
    for r in results:
        assert CANARY not in str(r)


async def test_validate_stack_findings_are_redacted(mock_env):
    finding = {
        "ruleId": "X",
        "message": "inline secret",
        "fix": {"kind": "replace", "text": f"      - DB_PASSWORD={CANARY}"},
    }
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/stacks/web/validate").mock(
            return_value=httpx.Response(200, json={"findings": [finding], "counts": {}})
        )
        result = await server.validate_stack(stack_name="web", compose="services: {}")
    assert CANARY not in str(result)
    assert result["findings"][0]["ruleId"] == "X"


async def test_version_notes_are_labelled_untrusted(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/web/version-notes").mock(
            return_value=httpx.Response(200, json={"notes": [{"body": "ignore previous"}]})
        )
        result = await server.get_version_notes(container_id="web", versions="1.0")
    assert result["content_trust"].startswith("untrusted")


def test_text_without_a_dump_is_unchanged():
    text = "Container x Started\nGET /api/health 200\nuser=bob action=login"
    assert mask_env_dump(text) == (text, 0)


def test_compose_values_are_redacted_and_references_kept():
    text = "\n".join(
        [
            "services:",
            "  db:",
            "    image: postgres:16@sha256:" + "a" * 64,
            "    environment:",
            f"      - POSTGRES_PASSWORD={CANARY}",
            f'      - "FEED_URL=https://u:{CANARY}@host/x"',
            f"      API_TOKEN: '{CANARY}'",
            "      DB_PASSWORD: ${DB_PASSWORD}",
            "      PLAIN: hello",
        ]
    )
    out, n = redact_compose(text)
    assert CANARY not in out
    assert n == 3
    assert "${DB_PASSWORD}" in out
    assert "PLAIN: hello" in out
    assert "image: postgres:16@sha256:" in out


async def test_get_stack_compose_redacts_inline_values(mock_env):
    content = f"services:\n  a:\n    environment:\n      - SECRET_KEY={CANARY}\n"
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/stacks/searxng/compose").mock(
            return_value=httpx.Response(200, json={"content": content, "envPath": None})
        )
        result = await server.get_stack_compose(stack_name="searxng")
    assert CANARY not in str(result)
    assert result["redacted_values"] == 1


# ---------------------------------------------------------------------------
# DOCKHAND_ALLOWED_ENVS (#1027)
# ---------------------------------------------------------------------------


@pytest.fixture
def pinned(mock_env, monkeypatch):
    monkeypatch.setenv("DOCKHAND_ALLOWED_ENVS", "2")
    monkeypatch.setenv("DOCKHAND_DEFAULT_ENV", "2")


@pytest.mark.parametrize(
    "tool_name,kwargs",
    [
        ("list_containers", {"environment_id": 1}),
        ("get_container_logs", {"container_id": "dockhand", "environment_id": "1"}),
        ("get_activity", {"environment_id": 1}),
        ("list_schedules", {"environment_id": 1}),
        ("get_schedule_executions", {"environment_id": 1}),
        ("scan_image", {"image_name": "nginx:latest", "environment_id": 1}),
        (
            "stack_action",
            {
                "stack_name": "searxng",
                "action": "restart",
                "environment_id": 1,
                "acknowledge_env_log": True,
            },
        ),
        ("update_container", {"container_id": "abc123", "environment_id": 1}),
        ("container_action", {"container_id": "abc123", "action": "stop", "environment_id": 1}),
    ],
)
async def test_an_env_outside_the_pin_makes_zero_requests(pinned, tool_name, kwargs):
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = _catch_all(mock)
        result = await getattr(server, tool_name)(**kwargs)
    assert route.call_count == 0
    assert "not allowed on this instance" in result["error"]


async def test_two_allowed_envs_require_an_explicit_env(mock_env, monkeypatch):
    monkeypatch.setenv("DOCKHAND_ALLOWED_ENVS", "2,3")
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = _catch_all(mock)
        result = await server.list_stacks()
    assert route.call_count == 0
    assert "environment_id is required" in result["error"]


async def test_a_pinned_instance_filters_optional_env_routes(pinned):
    """activity has an optional env filter; pinned, it is always sent."""
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/activity").mock(
            return_value=httpx.Response(200, json={"events": [], "total": 0})
        )
        await server.get_activity()
    assert route.calls[0].request.url.params["environmentId"] == "2"


async def test_a_pinned_instance_drops_other_envs_schedules(pinned):
    schedules = [
        {"id": 1, "environmentId": 1, "name": "local"},
        {"id": 2, "environmentId": 2, "name": "remote"},
        {"id": 3, "environmentId": None, "name": "system"},
    ]
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/schedules").mock(
            return_value=httpx.Response(200, json={"schedules": schedules})
        )
        result = await server.list_schedules()
    assert [s["name"] for s in result["schedules"]] == ["remote"]


async def test_a_deploy_log_from_another_env_is_refused(pinned):
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        mock.get("/api/stacks/searxng/deploys/7").mock(
            return_value=httpx.Response(200, json={"id": 7, "environmentId": 1})
        )
        log_route = mock.get("/api/stacks/searxng/deploys/7/log").mock(
            return_value=httpx.Response(200, text="x")
        )
        result = await server.get_stack_deploy_log(stack_name="searxng", run_id=7)
    assert log_route.call_count == 0
    assert "belongs to environment 1" in result["error"]


async def test_unpinned_behaviour_is_unchanged(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/activity").mock(
            return_value=httpx.Response(200, json={"events": [], "total": 0})
        )
        await server.get_activity()
    assert "environmentId" not in route.calls[0].request.url.params


@pytest.mark.parametrize("raw", ["x", "1,,y", ","])
async def test_a_malformed_pin_is_a_config_error(mock_env, monkeypatch, raw):
    monkeypatch.setenv("DOCKHAND_ALLOWED_ENVS", raw)
    result = await server.list_stacks()
    assert "DOCKHAND_ALLOWED_ENVS" in result["error"]


# ---------------------------------------------------------------------------
# update_container name resolution
# ---------------------------------------------------------------------------


async def test_update_container_resolves_a_name_then_posts_the_full_id(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        lookup = mock.get("/api/containers/nginx").mock(
            return_value=httpx.Response(200, json=INSPECT_FOR_RESOLVE)
        )
        post = mock.post("/api/containers/batch-update").mock(
            return_value=httpx.Response(200, json=BATCH_UPDATE_SUCCESS)
        )
        result = await server.update_container(container_id="nginx")

    assert lookup.calls[0].request.url.params["env"] == "1"
    assert json.loads(post.calls[0].request.content) == {"containerIds": [FULL_ID]}
    assert result["success"] is True


@pytest.mark.parametrize(
    "lookup",
    [
        httpx.Response(404, json={"error": "No such container: nope"}),
        httpx.Response(200, json={"Name": "/nope"}),  # no Id
        httpx.Response(200, json={"Id": "short"}),  # not a full id
    ],
)
async def test_update_container_posts_nothing_for_an_unknown_name(mock_env, lookup):
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        mock.get("/api/containers/nope").mock(return_value=lookup)
        post = mock.post("/api/containers/batch-update").mock(
            return_value=httpx.Response(200, json=BATCH_UPDATE_SUCCESS)
        )
        result = await server.update_container(container_id="nope")
    assert post.call_count == 0
    assert "error" in result


# ---------------------------------------------------------------------------
# Destructive negatives: bad input makes zero requests
# ---------------------------------------------------------------------------

# "abc\n": `$` with .match() accepts a trailing newline, and httpx then raised
# InvalidURL straight out of the tool (pre-audit baseline, IV-70).
_BAD_IDS = ["../x", "a/b", "", ".hidden", "a b", "a?b=1", "..", "abc\n", "abc\r\n"]


@pytest.mark.parametrize("bad", _BAD_IDS)
@pytest.mark.parametrize(
    "tool_name,kwargs,field",
    [
        ("container_action", {"action": "stop"}, "container_id"),
        ("update_container", {}, "container_id"),
        ("stack_action", {"action": "restart", "acknowledge_env_log": True}, "stack_name"),
        ("get_container_logs", {}, "container_id"),
        ("get_stack_deploy_log", {"run_id": 1}, "stack_name"),
        ("get_scheduled_actions", {}, "container_name"),
        ("validate_stack", {"compose": "services: {}"}, "stack_name"),
    ],
)
async def test_an_invalid_name_makes_zero_requests(mock_env, bad, tool_name, kwargs, field):
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = _catch_all(mock)
        result = await getattr(server, tool_name)(**{field: bad, **kwargs})
    assert route.call_count == 0
    assert "Invalid" in result["error"]


@pytest.mark.parametrize(
    "tool_name,kwargs",
    [
        ("container_action", {"container_id": "abc123", "action": "kill"}),
        ("stack_action", {"stack_name": "s", "action": "down", "acknowledge_env_log": True}),
    ],
)
async def test_an_invalid_action_makes_zero_requests(mock_env, tool_name, kwargs):
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = _catch_all(mock)
        result = await getattr(server, tool_name)(**kwargs)
    assert route.call_count == 0
    assert "action must be one of" in result["error"]


@pytest.mark.parametrize("env", ["prod", "1.5", True])
@pytest.mark.parametrize(
    "tool_name,kwargs",
    [
        ("container_action", {"container_id": "abc123", "action": "stop"}),
        ("update_container", {"container_id": "abc123"}),
        ("stack_action", {"stack_name": "s", "action": "stop", "acknowledge_env_log": True}),
    ],
)
async def test_a_non_integer_env_makes_zero_requests(mock_env, env, tool_name, kwargs):
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = _catch_all(mock)
        result = await getattr(server, tool_name)(environment_id=env, **kwargs)
    assert route.call_count == 0
    assert "Invalid Dockhand environment id" in result["error"]


@pytest.mark.parametrize("versions", ["", "1.0;rm", "a b", ",".join(["1"] * 21)])
async def test_get_version_notes_rejects_bad_versions(mock_env, versions):
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = _catch_all(mock)
        result = await server.get_version_notes(container_id="abc123", versions=versions)
    assert route.call_count == 0
    assert "Invalid versions" in result["error"]


@pytest.mark.parametrize("run_id", [-1, True])
async def test_get_stack_deploy_log_rejects_a_bad_run_id(mock_env, run_id):
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = _catch_all(mock)
        result = await server.get_stack_deploy_log(stack_name="s", run_id=run_id)
    assert route.call_count == 0
    assert "Invalid run_id" in result["error"]


def test_the_only_mutating_requests_are_the_three_hitl_tools_and_two_reads():
    """Every POST/DELETE call site in server.py, by enclosing tool. A new one has
    to be added here, and it needs a HITL line in every manifest that holds
    dockhand-mcp before the proxy restart (F-05, #1225)."""
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path(server.__file__).read_text())
    callers = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                if name in {"post", "delete", "_timed_post", "put", "patch"}:
                    callers.add(fn.name)
    callers.discard("_timed_post")
    assert callers == {
        # HITL gated in every manifest.
        "container_action",
        "stack_action",
        "update_container",
        # POST, but read-only: a fresh check and a lint, neither changes state.
        "check_updates",
        "validate_stack",
        # Starts a scan and stores its result; changes no container.
        "scan_image",
    }


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


async def test_get_activity_query_string_clamp_and_filters(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/activity").mock(
            return_value=httpx.Response(200, json={"events": [], "total": 0})
        )
        await server.get_activity(
            limit=500,
            offset=-3,
            container_name="nginx",
            actions="die,restart",
            from_date="2026-10-01",
            environment_id=1,
        )
    params = route.calls[0].request.url.params
    assert params["limit"] == "100"
    assert params["offset"] == "0"
    assert params["containerName"] == "nginx"
    assert params["actions"] == "die,restart"
    assert params["fromDate"] == "2026-10-01"
    assert params["environmentId"] == "1"
    assert "toDate" not in params


async def test_get_activity_clamps_limit_up_to_one(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/activity").mock(
            return_value=httpx.Response(200, json={"events": [], "total": 0})
        )
        await server.get_activity(limit=0)
    assert route.calls[0].request.url.params["limit"] == "1"


async def test_get_health_returns_dockhands_body(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/health").mock(
            return_value=httpx.Response(200, json={"status": "ok", "timestamp": "t"})
        )
        assert await server.get_health() == {"status": "ok", "timestamp": "t"}


async def test_scan_image_body_and_optional_env(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.post("/api/images/scan").mock(
            return_value=httpx.Response(200, json={"imageName": "nginx:latest"})
        )
        await server.scan_image(image_name="nginx:latest")
        await server.scan_image(image_name="nginx:latest", environment_id=2)
    assert json.loads(route.calls[0].request.content) == {"imageName": "nginx:latest"}
    assert "env" not in route.calls[0].request.url.params
    assert route.calls[1].request.url.params["env"] == "2"


_STACK_ROW = {
    "name": "searxng",
    "status": "running",
    "health": "healthy",
    "sourceType": "internal",
    "containers": ["a" * 64, "b" * 64],
    "updateCount": 1,
    "pinnedDigestCount": 0,
    "containerDetails": [
        {
            "id": "a" * 64,
            "name": "searxng",
            "service": "searxng",
            "state": "running",
            "status": "Up 2 hours (healthy)",
            "labels": {"com.docker.compose.project": "searxng", "x": "y" * 500},
            "ports": [{"PublicPort": 8080}],
            "networks": [{"name": "n", "ipAddress": "172.20.0.2"}],
        },
        {"id": "b" * 64, "name": "redis", "service": "redis", "state": "running"},
    ],
}


async def test_list_stacks_compact_row(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/stacks").mock(return_value=httpx.Response(200, json=[_STACK_ROW]))
        result = await server.list_stacks()
    row = result["stacks"][0]
    assert row == {
        "name": "searxng",
        "status": "running",
        "health": "healthy",
        "sourceType": "internal",
        "service_count": 2,
        "container_count": 2,
        "containers": [
            {
                "name": "searxng",
                "service": "searxng",
                "state": "running",
                "status": "Up 2 hours (healthy)",
            },
            {"name": "redis", "service": "redis", "state": "running", "status": None},
        ],
        "updateCount": 1,
    }
    assert "y" * 500 not in str(result)


async def test_list_stacks_detail_and_names(mock_env):
    other = {**_STACK_ROW, "name": "other"}
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/stacks").mock(return_value=httpx.Response(200, json=[_STACK_ROW, other]))
        full = await server.list_stacks(detail=True)
        some = await server.list_stacks(names=["other", "ghost"])
    assert full["stacks"] == [_STACK_ROW, other]
    assert some["stacks"] == [other]
    assert some["not_found"] == ["ghost"]
    assert some["total"] == 2


async def test_list_stacks_default_stays_small_for_a_large_host(mock_env):
    """34 real stacks came to 179,542 characters before 0.8.0. A synthetic 40
    with heavy labels must stay well under the ~20k budget."""
    rows = [{**_STACK_ROW, "name": f"s{i}"} for i in range(40)]
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/stacks").mock(return_value=httpx.Response(200, json=rows))
        result = await server.list_stacks()
    assert len(json.dumps(result)) < 20_000


async def test_check_updates_filters_to_rows_needing_attention(mock_env):
    rows = [
        {"containerName": "quiet", "imageName": "a:1", "hasUpdate": False},
        {"containerName": "update", "imageName": "b:1", "hasUpdate": True},
        {"containerName": "broken", "imageName": "c:1", "hasUpdate": False, "error": "401"},
        # A pin with no report is not_assessed, which needs attention.
        {"containerName": "pin", "imageName": "d@sha256:" + "0" * 64, "hasUpdate": False},
    ]
    body = {"total": 4, "updatesFound": 1, "results": rows}
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/containers/check-updates").mock(return_value=httpx.Response(200, json=body))
        result = await server.check_updates()
    assert [r["containerName"] for r in result["results"]] == ["update", "broken", "pin"]
    assert result["attention_summary"] == {
        "checked": 4,
        "attention": 3,
        "has_update": 1,
        "errors": 1,
    }
    assert result["filtered"] is True
    assert result["total"] == 4  # Dockhand's own field, untouched


async def test_get_pending_updates_marks_stale_rows(mock_env):
    now = datetime.now(UTC)
    rows = [
        {"containerName": "fresh", "checkedAt": (now - timedelta(hours=2)).isoformat()},
        {"containerName": "old", "checkedAt": "2026-10-01T00:00:00.000Z"},
        {"containerName": "unknown"},
        {"containerName": "garbage", "checkedAt": "yesterday"},
    ]
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/pending-updates").mock(
            return_value=httpx.Response(200, json={"pendingUpdates": rows})
        )
        result = await server.get_pending_updates()
    by = {r["containerName"]: r for r in result["pendingUpdates"]}
    assert by["fresh"]["stale"] is False
    assert 1.5 < by["fresh"]["checked_age_hours"] < 2.5
    assert by["old"]["stale"] is True
    assert by["unknown"]["stale"] is True
    assert by["garbage"]["stale"] is True
    assert result["stale"] == 3


async def test_get_stack_stats_shape(mock_env):
    row = {"name": "a", "cpuPercent": 0.3, "memoryUsage": 1}
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/stack-stats").mock(return_value=httpx.Response(200, json=[row]))
        result = await server.get_stack_stats()
    assert route.calls[0].request.url.params["env"] == "1"
    assert result == {"stacks": [row], "total": 1}


async def test_get_disk_usage_summarises(mock_env):
    usage = {
        "LayersSize": 10,
        "Images": [
            {"Id": "sha256:" + "1" * 64, "RepoTags": ["big:1"], "Size": 900, "Labels": {"k": "v"}},
            {"Id": "sha256:" + "2" * 64, "RepoTags": None, "Size": 100},
        ],
        "Volumes": [{"Name": "v1", "UsageData": {"Size": 5}}, {"Name": "v2", "UsageData": None}],
        "Containers": [{"Id": "c", "Labels": {"SECRET": CANARY}}],
        "ImageUsage": {
            "TotalCount": 2,
            "ActiveCount": 1,
            "TotalSize": 1000,
            "Reclaimable": 100,
            "Items": ["huge"],
        },
    }
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/system/disk").mock(
            return_value=httpx.Response(200, json={"diskUsage": usage})
        )
        result = await server.get_disk_usage()
    assert result["layers_size"] == 10
    assert result["images"] == {
        "TotalCount": 2,
        "ActiveCount": 1,
        "TotalSize": 1000,
        "Reclaimable": 100,
    }
    assert result["largest_images"] == [
        {"name": "big:1", "size": 900},
        {"name": "sha256:222222222222", "size": 100},
    ]
    assert result["largest_volumes"][0] == {"name": "v1", "size": 5}
    assert result["containers"] is None
    assert CANARY not in str(result)


async def test_get_disk_usage_null(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/system/disk").mock(
            return_value=httpx.Response(200, json={"diskUsage": None})
        )
        assert await server.get_disk_usage() == {"diskUsage": None}


async def test_get_vulnerability_summary_params(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        count = mock.get("/api/vulnerabilities/count").mock(
            return_value=httpx.Response(200, json={"total": 3, "summary": {"high": 3}})
        )
        page = mock.get("/api/vulnerabilities").mock(
            return_value=httpx.Response(200, json={"findings": [{"cve": "CVE-1"}], "total": 3})
        )
        result = await server.get_vulnerability_summary(
            severity="high", stack="web", query="openssl", limit=999
        )
    assert count.calls[0].request.url.params["env"] == "1"
    params = page.calls[0].request.url.params
    assert (params["severity"], params["stack"], params["q"], params["limit"]) == (
        "high",
        "web",
        "openssl",
        "100",
    )
    assert "image" not in params
    assert result == {
        "summary": {"total": 3, "summary": {"high": 3}},
        "findings": [{"cve": "CVE-1"}],
        "total": 3,
    }


async def test_list_stack_deploys_limit(mock_env):
    runs = [{"id": i, "environmentId": 1} for i in range(30)]
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/stacks/web/deploys").mock(
            return_value=httpx.Response(200, json={"runs": runs})
        )
        result = await server.list_stack_deploys(stack_name="web", limit=5)
    assert route.calls[0].request.url.params["env"] == "1"
    assert [r["id"] for r in result["runs"]] == [0, 1, 2, 3, 4]
    assert result["total"] == 30


async def test_get_stack_deploy_log_tail_after_masking(mock_env):
    text = "\n".join(f"line {i}" for i in range(50))
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/stacks/web/deploys/3").mock(
            return_value=httpx.Response(200, json={"id": 3, "environmentId": 1, "status": "ok"})
        )
        mock.get("/api/stacks/web/deploys/3/log").mock(return_value=httpx.Response(200, text=text))
        result = await server.get_stack_deploy_log(stack_name="web", run_id=3, tail=2)
    assert result["log"] == "line 48\nline 49"
    assert result["total_lines"] == 50
    assert result["status"] == "ok"


async def test_get_version_notes_params(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/containers/web/version-notes").mock(
            return_value=httpx.Response(200, json={"notes": []})
        )
        await server.get_version_notes(container_id="web", versions="1.2.0,1.1.9")
    params = route.calls[0].request.url.params
    assert (params["env"], params["versions"]) == ("1", "1.2.0,1.1.9")


async def test_list_schedules_drops_recent_executions_and_filters_env(mock_env):
    rows = [
        {"id": 1, "environmentId": 1, "recentExecutions": [{"logs": CANARY}]},
        {"id": 2, "environmentId": 2},
    ]
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/schedules").mock(return_value=httpx.Response(200, json={"schedules": rows}))
        everything = await server.list_schedules()
        one = await server.list_schedules(environment_id=2)
    assert everything["total"] == 2
    assert CANARY not in str(everything)
    assert [s["id"] for s in one["schedules"]] == [2]


async def test_get_schedule_executions_params(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/schedules/executions").mock(
            return_value=httpx.Response(200, json={"executions": [], "total": 0})
        )
        await server.get_schedule_executions(
            schedule_type="container_update", schedule_id=4, status="failed", limit=1000
        )
    params = route.calls[0].request.url.params
    assert params["scheduleType"] == "container_update"
    assert params["scheduleId"] == "4"
    assert params["status"] == "failed"
    assert params["limit"] == "100"
    assert "environmentId" not in params


async def test_get_activity_stats_uses_the_snake_case_param(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/activity/stats").mock(
            return_value=httpx.Response(200, json={"total": 1, "today": 0})
        )
        await server.get_activity_stats(environment_id=1)
        await server.get_activity_stats()
    assert route.calls[0].request.url.params["environment_id"] == "1"
    assert "environment_id" not in route.calls[1].request.url.params


@pytest.mark.parametrize(
    "tool_name,path",
    [
        ("get_scheduled_actions", "/api/scheduled-actions/web"),
        ("get_auto_update_policy", "/api/auto-update/web"),
    ],
)
async def test_container_name_read_tools(mock_env, tool_name, path):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get(path).mock(return_value=httpx.Response(200, json={"enabled": False}))
        result = await getattr(server, tool_name)(container_name="web")
    assert route.calls[0].request.url.params["env"] == "1"
    assert result == {"enabled": False}


async def test_validate_stack_fetches_the_stored_file_when_none_is_given(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/stacks/web/compose").mock(
            return_value=httpx.Response(200, json={"content": "services: {}\n"})
        )
        route = mock.post("/api/stacks/web/validate").mock(
            return_value=httpx.Response(200, json={"findings": [], "counts": {"error": 0}})
        )
        result = await server.validate_stack(stack_name="web")
    assert json.loads(route.calls[0].request.content) == {
        "compose": "services: {}\n",
        "existing": True,
    }
    assert result["counts"] == {"error": 0}


async def test_validate_stack_with_given_compose_sends_no_env(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.post("/api/stacks/web/validate").mock(
            return_value=httpx.Response(200, json={"findings": []})
        )
        await server.validate_stack(stack_name="web", compose="services: {}")
    assert json.loads(route.calls[0].request.content) == {
        "compose": "services: {}",
        "existing": False,
    }


async def test_validate_stack_with_no_stored_file(mock_env):
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        mock.get("/api/stacks/web/compose").mock(return_value=httpx.Response(200, json={}))
        post = mock.post("/api/stacks/web/validate")
        result = await server.validate_stack(stack_name="web")
    assert post.call_count == 0
    assert "No compose content" in result["error"]


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


async def test_without_a_default_env_an_explicit_env_still_works(monkeypatch):
    """Every other test forces DOCKHAND_DEFAULT_ENV through mock_env."""
    monkeypatch.setenv("DOCKHAND_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("DOCKHAND_API_TOKEN", "test-token-abc123")
    monkeypatch.delenv("DOCKHAND_DEFAULT_ENV", raising=False)
    monkeypatch.delenv("DOCKHAND_ALLOWED_ENVS", raising=False)
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/stacks").mock(return_value=httpx.Response(200, json=STACKS_RESPONSE))
        result = await server.list_stacks(environment_id=3)
        missing = await server.list_containers()
    assert route.calls[0].request.url.params["env"] == "3"
    assert result["total"] == 2
    assert "DOCKHAND_DEFAULT_ENV" in missing["error"]
