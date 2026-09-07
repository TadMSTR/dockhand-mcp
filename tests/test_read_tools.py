"""
Phase 6 read-only tool surface — route, ?env= propagation, unwrapping, and the
redaction that inspect_container depends on.

Written against openapi-v1.0.46.json's route contracts, not against what the
code happens to do. The repo has been burned once by a test that asserted the
same wrong thing the code sent (vikunja#702).
"""

import httpx
import pytest
import respx

from dockhand_mcp import server

from .conftest import ENDPOINT


def _env_of(route):
    return route.calls[0].request.url.params.get("env")


# ---------------------------------------------------------------------------
# Route + env contract, one per tool
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "kwargs", "path", "payload"),
    [
        (
            "inspect_container",
            {"container_id": "abc123"},
            "/api/containers/abc123",
            {"Id": "abc123", "Config": {"Env": []}},
        ),
        (
            "get_container_logs",
            {"container_id": "abc123"},
            "/api/containers/abc123/logs",
            {"logs": "hello"},
        ),
        (
            "get_container_stats",
            {"container_id": "abc123"},
            "/api/containers/abc123/stats",
            {"cpu": 1.5},
        ),
        (
            "get_stack_compose",
            {"stack_name": "searxng"},
            "/api/stacks/searxng/compose",
            {"content": "services: {}"},
        ),
        ("list_images", {}, "/api/images", []),
        ("list_volumes", {}, "/api/volumes", []),
        ("list_networks", {}, "/api/networks", []),
        ("get_pending_updates", {}, "/api/containers/pending-updates", []),
        ("get_host_info", {}, "/api/host", {"hostname": "forge"}),
    ],
)
@pytest.mark.asyncio
async def test_read_tool_hits_its_route_with_env(mock_env, tool, kwargs, path, payload):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get(path).mock(return_value=httpx.Response(200, json=payload))

        result = await getattr(server, tool)(**kwargs)

        assert _env_of(route) == "1"
        assert "error" not in result


@pytest.mark.parametrize(
    ("tool", "path", "key"),
    [
        ("list_images", "/api/images", "images"),
        ("list_volumes", "/api/volumes", "volumes"),
        ("list_networks", "/api/networks", "networks"),
    ],
)
@pytest.mark.asyncio
async def test_listings_unwrap_and_count(mock_env, tool, path, key):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get(path).mock(return_value=httpx.Response(200, json=[{"a": 1}, {"b": 2}]))

        result = await getattr(server, tool)()

        assert result["total"] == 2
        assert len(result[key]) == 2


# ---------------------------------------------------------------------------
# pending-updates has its own envelope, and reading the wrong key reports zero
# ---------------------------------------------------------------------------

# Captured from the live v1.0.46 response on 2026-09-07. The first draft of
# get_pending_updates unwrapped data["updates"]; the real key is
# "pendingUpdates", so it reported total=0 against a host with 27 — a zero
# indistinguishable from a genuine "nothing pending". The bare-[] fixture used
# elsewhere passed happily either way, which is exactly why this one exists.
PENDING_UPDATES_LIVE = {
    "environmentId": 1,
    "pendingUpdates": [
        {
            "containerId": "aaa111",
            "containerName": "plane-db",
            "currentImage": "postgres:15",
            "checkedAt": "2026-09-07T19:00:00Z",
            "hasImageUpdate": True,
            "newerVersion": "postgres:16",
        },
        {
            "containerId": "bbb222",
            "containerName": "langfuse-db",
            "currentImage": "postgres:15",
            "checkedAt": "2026-09-07T19:00:00Z",
            "hasImageUpdate": True,
        },
        {
            "containerId": "ccc333",
            "containerName": "settled",
            "currentImage": "redis:7",
            "checkedAt": "2026-09-07T19:00:00Z",
            "hasImageUpdate": False,
        },
    ],
}


@pytest.mark.asyncio
async def test_get_pending_updates_reads_the_real_envelope_key(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/pending-updates").mock(
            return_value=httpx.Response(200, json=PENDING_UPDATES_LIVE)
        )

        result = await server.get_pending_updates()

        assert result["total"] == 3, "reading the wrong envelope key reports zero"
        assert result["withUpdateAvailable"] == 2
        assert result["pendingUpdates"][0]["containerName"] == "plane-db"


# ---------------------------------------------------------------------------
# The silent-empty failure mode resolve_env() exists to prevent (vikunja#10, #126)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "path"),
    [
        ("list_images", "/api/images"),
        ("list_volumes", "/api/volumes"),
        ("list_networks", "/api/networks"),
        ("get_pending_updates", "/api/containers/pending-updates"),
    ],
)
@pytest.mark.asyncio
async def test_unresolvable_env_fails_before_the_request(monkeypatch, tool, path):
    """Dockhand answers [] rather than erroring when env is missing, so an
    unresolved env must fail loudly here instead of returning an empty list that
    reads exactly like a real 'nothing found'."""
    monkeypatch.setenv("DOCKHAND_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("DOCKHAND_API_TOKEN", "test-token-abc123")
    monkeypatch.delenv("DOCKHAND_DEFAULT_ENV", raising=False)

    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        route = mock.get(path).mock(return_value=httpx.Response(200, json=[]))

        result = await getattr(server, tool)()

        assert "error" in result
        assert "environment" in result["error"].lower()
        # The point: it never reached the wire, so it cannot have returned [].
        assert route.call_count == 0
        assert "total" not in result


# ---------------------------------------------------------------------------
# SECURITY — the unmasked route must never be wrapped, and redaction must fire
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inspect_container_never_calls_the_unmasked_inspect_route(mock_env):
    """/api/containers/{id}/inspect returns the raw payload with no masking pass.

    Registered here so a call would be recorded rather than raising; the
    assertion is that it is never reached.
    """
    with respx.mock(base_url=ENDPOINT, assert_all_called=False) as mock:
        unmasked = mock.get("/api/containers/abc123/inspect").mock(
            return_value=httpx.Response(200, json={"Config": {"Env": []}})
        )
        masked = mock.get("/api/containers/abc123").mock(
            return_value=httpx.Response(200, json={"Config": {"Env": []}})
        )

        await server.inspect_container(container_id="abc123")

        assert unmasked.call_count == 0
        # Without this the test passes just as well if no request happens at all.
        assert masked.call_count == 1


@pytest.mark.parametrize(
    "entry",
    [
        "ANTHROPIC_API_KEY=sk-ant-live-supersecret",
        "POSTGRES_PASSWORD=hunter2",
        "AUTHENTIK_SECRET_KEY=abcdef123456",
        "DOCKHAND_API_TOKEN=dh-live-token",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI",
        "BACKREST_REPO_PASSWORD=repo-pass",
        "CREDS_KEY=abc",
        "COREPACK_INTEGRITY_KEYS=xyz",
        "SESSION_SALT=peppery",
        "MY_BEARER=abc123",
        # Real key names from forge containers that the first version of this
        # regex missed. POSTGRES_PWD and DFLY_requirepass were found by the
        # security audit against live deployed compose files; the rest came out
        # of scanning all 123 containers afterwards. "requirepass" contains
        # neither "password" nor "passwd", and "PWD" is not "PASSWD".
        "POSTGRES_PWD=e3b0c44298fc1c149afbf4c8996fb924",
        "DFLY_requirepass=27ae41e4649b934ca495991b7852b855",
        "RABBITMQ_DEFAULT_PASS=da39a3ee5e6b4b0d3255bfef95601890",
        "NEO4J_AUTH=neo4j/5e884898da28047151d0e56f8dc62927",
        "REDIS_AUTH=6b86b273ff34fce19d6b804eff5a3f57",
        "CREDS_IV=d4735e3a265e16eee03f59718b9b5d03",
    ],
)
@pytest.mark.asyncio
async def test_inspect_container_redacts_secret_shaped_env(mock_env, entry):
    """Dockhand's own masking does not fire on forge — measured 322/322 unmasked
    across 123 containers on v1.0.46 — so this pass is the only protection."""
    secret_value = entry.split("=", 1)[1]
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/abc123").mock(
            return_value=httpx.Response(200, json={"Config": {"Env": [entry, "TZ=Europe/London"]}})
        )

        result = await server.inspect_container(container_id="abc123")

        env = result["Config"]["Env"]
        assert secret_value not in str(result)
        assert any(e.endswith("***REDACTED***") for e in env)
        # Non-secret config is still readable, or the tool is useless.
        assert "TZ=Europe/London" in env


@pytest.mark.parametrize(
    ("entry", "why"),
    [
        # A greedy key pattern (PASS/PWD/AUTH/_KEY) would bury this host's ~30
        # GF_AUTH_*/VIKUNJA_AUTH_* config flags. A value that cannot be a
        # credential is shown whatever its key is called.
        ("GF_AUTH_GENERIC_OAUTH_ENABLED=true", "boolean"),
        ("VIKUNJA_AUTH_LOCAL_ENABLED=false", "boolean"),
        ("AUTHENTIK_EMAIL__PORT=587", "numeric"),
        ("AUTHENTIK_LOG_LEVEL=info", "log level"),
        ("SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt", "absolute path"),
        ("REDIS_URL=redis://cache:6379/0", "URL with no userinfo"),
    ],
)
@pytest.mark.asyncio
async def test_inspect_container_keeps_values_that_cannot_be_secrets(mock_env, entry, why):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/abc123").mock(
            return_value=httpx.Response(200, json={"Config": {"Env": [entry]}})
        )

        result = await server.inspect_container(container_id="abc123")

        assert result["Config"]["Env"] == [entry], f"{why} should stay readable"


@pytest.mark.asyncio
async def test_secret_shaped_key_does_not_escape_via_a_path_or_url_value(mock_env):
    """Records a deliberate usability trade-off, not an oversight.

    TEMPORAL_TLS_KEY=/etc/temporal/config/tls.key is a *path to* a key, not a
    key, and is live on temporal-ui — redacting it loses harmless information.
    It is redacted anyway, because the path/URL escape running ahead of the key
    test is exactly what leaked WEBHOOK_SECRET=https://hooks.example.com/... in
    the test below. A secret-shaped key gets only the narrow escape (flag,
    number, empty). Safety wins over legibility on this one payload, which the
    audit called "the ONLY control".
    """
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/abc123").mock(
            return_value=httpx.Response(
                200,
                json={
                    "Config": {
                        "Env": [
                            "TEMPORAL_TLS_KEY=/etc/temporal/config/tls.key",
                            "TEMPORAL_TLS_ENABLED=false",
                        ]
                    }
                },
            )
        )

        env = (await server.inspect_container(container_id="abc123"))["Config"]["Env"]

        assert env[0] == "TEMPORAL_TLS_KEY=***REDACTED***"
        # The narrow escape still applies, so config flags stay readable.
        assert env[1] == "TEMPORAL_TLS_ENABLED=false"


@pytest.mark.parametrize(
    "entry",
    [
        # The half a key allowlist cannot provide: an opaque token under a key
        # nobody thought to pattern-match. A name-based list is only ever current
        # up to the last audit that tried to defeat it.
        "SOME_UNGUESSABLE_NAME=e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
        "DFLY_requirepass_alt=27ae41e4649b934ca495991b7852b8557ae41e44",
        "X=da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ],
)
@pytest.mark.asyncio
async def test_inspect_container_redacts_opaque_values_under_any_key(mock_env, entry):
    secret = entry.split("=", 1)[1]
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/abc123").mock(
            return_value=httpx.Response(200, json={"Config": {"Env": [entry]}})
        )

        result = await server.inspect_container(container_id="abc123")

        assert secret not in str(result)


@pytest.mark.asyncio
async def test_inspect_container_redacts_a_url_valued_secret_key(mock_env):
    """A secret-shaped key whose value is a URL must not escape via the URL rule."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/abc123").mock(
            return_value=httpx.Response(
                200,
                json={"Config": {"Env": ["WEBHOOK_SECRET=https://hooks.example.com/T00/B01/xxxx"]}},
            )
        )

        result = await server.inspect_container(container_id="abc123")

        assert "B01" not in str(result)


@pytest.mark.asyncio
async def test_inspect_container_redacts_a_token_in_a_url_query(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/abc123").mock(
            return_value=httpx.Response(
                200,
                json={
                    "Config": {"Env": ["FEED_URL=https://api.example.com/v1?access_token=s3cr3t"]}
                },
            )
        )

        result = await server.inspect_container(container_id="abc123")

        assert "s3cr3t" not in str(result)


@pytest.mark.asyncio
async def test_inspect_container_redacts_credentials_inside_urls(mock_env):
    """A bland *_URL key hides credentials that a key-name test cannot see."""
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/abc123").mock(
            return_value=httpx.Response(
                200,
                json={
                    "Config": {
                        "Env": [
                            "DATABASE_URL=postgres://admin:sup3rs3cret@db:5432/app",
                            "PLAIN_URL=https://example.com/path",
                        ]
                    }
                },
            )
        )

        result = await server.inspect_container(container_id="abc123")

        env = result["Config"]["Env"]
        assert "sup3rs3cret" not in str(result)
        assert "postgres://" in env[0]  # scheme kept — the value stays legible
        assert env[1] == "PLAIN_URL=https://example.com/path"


@pytest.mark.asyncio
async def test_inspect_container_redacts_secret_shaped_labels(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/abc123").mock(
            return_value=httpx.Response(
                200,
                json={
                    "Config": {
                        "Env": [],
                        "Labels": {"com.example.API_KEY": "leaked", "role": "web"},
                    }
                },
            )
        )

        result = await server.inspect_container(container_id="abc123")

        assert result["Config"]["Labels"]["com.example.API_KEY"] == "***REDACTED***"
        assert result["Config"]["Labels"]["role"] == "web"


# ---------------------------------------------------------------------------
# Bounded logs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [(None, "100"), (50, "50"), (999999, "5000"), (0, "1"), (-5, "1")],
)
@pytest.mark.asyncio
async def test_get_container_logs_bounds_tail(mock_env, supplied, expected):
    """An unbounded default would pull a whole log history into the caller."""
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/containers/abc123/logs").mock(
            return_value=httpx.Response(200, json={"logs": ""})
        )

        kwargs = {} if supplied is None else {"tail": supplied}
        await server.get_container_logs(container_id="abc123", **kwargs)

        assert route.calls[0].request.url.params.get("tail") == expected


@pytest.mark.asyncio
async def test_get_container_logs_passes_since_and_until(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/containers/abc123/logs").mock(
            return_value=httpx.Response(200, json={"logs": ""})
        )

        await server.get_container_logs(
            container_id="abc123", since="2026-09-07T00:00:00Z", until="2026-09-07T12:00:00Z"
        )

        params = route.calls[0].request.url.params
        assert params.get("since") == "2026-09-07T00:00:00Z"
        assert params.get("until") == "2026-09-07T12:00:00Z"


@pytest.mark.asyncio
async def test_get_container_logs_omits_unset_time_filters(mock_env):
    with respx.mock(base_url=ENDPOINT) as mock:
        route = mock.get("/api/containers/abc123/logs").mock(
            return_value=httpx.Response(200, json={"logs": ""})
        )

        await server.get_container_logs(container_id="abc123")

        params = route.calls[0].request.url.params
        assert "since" not in params
        assert "until" not in params


# ---------------------------------------------------------------------------
# The route surface is a closed set, enforced rather than reviewed
# ---------------------------------------------------------------------------


def _route_literals() -> set[str]:
    """Every Dockhand route literal the module can request.

    Read out of the source rather than by calling tools: a behavioural test can
    only cover routes it thinks to exercise, and the thing being guarded here is
    the route that nobody thought to exercise.
    """
    import pathlib
    import re as _re

    from dockhand_mcp import client as client_module

    found: set[str] = set()
    # Both modules, not just server.py — client.poll_job issues its own request,
    # so a module-scoped check would have a blind spot exactly where a reviewer
    # would not think to look.
    for module in (server, client_module):
        src = pathlib.Path(module.__file__).read_text()
        # Strip whole-line comments so the prose explaining why /inspect is
        # avoided is not mistaken for a call to it.
        body = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        found |= set(_re.findall(r'f?"(/api/[^"]*)"', body))
    return found


@pytest.mark.parametrize(
    "forbidden",
    [
        # Returns the raw Docker inspect payload with no masking pass upstream.
        "/inspect",
        # Return a stack's environment variables with no masking rationale.
        "/env",
    ],
)
def test_no_forbidden_route_is_reachable(forbidden):
    """Guards the Phase 6 security boundary in the place a reviewer cannot forget.

    Note this catches the path *segment*, so /api/stacks/{name}/env and
    /env/raw are both covered, while a ``?env=`` query param is not a path and
    does not match.
    """
    offenders = [r for r in _route_literals() if r.endswith(forbidden) or f"{forbidden}/" in r]
    assert offenders == [], f"forbidden route(s) reachable: {offenders}"


def test_route_surface_matches_the_declared_allowlist():
    """A new route must be added here deliberately, with the security question asked."""
    expected = {
        "/api/activity?limit={min(limit, 100)}&offset={offset}",
        "/api/containers",
        "/api/containers/batch-update",
        "/api/containers/check-updates",
        "/api/containers/pending-updates",
        "/api/containers/{container_id}",
        "/api/containers/{container_id}/logs",
        "/api/containers/{container_id}/stats",
        "/api/containers/{container_id}/{action}",
        "/api/health",
        "/api/host",
        "/api/images",
        "/api/images/scan",
        "/api/jobs/{job_id}",
        "/api/networks",
        "/api/stacks",
        "/api/stacks/{stack_name}/compose",
        "/api/stacks/{stack_name}/{action}",
        "/api/volumes",
    }
    assert _route_literals() == expected


def test_readme_documents_every_tool():
    """The README tool table and the registered tools are one fact in two places.

    This repo's recurring defect is documentation that describes behaviour the
    code does not have — update_container's docstring was wrong from v0.1.0 to
    2026-09-07. A table that drifts is the same failure in a more public place.
    """
    import pathlib
    import re as _re

    from .test_tool_errors_and_metrics import ALL_TOOLS

    readme = pathlib.Path(server.__file__).parent.parent / "README.md"
    table = readme.read_text().split("## Tool Reference", 1)[1].split("\n## ", 1)[0]
    documented = set(_re.findall(r"^\| `(\w+)`", table, _re.MULTILINE))

    assert documented == {name for name, _ in ALL_TOOLS}
