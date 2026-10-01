"""Digest-pin report overlay on check_updates / get_pending_updates.

Fixtures in tests/fixtures/ are frozen copies of real data, not shapes written
from a plan:

- check_updates_live.json / pending_updates_live.json: rows recorded verbatim
  from Dockhand 1.0.46 (2026-09-30). The results list is a trimmed subset; the
  top-level counts are the real ones.
- pin_report_v1.json: rows copied verbatim from a real schema-v1 report
  written by the digest-pin checker, one per observed status. The ``drift`` row
  was captured before its container was recreated. ``compose_root`` is
  neutralised.

Assertions compare whole dicts. A subset match passes when extra or wrong keys
are present, which is how a mocked ``results: []`` let an earlier shape bug in
this repo through.
"""

from __future__ import annotations

import copy
import inspect
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import respx

import dockhand_mcp.server as server
from dockhand_mcp import pin_report
from tests.conftest import ENDPOINT

FIXTURES = Path(__file__).parent / "fixtures"
CHECK_UPDATES_LIVE = json.loads((FIXTURES / "check_updates_live.json").read_text())
PENDING_UPDATES_LIVE = json.loads((FIXTURES / "pending_updates_live.json").read_text())
REPORT_V1 = json.loads((FIXTURES / "pin_report_v1.json").read_text())

NUQ_REF = (
    "ghcr.io/firecrawl/nuq-postgres:latest"
    "@sha256:4ca6718b2cef40404b046db5cd37ae45db3e44d1a5750c80522f3587a5b193d5"
)
PINNED = {"firecrawl-v2-postgres", "kiwix", "bentopdf"}
FLOATING = {"agent-postgres", "vikunja", "agent-dragonfly"}

ALL_REPORT_STATUSES = [
    "current",
    "update",
    "exempt",
    "exempt-expired",
    "unresolvable",
    "error",
    "known-stale",
    "known-stale-expired",
    "drift",
    "undeclared",
]


def _fresh(report: dict, age: timedelta = timedelta(hours=1)) -> dict:
    """The fixture with ``generated`` moved to ``age`` before the test's clock."""
    out = copy.deepcopy(report)
    out["generated"] = (datetime.now(timezone.utc) - age).isoformat()
    return out


def _write(monkeypatch, tmp_path, content) -> Path:
    path = tmp_path / "report.json"
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    monkeypatch.setenv("DIGEST_PIN_REPORT", str(path))
    return path


def _row(report: dict, container: str) -> dict:
    return next(r for r in report["containers"] if r["container"] == container)


async def _check_updates(dockhand_response: dict) -> dict:
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.post("/api/containers/check-updates").mock(
            return_value=httpx.Response(200, json=dockhand_response)
        )
        return await server.check_updates()


def _by_name(result: dict) -> dict:
    return {r["containerName"]: r for r in result["results"]}


def _strip_overlay(result: dict) -> dict:
    """The response with every overlay key removed: what Dockhand sent."""
    out = copy.deepcopy(result)
    out.pop("digest_pins", None)
    for row in out.get("results", []):
        row.pop("pin_assessment", None)
    return out


# ---------------------------------------------------------------------------
# A good report
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_updates_overlays_every_pinned_row_from_a_fresh_report(
    mock_env, monkeypatch, tmp_path
):
    report = _fresh(REPORT_V1)
    _write(monkeypatch, tmp_path, report)

    result = await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE))
    rows = _by_name(result)

    # nuq-postgres: Dockhand says no update; the report says update. Both stand.
    assert rows["firecrawl-v2-postgres"]["hasUpdate"] is False
    assert rows["firecrawl-v2-postgres"]["pin_assessment"] == {
        "status": "update",
        "detail": (
            "ghcr.io/firecrawl/nuq-postgres:latest now resolves elsewhere "
            "(platform-manifest via index -> linux/amd64)"
        ),
        "report_generated": report["generated"],
        "report_state": "ok",
    }
    assert rows["bentopdf"]["pin_assessment"] == {
        "status": "drift",
        "detail": _row(REPORT_V1, "bentopdf")["detail"],
        "report_generated": report["generated"],
        "report_state": "ok",
    }
    # kiwix's row is in Dockhand's output but not in this report.
    assert rows["kiwix"]["pin_assessment"] == {
        "status": "not_assessed",
        "detail": "not in report",
        "report_generated": report["generated"],
        "report_state": "ok",
    }
    for name in FLOATING:
        assert "pin_assessment" not in rows[name], f"{name} is floating; no overlay"

    digest_pins = result["digest_pins"]
    assert digest_pins == {
        "report_state": "ok",
        "report_generated": report["generated"],
        "report_age_hours": digest_pins["report_age_hours"],
        "report_reason": None,
        "pinned": 3,
        "by_status": {"update": 1, "drift": 1, "not_assessed": 1},
    }
    assert 0.9 < digest_pins["report_age_hours"] < 1.1
    assert sum(digest_pins["by_status"].values()) == digest_pins["pinned"]


@pytest.mark.asyncio
async def test_dockhand_fields_are_passed_through_untouched(mock_env, monkeypatch, tmp_path):
    _write(monkeypatch, tmp_path, _fresh(REPORT_V1))

    result = await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE))

    # Remove only the overlay and what is left is exactly what Dockhand sent:
    # hasUpdate, updatesFound, currentDigest, error rows, all of it.
    assert _strip_overlay(result) == CHECK_UPDATES_LIVE
    assert result["updatesFound"] == 25


@pytest.mark.parametrize("status", ALL_REPORT_STATUSES + ["pin-missing"])
@pytest.mark.asyncio
async def test_report_status_passes_through_verbatim(mock_env, monkeypatch, tmp_path, status):
    """All 10 schema-v1 statuses, hyphens intact, plus one this code has never
    seen (a later checker may add one without bumping the schema)."""
    report = _fresh(REPORT_V1)
    _row(report, "firecrawl-v2-postgres")["status"] = status
    _write(monkeypatch, tmp_path, report)

    result = await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE))

    assert _by_name(result)["firecrawl-v2-postgres"]["pin_assessment"]["status"] == status
    expected: dict[str, int] = {"drift": 1, "not_assessed": 1}
    expected[status] = expected.get(status, 0) + 1
    assert result["digest_pins"]["by_status"] == expected


@pytest.mark.parametrize("status", ["", None, 7])
@pytest.mark.asyncio
async def test_report_row_without_a_usable_status_is_not_assessed(
    mock_env, monkeypatch, tmp_path, status
):
    report = _fresh(REPORT_V1)
    _row(report, "firecrawl-v2-postgres")["status"] = status
    _write(monkeypatch, tmp_path, report)

    result = await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE))

    a = _by_name(result)["firecrawl-v2-postgres"]["pin_assessment"]
    assert (a["status"], a["detail"]) == ("not_assessed", "report row has no status")


# ---------------------------------------------------------------------------
# A bad report fails closed. These are the cases a broken implementation
# defaults to "current".
# ---------------------------------------------------------------------------


def _schema(v):
    r = _fresh(REPORT_V1)
    r["schema_version"] = v
    return r


def _without(key):
    r = _fresh(REPORT_V1)
    del r[key]
    return r


def _generated(value):
    r = _fresh(REPORT_V1)
    r["generated"] = value
    return r


BAD_REPORTS = [
    pytest.param(None, "missing", id="missing"),
    pytest.param(_fresh(REPORT_V1, timedelta(hours=31)), "stale", id="stale-31h"),
    pytest.param(_schema(2), "schema_mismatch", id="schema-2"),
    pytest.param(_schema("1"), "schema_mismatch", id="schema-string"),
    pytest.param(_schema(True), "schema_mismatch", id="schema-bool"),
    pytest.param(_without("schema_version"), "schema_mismatch", id="schema-absent"),
    pytest.param('{"schema_version": 1, "generated": ', "unreadable", id="truncated-json"),
    pytest.param("[]", "unreadable", id="not-an-object"),
    pytest.param("[" * 100_000 + "]" * 100_000, "unreadable", id="deeply-nested-json"),
    pytest.param(_without("containers"), "unreadable", id="no-containers"),
    pytest.param(_without("generated"), "unreadable", id="no-generated"),
    pytest.param(_generated("2026-09-30T22:42:42"), "unreadable", id="naive-generated"),
    pytest.param(_generated("yesterday"), "unreadable", id="garbage-generated"),
    pytest.param(_fresh(REPORT_V1, timedelta(hours=-2)), "unreadable", id="generated-in-future"),
]


@pytest.mark.parametrize("content, state", BAD_REPORTS)
@pytest.mark.asyncio
async def test_bad_report_makes_every_pinned_row_not_assessed(
    mock_env, monkeypatch, tmp_path, content, state
):
    if content is not None:
        _write(monkeypatch, tmp_path, content)

    result = await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE))
    rows = _by_name(result)

    for name in PINNED:
        a = rows[name]["pin_assessment"]
        assert a["status"] == "not_assessed", f"{name} read {a['status']!r} from a {state} report"
        assert a["report_state"] == state
        assert a["detail"] == result["digest_pins"]["report_reason"]
    for name in FLOATING:
        assert "pin_assessment" not in rows[name]
    assert result["digest_pins"]["report_state"] == state
    assert result["digest_pins"]["report_reason"]
    assert result["digest_pins"]["pinned"] == 3
    assert result["digest_pins"]["by_status"] == {"not_assessed": 3}
    # The tool still succeeds, with Dockhand's data intact.
    assert _strip_overlay(result) == CHECK_UPDATES_LIVE


@pytest.mark.asyncio
async def test_unreadable_path_does_not_raise_out_of_the_tool(mock_env, monkeypatch, tmp_path):
    # A directory where the file should be: read_text raises IsADirectoryError.
    monkeypatch.setenv("DIGEST_PIN_REPORT", str(tmp_path))

    result = await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE))

    assert result["digest_pins"]["report_state"] == "unreadable"
    assert result["digest_pins"]["by_status"] == {"not_assessed": 3}


@pytest.mark.asyncio
async def test_nul_in_report_path_does_not_raise_out_of_the_tool(mock_env, monkeypatch, tmp_path):
    """Path.stat() raises ValueError, not OSError, on an embedded NUL (audit L-1).

    Not reachable through DIGEST_PIN_REPORT itself: os.environ refuses a NUL and
    an execve environment cannot carry one. So the path is injected directly,
    and this pins the handler, not a live route.
    """
    monkeypatch.setattr(pin_report, "report_path", lambda: tmp_path / "rep\x00ort.json")

    result = await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE))

    assert result["digest_pins"]["report_state"] == "unreadable"
    assert result["digest_pins"]["report_reason"] == "cannot read report: ValueError"
    assert _strip_overlay(result) == CHECK_UPDATES_LIVE


@pytest.mark.asyncio
async def test_unforeseen_reader_error_fails_closed(mock_env, monkeypatch):
    """The boundary catch-all: an exception no specific handler anticipated."""

    def boom(now):
        raise KeyError("unforeseen")

    monkeypatch.setattr(pin_report, "_read_report", boom)

    result = await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE))

    assert result["digest_pins"]["report_state"] == "unreadable"
    assert result["digest_pins"]["report_reason"] == "unexpected error reading report: KeyError"
    assert result["digest_pins"]["by_status"] == {"not_assessed": 3}
    assert _strip_overlay(result) == CHECK_UPDATES_LIVE


@pytest.mark.asyncio
async def test_oversized_report_is_not_parsed(mock_env, monkeypatch, tmp_path):
    monkeypatch.setattr(pin_report, "MAX_REPORT_BYTES", 1024)
    _write(monkeypatch, tmp_path, _fresh(REPORT_V1))

    result = await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE))

    assert result["digest_pins"]["report_state"] == "unreadable"
    assert result["digest_pins"]["report_reason"] == "report exceeds 1024 bytes"
    assert result["digest_pins"]["by_status"] == {"not_assessed": 3}


@pytest.mark.asyncio
async def test_schema_value_echoed_in_the_reason_is_bounded(mock_env, monkeypatch, tmp_path):
    _write(monkeypatch, tmp_path, _schema("x" * 5000))

    result = await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE))

    assert result["digest_pins"]["report_state"] == "schema_mismatch"
    assert len(result["digest_pins"]["report_reason"]) < 100


@pytest.mark.asyncio
async def test_max_age_is_configurable(mock_env, monkeypatch, tmp_path):
    _write(monkeypatch, tmp_path, _fresh(REPORT_V1, timedelta(hours=3)))

    monkeypatch.setenv("DIGEST_PIN_MAX_AGE_H", "2")
    assert (await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE)))["digest_pins"][
        "report_state"
    ] == "stale"

    monkeypatch.setenv("DIGEST_PIN_MAX_AGE_H", "4")
    assert (await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE)))["digest_pins"][
        "report_state"
    ] == "ok"


@pytest.mark.parametrize("raw", ["abc", "0", "-5", "nan", "inf", "1e999"])
def test_invalid_max_age_falls_back_to_default(monkeypatch, raw):
    monkeypatch.setenv("DIGEST_PIN_MAX_AGE_H", raw)
    assert pin_report.max_age_hours() == pin_report.DEFAULT_MAX_AGE_H


def test_report_path_is_not_a_tool_argument():
    """A caller must not be able to point the server at an arbitrary file."""
    for tool in (server.check_updates, server.get_pending_updates):
        fn = getattr(tool, "fn", tool)
        assert list(inspect.signature(fn).parameters) == ["environment_id"]


# ---------------------------------------------------------------------------
# Joining Dockhand rows to report rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_container_recreated_since_the_report_is_not_assessed(
    mock_env, monkeypatch, tmp_path
):
    """Same name, different running image: the report is about an image that is
    no longer running (e.g. the drifted container was recreated after the run)."""
    report = _fresh(REPORT_V1)
    report["containers"].append("not-a-row")  # skipped, not fatal
    _write(monkeypatch, tmp_path, report)
    dockhand = copy.deepcopy(CHECK_UPDATES_LIVE)
    bento = next(r for r in dockhand["results"] if r["containerName"] == "bentopdf")
    bento["imageName"] = _row(REPORT_V1, "bentopdf")["declared_ref"]

    a = _by_name(await _check_updates(dockhand))["bentopdf"]["pin_assessment"]

    assert (a["status"], a["detail"]) == (
        "not_assessed",
        "running image differs from the one the report assessed",
    )


@pytest.mark.asyncio
async def test_falls_back_to_image_ref_when_the_name_is_unknown(mock_env, monkeypatch, tmp_path):
    report = _fresh(REPORT_V1)
    _row(report, "firecrawl-v2-postgres")["container"] = "firecrawl-v2-postgres-old"
    _write(monkeypatch, tmp_path, report)

    a = _by_name(await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE)))["firecrawl-v2-postgres"][
        "pin_assessment"
    ]

    assert a["status"] == "update"
    assert a["detail"].endswith("[matched by image ref, not container name]")


@pytest.mark.asyncio
async def test_ambiguous_image_ref_is_not_assessed(mock_env, monkeypatch, tmp_path):
    """One ref on two report rows with different statuses: the fallback cannot
    choose, so it does not. Real case: an ephemeral CI container reported as
    ``undeclared`` running the same pinned image as a declared service."""
    report = _fresh(REPORT_V1)
    _row(report, "firecrawl-v2-postgres")["container"] = "renamed"
    twin = copy.deepcopy(_row(REPORT_V1, "wp_01M3T9W6HEV4SW1KCCAGJJSZA7"))
    twin["running_ref"] = NUQ_REF
    report["containers"].append(twin)
    _write(monkeypatch, tmp_path, report)

    a = _by_name(await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE)))["firecrawl-v2-postgres"][
        "pin_assessment"
    ]

    assert a["status"] == "not_assessed"
    assert "conflicting statuses ['undeclared', 'update']" in a["detail"]


@pytest.mark.parametrize("status", [["update"], {"s": "update"}])
@pytest.mark.asyncio
async def test_unhashable_status_on_the_ref_fallback_does_not_raise(
    mock_env, monkeypatch, tmp_path, status
):
    """A list/object status reached through the image-ref fallback must not
    raise out of the tool (CodeRabbit CR-01 on PR #13)."""
    report = _fresh(REPORT_V1)
    row = _row(report, "firecrawl-v2-postgres")
    row["container"] = "renamed"
    row["status"] = status
    _write(monkeypatch, tmp_path, report)

    result = await _check_updates(copy.deepcopy(CHECK_UPDATES_LIVE))

    a = _by_name(result)["firecrawl-v2-postgres"]["pin_assessment"]
    assert (a["status"], a["detail"]) == ("not_assessed", "report row has no status")
    assert _strip_overlay(result) == CHECK_UPDATES_LIVE


# ---------------------------------------------------------------------------
# get_pending_updates
# ---------------------------------------------------------------------------


async def _pending(dockhand_response: dict) -> dict:
    with respx.mock(base_url=ENDPOINT) as mock:
        mock.get("/api/containers/pending-updates").mock(
            return_value=httpx.Response(200, json=dockhand_response)
        )
        return await server.get_pending_updates()


@pytest.mark.asyncio
async def test_pending_updates_live_shape_has_no_pinned_rows(mock_env, monkeypatch, tmp_path):
    """Dockhand lists only hasImageUpdate:true rows, and never flags a pin, so the
    real response carries no pinned row. The summary says so explicitly."""
    report = _fresh(REPORT_V1)
    _write(monkeypatch, tmp_path, report)

    result = await _pending(copy.deepcopy(PENDING_UPDATES_LIVE))

    assert result["pendingUpdates"] == PENDING_UPDATES_LIVE["pendingUpdates"]
    assert result["total"] == 1
    assert result["withUpdateAvailable"] == 1
    assert result["digest_pins"] == {
        "report_state": "ok",
        "report_generated": report["generated"],
        "report_age_hours": result["digest_pins"]["report_age_hours"],
        "report_reason": None,
        "pinned": 0,
        "by_status": {},
    }


@pytest.mark.asyncio
async def test_pending_updates_overlays_a_pinned_row_if_one_appears(
    mock_env, monkeypatch, tmp_path
):
    """Synthetic: the live row with its image swapped for a pinned ref. Dockhand
    has not been seen to produce this; the test holds the overlay to the same
    contract in case it ever does."""
    _write(monkeypatch, tmp_path, _fresh(REPORT_V1))
    dockhand = copy.deepcopy(PENDING_UPDATES_LIVE)
    row = dockhand["pendingUpdates"][0]
    row["containerName"] = "firecrawl-v2-postgres"
    row["currentImage"] = NUQ_REF

    result = await _pending(dockhand)

    assert result["pendingUpdates"][0]["pin_assessment"]["status"] == "update"
    assert result["pendingUpdates"][0]["hasImageUpdate"] is True
    assert result["digest_pins"]["by_status"] == {"update": 1}


@pytest.mark.asyncio
async def test_pending_updates_missing_report_is_not_assessed(mock_env):
    dockhand = copy.deepcopy(PENDING_UPDATES_LIVE)
    dockhand["pendingUpdates"][0]["currentImage"] = NUQ_REF

    result = await _pending(dockhand)

    assert result["pendingUpdates"][0]["pin_assessment"]["status"] == "not_assessed"
    assert result["digest_pins"]["report_state"] == "missing"
