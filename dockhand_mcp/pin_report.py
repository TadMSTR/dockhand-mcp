"""Digest-pin report overlay for check_updates / get_pending_updates.

Dockhand resolves ``repo@sha256:X`` to X, so a digest-pinned container can never
show an update there: its ``hasUpdate`` is always false. The answer comes from a
separate scheduled checker that writes a JSON report (schema v1) to disk. This
module reads that report and attaches an explicit ``pin_assessment`` to every
pinned row. It never talks to a registry and never runs the checker.

The rule the whole module exists for: a report that is missing, stale,
unparseable or of an unknown schema makes every pinned row ``not_assessed``. It
never falls back to "no update".

Report statuses pass through verbatim, including ones this code has never seen.
The only status added here is ``not_assessed``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import structlog

log = structlog.get_logger()

SUPPORTED_SCHEMA = 1
DEFAULT_MAX_AGE_H = 30.0
DEFAULT_REPORT_PATH = Path.home() / ".local" / "state" / "digest-pin-check" / "report.json"

NOT_ASSESSED = "not_assessed"

# The real report is ~50 KB for ~50 containers. Anything this large is not a
# report, and is not parsed.
MAX_REPORT_BYTES = 4 * 1024 * 1024

# Allowance for clock skew between the checker and this process. A `generated`
# further in the future than this is not a timestamp we can reason about.
_FUTURE_SKEW_S = 300


@dataclass(frozen=True)
class PinReport:
    """Outcome of one report read. ``state`` is ``ok`` or the reason it is not."""

    state: str  # ok | missing | unreadable | schema_mismatch | stale
    reason: Optional[str] = None
    generated: Optional[str] = None
    age_hours: Optional[float] = None
    by_name: dict[str, dict] = field(default_factory=dict)
    by_ref: dict[str, list[dict]] = field(default_factory=dict)


def report_path() -> Path:
    # Env or default only. Never a tool argument: a caller must not be able to
    # point the server at an arbitrary file.
    configured = os.environ.get("DIGEST_PIN_REPORT", "").strip()
    return Path(configured) if configured else DEFAULT_REPORT_PATH


def max_age_hours() -> float:
    raw = os.environ.get("DIGEST_PIN_MAX_AGE_H", "").strip()
    if not raw:
        return DEFAULT_MAX_AGE_H
    try:
        value = float(raw)
    except ValueError:
        value = 0.0
    if not value > 0:
        log.warning("digest_pin_max_age_invalid", value=raw, using=DEFAULT_MAX_AGE_H)
        return DEFAULT_MAX_AGE_H
    return value


def _name(value: Any) -> Optional[str]:
    return value.lstrip("/") if isinstance(value, str) and value else None


def read_report(now: Optional[datetime] = None) -> PinReport:
    """Read and validate the report. Never raises."""
    path = report_path()
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            return PinReport("unreadable", reason=f"report exceeds {MAX_REPORT_BYTES} bytes")
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return PinReport("missing", reason=f"no report at {path}")
    except (OSError, UnicodeDecodeError) as e:
        return PinReport("unreadable", reason=f"cannot read report: {type(e).__name__}")

    try:
        data = json.loads(raw)
    except ValueError:
        return PinReport("unreadable", reason="report is not valid JSON")
    if not isinstance(data, dict):
        return PinReport("unreadable", reason="report top level is not an object")

    # Checked before anything else: a future schema may change every other field.
    schema = data.get("schema_version")
    if schema != SUPPORTED_SCHEMA or isinstance(schema, bool):
        return PinReport(
            "schema_mismatch",
            reason=f"report schema_version {repr(schema)[:40]}; this server reads {SUPPORTED_SCHEMA}",
        )

    generated = data.get("generated")
    try:
        ts = datetime.fromisoformat(generated) if isinstance(generated, str) else None
    except ValueError:
        ts = None
    if ts is None or ts.tzinfo is None:
        return PinReport("unreadable", reason="report has no timezone-aware 'generated'")

    now = now or datetime.now(timezone.utc)
    age_s = (now - ts).total_seconds()
    if age_s < -_FUTURE_SKEW_S:
        return PinReport(
            "unreadable", reason="report 'generated' is in the future", generated=generated
        )
    age_h = round(max(age_s, 0.0) / 3600, 2)
    limit = max_age_hours()
    if age_h > limit:
        return PinReport(
            "stale",
            reason=f"report is {age_h} h old; limit is {limit:g} h",
            generated=generated,
            age_hours=age_h,
        )

    containers = data.get("containers")
    if not isinstance(containers, list):
        return PinReport(
            "unreadable",
            reason="report has no 'containers' list",
            generated=generated,
            age_hours=age_h,
        )

    by_name: dict[str, dict] = {}
    by_ref: dict[str, list[dict]] = {}
    for row in containers:
        if not isinstance(row, dict):
            continue
        name = _name(row.get("container"))
        if name:
            by_name[name] = row
        ref = row.get("running_ref")
        if isinstance(ref, str) and ref:
            by_ref.setdefault(ref, []).append(row)

    return PinReport("ok", generated=generated, age_hours=age_h, by_name=by_name, by_ref=by_ref)


def is_pinned(ref: Any) -> bool:
    return isinstance(ref, str) and "@sha256:" in ref


def _assessment(report: PinReport, status: str, detail: Optional[str]) -> dict:
    return {
        "status": status,
        "detail": detail,
        "report_generated": report.generated,
        "report_state": report.state,
    }


def _from_row(report: PinReport, row: dict, how: Optional[str] = None) -> dict:
    status = row.get("status")
    if not isinstance(status, str) or not status:
        return _assessment(report, NOT_ASSESSED, "report row has no status")
    detail = row.get("detail")
    if how:
        detail = f"{detail} [{how}]" if detail else f"[{how}]"
    return _assessment(report, status, detail)


def assess(report: PinReport, name: Any, ref: str) -> dict:
    """The pin_assessment for one pinned container."""
    if report.state != "ok":
        return _assessment(report, NOT_ASSESSED, report.reason)

    row = report.by_name.get(_name(name) or "")
    if row is not None:
        # Same name, different image: the container was recreated on one side
        # of the report run, so the report's verdict is about another image.
        if row.get("running_ref") != ref:
            return _assessment(
                report, NOT_ASSESSED, "running image differs from the one the report assessed"
            )
        return _from_row(report, row)

    rows = report.by_ref.get(ref, [])
    if not rows:
        return _assessment(report, NOT_ASSESSED, "not in report")
    # Fall back to the image ref only when it is unambiguous. The same ref can
    # sit on several rows with different statuses (e.g. one container drifted,
    # another is an ephemeral CI container reported as undeclared).
    # Non-string statuses collapse to None before hashing: a JSON list or object
    # here would otherwise raise out of set() and fail the whole tool call.
    statuses = {r.get("status") if isinstance(r.get("status"), str) else None for r in rows}
    if len(statuses) != 1:
        return _assessment(
            report,
            NOT_ASSESSED,
            f"container not in report; its image ref maps to conflicting statuses "
            f"{sorted(str(s) for s in statuses)}",
        )
    return _from_row(report, rows[0], how="matched by image ref, not container name")


def overlay(rows: Any, ref_key: str, name_key: str, report: PinReport) -> dict:
    """Attach pin_assessment to every pinned row in place; return the summary.

    Dockhand's own fields are never modified. Rows that are not pinned get no
    pin_assessment key at all.
    """
    by_status: dict[str, int] = {}
    pinned = 0
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not is_pinned(row.get(ref_key)):
            continue
        a = assess(report, row.get(name_key), row[ref_key])
        row["pin_assessment"] = a
        pinned += 1
        by_status[a["status"]] = by_status.get(a["status"], 0) + 1
    return {
        "report_state": report.state,
        "report_generated": report.generated,
        "report_age_hours": report.age_hours,
        "report_reason": report.reason,
        "pinned": pinned,
        "by_status": by_status,
    }
