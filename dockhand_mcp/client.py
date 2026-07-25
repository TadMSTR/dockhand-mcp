"""
Dockhand HTTP client — bearer token auth.

All requests use Authorization: Bearer <DOCKHAND_API_TOKEN>.
4xx/5xx responses raise DockhandError. Configuration errors raise DockhandConfigError.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from typing import Any, Optional, Union

import httpx
import structlog

# Dockhand job ids are UUIDs; validate before interpolating into a URL path so a
# malformed value can't redirect the authenticated GET to another endpoint.
_JOB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

log = structlog.get_logger(__name__)


class DockhandError(Exception):
    """Raised when Dockhand returns an error response."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"Dockhand error {status_code}: {message}")


class DockhandConfigError(Exception):
    """Raised for missing or invalid configuration (not an HTTP error)."""


class DockhandClient:
    """
    Async HTTP client for Dockhand.

    A single instance should be reused for the lifetime of the MCP server
    so the httpx connection pool is shared across tool calls.
    """

    def __init__(self) -> None:
        endpoint = os.environ.get("DOCKHAND_ENDPOINT", "").rstrip("/")
        if not endpoint:
            raise RuntimeError("DOCKHAND_ENDPOINT is required")

        self._token = os.environ.get("DOCKHAND_API_TOKEN", "")
        if not self._token:
            raise RuntimeError("DOCKHAND_API_TOKEN is required")

        self._default_env = os.environ.get("DOCKHAND_DEFAULT_ENV", "")

        self._http = httpx.AsyncClient(
            base_url=endpoint,
            timeout=30.0,
            headers={"Accept": "application/json"},
            trust_env=False,
        )

    async def close(self) -> None:
        await self._http.aclose()

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    def resolve_env(self, environment_id: Union[str, int, None] = None) -> int:
        """Resolve the Dockhand environment id to an int for the ``?env=`` query param.

        Precedence: explicit ``environment_id`` arg → ``DOCKHAND_DEFAULT_ENV``.
        Every Dockhand REST endpoint reads the environment from ``?env=<int>``
        (parsed with ``parseInt``) and silently returns an empty result — or fails
        the async job — when it is absent. Resolving it here, and raising a clear
        error when neither source is set, prevents that silent-empty failure mode.

        Raises:
            DockhandConfigError: if no environment id can be resolved, or the
                resolved value is not an integer.
        """
        raw: Union[str, int, None] = (
            environment_id if environment_id not in (None, "") else self._default_env
        )
        if raw in (None, ""):
            raise DockhandConfigError(
                "No Dockhand environment resolved. Pass environment_id or set "
                "DOCKHAND_DEFAULT_ENV to the Dockhand environment ID (e.g. '1'). "
                "Without it, Dockhand returns an empty result and jobs fail with "
                "'No environment specified'."
            )
        try:
            return int(raw)
        except (ValueError, TypeError):
            raise DockhandConfigError(
                f"Invalid Dockhand environment id {raw!r}: must be an integer "
                "(e.g. '1'). Check DOCKHAND_DEFAULT_ENV or the environment_id argument."
            )

    async def poll_job(
        self, job_id: str, *, timeout: float = 120.0, interval: float = 1.0
    ) -> dict:
        """Poll ``GET /api/jobs/{job_id}`` until the job reaches a terminal state.

        Dockhand action endpoints (stack deploy/start/stop/restart, container
        update) return ``{"jobId": ...}`` immediately and run asynchronously. The
        job record accumulates ``lines`` and, when finished, exposes a terminal
        ``result`` of ``{"success": bool, "output"|"error": str}``. This polls that
        record and returns the ``result`` dict.

        On timeout, returns a synthetic failure result carrying the last status so
        the caller never blocks indefinitely or reports a false success.
        """
        if not _JOB_ID.match(str(job_id)):
            return {
                "success": False,
                "error": f"malformed job id {str(job_id)[:64]!r}; refusing to poll",
            }
        deadline = time.monotonic() + timeout
        last_status = "unknown"
        while True:
            resp = await self.get(f"/api/jobs/{job_id}")
            data = resp.json()
            last_status = data.get("status", last_status)
            if last_status in ("done", "complete", "completed", "error", "failed"):
                return data.get("result", {}) or {}
            if time.monotonic() >= deadline:
                return {
                    "success": False,
                    "error": f"job {job_id} did not complete within {timeout:.0f}s "
                    f"(last status: {last_status})",
                    "status": last_status,
                }
            await asyncio.sleep(interval)

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        resp = await self._http.get(path, headers=self._auth_headers(), **kwargs)
        _raise_for_status(resp)
        return resp

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        resp = await self._http.post(path, headers=self._auth_headers(), **kwargs)
        _raise_for_status(resp)
        return resp

    async def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        resp = await self._http.delete(path, headers=self._auth_headers(), **kwargs)
        _raise_for_status(resp)
        return resp


def _raise_for_status(resp: httpx.Response) -> None:
    """Raise DockhandError for 4xx/5xx, preserving the JSON error message."""
    if resp.is_success:
        return
    try:
        body = resp.json()
        msg = body.get("error") or body.get("message") or resp.text
        details = body.get("details", "")
        if details:
            msg = f"{msg}: {details}"
    except Exception:
        msg = resp.text or resp.reason_phrase
    raise DockhandError(resp.status_code, msg)


# Module-level singleton
_client: Optional[DockhandClient] = None


def get_client() -> DockhandClient:
    global _client
    if _client is None:
        _client = DockhandClient()
    return _client


async def close_client() -> None:
    """Close the shared client if one was created, and reset the singleton.

    Called from the server lifespan on shutdown so the httpx connection pool is
    released cleanly. No-op when no tool ever built a client (so it never forces
    a client — and its required-env check — during teardown).
    """
    global _client
    if _client is not None:
        await _client.close()
        _client = None
