"""
Dockhand HTTP client — bearer token auth.

All requests use Authorization: Bearer <DOCKHAND_API_TOKEN>.
4xx/5xx responses, transport failures and non-JSON bodies raise DockhandError.
Configuration errors, and an environment outside DOCKHAND_ALLOWED_ENVS, raise
DockhandConfigError.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from typing import Any

import httpx
import structlog

# Dockhand job ids are UUIDs; validate before interpolating into a URL path so a
# malformed value can't redirect the authenticated GET to another endpoint.
_JOB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

log = structlog.get_logger(__name__)


# status_code for a failure that never produced an HTTP status: a timeout, a
# refused connection, or a 2xx whose body is not JSON. 0 cannot collide with a
# real status, so a caller can tell "Dockhand said no" from "Dockhand never
# answered" (vikunja#1239).
TRANSPORT_FAILURE = 0


class DockhandError(Exception):
    """Raised when Dockhand returns an error response, or no usable response."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"Dockhand error {status_code}: {message}")


def _parse_allowed_envs(raw: str) -> frozenset[int] | None:
    """Parse DOCKHAND_ALLOWED_ENVS ("2" or "1,2"). Unset or blank means no pin."""
    if not raw.strip():
        return None
    try:
        envs = frozenset(int(part) for part in raw.split(",") if part.strip())
    except ValueError:
        raise DockhandConfigError(
            f"Invalid DOCKHAND_ALLOWED_ENVS {raw!r}: must be comma-separated integer ids"
        ) from None
    if not envs:
        raise DockhandConfigError(f"Invalid DOCKHAND_ALLOWED_ENVS {raw!r}: no ids")
    return envs


class DockhandConfigError(Exception):
    """Raised for missing or invalid configuration (not an HTTP error)."""


class DockhandClient:
    """
    Async HTTP client for Dockhand.

    A single instance should be reused for the lifetime of the MCP server
    so the httpx connection pool is shared across tool calls.
    """

    def __init__(self) -> None:
        # DockhandConfigError, not RuntimeError: every tool catches
        # (DockhandError, DockhandConfigError), so a RuntimeError here escaped the
        # handler entirely and was never even logged — _tool_error() is what logs,
        # and it never ran. resolve_env() below was deliberately given this type
        # for exactly this reason (vikunja#576).
        endpoint = os.environ.get("DOCKHAND_ENDPOINT", "").rstrip("/")
        if not endpoint:
            raise DockhandConfigError("DOCKHAND_ENDPOINT is required")

        self._token = os.environ.get("DOCKHAND_API_TOKEN", "")
        if not self._token:
            raise DockhandConfigError("DOCKHAND_API_TOKEN is required")

        self._default_env = os.environ.get("DOCKHAND_DEFAULT_ENV", "")
        # The pin is enforced here and only here: one Dockhand API token is valid
        # for every environment, so nothing upstream would stop a pinned instance
        # from reaching another env (vikunja#1027).
        self._allowed_envs = _parse_allowed_envs(os.environ.get("DOCKHAND_ALLOWED_ENVS", ""))

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

    @property
    def allowed_envs(self) -> frozenset[int] | None:
        """The DOCKHAND_ALLOWED_ENVS pin, or None when this instance is unpinned."""
        return self._allowed_envs

    def resolve_env(self, environment_id: str | int | None = None) -> int:
        """Resolve the Dockhand environment id to an int for the ``?env=`` query param.

        Precedence: explicit ``environment_id`` arg → ``DOCKHAND_DEFAULT_ENV``.
        Every Dockhand REST endpoint reads the environment from ``?env=<int>``
        (parsed with ``parseInt``) and silently returns an empty result — or fails
        the async job — when it is absent. Resolving it here, and raising a clear
        error when neither source is set, prevents that silent-empty failure mode.

        With ``DOCKHAND_ALLOWED_ENVS`` set, the resolved id must be in it, and when
        it lists more than one id the default is not applied: the caller has to
        say which environment it means.

        Raises:
            DockhandConfigError: if no environment id can be resolved, the
                resolved value is not an integer, or it is outside the pin.
        """
        explicit = environment_id not in (None, "")
        if not explicit and self._allowed_envs is not None and len(self._allowed_envs) > 1:
            raise DockhandConfigError(
                "environment_id is required: this instance is pinned to environments "
                f"{sorted(self._allowed_envs)} by DOCKHAND_ALLOWED_ENVS, so no default applies."
            )
        raw: str | int | None = environment_id if explicit else self._default_env
        if raw in (None, ""):
            raise DockhandConfigError(
                "No Dockhand environment resolved. Pass environment_id or set "
                "DOCKHAND_DEFAULT_ENV to the Dockhand environment ID (e.g. '1'). "
                "Without it, Dockhand returns an empty result and jobs fail with "
                "'No environment specified'."
            )
        # bool is an int subclass; True would otherwise resolve to env 1.
        if isinstance(raw, bool):
            raise DockhandConfigError(f"Invalid Dockhand environment id {raw!r}")
        try:
            env = int(raw)
        except (ValueError, TypeError):
            raise DockhandConfigError(
                f"Invalid Dockhand environment id {raw!r}: must be an integer "
                "(e.g. '1'). Check DOCKHAND_DEFAULT_ENV or the environment_id argument."
            ) from None
        if self._allowed_envs is not None and env not in self._allowed_envs:
            raise DockhandConfigError(
                f"Environment {env} is not allowed on this instance "
                f"(DOCKHAND_ALLOWED_ENVS={sorted(self._allowed_envs)})."
            )
        return env

    def env_filter(self, environment_id: str | int | None = None) -> int | None:
        """The environment filter for a route where the filter is optional.

        Unpinned and not asked for: None, meaning every environment, which is the
        historical behaviour. Pinned, or asked for: a resolved, pin-checked id.
        A pinned instance never makes an unfiltered cross-environment read.
        """
        if environment_id in (None, "") and self._allowed_envs is None:
            return None
        return self.resolve_env(environment_id)

    async def poll_job(self, job_id: str, *, timeout: float = 120.0, interval: float = 1.0) -> dict:
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
            data = json_body(resp)
            if not isinstance(data, dict):
                data = {}
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

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        # A timeout or refused connection used to escape every tool, because they
        # catch DockhandError only: the "always returns an error dict" contract
        # broke and _tool_error never logged it (vikunja#1239).
        try:
            resp = await self._http.request(method, path, headers=self._auth_headers(), **kwargs)
        except httpx.TransportError as e:
            raise DockhandError(TRANSPORT_FAILURE, f"{type(e).__name__}: {e}") from e
        _raise_for_status(resp)
        return resp

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self._request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self._request("POST", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self._request("DELETE", path, **kwargs)

    async def resolve_container_id(self, container: str, env: int) -> str:
        """Resolve a container name, or a short id, to its full id.

        batch-update matches full ids only: a name answers ``success:false,
        "Container not found"`` *after* the HITL approval has been spent, and a
        rejected attempt still counts against the hourly limit (dockhand-2026-10
        p1). ``GET /api/containers/{id}`` accepts a name or an id, so it does the
        lookup. A container that does not resolve raises, and nothing is POSTed.
        """
        resp = await self.get(f"/api/containers/{container}", params={"env": env})
        data = json_body(resp)
        full_id = data.get("Id") or data.get("id") if isinstance(data, dict) else None
        if not isinstance(full_id, str) or not _FULL_ID.match(full_id):
            raise DockhandError(
                resp.status_code, f"could not resolve container {container!r} to a full id"
            )
        return full_id


_FULL_ID = re.compile(r"^[0-9a-f]{64}$")


def json_body(resp: httpx.Response) -> Any:
    """``resp.json()``, with a non-JSON body raised as DockhandError.

    A 2xx HTML page (an auth proxy's login form, a SvelteKit error page) used to
    raise JSONDecodeError straight out of the tool.
    """
    try:
        return resp.json()
    except ValueError as e:
        ctype = resp.headers.get("content-type", "unknown")
        raise DockhandError(
            TRANSPORT_FAILURE,
            f"non-JSON response from {resp.request.url.path} "
            f"(HTTP {resp.status_code}, content-type {ctype})",
        ) from e


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
_client: DockhandClient | None = None


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
