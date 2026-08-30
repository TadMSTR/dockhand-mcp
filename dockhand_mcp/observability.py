"""
Observability setup — structlog (always on) + optional InfluxDB/OTEL/NATS.

Each backend is gated on its env var. Missing env var = backend disabled.
No import errors if optional packages are absent.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# Library loggers demoted to WARNING by configure_logging(). Names are logger
# *prefixes* — `logging` applies the level to every child (`httpcore.http11`,
# `mcp.server.lowlevel`, `nats.aio.client`, ...) through normal propagation.
_THIRD_PARTY_LOGGERS = ("httpx", "httpcore", "mcp", "nats")


def configure_logging() -> None:
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_file = os.environ.get("LOG_FILE", "/opt/appdata/dockhand-mcp/logs/dockhand-mcp.log")

    shared_processors = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    # ONE sink, not two. A stderr StreamHandler and a FileHandler were both
    # attached, so under PM2 every line was written to `error_file` *and* to
    # LOG_FILE — two near-identical unrotated files (vikunja#574 P4, same shape
    # as #552). The file handler wins when LOG_FILE is writable; stderr is the
    # fallback, which is what keeps CI (and any restricted-perms runner) alive.
    handlers: list[logging.Handler] = []
    if log_file:
        try:
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            handlers.append(logging.FileHandler(log_file))
        except OSError as exc:
            # An unwritable log path (CI runner, restricted perms) must not crash
            # startup — fall back to stderr-only logging.
            print(
                f"dockhand-mcp: file logging disabled ({log_file}): {exc}",
                file=sys.stderr,
            )
    if not handlers:
        handlers.append(logging.StreamHandler(sys.stderr))

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    for h in handlers:
        root_logger.addHandler(h)
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))

    # Third-party wire trace is not this service's log. The root logger sits at
    # LOG_LEVEL, so httpx/httpcore/mcp/nats all inherited INFO and drowned the
    # app's own lines (measured: 76 ListToolsRequest, 58 CallToolRequest, 11
    # httpx request lines, plus the NATS reconnect flood). Demote them to
    # WARNING and leave the dockhand_mcp logger at LOG_LEVEL — same fix as
    # task-dispatcher (vikunja#552) and scoped-mcp (#554).
    for _noisy in _THIRD_PARTY_LOGGERS:
        logging.getLogger(_noisy).setLevel(logging.WARNING)

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )
    for h in handlers:
        h.setFormatter(formatter)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


# ---------------------------------------------------------------------------
# OTEL tracing (opt-in)
# ---------------------------------------------------------------------------

_tracer = None
_provider = None


def get_tracer():
    global _tracer, _provider
    if _tracer is not None:
        return _tracer
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return None
    try:
        from opentelemetry import trace  # type: ignore
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,  # type: ignore
        )
        from opentelemetry.sdk.resources import Resource  # type: ignore
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore

        resource = Resource.create({"service.name": "dockhand-mcp"})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        _provider = provider
        _tracer = trace.get_tracer("dockhand-mcp")
    except Exception:
        # EXEMPT from the no-exc_info rule the credential-bearing backends follow
        # (audit 2026-08-29, LOW-1). Two reasons this one keeps its traceback:
        # OTEL_EXPORTER_OTLP_ENDPOINT is a bare URL with no credential in it, and
        # the try block above spans five separate imports plus a gRPC exporter
        # build — `error_class=ImportError` alone would not say *which* failed,
        # which is the whole diagnostic question when the [otel] extra is missing.
        log.warning("otel_init_failed", exc_info=True)
    return _tracer


async def shutdown_observability() -> None:
    """Flush and release telemetry backends on process shutdown.

    Under the long-lived HTTP service this runs from the FastMCP lifespan on
    stop, so the OTel ``BatchSpanProcessor`` exports any buffered spans and the
    NATS connection drains cleanly instead of being torn down mid-flush (the
    per-turn-subprocess failure mode this migration fixes). All best-effort —
    shutdown must never raise.
    """
    global _nats_client
    if _provider is not None:
        try:
            _provider.shutdown()  # flushes BatchSpanProcessor then exits exporter
        except Exception:
            # Same exemption as otel_init_failed above: no credential in the OTel
            # config, and a flush failure is worth a full traceback.
            log.warning("otel_shutdown_failed", exc_info=True)
    if _nats_client is not None:
        try:
            await _nats_client.drain()
        except Exception as exc:
            # NOT exempt (audit 2026-08-29, LOW-1). NATS is the credential-bearing
            # backend — a NATS URL is nats://user:password@host — so this matches
            # the discipline of the init/publish warnings: exception class only,
            # never a rendered traceback that a future nats-py could seed with
            # connection detail.
            log.warning("nats_shutdown_failed", error_class=type(exc).__name__)
        finally:
            _nats_client = None


# A *configured but failing* backend must be visible and must not be retried on
# every tool call. `except Exception: pass` left the client global at None, which
# meant (a) 35 days of logs with zero lines mentioning influx, and (b) every
# emit_metric() re-entering the connect path — for NATS that spawned a fresh
# allow_reconnect background loop per call, turning one bad env var into 2,867
# error lines (vikunja#574 P1, #575 item 3).
#
# The sentinel is a distinct flag rather than an overloaded None so "never tried"
# and "tried and failed" stay distinguishable: a missing env var is the intended
# disabled path and must stay silent, a failed init must warn exactly once.
#
# SECURITY: the warning carries the exception *class*, never str(exc). A NATS URL
# is `nats://user:password@host` and an InfluxDB error can echo the host/token —
# both would land verbatim in a log this build is otherwise making quieter.
_influx_client = None
_influx_failed = False
_influx_write_failed_logged = False


def _get_influx():
    global _influx_client, _influx_failed
    if _influx_client is not None:
        return _influx_client
    if _influx_failed:
        return None
    url = os.environ.get("INFLUXDB_URL", "")
    if not url:
        return None  # backend not configured — intended disabled path, stay silent
    try:
        from influxdb_client_3 import InfluxDBClient3
        _influx_client = InfluxDBClient3(
            host=url,
            token=os.environ.get("INFLUXDB_TOKEN", ""),
            database=os.environ.get("INFLUXDB_BUCKET", "dockhand-mcp"),
        )
    except Exception as exc:
        _influx_failed = True
        log.warning(
            "influx_init_failed",
            error_class=type(exc).__name__,
            detail=(
                "INFLUXDB_URL is set but the client could not be built; metric "
                "writes are disabled for the lifetime of this process. Check the "
                "URL is reachable and the influxdb3-python extra is installed."
            ),
        )
    return _influx_client


_nats_client = None
_nats_failed = False
_nats_publish_failed_logged = False
_nats_error_logged = False

# nats-py's own reconnect machinery is the larger half of the 2,867-line flood —
# the per-call re-entry fixed by the sentinel above is only the other half.
# Measured against a refused port: ONE default nats.connect() blocks the calling
# tool for ~120 s and invokes error_cb ~60 times before it ever raises, because
# _select_next_server() loops with max_reconnect_attempts=60 / reconnect_time_wait=2
# and reports every failed attempt.
#
# Note max_reconnect_attempts=0 is a trap: the discard check in _select_next_server
# is `if self.options["max_reconnect_attempts"] > 0`, so 0 never discards the server
# and retries *forever*. 1 is the fail-fast value (two attempts, then NoServersError).
#
# allow_reconnect=False additionally stops a dropped connection from spawning the
# background retry loop that was never closed.
_NATS_CONNECT_OPTS = {
    "allow_reconnect": False,
    "max_reconnect_attempts": 1,
    "reconnect_time_wait": 0,
    "connect_timeout": 2,
}
# Hard ceiling on how long a broken NATS may delay a tool call, whatever the
# library does internally.
_NATS_CONNECT_DEADLINE = 5.0


async def _nats_error_cb(exc: Exception) -> None:
    """Replace nats-py's default error callback.

    The default is ``_logger.error("nats: encountered error", exc_info=ex)`` on the
    ``nats.aio.client`` logger — at ERROR, so demoting that logger to WARNING (see
    ``_THIRD_PARTY_LOGGERS``) does **not** silence it, and it fires once per
    reconnect attempt. Warn once per process and drop the rest, carrying the
    exception class only: a NATS URL is ``nats://user:password@host``.
    """
    global _nats_error_logged
    if not _nats_error_logged:
        _nats_error_logged = True
        log.warning(
            "nats_transport_error",
            error_class=type(exc).__name__,
            detail="first NATS transport error; further ones are not logged",
        )


async def _get_nats():
    global _nats_client, _nats_failed
    if _nats_client is not None:
        return _nats_client
    if _nats_failed:
        return None
    url = os.environ.get("NATS_URL", "")
    if not url:
        return None  # backend not configured — intended disabled path, stay silent
    try:
        import nats
        _nats_client = await asyncio.wait_for(
            nats.connect(url, error_cb=_nats_error_cb, **_NATS_CONNECT_OPTS),
            timeout=_NATS_CONNECT_DEADLINE,
        )
    except Exception as exc:
        _nats_failed = True
        log.warning(
            "nats_init_failed",
            error_class=type(exc).__name__,
            detail=(
                "NATS_URL is set but the connection failed; metric publishes are "
                "disabled for the lifetime of this process. Check the URL and that "
                "a NATS user is provisioned for this service."
            ),
        )
    return _nats_client


async def emit_metric(
    measurement: str,
    tags: dict[str, str],
    fields: dict[str, Any],
) -> None:
    global _influx_write_failed_logged, _nats_publish_failed_logged

    influx = _get_influx()
    if influx:
        try:
            from influxdb_client_3 import Point
            p = Point(measurement)
            for k, v in tags.items():
                p = p.tag(k, v)
            for k, v in fields.items():
                p = p.field(k, v)
            influx.write(record=p)
        except Exception as exc:
            # Warn once per process, then stay quiet. A write failure is often
            # transient (collector restart), so unlike an init failure it does not
            # disable the backend — but it must not be silent either, which is how
            # a whole telemetry layer went unnoticed for 35 days.
            if not _influx_write_failed_logged:
                _influx_write_failed_logged = True
                log.warning(
                    "influx_write_failed",
                    measurement=measurement,
                    error_class=type(exc).__name__,
                    detail="first metric write failure; further ones are not logged",
                )

    nats_client = await _get_nats()
    if nats_client:
        try:
            import json
            prefix = os.environ.get("NATS_SUBJECT_PREFIX", "dockhand")
            tool = tags.get("tool", "unknown")
            subject = f"{prefix}.tool.{tool}"
            payload = json.dumps({"measurement": measurement, "tags": tags, "fields": fields})
            await nats_client.publish(subject, payload.encode())
        except Exception as exc:
            if not _nats_publish_failed_logged:
                _nats_publish_failed_logged = True
                log.warning(
                    "nats_publish_failed",
                    measurement=measurement,
                    error_class=type(exc).__name__,
                    detail="first metric publish failure; further ones are not logged",
                )


# ---------------------------------------------------------------------------
# Tool-call tracing middleware
# ---------------------------------------------------------------------------

from fastmcp.server.middleware import Middleware, MiddlewareContext  # noqa: E402


class ToolTracingMiddleware(Middleware):
    """Wrap every MCP tool call in an OTel span named ``dockhand.tool.<name>``.

    A no-op when no tracer is configured (``OTEL_EXPORTER_OTLP_ENDPOINT`` unset),
    so it is always safe to register. This is the piece that makes tool calls
    actually appear as spans in SigNoz — ``get_tracer()`` builds the exporter but
    nothing emitted spans before this.
    """

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        tracer = get_tracer()
        if tracer is None:
            return await call_next(context)
        tool_name = getattr(context.message, "name", "unknown")
        with tracer.start_as_current_span(f"dockhand.tool.{tool_name}") as span:
            try:
                span.set_attribute("mcp.tool.name", tool_name)
            except Exception:
                pass
            try:
                return await call_next(context)
            except Exception as exc:
                try:
                    span.record_exception(exc)
                    from opentelemetry.trace import Status, StatusCode  # type: ignore

                    span.set_status(Status(StatusCode.ERROR, str(exc)))
                except Exception:
                    pass
                raise
