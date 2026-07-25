"""
Observability setup — structlog (always on) + optional InfluxDB/OTEL/NATS.

Each backend is gated on its env var. Missing env var = backend disabled.
No import errors if optional packages are absent.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

import structlog


def configure_logging() -> None:
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_file = os.environ.get("LOG_FILE", "/opt/appdata/dockhand-mcp/logs/dockhand-mcp.log")

    shared_processors = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    stderr_handler: logging.Handler = logging.StreamHandler(sys.stderr)
    handlers: list[logging.Handler] = [stderr_handler]
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

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    for h in handlers:
        root_logger.addHandler(h)
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))

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
        structlog.get_logger().warning("otel_init_failed", exc_info=True)
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
            structlog.get_logger().warning("otel_shutdown_failed", exc_info=True)
    if _nats_client is not None:
        try:
            await _nats_client.drain()
        except Exception:
            structlog.get_logger().warning("nats_shutdown_failed", exc_info=True)
        finally:
            _nats_client = None


_influx_client = None


def _get_influx():
    global _influx_client
    if _influx_client is not None:
        return _influx_client
    url = os.environ.get("INFLUXDB_URL", "")
    if not url:
        return None
    try:
        from influxdb_client_3 import InfluxDBClient3
        _influx_client = InfluxDBClient3(
            host=url,
            token=os.environ.get("INFLUXDB_TOKEN", ""),
            database=os.environ.get("INFLUXDB_BUCKET", "dockhand-mcp"),
        )
    except Exception:
        pass
    return _influx_client


_nats_client = None


async def _get_nats():
    global _nats_client
    if _nats_client is not None:
        return _nats_client
    url = os.environ.get("NATS_URL", "")
    if not url:
        return None
    try:
        import nats
        _nats_client = await nats.connect(url)
    except Exception:
        pass
    return _nats_client


async def emit_metric(
    measurement: str,
    tags: dict[str, str],
    fields: dict[str, Any],
) -> None:
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
        except Exception:
            pass

    nats_client = await _get_nats()
    if nats_client:
        try:
            import json
            prefix = os.environ.get("NATS_SUBJECT_PREFIX", "dockhand")
            tool = tags.get("tool", "unknown")
            subject = f"{prefix}.tool.{tool}"
            payload = json.dumps({"measurement": measurement, "tags": tags, "fields": fields})
            await nats_client.publish(subject, payload.encode())
        except Exception:
            pass


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
