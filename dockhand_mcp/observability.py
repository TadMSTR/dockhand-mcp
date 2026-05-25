"""
Observability setup — structlog (always on) + optional InfluxDB/OTEL/NATS.

Each backend is gated on its env var. Missing env var = backend disabled.
No import errors if optional packages are absent.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import structlog


def configure_logging() -> None:
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_file = os.environ.get("LOG_FILE", "")

    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        handlers=handlers,
        format="%(message)s",
    )

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level, logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )


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
