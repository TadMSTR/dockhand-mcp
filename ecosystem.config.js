// PM2 process definition for dockhand-mcp as a long-lived HTTP service.
//
// Start with:
//   pm2 start ecosystem.config.js --env-file ~/.secrets/forge.env
//   pm2 save
//
// The --env-file supplies the SECRETS and forge-specific telemetry endpoints
// (kept out of this repo):
//   DOCKHAND_API_TOKEN            — Dockhand REST bearer (required)
//   DOCKHAND_MCP_BEARER           — token scoped-mcp presents to THIS endpoint
//                                   (required in http mode; >= 16 chars)
//   OTEL_EXPORTER_OTLP_ENDPOINT   — SigNoz OTLP gRPC endpoint (enables tracing)
//   INFLUXDB_URL / INFLUXDB_TOKEN — InfluxDB metrics (enables emit_metric points)
//   NATS_URL                      — NATS server (enables dockhand.tool.* events)
//
// The endpoint listens on 127.0.0.1:8505/mcp only; scoped-mcp fronts it via
// `url:` + `Authorization: Bearer ${DOCKHAND_MCP_BEARER}`. Do not expose the port.
module.exports = {
  apps: [{
    name: 'dockhand-mcp',
    script: '/home/ted/repos/personal/dockhand-mcp/.venv/bin/python',
    args: ['-m', 'dockhand_mcp.server'],
    cwd: '/home/ted/repos/personal/dockhand-mcp',
    interpreter: 'none',
    autorestart: true,
    watch: false,
    max_restarts: 10,
    restart_delay: 2000,
    // Centralized logs (rotate with the pm2-logrotate module).
    out_file: '/home/ted/logs/dockhand-mcp.out.log',
    error_file: '/home/ted/logs/dockhand-mcp.err.log',
    merge_logs: true,
    time: true,
    env: {
      // Transport — long-lived HTTP service on loopback.
      MCP_TRANSPORT: 'http',
      DOCKHAND_MCP_HTTP_HOST: '127.0.0.1',
      DOCKHAND_MCP_HTTP_PORT: '8505',
      DOCKHAND_MCP_HTTP_PATH: '/mcp',
      // Dockhand backend.
      DOCKHAND_ENDPOINT: 'http://localhost:7777',
      DOCKHAND_DEFAULT_ENV: '1',
      // Logging (structlog also writes JSON here alongside stderr/PM2).
      LOG_LEVEL: 'INFO',
      LOG_FILE: '/home/ted/logs/dockhand-mcp.log',
      // Telemetry naming defaults; endpoints + tokens come from --env-file.
      INFLUXDB_BUCKET: 'dockhand-mcp',
      NATS_SUBJECT_PREFIX: 'dockhand',
      // Secrets + telemetry endpoints injected via:
      //   pm2 start ecosystem.config.js --env-file ~/.secrets/forge.env
    },
  }],
};
