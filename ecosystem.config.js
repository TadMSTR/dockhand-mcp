// PM2 ecosystem — long-lived HTTP-transport dockhand-mcp process.
//
// Secrets are NOT hardcoded here. This file parses ~/.secrets/forge.env itself
// at load time (same pattern as backrest-mcp/githost-mcp ecosystem.config.js) —
// PM2 6.x has no `--env-file` flag on `pm2 start`, so that has to happen here
// rather than on the CLI. forge.env supplies:
//   DOCKHAND_API_TOKEN            — Dockhand REST bearer (required)
//   DOCKHAND_MCP_BEARER           — token scoped-mcp presents to THIS endpoint
//                                   (required in http mode; >= 16 chars)
//   OTEL_EXPORTER_OTLP_ENDPOINT   — SigNoz OTLP gRPC endpoint (enables tracing)
//   INFLUXDB_URL / INFLUXDB_TOKEN — InfluxDB metrics (enables emit_metric points)
//
// NATS_URL is intentionally NOT wired through: forge's NATS server requires
// per-agent user auth (~/.claude-secrets/nats-agent-users.env) and no
// NATS_AGENT_DOCKHAND_PASSWORD has been provisioned yet. Passing the bare
// shared NATS_URL causes an infinite reconnect loop ("Authorization
// Violation") since nats.connect() gets no credentials. Re-add once a
// dedicated user exists server-side.
//
// The endpoint listens on 127.0.0.1:8505/mcp only; scoped-mcp fronts it via
// `url:` + `Authorization: Bearer ${DOCKHAND_MCP_BEARER}`. Do not expose the port.
// Run: pm2 start ecosystem.config.js ; pm2 save
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

function parseEnvFile(filePath) {
  const env = {};
  if (!fs.existsSync(filePath)) return env;
  for (const line of fs.readFileSync(filePath, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
    const idx = trimmed.indexOf("=");
    env[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
  }
  return env;
}

const HOME = os.homedir();
const sharedEnv = parseEnvFile(path.join(HOME, ".secrets", "forge.env"));

const env = {
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
  // Telemetry naming defaults; endpoints + tokens come from forge.env.
  INFLUXDB_BUCKET: 'dockhand-mcp',
  NATS_SUBJECT_PREFIX: 'dockhand',
};

for (const key of [
  "DOCKHAND_API_TOKEN",
  "DOCKHAND_MCP_BEARER",
  "OTEL_EXPORTER_OTLP_ENDPOINT",
  "INFLUXDB_URL",
  "INFLUXDB_TOKEN",
  // NATS_URL deliberately excluded — see note above.
]) {
  if (sharedEnv[key]) env[key] = sharedEnv[key];
}

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
    env,
  }],
};
