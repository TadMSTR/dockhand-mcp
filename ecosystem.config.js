// PM2 ecosystem — long-lived HTTP-transport dockhand-mcp process.
//
// Secrets are NOT hardcoded here. This file parses ~/.secrets/forge.env itself
// at load time (same pattern as backrest-mcp/githost-mcp ecosystem.config.js) —
// PM2 6.x has no `--env-file` flag on `pm2 start`, so that has to happen here
// rather than on the CLI. forge.env supplies:
//   DOCKHAND_API_TOKEN            — Dockhand REST bearer (required)
//   DOCKHAND_MCP_BEARER           — token scoped-mcp presents to dockhand-mcp
//   DOCKHAND_MCP_FLEET_BEARER     — same, for dockhand-mcp-fleet
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
// Two apps, same code, separate processes:
//   dockhand-mcp        127.0.0.1:8505/mcp  every environment, default env 1 (forge)
//   dockhand-mcp-fleet  127.0.0.1:8510/mcp  pinned to env 2 (one remote host) by
//                       DOCKHAND_ALLOWED_ENVS. It has its own bearer
//                       (DOCKHAND_MCP_FLEET_BEARER in forge.env, passed in as
//                       DOCKHAND_MCP_BEARER), so the fleet agent's broker never holds
//                       the main instance's token.
// The Dockhand API token covers every environment. The pin is enforced on this
// side only. scoped-mcp fronts each instance via `url:` +
// `Authorization: Bearer ...`. Do not expose either port.
//
// Start ONE app at a time. A bare `pm2 start ecosystem.config.js` starts or
// restarts both. Run it from a clean env so the shell's exports don't leak in:
//   env -i HOME=$HOME PATH=/usr/local/bin:/usr/bin:/bin pm2 start ecosystem.config.js --only dockhand-mcp-fleet
//   env -i HOME=$HOME PATH=/usr/local/bin:/usr/bin:/bin pm2 save
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

// Shared by both apps. Per-app overrides go in app() below.
const baseEnv = {
  // Transport — long-lived HTTP service on loopback.
  MCP_TRANSPORT: 'http',
  DOCKHAND_MCP_HTTP_HOST: '127.0.0.1',
  DOCKHAND_MCP_HTTP_PATH: '/mcp',
  // Dockhand backend.
  DOCKHAND_ENDPOINT: 'http://localhost:7777',
  // Logging. As of 0.4.0 this is the SINGLE sink: when LOG_FILE is writable the
  // stderr handler is not attached, so out_file/error_file below carry only PM2's
  // own output and genuine uncaught stderr — not a second copy of every log line.
  // Set LOG_FILE to '' to hand the files to PM2 entirely instead.
  LOG_LEVEL: 'INFO',
  // Telemetry naming defaults; endpoints + tokens come from forge.env.
  INFLUXDB_BUCKET: 'dockhand-mcp',
  NATS_SUBJECT_PREFIX: 'dockhand',
};

for (const key of [
  "DOCKHAND_API_TOKEN",
  "OTEL_EXPORTER_OTLP_ENDPOINT",
  "INFLUXDB_URL",
  "INFLUXDB_TOKEN",
  // NATS_URL deliberately excluded — see note above.
]) {
  if (sharedEnv[key]) baseEnv[key] = sharedEnv[key];
}

// bearerKey names the forge.env variable this app's bearer comes from. There is
// no fallback to the other app's bearer: if it is missing, server.py refuses to
// start in http mode, which is the intended failure.
function app(name, port, bearerKey, overrides) {
  const env = Object.assign({}, baseEnv, {
    DOCKHAND_MCP_HTTP_PORT: String(port),
    LOG_FILE: `/home/ted/logs/${name}.log`,
  }, overrides);
  if (sharedEnv[bearerKey]) env.DOCKHAND_MCP_BEARER = sharedEnv[bearerKey];
  return {
    name,
    script: '/home/ted/repos/personal/dockhand-mcp/.venv/bin/python',
    args: ['-m', 'dockhand_mcp.server'],
    cwd: '/home/ted/repos/personal/dockhand-mcp',
    interpreter: 'none',
    autorestart: true,
    watch: false,
    max_restarts: 10,
    restart_delay: 2000,
    // Centralized logs. Rotated by /etc/logrotate.d/forge-logs (daily, rotate 14,
    // copytruncate) — installed 2026-08-29 for vikunja#574/#571. pm2-logrotate is
    // NOT installed; the previous comment here claimed rotation that did not exist,
    // which is how /home/ted/logs reached 598 MB across 1,313 files.
    out_file: `/home/ted/logs/${name}.out.log`,
    error_file: `/home/ted/logs/${name}.err.log`,
    merge_logs: true,
    time: true,
    env,
  };
}

module.exports = {
  apps: [
    app('dockhand-mcp', 8505, 'DOCKHAND_MCP_BEARER', {
      DOCKHAND_DEFAULT_ENV: '1',
    }),
    // Fleet agent's instance, confined to Dockhand env 2 (a Hawser agent).
    // Calls naming any other environment are refused before any request is made.
    app('dockhand-mcp-fleet', 8510, 'DOCKHAND_MCP_FLEET_BEARER', {
      DOCKHAND_DEFAULT_ENV: '2',
      DOCKHAND_ALLOWED_ENVS: '2',
    }),
  ],
};
