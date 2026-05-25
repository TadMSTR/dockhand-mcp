module.exports = {
  apps: [{
    name: 'dockhand-mcp',
    script: 'python3',
    args: ['-m', 'dockhand_mcp.server'],
    cwd: '/home/ted/repos/personal/dockhand-mcp',
    interpreter: 'none',
    autorestart: true,
    watch: false,
    env: {
      DOCKHAND_ENDPOINT: 'http://localhost:7777',
      DOCKHAND_DEFAULT_ENV: '1',
      LOG_LEVEL: 'INFO',
      LOG_FILE: '/home/ted/logs/dockhand-mcp.log',
      // DOCKHAND_API_TOKEN injected via: pm2 start ecosystem.config.js --env-file ~/.secrets/forge.env
    },
  }],
};
