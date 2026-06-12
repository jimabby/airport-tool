const express = require('express');
const fs      = require('fs');
const net     = require('net');
const path    = require('path');
const QRCode  = require('qrcode');

const app  = express();
const PORT = process.env.PORT || 3000;
// Bind to loopback by default — the config holds the proxy password, so it
// should not be reachable from other machines unless explicitly opted in.
const HOST = process.env.HOST || '127.0.0.1';
const CFG_PATH = process.env.CFG_PATH || path.join(__dirname, '..', 'config-gen', 'server.json');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Helpers ───────────────────────────────────────────────────────────────── //
function loadConfig() {
  if (!fs.existsSync(CFG_PATH)) return null;
  try { return JSON.parse(fs.readFileSync(CFG_PATH, 'utf8')); }
  catch { return null; }
}

function buildSsUri(cfg) {
  const userinfo = Buffer.from(`${cfg.method}:${cfg.password}`).toString('base64');
  const plugin   = cfg.plugin || 'v2ray-plugin';
  const opts     = cfg.plugin_opts || 'server';
  const tag      = encodeURIComponent(cfg.remarks || 'Airport');
  return `ss://${userinfo}@${cfg.server}:${cfg.port}?plugin=${encodeURIComponent(plugin + ';' + opts)}#${tag}`;
}

function buildClashProxy(cfg) {
  const tls  = (cfg.plugin_opts || '').includes('tls');
  const hostM = (cfg.plugin_opts || '').match(/host=([^;]+)/);
  const pathM = (cfg.plugin_opts || '').match(/path=([^;]+)/);
  return {
    name:    cfg.remarks || 'Airport',
    type:    'ss',
    server:  cfg.server,
    port:    cfg.port,
    cipher:  cfg.method,
    password: cfg.password,
    plugin:  'v2ray-plugin',
    'plugin-opts': {
      mode: 'websocket',
      tls,
      host: hostM ? hostM[1] : cfg.server,
      path: pathM ? pathM[1] : '/ws',
    },
  };
}

// ── API routes ────────────────────────────────────────────────────────────── //
app.get('/api/config', (req, res) => {
  const cfg = loadConfig();
  if (!cfg) return res.status(404).json({ error: 'No server.json found. Add your server details.' });
  const ssUri = buildSsUri(cfg);
  res.json({ ...cfg, ssUri });
});

app.post('/api/config', (req, res) => {
  const { server, port, password, method, plugin, plugin_opts, remarks } = req.body;
  if (!server || !port || !password || !method) {
    return res.status(400).json({ error: 'server, port, password, and method are required.' });
  }
  const cfg = { server, port: Number(port), password, method,
    plugin: plugin || 'v2ray-plugin',
    plugin_opts: plugin_opts || 'server',
    remarks: remarks || 'Airport' };
  fs.mkdirSync(path.dirname(CFG_PATH), { recursive: true });
  // 0600 — the file holds the proxy password; keep it owner-only.
  fs.writeFileSync(CFG_PATH, JSON.stringify(cfg, null, 2), { encoding: 'utf8', mode: 0o600 });
  res.json({ ok: true, ssUri: buildSsUri(cfg) });
});

app.get('/api/qrcode', async (req, res) => {
  const cfg = loadConfig();
  if (!cfg) return res.status(404).json({ error: 'No config found.' });
  const ssUri = buildSsUri(cfg);
  try {
    const dataUrl = await QRCode.toDataURL(ssUri, { errorCorrectionLevel: 'L', width: 400 });
    res.json({ qrcode: dataUrl, ssUri });
  } catch (err) {
    res.status(500).json({ error: `Failed to generate QR code: ${err.message}` });
  }
});

app.get('/api/download/clash', (req, res) => {
  const cfg = loadConfig();
  if (!cfg) return res.status(404).send('No config');
  const yaml = buildClashYaml(cfg);
  res.setHeader('Content-Type', 'text/yaml');
  res.setHeader('Content-Disposition', 'attachment; filename="clash-config.yaml"');
  res.send(yaml);
});

app.get('/api/download/singbox', (req, res) => {
  const cfg = loadConfig();
  if (!cfg) return res.status(404).send('No config');
  const singbox = buildSingBoxConfig(cfg);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="singbox-config.json"');
  res.send(JSON.stringify(singbox, null, 2));
});

app.get('/api/download/uri', (req, res) => {
  const cfg = loadConfig();
  if (!cfg) return res.status(404).send('No config');
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename="ss-uri.txt"');
  res.send(buildSsUri(cfg) + '\n');
});

// ── Connectivity test ─────────────────────────────────────────────────────── //
// Opens a raw TCP connection to server:port to confirm the port is reachable.
// This checks reachability only — it does not verify the Shadowsocks handshake.
app.get('/api/test', (req, res) => {
  const cfg = loadConfig();
  if (!cfg) return res.status(404).json({ error: 'No config found.' });

  const timeoutMs = 5000;
  const start = Date.now();
  const socket = new net.Socket();
  let settled = false;
  const done = (ok, message) => {
    if (settled) return;
    settled = true;
    socket.destroy();
    res.json({ ok, message, latencyMs: Date.now() - start });
  };

  socket.setTimeout(timeoutMs);
  socket.once('connect', () => done(true, `Reachable on ${cfg.server}:${cfg.port}`));
  socket.once('timeout', () => done(false, `Timed out after ${timeoutMs}ms — port may be blocked or filtered.`));
  socket.once('error', (err) => done(false, `Connection failed: ${err.code || err.message}`));
  socket.connect(Number(cfg.port), cfg.server);
});

// ── Config builders ───────────────────────────────────────────────────────── //
// Escape an arbitrary value for safe use inside a YAML double-quoted scalar,
// so a password/remark containing " \ or control chars can't break or inject
// into the generated config.
function yamlStr(value) {
  const escaped = String(value)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
  return `"${escaped}"`;
}

function buildClashYaml(cfg) {
  const proxy = buildClashProxy(cfg);
  return `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info

dns:
  enable: true
  nameserver:
    - 8.8.8.8
    - 1.1.1.1

proxies:
  - name: ${yamlStr(proxy.name)}
    type: ss
    server: ${yamlStr(proxy.server)}
    port: ${Number(proxy.port)}
    cipher: ${yamlStr(proxy.cipher)}
    password: ${yamlStr(proxy.password)}
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      tls: ${proxy['plugin-opts'].tls}
      host: ${yamlStr(proxy['plugin-opts'].host)}
      path: ${yamlStr(proxy['plugin-opts'].path)}

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - ${yamlStr(proxy.name)}
      - DIRECT

rules:
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
`;
}

function buildSingBoxConfig(cfg) {
  return {
    log: { level: 'info' },
    inbounds: [
      { type: 'socks', listen: '127.0.0.1', listen_port: 2080, tag: 'socks-in' },
      { type: 'http',  listen: '127.0.0.1', listen_port: 2081, tag: 'http-in' },
    ],
    outbounds: [
      {
        type: 'shadowsocks',
        tag: cfg.remarks || 'Airport',
        server: cfg.server,
        server_port: cfg.port,
        method: cfg.method,
        password: cfg.password,
        plugin: cfg.plugin || 'v2ray-plugin',
        plugin_opts: cfg.plugin_opts || 'server',
      },
      { type: 'direct', tag: 'direct' },
      { type: 'dns',    tag: 'dns-out' },
    ],
    route: {
      rules: [
        { protocol: 'dns', outbound: 'dns-out' },
        { geoip: ['cn', 'private'], outbound: 'direct' },
      ],
      final: cfg.remarks || 'Airport',
    },
  };
}

app.listen(PORT, HOST, () => {
  console.log(`Airport Web UI running at http://${HOST}:${PORT}`);
  console.log(`Config file: ${CFG_PATH}`);
  if (HOST !== '127.0.0.1' && HOST !== 'localhost') {
    console.warn('⚠  Listening on a non-loopback address — the config password is exposed to your network. Make sure this is intended.');
  }
});
