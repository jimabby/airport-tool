#!/usr/bin/env node
// Generates client config files + QR codes for Shadowsocks + v2ray-plugin
// Usage: node gen.js [--config server.json]

const fs   = require('fs');
const path = require('path');
const QRCode = require('qrcode');

// ── Load server config ───────────────────────────────────────────────────── //
const configPath = process.argv[3] || path.join(__dirname, 'server.json');

if (!fs.existsSync(configPath)) {
  console.error(`Config file not found: ${configPath}`);
  console.error(`Create server.json with your server details. Example:`);
  console.error(JSON.stringify({
    server: "1.2.3.4",
    port: 8388,
    password: "your-password",
    method: "chacha20-ietf-poly1305",
    plugin: "v2ray-plugin",
    plugin_opts: "server",
    remarks: "My Airport"
  }, null, 2));
  process.exit(1);
}

const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const { server, port, password, method, plugin, plugin_opts, remarks = 'Airport' } = cfg;

const outDir = path.join(__dirname, 'output');
fs.mkdirSync(outDir, { recursive: true });

// ── Build SS URI ─────────────────────────────────────────────────────────── //
function buildSsUri() {
  const userinfo = Buffer.from(`${method}:${password}`).toString('base64');
  const encodedPlugin = encodeURIComponent(`${plugin};${plugin_opts}`);
  const tag = encodeURIComponent(remarks);
  return `ss://${userinfo}@${server}:${port}?plugin=${encodedPlugin}#${tag}`;
}

const ssUri = buildSsUri();
console.log('\nSS URI:', ssUri);

// ── 1. Clash / ClashX config (Windows + macOS) ───────────────────────────── //
function writeClashConfig() {
  const clash = {
    mixed_port: 7890,
    allow_lan: false,
    mode: 'rule',
    log_level: 'info',
    dns: {
      enable: true,
      nameserver: ['8.8.8.8', '1.1.1.1'],
    },
    proxies: [
      {
        name: remarks,
        type: 'ss',
        server,
        port,
        cipher: method,
        password,
        plugin: 'v2ray-plugin',
        'plugin-opts': {
          mode: plugin_opts.includes('tls') ? 'websocket' : 'websocket',
          tls: plugin_opts.includes('tls'),
          host: extractHost(plugin_opts) || server,
          path: extractPath(plugin_opts) || '/ws',
        },
      },
    ],
    'proxy-groups': [
      {
        name: 'PROXY',
        type: 'select',
        proxies: [remarks, 'DIRECT'],
      },
    ],
    rules: [
      'GEOIP,CN,DIRECT',
      'MATCH,PROXY',
    ],
  };

  // Simple YAML serializer (avoids yaml dependency)
  const yaml = toYaml(clash);
  const outPath = path.join(outDir, 'clash-config.yaml');
  fs.writeFileSync(outPath, yaml, 'utf8');
  console.log('✓ Clash/ClashX config:', outPath);
}

// ── 2. Shadowsocks-Windows / ShadowsocksX-NG config ─────────────────────── //
function writeSsWindowsConfig() {
  const config = {
    configs: [
      {
        server,
        server_port: port,
        password,
        method,
        plugin: plugin,
        plugin_opts: plugin_opts,
        remarks,
        timeout: 5,
      },
    ],
    index: 0,
    global: false,
    enabled: true,
    shareOverLan: false,
    isDefault: false,
    localPort: 1080,
  };
  const outPath = path.join(outDir, 'ss-windows-gui.json');
  fs.writeFileSync(outPath, JSON.stringify(config, null, 2), 'utf8');
  console.log('✓ Shadowsocks-Windows GUI config:', outPath);
}

// ── 3. v2rayNG / Sing-Box (Android + iOS) — export SS URI ───────────────── //
function writeMobileUri() {
  const outPath = path.join(outDir, 'mobile-ss-uri.txt');
  fs.writeFileSync(outPath, ssUri + '\n', 'utf8');
  console.log('✓ Mobile SS URI (v2rayNG / Shadowrocket):', outPath);
}

// ── 4. Sing-Box config (iOS / Android alternative) ───────────────────────── //
function writeSingBoxConfig() {
  const singbox = {
    log: { level: 'info' },
    inbounds: [
      { type: 'socks', listen: '127.0.0.1', listen_port: 2080, tag: 'socks-in' },
      { type: 'http',  listen: '127.0.0.1', listen_port: 2081, tag: 'http-in' },
    ],
    outbounds: [
      {
        type: 'shadowsocks',
        tag: remarks,
        server,
        server_port: port,
        method,
        password,
        plugin: 'v2ray-plugin',
        plugin_opts: plugin_opts,
      },
      { type: 'direct', tag: 'direct' },
      { type: 'dns',    tag: 'dns-out' },
    ],
    route: {
      rules: [
        { protocol: 'dns', outbound: 'dns-out' },
        { geoip: ['cn', 'private'], outbound: 'direct' },
      ],
      final: remarks,
    },
  };
  const outPath = path.join(outDir, 'singbox-config.json');
  fs.writeFileSync(outPath, JSON.stringify(singbox, null, 2), 'utf8');
  console.log('✓ Sing-Box config (iOS/Android):', outPath);
}

// ── 5. QR code PNG + terminal output ─────────────────────────────────────── //
async function writeQrCode() {
  const pngPath = path.join(outDir, 'qrcode.png');
  await QRCode.toFile(pngPath, ssUri, { errorCorrectionLevel: 'L', width: 512 });
  console.log('✓ QR code PNG:', pngPath);

  // Also print to terminal
  const termQr = await QRCode.toString(ssUri, { type: 'terminal', small: true });
  console.log('\nScan with your phone:\n');
  console.log(termQr);
}

// ── 6. Summary JSON (used by web UI) ─────────────────────────────────────── //
function writeSummary() {
  const summary = {
    server, port, method, plugin, plugin_opts, remarks,
    ssUri,
    generatedAt: new Date().toISOString(),
    clients: {
      windows: 'Clash for Windows — import clash-config.yaml',
      macos:   'ClashX — import clash-config.yaml',
      android: 'v2rayNG — scan QR code or import mobile-ss-uri.txt',
      ios:     'Shadowrocket or Sing-Box — scan QR code',
    },
  };
  const outPath = path.join(outDir, 'summary.json');
  fs.writeFileSync(outPath, JSON.stringify(summary, null, 2), 'utf8');
  console.log('✓ Summary:', outPath);
}

// ── Helpers ───────────────────────────────────────────────────────────────── //
function extractHost(opts) {
  const m = opts.match(/host=([^;]+)/);
  return m ? m[1] : null;
}
function extractPath(opts) {
  const m = opts.match(/path=([^;]+)/);
  return m ? m[1] : null;
}

function toYaml(obj, indent = 0) {
  const pad = ' '.repeat(indent);
  let out = '';
  for (const [k, v] of Object.entries(obj)) {
    if (Array.isArray(v)) {
      out += `${pad}${k}:\n`;
      for (const item of v) {
        if (typeof item === 'object') {
          out += `${pad}  -\n`;
          out += toYaml(item, indent + 4).replace(/^/gm, '  ');
        } else {
          out += `${pad}  - ${item}\n`;
        }
      }
    } else if (v !== null && typeof v === 'object') {
      out += `${pad}${k}:\n`;
      out += toYaml(v, indent + 2);
    } else if (typeof v === 'boolean') {
      out += `${pad}${k}: ${v}\n`;
    } else if (typeof v === 'number') {
      out += `${pad}${k}: ${v}\n`;
    } else {
      out += `${pad}${k}: "${v}"\n`;
    }
  }
  return out;
}

// ── Main ──────────────────────────────────────────────────────────────────── //
(async () => {
  console.log(`\nGenerating configs for: ${remarks} (${server}:${port})`);
  writeClashConfig();
  writeSsWindowsConfig();
  writeMobileUri();
  writeSingBoxConfig();
  await writeQrCode();
  writeSummary();
  console.log(`\nAll files written to: ${outDir}\n`);
})();
