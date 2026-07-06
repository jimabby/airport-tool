#!/usr/bin/env node
// Generates client config files + QR codes for all configured server profiles.
// Supports Shadowsocks (v2ray-plugin) and VLESS + Reality.
// Usage: node gen.js [--config servers.json]

const fs   = require('fs');
const path = require('path');
const QRCode = require('qrcode');
const C = require('./lib/configs');

// ── Load config ────────────────────────────────────────────────────────────── //
// Accept either `node gen.js --config path` or `node gen.js path`.
function resolveConfigPath(argv) {
  const flagIdx = argv.indexOf('--config');
  if (flagIdx !== -1 && argv[flagIdx + 1]) return argv[flagIdx + 1];
  const positional = argv.slice(2).find((a) => !a.startsWith('--'));
  if (positional) return positional;
  // Prefer servers.json, fall back to legacy server.json.
  const multi = path.join(__dirname, 'servers.json');
  const single = path.join(__dirname, 'server.json');
  return fs.existsSync(multi) ? multi : single;
}
const configPath = resolveConfigPath(process.argv);

if (!fs.existsSync(configPath)) {
  console.error(`Config file not found: ${configPath}`);
  console.error(`Create servers.json (see servers.json.example).`);
  process.exit(1);
}

const store = C.normalizeStore(JSON.parse(fs.readFileSync(configPath, 'utf8')));
if (!store.profiles.length) {
  console.error('No profiles found in config.');
  process.exit(1);
}

// Validate every profile before writing anything.
let hasError = false;
store.profiles.forEach((p, i) => {
  const missing = C.missingFields(p);
  if (missing.length) {
    console.error(`Profile #${i + 1} (${p.remarks}) is missing: ${missing.join(', ')}`);
    hasError = true;
  }
  if (p.protocol === 'vless-reality' && !p.shortId) {
    console.warn(`⚠  Profile "${p.remarks}" has no shortId — some clients require one.`);
  }
  if (p.protocol === 'shadowsocks' && (p.plugin_opts || '').includes('tls') &&
      !/host=/.test(p.plugin_opts || '')) {
    console.warn(`⚠  Profile "${p.remarks}" uses TLS but has no host= — clients will use the server IP as SNI, which usually fails.`);
  }
});
if (hasError) process.exit(1);

const outDir = path.join(__dirname, 'output');
fs.mkdirSync(outDir, { recursive: true });

const write = (name, data) => {
  const outPath = path.join(outDir, name);
  fs.writeFileSync(outPath, data, 'utf8');
  console.log('✓', name.padEnd(22), '→', outPath);
};

(async () => {
  const { profiles, active } = store;
  const activeProfile = profiles[active];

  console.log(`\nGenerating configs for ${profiles.length} profile(s). Active: ${activeProfile.remarks}\n`);

  // ── Bundled configs (all profiles) ──────────────────────────────────────── //
  write('clash-config.yaml', C.buildClashYaml(profiles));
  write('singbox-config.json', JSON.stringify(C.buildSingBox(profiles), null, 2));
  write('subscription-base64.txt', C.buildSubscription(profiles) + '\n');
  write('uris.txt', profiles.map(C.buildUri).join('\n') + '\n');

  // ── Active profile URI + QR ─────────────────────────────────────────────── //
  const activeUri = C.buildUri(activeProfile);
  write('active-uri.txt', activeUri + '\n');

  const pngPath = path.join(outDir, 'qrcode.png');
  await QRCode.toFile(pngPath, activeUri, { errorCorrectionLevel: 'L', width: 512 });
  console.log('✓', 'qrcode.png'.padEnd(22), '→', pngPath);

  // ── Summary (used by tooling) ───────────────────────────────────────────── //
  const summary = {
    generatedAt: new Date().toISOString(),
    active: activeProfile.id,
    profiles: profiles.map((p) => ({
      id: p.id, remarks: p.remarks, protocol: p.protocol,
      server: p.server, port: p.port, uri: C.buildUri(p),
    })),
  };
  write('summary.json', JSON.stringify(summary, null, 2));

  // ── Terminal QR for the active profile ──────────────────────────────────── //
  const termQr = await QRCode.toString(activeUri, { type: 'terminal', small: true });
  console.log(`\nScan the active profile (${activeProfile.remarks}):\n`);
  console.log(termQr);
  console.log(`All files written to: ${outDir}\n`);
})();
