const express = require('express');
const fs      = require('fs');
const net     = require('net');
const tls     = require('tls');
const path    = require('path');
const QRCode  = require('qrcode');
const C       = require('../config-gen/lib/configs');

const app  = express();
const PORT = process.env.PORT || 3000;
// Bind to loopback by default — the config holds proxy secrets, so it should
// not be reachable from other machines unless explicitly opted in.
const HOST = process.env.HOST || '127.0.0.1';
// Store lives next to the CLI generator so both tools share it. Prefer the new
// multi-profile servers.json, fall back to legacy server.json.
const CFG_PATH = process.env.CFG_PATH || (() => {
  const base = path.join(__dirname, '..', 'config-gen');
  const multi = path.join(base, 'servers.json');
  const single = path.join(base, 'server.json');
  return fs.existsSync(multi) ? multi : (fs.existsSync(single) ? single : multi);
})();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Store helpers ───────────────────────────────────────────────────────────── //
function loadStore() {
  if (!fs.existsSync(CFG_PATH)) return { active: 0, profiles: [] };
  try { return C.normalizeStore(JSON.parse(fs.readFileSync(CFG_PATH, 'utf8'))); }
  catch { return { active: 0, profiles: [] }; }
}

function saveStore(store) {
  fs.mkdirSync(path.dirname(CFG_PATH), { recursive: true });
  // 0600 — holds proxy secrets; keep it owner-only. The `mode` option only
  // applies when the file is first created, so chmod after every write to also
  // tighten a pre-existing file. chmod is a no-op on Windows; ignore its errors.
  fs.writeFileSync(CFG_PATH, JSON.stringify(store, null, 2), { encoding: 'utf8', mode: 0o600 });
  try { fs.chmodSync(CFG_PATH, 0o600); } catch { /* unsupported filesystem/platform */ }
}

// Attach the import URI to each profile for the UI.
function decorate(store) {
  return {
    active: store.active,
    activeId: store.profiles[store.active] ? store.profiles[store.active].id : null,
    profiles: store.profiles.map((p) => ({ ...p, uri: C.buildUri(p) })),
  };
}

function findProfile(store, id) {
  const idx = store.profiles.findIndex((p) => p.id === id);
  return { idx, profile: store.profiles[idx] };
}

// Resolve ?id= to a profile, defaulting to the active one.
function resolveProfile(store, id) {
  if (id) return store.profiles.find((p) => p.id === id) || null;
  return store.profiles[store.active] || null;
}

// ── Profile CRUD ────────────────────────────────────────────────────────────── //
app.get('/api/config', (req, res) => {
  res.json(decorate(loadStore()));
});

// Create or update a profile. Body is a single profile object; if it carries an
// `id` that already exists it's updated in place, otherwise it's appended.
app.post('/api/profiles', (req, res) => {
  const profile = C.normalizeProfile(req.body || {});
  const missing = C.missingFields(profile);
  if (missing.length) {
    return res.status(400).json({ error: `Missing required field(s): ${missing.join(', ')}` });
  }
  const store = loadStore();
  const { idx } = findProfile(store, req.body.id);
  if (idx !== -1) {
    profile.id = store.profiles[idx].id; // preserve id on update
    store.profiles[idx] = profile;
    store.active = idx;
  } else {
    store.profiles.push(profile);
    store.active = store.profiles.length - 1;
  }
  saveStore(store);
  res.json({ ok: true, ...decorate(store) });
});

app.delete('/api/profiles/:id', (req, res) => {
  const store = loadStore();
  const { idx } = findProfile(store, req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Profile not found.' });
  store.profiles.splice(idx, 1);
  if (store.active >= store.profiles.length) store.active = Math.max(0, store.profiles.length - 1);
  saveStore(store);
  res.json({ ok: true, ...decorate(store) });
});

app.post('/api/active', (req, res) => {
  const store = loadStore();
  const { idx } = findProfile(store, req.body.id);
  if (idx === -1) return res.status(404).json({ error: 'Profile not found.' });
  store.active = idx;
  saveStore(store);
  res.json({ ok: true, ...decorate(store) });
});

// ── QR + downloads ──────────────────────────────────────────────────────────── //
app.get('/api/qrcode', async (req, res) => {
  const p = resolveProfile(loadStore(), req.query.id);
  if (!p) return res.status(404).json({ error: 'No profile found.' });
  try {
    const uri = C.buildUri(p);
    const dataUrl = await QRCode.toDataURL(uri, { errorCorrectionLevel: 'L', width: 400 });
    res.json({ qrcode: dataUrl, uri });
  } catch (err) {
    res.status(500).json({ error: `Failed to generate QR code: ${err.message}` });
  }
});

app.get('/api/download/clash', (req, res) => {
  const store = loadStore();
  if (!store.profiles.length) return res.status(404).send('No profiles');
  res.setHeader('Content-Type', 'text/yaml');
  res.setHeader('Content-Disposition', 'attachment; filename="clash-config.yaml"');
  res.send(C.buildClashYaml(store.profiles));
});

app.get('/api/download/singbox', (req, res) => {
  const store = loadStore();
  if (!store.profiles.length) return res.status(404).send('No profiles');
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="singbox-config.json"');
  res.send(JSON.stringify(C.buildSingBox(store.profiles), null, 2));
});

app.get('/api/download/uri', (req, res) => {
  const p = resolveProfile(loadStore(), req.query.id);
  if (!p) return res.status(404).send('No profile');
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename="ss-uri.txt"');
  res.send(C.buildUri(p) + '\n');
});

// Subscription URL — clients poll this to auto-update. Standard format: base64
// of the newline-joined profile URIs.
app.get('/api/subscription', (req, res) => {
  const store = loadStore();
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Profile-Update-Interval', '24');
  res.send(C.buildSubscription(store.profiles));
});

// ── Connectivity test ─────────────────────────────────────────────────────── //
// Two-stage check: a raw TCP connect (is the port reachable?), then — for
// TLS-based profiles (Reality, or Shadowsocks in TLS mode) — a real TLS
// handshake with the configured SNI (does the port actually speak TLS?).
// It does not verify credentials, but it's a meaningful step past bare TCP.
function tcpProbe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let settled = false;
    const done = (ok, message) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ ok, message, latencyMs: Date.now() - start });
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true, `TCP reachable on ${host}:${port}`));
    socket.once('timeout', () => done(false, `TCP timed out after ${timeoutMs}ms — port may be blocked or filtered.`));
    socket.once('error', (err) => done(false, `TCP connection failed: ${err.code || err.message}`));
    socket.connect(Number(port), host);
  });
}

function tlsProbe(host, port, servername, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    // rejectUnauthorized:false — Reality intentionally serves a borrowed cert,
    // and we only care that the TLS handshake completes, not that it validates.
    const socket = tls.connect(
      { host, port: Number(port), servername, rejectUnauthorized: false, timeout: timeoutMs },
      () => {
        const proto = socket.getProtocol();
        socket.destroy();
        resolve({ ok: true, message: `TLS handshake OK (${proto}) with SNI ${servername}`, latencyMs: Date.now() - start });
      },
    );
    socket.once('timeout', () => { socket.destroy(); resolve({ ok: false, message: `TLS handshake timed out after ${timeoutMs}ms.`, latencyMs: Date.now() - start }); });
    socket.once('error', (err) => resolve({ ok: false, message: `TLS handshake failed: ${err.code || err.message}`, latencyMs: Date.now() - start }));
  });
}

app.get('/api/test', async (req, res) => {
  const p = resolveProfile(loadStore(), req.query.id);
  if (!p) return res.status(404).json({ error: 'No profile found.' });
  const timeoutMs = 5000;

  const tcp = await tcpProbe(p.server, p.port, timeoutMs);
  if (!tcp.ok) return res.json({ ...tcp, stage: 'tcp' });

  const usesTls = p.protocol === 'vless-reality' || (p.plugin_opts || '').includes('tls');
  if (!usesTls) return res.json({ ...tcp, stage: 'tcp' });

  const servername = p.sni || (p.plugin_opts || '').match(/host=([^;]+)/)?.[1] || p.server;
  const tlsResult = await tlsProbe(p.server, p.port, servername, timeoutMs);
  res.json({ ...tlsResult, stage: 'tls' });
});

app.listen(PORT, HOST, () => {
  console.log(`Airport Web UI running at http://${HOST}:${PORT}`);
  console.log(`Config file: ${CFG_PATH}`);
  if (HOST !== '127.0.0.1' && HOST !== 'localhost') {
    console.warn('⚠  Listening on a non-loopback address — proxy secrets are exposed to your network. Make sure this is intended.');
  }
});
