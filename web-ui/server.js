const express = require('express');
const fs      = require('fs');
const net     = require('net');
const os      = require('os');
const tls     = require('tls');
const crypto  = require('crypto');
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

app.use(express.json({ limit: '256kb' }));

// ── Host header allow-list (DNS-rebinding defence) ──────────────────────────── //
// Binding to loopback is not enough on its own: any page the user visits can
// point a hostname it controls at 127.0.0.1 and then read this API cross-origin,
// walking off with every proxy credential. Rebinding needs a *name*, so we only
// accept `localhost`, a bare IP literal, or a name explicitly allow-listed via
// ALLOWED_HOSTS (needed if you reach the UI through a DDNS name).
const EXTRA_HOSTS = (process.env.ALLOWED_HOSTS || '')
  .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

function hostnameOf(hostHeader) {
  const h = String(hostHeader || '');
  const bracketed = /^\[(.+)\](?::\d+)?$/.exec(h);
  if (bracketed) return bracketed[1];
  const idx = h.lastIndexOf(':');
  // Only strip the port when there is exactly one colon, so a bare IPv6
  // literal like "::1" isn't mangled.
  if (idx !== -1 && h.indexOf(':') === idx && /^\d+$/.test(h.slice(idx + 1))) return h.slice(0, idx);
  return h;
}

function hostAllowed(hostHeader) {
  const name = hostnameOf(hostHeader).toLowerCase();
  if (!name) return false;
  if (name === 'localhost' || name === '127.0.0.1' || name === '::1') return true;
  if (net.isIP(name)) return true;
  return EXTRA_HOSTS.includes(name);
}

app.use((req, res, next) => {
  if (hostAllowed(req.headers.host)) return next();
  res.status(403).type('text/plain').send(
    `Refused: unexpected Host header "${req.headers.host}".\n` +
    'Reach this UI at http://localhost:' + PORT + '/ or by IP address.\n' +
    'If you use a hostname on purpose, set ALLOWED_HOSTS=your.host to permit it.\n',
  );
});

app.use(express.static(path.join(__dirname, 'public')));

// ── Store helpers ───────────────────────────────────────────────────────────── //
class ConfigError extends Error {}

function saveStore(store) {
  fs.mkdirSync(path.dirname(CFG_PATH), { recursive: true });
  // 0600 — holds proxy secrets; keep it owner-only. The `mode` option only
  // applies when the file is first created, so chmod after every write to also
  // tighten a pre-existing file. chmod is a no-op on Windows; ignore its errors.
  fs.writeFileSync(CFG_PATH, JSON.stringify(store, null, 2), { encoding: 'utf8', mode: 0o600 });
  try { fs.chmodSync(CFG_PATH, 0o600); } catch { /* unsupported filesystem/platform */ }
}

// True when the on-disk shape already matches what we'd write back, so a read
// doesn't rewrite the file on every request.
function isCanonical(parsed) {
  if (!parsed || Array.isArray(parsed) || !Array.isArray(parsed.profiles)) return false;
  if (typeof parsed.token !== 'string' || parsed.token.length < 16) return false;
  return parsed.profiles.every((p) => p && C.isUuid(p.id));
}

function loadStore() {
  if (!fs.existsSync(CFG_PATH)) return { active: 0, profiles: [], token: null };
  let raw;
  try {
    raw = fs.readFileSync(CFG_PATH, 'utf8');
  } catch (err) {
    throw new ConfigError(`Cannot read ${CFG_PATH}: ${err.message}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    // Never fall back to an empty store here. Doing so used to mean the next
    // save silently overwrote a merely-malformed file, destroying every stored
    // credential. Refuse to read *or* write until a human fixes it.
    throw new ConfigError(
      `${CFG_PATH} is not valid JSON: ${err.message}. ` +
      'Refusing to read or overwrite it — fix the file (or move it aside) and reload.',
    );
  }
  const store = C.normalizeStore(parsed);
  if (!store.token) store.token = C.newToken();
  // Persist repaired ids / a freshly minted token so they stay stable across
  // requests — the UI tracks the selected profile by id.
  if (!isCanonical(parsed)) saveStore(store);
  return store;
}

// Create the store on first boot so the subscription token is stable from the
// very first request rather than being minted per-write.
function ensureStore() {
  if (fs.existsSync(CFG_PATH)) return loadStore();
  const store = { active: 0, profiles: [], token: C.newToken() };
  saveStore(store);
  return store;
}

// Attach the import URI to each profile for the UI.
function decorate(store) {
  return {
    active: store.active,
    activeId: store.profiles[store.active] ? store.profiles[store.active].id : null,
    subscriptionPath: store.token ? `/api/subscription/${store.token}` : null,
    lanUrls: lanUrls(store.token),
    profiles: store.profiles.map((p) => ({ ...p, uri: C.buildUri(p) })),
  };
}

// When the UI is deliberately exposed on the LAN, a phone can't use
// "localhost" — surface the reachable addresses so the subscription URL is
// copy-pasteable onto the device that needs it.
function lanUrls(token) {
  if (!token || HOST === '127.0.0.1' || HOST === 'localhost' || HOST === '::1') return [];
  const out = [];
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === 'IPv4' && !a.internal) out.push(`http://${a.address}:${PORT}/api/subscription/${token}`);
    }
  }
  return out;
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

// Wrap a handler so a broken config file becomes a clear 500 instead of an
// unhandled throw (or, worse, silent data loss).
function route(handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      if (err instanceof ConfigError) return res.status(500).json({ error: err.message });
      console.error(err);
      res.status(500).json({ error: err.message || 'Internal error' });
    }
  };
}

// ── Profile CRUD ────────────────────────────────────────────────────────────── //
app.get('/api/config', route((req, res) => {
  res.json(decorate(loadStore()));
}));

// Create or update a profile. Body is a single profile object; if it carries an
// `id` that already exists it's updated in place, otherwise it's appended.
app.post('/api/profiles', route((req, res) => {
  const body = req.body || {};
  const profile = C.normalizeProfile(body);
  const { errors, warnings } = C.validateProfile(profile);
  if (errors.length) {
    return res.status(400).json({ error: errors.join('; ') });
  }
  const store = loadStore();
  const { idx } = findProfile(store, body.id);
  if (idx !== -1) {
    profile.id = store.profiles[idx].id; // preserve id on update
    store.profiles[idx] = profile;
    // Editing a profile must not steal the ★ from whichever one is active —
    // switching active is an explicit action (/api/active).
  } else {
    store.profiles.push(profile);
    if (store.profiles.length === 1) store.active = 0;
  }
  saveStore(store);
  res.json({ ok: true, savedId: profile.id, warnings, ...decorate(store) });
}));

app.delete('/api/profiles/:id', route((req, res) => {
  const store = loadStore();
  const { idx } = findProfile(store, req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Profile not found.' });
  store.profiles.splice(idx, 1);
  if (store.active >= store.profiles.length) store.active = Math.max(0, store.profiles.length - 1);
  saveStore(store);
  res.json({ ok: true, ...decorate(store) });
}));

app.post('/api/active', route((req, res) => {
  const store = loadStore();
  const { idx } = findProfile(store, (req.body || {}).id);
  if (idx === -1) return res.status(404).json({ error: 'Profile not found.' });
  store.active = idx;
  saveStore(store);
  res.json({ ok: true, ...decorate(store) });
}));

// ── Import ──────────────────────────────────────────────────────────────────── //
// Accepts a share link (ss:// / vless:// / hysteria2://), several of them on
// separate lines, a base64 subscription blob, or the JSON that setup.sh writes
// to /etc/airport-tool/profile.json. Beats retyping six fields by hand.
app.post('/api/import', route((req, res) => {
  const text = String((req.body || {}).text || '').trim();
  if (!text) return res.status(400).json({ error: 'Nothing to import.' });

  let parsed = [];
  const problems = [];

  if (text.startsWith('{') || text.startsWith('[')) {
    let json;
    try { json = JSON.parse(text); } catch (err) {
      return res.status(400).json({ error: `Not valid JSON: ${err.message}` });
    }
    const list = Array.isArray(json) ? json : (Array.isArray(json.profiles) ? json.profiles : [json]);
    parsed = list.map(C.normalizeProfile);
  } else {
    const result = C.parseSubscription(text);
    parsed = result.profiles;
    problems.push(...result.errors);
  }

  const store = loadStore();
  const added = [];
  const skipped = [];
  for (const p of parsed) {
    const { errors } = C.validateProfile(p);
    if (errors.length) { problems.push(`${p.remarks}: ${errors.join(', ')}`); continue; }
    const dup = store.profiles.find((e) =>
      e.protocol === p.protocol && e.server === p.server && Number(e.port) === Number(p.port));
    if (dup) { skipped.push(p.remarks); continue; }
    store.profiles.push(p);
    added.push(p.remarks);
  }

  if (!added.length) {
    return res.status(400).json({
      error: problems.length ? problems.join('; ')
        : (skipped.length ? `Already have ${skipped.join(', ')}.` : 'Nothing importable found.'),
    });
  }
  if (store.profiles.length === added.length) store.active = 0;
  saveStore(store);
  res.json({ ok: true, added, skipped, problems, ...decorate(store) });
}));

// ── QR + downloads ──────────────────────────────────────────────────────────── //
app.get('/api/qrcode', route(async (req, res) => {
  const p = resolveProfile(loadStore(), req.query.id);
  if (!p) return res.status(404).json({ error: 'No profile found.' });
  const uri = C.buildUri(p);
  // Level M survives a bit of glare/creasing on a phone screen; the URIs are
  // short enough that the extra redundancy costs nothing in scannability.
  const dataUrl = await QRCode.toDataURL(uri, { errorCorrectionLevel: 'M', width: 400 });
  res.json({ qrcode: dataUrl, uri });
}));

app.get('/api/download/clash', route((req, res) => {
  const store = loadStore();
  if (!store.profiles.length) return res.status(404).send('No profiles');
  res.setHeader('Content-Type', 'text/yaml');
  res.setHeader('Content-Disposition', 'attachment; filename="clash-config.yaml"');
  res.send(C.buildClashYaml(store.profiles));
}));

app.get('/api/download/singbox', route((req, res) => {
  const store = loadStore();
  if (!store.profiles.length) return res.status(404).send('No profiles');
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="singbox-config.json"');
  res.send(JSON.stringify(C.buildSingBox(store.profiles), null, 2));
}));

app.get('/api/download/uri', route((req, res) => {
  const p = resolveProfile(loadStore(), req.query.id);
  if (!p) return res.status(404).send('No profile');
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename="ss-uri.txt"');
  res.send(C.buildUri(p) + '\n');
}));

// Subscription URL — clients poll this to auto-update. Standard format: base64
// of the newline-joined profile URIs.
//
// It is gated by a per-store token: the response *is* every credential you own,
// so an unauthenticated path would hand them to anyone who can reach the port —
// which is exactly the situation you're in the moment you set HOST=0.0.0.0 to
// make the subscription reachable from a phone.
function timingSafeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

app.get('/api/subscription/:token', route((req, res) => {
  const store = loadStore();
  if (!store.token || !timingSafeEqual(req.params.token, store.token)) {
    return res.status(404).type('text/plain').send('Not found\n');
  }
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Profile-Update-Interval', '24');
  res.setHeader('Cache-Control', 'no-store');
  res.send(C.buildSubscription(store.profiles));
}));

// The old unauthenticated path. Kept only to explain itself to anyone (or any
// client) still pointed at it.
app.get('/api/subscription', (req, res) => {
  res.status(401).type('text/plain').send(
    'This subscription URL now requires a token.\n' +
    'Open the web UI and copy the new Subscription URL from the dashboard.\n',
  );
});

// ── Connectivity test ─────────────────────────────────────────────────────── //
// Two-stage check: a raw TCP connect (is the port reachable?), then — for
// TLS-based profiles (Reality, or Shadowsocks in TLS mode) — a real TLS
// handshake with the configured SNI (does the port actually speak TLS?).
// It does not verify credentials, but it's a meaningful step past bare TCP.
//
// Hysteria2 is QUIC/UDP, so neither probe applies: a UDP port can't be probed
// without speaking the protocol, and silence is indistinguishable from a drop.
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
    let settled = false;
    let socket;
    const done = (ok, message) => {
      if (settled) return;
      settled = true;
      if (socket) socket.destroy();
      resolve({ ok, message, latencyMs: Date.now() - start });
    };
    // rejectUnauthorized:false — Reality intentionally serves a borrowed cert,
    // and we only care that the TLS handshake completes, not that it validates.
    socket = tls.connect(
      { host, port: Number(port), servername, rejectUnauthorized: false, timeout: timeoutMs },
      () => done(true, `TLS handshake OK (${socket.getProtocol()}) with SNI ${servername}`),
    );
    socket.once('timeout', () => done(false, `TLS handshake timed out after ${timeoutMs}ms.`));
    socket.once('error', (err) => done(false, `TLS handshake failed: ${err.code || err.message}`));
  });
}

async function probeProfile(p, timeoutMs) {
  if (p.protocol === 'hysteria2') {
    return {
      ok: null, stage: 'skipped', latencyMs: 0,
      message: 'Hysteria2 runs over UDP/QUIC — reachability can\'t be probed from here. Test by connecting.',
    };
  }
  const tcp = await tcpProbe(p.server, p.port, timeoutMs);
  if (!tcp.ok) return { ...tcp, stage: 'tcp' };

  const usesTls = p.protocol === 'vless-reality' || (p.plugin_opts || '').includes('tls');
  if (!usesTls) return { ...tcp, stage: 'tcp' };

  const servername = p.sni || (p.plugin_opts || '').match(/host=([^;]+)/)?.[1] || p.server;
  return { ...(await tlsProbe(p.server, p.port, servername, timeoutMs)), stage: 'tls' };
}

app.get('/api/test', route(async (req, res) => {
  const p = resolveProfile(loadStore(), req.query.id);
  if (!p) return res.status(404).json({ error: 'No profile found.' });
  res.json(await probeProfile(p, 5000));
}));

// Probe every profile at once and rank by latency — turns "is this one up?"
// into "which server should I be on right now?".
app.get('/api/test-all', route(async (req, res) => {
  const store = loadStore();
  if (!store.profiles.length) return res.status(404).json({ error: 'No profiles.' });
  const results = await Promise.all(store.profiles.map(async (p) => ({
    id: p.id, remarks: p.remarks, protocol: p.protocol,
    ...(await probeProfile(p, 5000)),
  })));
  // Reachable first (fastest first), then untestable, then failures.
  const rank = (r) => (r.ok === true ? 0 : r.ok === null ? 1 : 2);
  results.sort((a, b) => rank(a) - rank(b) || a.latencyMs - b.latencyMs);
  res.json({ results });
}));

const boot = (() => {
  try { return ensureStore(); } catch (err) {
    console.error(`\n⚠  ${err.message}\n`);
    return null;
  }
})();

app.listen(PORT, HOST, () => {
  console.log(`Airport Web UI running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`Config file: ${CFG_PATH}`);
  if (boot && boot.token) {
    console.log(`Subscription: http://localhost:${PORT}/api/subscription/${boot.token}`);
  }
  if (HOST !== '127.0.0.1' && HOST !== 'localhost') {
    console.warn('⚠  Listening on a non-loopback address. The subscription URL is token-gated,');
    console.warn('   but treat that token as a password — anyone holding it has your servers.');
  }
});
