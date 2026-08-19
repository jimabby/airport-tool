const express   = require('express');
const fs        = require('fs');
const http      = require('http');
const net       = require('net');
const os        = require('os');
const tls       = require('tls');
const crypto    = require('crypto');
const path      = require('path');
const { spawn, spawnSync } = require('child_process');
const QRCode    = require('qrcode');
const C         = require('../config-gen/lib/configs');

const app  = express();
const PORT = process.env.PORT || 3000;
// Bind to loopback by default — the config holds proxy secrets, so it should
// not be reachable from other machines unless explicitly opted in.
const HOST = process.env.HOST || '127.0.0.1';
const IS_LOOPBACK = ['127.0.0.1', 'localhost', '::1'].includes(HOST);
// Store lives next to the CLI generator so both tools share it. Prefer the new
// multi-profile servers.json, fall back to legacy server.json.
const CFG_PATH = process.env.CFG_PATH || (() => {
  const base = path.join(__dirname, '..', 'config-gen');
  const multi = path.join(base, 'servers.json');
  const single = path.join(base, 'server.json');
  return fs.existsSync(multi) ? multi : (fs.existsSync(single) ? single : multi);
})();
// Latency samples live beside the store rather than inside it: they're written
// on every probe, and churning a file full of credentials that often is a good
// way to eventually lose it.
const HISTORY_PATH = process.env.HISTORY_PATH || path.join(path.dirname(CFG_PATH), 'test-history.json');

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

// ── Store helpers ───────────────────────────────────────────────────────────── //
class ConfigError extends Error {}

function timingSafeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// Write through a temporary file and rename over the target. A plain
// writeFileSync that dies halfway — power cut, disk full, Ctrl-C — leaves a
// truncated file, and this one holds every credential you own.
function writeFileAtomic(file, data, mode) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = fs.openSync(tmp, 'w', mode);
  try {
    fs.writeFileSync(fd, data, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  // chmod is a no-op on Windows; ignore its errors there.
  try { fs.chmodSync(tmp, mode); } catch { /* unsupported filesystem/platform */ }
  fs.renameSync(tmp, file);
}

function saveStore(store) {
  // 0600 — holds proxy secrets; keep it owner-only.
  writeFileAtomic(CFG_PATH, JSON.stringify(store, null, 2), 0o600);
}

// True when the on-disk shape already matches what we'd write back, so a read
// doesn't rewrite the file on every request.
function isCanonical(parsed) {
  if (!parsed || Array.isArray(parsed) || !Array.isArray(parsed.profiles)) return false;
  if (typeof parsed.token !== 'string' || parsed.token.length < 16) return false;
  if (typeof parsed.uiToken !== 'string' || parsed.uiToken.length < 16) return false;
  return parsed.profiles.every((p) => p && C.isUuid(p.id));
}

function loadStore() {
  if (!fs.existsSync(CFG_PATH)) return { active: 0, profiles: [], token: null, uiToken: null };
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
  if (!store.uiToken) store.uiToken = C.newToken();
  // Persist repaired ids / freshly minted tokens so they stay stable across
  // requests — the UI tracks the selected profile by id.
  if (!isCanonical(parsed)) saveStore(store);
  return store;
}

// Create the store on first boot so the tokens are stable from the very first
// request rather than being minted per-write.
function ensureStore() {
  if (fs.existsSync(CFG_PATH)) return loadStore();
  const store = { active: 0, profiles: [], token: C.newToken(), uiToken: C.newToken() };
  saveStore(store);
  return store;
}

// ── Probe history (separate, non-secret file) ───────────────────────────────── //
const HISTORY_LIMIT = 30;

function loadHistory() {
  try {
    const parsed = JSON.parse(fs.readFileSync(HISTORY_PATH, 'utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    // A missing or corrupt history file is not worth failing a request over —
    // it caches latency numbers, not anything that can't be re-measured.
    return {};
  }
}

function recordHistory(entries) {
  const hist = loadHistory();
  const at = Date.now();
  for (const e of entries) {
    if (!e || !e.id) continue;
    const list = Array.isArray(hist[e.id]) ? hist[e.id] : [];
    list.push({ at, ok: e.ok, latencyMs: e.latencyMs, stage: e.stage });
    hist[e.id] = list.slice(-HISTORY_LIMIT);
  }
  try { writeFileAtomic(HISTORY_PATH, JSON.stringify(hist), 0o600); } catch { /* best effort */ }
  return hist;
}

// Collapse a profile's samples into the numbers the dashboard shows. Probes
// that returned ok:null (untestable, e.g. bare QUIC) are excluded from the
// success rate rather than counted as failures.
function summarizeHistory(list) {
  const samples = Array.isArray(list) ? list : [];
  const timed = samples.filter((s) => s.ok === true && Number.isFinite(s.latencyMs));
  const attempted = samples.filter((s) => s.ok !== null);
  return {
    samples: samples.length,
    lastAt: samples.length ? samples[samples.length - 1].at : null,
    lastOk: samples.length ? samples[samples.length - 1].ok : null,
    bestMs: timed.length ? Math.min(...timed.map((s) => s.latencyMs)) : null,
    avgMs: timed.length ? Math.round(timed.reduce((a, s) => a + s.latencyMs, 0) / timed.length) : null,
    successRate: attempted.length
      ? Math.round((attempted.filter((s) => s.ok === true).length / attempted.length) * 100)
      : null,
  };
}

// ── Dashboard authentication ────────────────────────────────────────────────── //
// The Host allow-list stops a web page from reaching this API; it does nothing
// about another machine on the network. Every endpoint here hands out (or
// rewrites) proxy credentials, so once the UI is off loopback it needs a real
// secret — token-gating only the subscription feed left /api/config, which
// returns the same credentials *plus* the subscription token, wide open.
//
// On loopback the token is off by default: whoever can reach it is already
// sitting at the machine that owns the file. Set UI_TOKEN to require it there.
const AUTH_REQUIRED = !IS_LOOPBACK || !!process.env.UI_TOKEN;
const COOKIE_NAME = 'airport_ui';

function readCookie(header, name) {
  for (const part of String(header || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    const raw = part.slice(eq + 1).trim();
    try { return decodeURIComponent(raw); } catch { return raw; }
  }
  return null;
}

function presentedToken(req) {
  const bearer = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ''));
  return req.query.ui_token
    || req.headers['x-ui-token']
    || (bearer && bearer[1])
    || readCookie(req.headers.cookie, COOKIE_NAME);
}

// The token the UI must present. An explicit UI_TOKEN wins so it can be pinned
// in a service file; otherwise it's the one minted into the store.
function uiSecret() {
  if (process.env.UI_TOKEN) return process.env.UI_TOKEN;
  try { return loadStore().uiToken; } catch { return null; }
}

app.use((req, res, next) => {
  if (!AUTH_REQUIRED) return next();
  // The subscription feed carries its own token in the path — clients polling
  // it can hold neither a cookie nor a header.
  if (req.path.startsWith('/api/subscription')) return next();

  const want = uiSecret();
  if (!want) {
    return res.status(500).type('text/plain').send('No dashboard token available — check the server log.\n');
  }
  const got = presentedToken(req);
  if (got && timingSafeEqual(got, want)) {
    // Trade a token in the URL for a cookie once, then redirect, so the secret
    // stops travelling through Referer headers, history and screenshots.
    // SameSite=Strict is what stops that cookie authorising a cross-site write.
    if (req.query.ui_token && req.method === 'GET') {
      res.setHeader('Set-Cookie',
        `${COOKIE_NAME}=${encodeURIComponent(want)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000`);
      const url = new URL(req.originalUrl, 'http://placeholder');
      url.searchParams.delete('ui_token');
      return res.redirect(302, url.pathname + (url.search || ''));
    }
    return next();
  }
  res.status(401).type('text/plain').send(
    'This dashboard requires a token.\n\n' +
    'Open the URL printed in the server log (it ends with ?ui_token=…), or set\n' +
    'UI_TOKEN yourself and pass it as ?ui_token=…, an X-UI-Token header, or a\n' +
    'Bearer token.\n',
  );
});

app.use(express.static(path.join(__dirname, 'public')));

// Attach the import URI and probe history to each profile for the UI.
function decorate(store) {
  const hist = loadHistory();
  return {
    active: store.active,
    activeId: store.profiles[store.active] ? store.profiles[store.active].id : null,
    subscriptionPath: store.token ? `/api/subscription/${store.token}` : null,
    lanUrls: lanUrls(store.token),
    deepTest: deepTestAvailability(),
    profiles: store.profiles.map((p) => ({
      ...p,
      uri: C.buildUri(p),
      history: summarizeHistory(hist[p.id]),
    })),
  };
}

// When the UI is deliberately exposed on the LAN, a phone can't use
// "localhost" — surface the reachable addresses so the subscription URL is
// copy-pasteable onto the device that needs it.
function lanUrls(token) {
  if (!token || IS_LOOPBACK) return [];
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
// unhandled throw (or, worse, silent data loss). Anything else goes to the
// JSON error handler at the bottom.
function route(handler) {
  return async (req, res, next) => {
    try {
      await handler(req, res);
    } catch (err) {
      if (err instanceof ConfigError) return res.status(500).json({ error: err.message });
      next(err);
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
// Accepts a share link (ss:// / vless:// / hysteria2:// / tuic://), several of
// them on separate lines, a base64 subscription blob, or the JSON that setup.sh
// writes to /etc/airport-tool/profile.json. Beats retyping six fields by hand.
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
// Level M survives a bit of glare/creasing on a phone screen; these payloads are
// short enough that the extra redundancy costs nothing in scannability.
const QR_OPTS = { errorCorrectionLevel: 'M', width: 400 };

app.get('/api/qrcode', route(async (req, res) => {
  const p = resolveProfile(loadStore(), req.query.id);
  if (!p) return res.status(404).json({ error: 'No profile found.' });
  const uri = C.buildUri(p);
  res.json({ qrcode: await QRCode.toDataURL(uri, QR_OPTS), uri });
}));

// A QR of the subscription URL itself. Typing a 32-character token into a phone
// by hand is the worst part of setting a client up.
app.get('/api/qrcode/subscription', route(async (req, res) => {
  const store = loadStore();
  if (!store.profiles.length) return res.status(404).json({ error: 'No profiles yet.' });
  if (!store.token) return res.status(404).json({ error: 'No subscription token.' });
  const url = `http://${req.headers.host}/api/subscription/${store.token}`;
  res.json({ qrcode: await QRCode.toDataURL(url, QR_OPTS), uri: url });
}));

// Downloads are named after what they hold — a hysteria2 profile written to
// "ss-uri.txt" is just confusing.
const URI_FILENAME = {
  shadowsocks: 'ss-uri.txt',
  'vless-reality': 'vless-uri.txt',
  hysteria2: 'hysteria2-uri.txt',
  tuic: 'tuic-uri.txt',
};

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
  res.setHeader('Content-Disposition', `attachment; filename="${URI_FILENAME[p.protocol] || 'uri.txt'}"`);
  res.send(C.buildUri(p) + '\n');
}));

// Full backup of the store. Losing this file means re-running setup.sh on every
// server, and setup.sh cannot reproduce a password it already generated — so
// being able to grab a copy matters more than it looks.
app.get('/api/download/backup', route((req, res) => {
  const store = loadStore();
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="servers.json"');
  res.setHeader('Cache-Control', 'no-store');
  res.send(JSON.stringify(store, null, 2));
}));

// Subscription URL — clients poll this to auto-update. Standard format: base64
// of the newline-joined profile URIs.
//
// It is gated by a per-store token: the response *is* every credential you own,
// so an unauthenticated path would hand them to anyone who can reach the port.
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
// Three levels, cheapest first:
//   tcp    raw connect — is the port reachable at all?
//   tls    a real TLS handshake with the configured SNI — does it speak TLS?
//   deep   dial through the proxy itself with a local sing-box — do the
//          credentials work, and does traffic actually come back?
//
// Only `deep` answers the question you care about. The first two are what's
// available without a proxy binary on the machine, and they are the only thing
// that works at all for the QUIC protocols, where a silent UDP port is
// indistinguishable from a dropped one.
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

// ── Deep probe: dial through the proxy with a local sing-box ────────────────── //
// sing-box already speaks every protocol this tool emits, so rather than
// reimplementing four wire formats we hand it a one-outbound config, point a
// local HTTP proxy at it and fetch a 204 through it.
const SINGBOX_BIN = process.env.SINGBOX_BIN || 'sing-box';
const DEEP_TEST_URL = process.env.DEEP_TEST_URL || 'http://www.gstatic.com/generate_204';

// Arguments to put in front of sing-box's own, for anyone who reaches it
// through a wrapper — `SINGBOX_BIN=docker SINGBOX_ARGS='run --rm … sing-box'`,
// a language runtime, or a launcher script. Kept separate from SINGBOX_BIN so a
// path containing spaces stays intact. JSON array or whitespace-separated.
const SINGBOX_ARGS = (() => {
  const raw = (process.env.SINGBOX_ARGS || '').trim();
  if (!raw) return [];
  if (raw.startsWith('[')) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed.map(String);
    } catch { /* fall through to the whitespace split */ }
  }
  return raw.split(/\s+/);
})();

const singboxArgv = (...args) => [...SINGBOX_ARGS, ...args];

let singboxCache = null;
function deepTestAvailability() {
  if (singboxCache) return singboxCache;
  let r;
  try { r = spawnSync(SINGBOX_BIN, singboxArgv('version'), { encoding: 'utf8', timeout: 5000 }); } catch { r = null; }
  singboxCache = r && r.status === 0
    ? { available: true, version: String(r.stdout || '').split('\n')[0].trim() }
    : { available: false, reason: `\`${SINGBOX_BIN}\` is not on PATH — install sing-box (or set SINGBOX_BIN) to enable the deep test.` };
  return singboxCache;
}

// Ask the OS for a free port by binding one and letting go immediately. There
// is a race with anything else doing the same, which is why the spawned proxy
// gets a moment to fail and its stderr is reported back rather than swallowed.
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function waitForPort(port, deadline) {
  return new Promise((resolve) => {
    const attempt = () => {
      if (Date.now() > deadline) return resolve(false);
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); resolve(true); });
      s.once('error', () => { s.destroy(); setTimeout(attempt, 100); });
    };
    attempt();
  });
}

// An absolute-form request URI *is* an HTTP proxy request, which the mixed
// inbound serves directly — no CONNECT needed for a plain-http target.
function fetchThroughProxy(proxyPort, target, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    const url = new URL(target);
    const req = http.request({
      host: '127.0.0.1', port: proxyPort, method: 'GET', path: target,
      headers: { Host: url.host, 'User-Agent': 'airport-tool' },
      timeout: timeoutMs,
    }, (res) => {
      res.resume();
      res.once('end', () => resolve({
        ok: res.statusCode >= 200 && res.statusCode < 400,
        status: res.statusCode,
        latencyMs: Date.now() - start,
      }));
    });
    req.once('timeout', () => {
      req.destroy();
      resolve({ ok: false, error: `no response in ${timeoutMs}ms`, latencyMs: Date.now() - start });
    });
    req.once('error', (err) => resolve({ ok: false, error: err.code || err.message, latencyMs: Date.now() - start }));
    req.end();
  });
}

async function deepProbe(p, timeoutMs) {
  const avail = deepTestAvailability();
  if (!avail.available) {
    return { ok: null, stage: 'deep-unavailable', latencyMs: 0, message: avail.reason };
  }
  let dir;
  let child;
  try {
    const port = await freePort();
    const outbound = C.buildSingBoxOutbound(p, 'probe');
    const config = {
      log: { level: 'error' },
      inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: port }],
      outbounds: [outbound],
      // No rule sets and no DNS detour: this config lives for one request and
      // must not spend the timeout downloading a geosite database.
      route: { final: outbound.tag },
    };
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-probe-'));
    const cfgFile = path.join(dir, 'config.json');
    fs.writeFileSync(cfgFile, JSON.stringify(config), { encoding: 'utf8', mode: 0o600 });

    let stderr = '';
    child = spawn(SINGBOX_BIN, singboxArgv('run', '-c', cfgFile), { stdio: ['ignore', 'ignore', 'pipe'] });
    child.stderr.on('data', (b) => { stderr += b.toString(); });
    child.on('error', (err) => { stderr += err.message; });

    const started = Date.now();
    const up = await waitForPort(port, Date.now() + Math.min(timeoutMs, 8000));
    if (!up) {
      const why = stderr.trim().split('\n').pop() || 'it never opened its listener';
      return { ok: false, stage: 'deep', latencyMs: Date.now() - started, message: `sing-box did not start: ${why}` };
    }
    const r = await fetchThroughProxy(port, DEEP_TEST_URL, timeoutMs);
    if (r.ok) {
      return {
        ok: true, stage: 'deep', latencyMs: r.latencyMs,
        message: `End-to-end OK — ${DEEP_TEST_URL} answered ${r.status} through the proxy.`,
      };
    }
    const why = r.error || `unexpected status ${r.status}`;
    const hint = stderr.trim().split('\n').pop();
    return {
      ok: false, stage: 'deep', latencyMs: r.latencyMs,
      message: `Proxy did not carry traffic: ${why}${hint ? ` (${hint})` : ''}`,
    };
  } catch (err) {
    return { ok: false, stage: 'deep', latencyMs: 0, message: `Deep test failed: ${err.message}` };
  } finally {
    if (child && !child.killed) child.kill();
    if (dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* temp dir */ } }
  }
}

async function probeProfile(p, timeoutMs, deep) {
  if (deep) return deepProbe(p, timeoutMs);

  // Hysteria2 and TUIC are QUIC over UDP: the port can't be probed without
  // speaking the protocol, and silence is indistinguishable from a drop. The
  // deep test is the only one that means anything for them.
  if (p.protocol === 'hysteria2' || p.protocol === 'tuic') {
    return {
      ok: null, stage: 'skipped', latencyMs: 0,
      message: `${p.protocol} runs over UDP/QUIC — reachability can't be probed from here. Use the deep test.`,
    };
  }
  const tcp = await tcpProbe(p.server, p.port, timeoutMs);
  if (!tcp.ok) return { ...tcp, stage: 'tcp' };

  const usesTls = p.protocol === 'vless-reality' || (p.plugin_opts || '').includes('tls');
  if (!usesTls) return { ...tcp, stage: 'tcp' };

  const servername = p.sni || (p.plugin_opts || '').match(/host=([^;]+)/)?.[1] || p.server;
  return { ...(await tlsProbe(p.server, p.port, servername, timeoutMs)), stage: 'tls' };
}

const isDeep = (req) => req.query.deep === '1' || req.query.deep === 'true';
// A deep probe has to boot a proxy and complete a real request, so it needs
// more room than a bare connect.
const timeoutFor = (deep) => (deep ? 15000 : 5000);

app.get('/api/test', route(async (req, res) => {
  const p = resolveProfile(loadStore(), req.query.id);
  if (!p) return res.status(404).json({ error: 'No profile found.' });
  const deep = isDeep(req);
  const result = await probeProfile(p, timeoutFor(deep), deep);
  const hist = recordHistory([{ id: p.id, ...result }]);
  res.json({ ...result, history: summarizeHistory(hist[p.id]) });
}));

// Probe every profile at once and rank by latency — turns "is this one up?"
// into "which server should I be on right now?".
async function testAll(store, deep) {
  const timeout = timeoutFor(deep);
  const results = await Promise.all(store.profiles.map(async (p) => ({
    id: p.id, remarks: p.remarks, protocol: p.protocol,
    ...(await probeProfile(p, timeout, deep)),
  })));
  const hist = recordHistory(results);
  // Reachable first (fastest first), then untestable, then failures.
  const rank = (r) => (r.ok === true ? 0 : r.ok === null ? 1 : 2);
  results.sort((a, b) => rank(a) - rank(b) || a.latencyMs - b.latencyMs);
  return results.map((r) => ({ ...r, history: summarizeHistory(hist[r.id]) }));
}

app.get('/api/test-all', route(async (req, res) => {
  const store = loadStore();
  if (!store.profiles.length) return res.status(404).json({ error: 'No profiles.' });
  res.json({ results: await testAll(store, isDeep(req)) });
}));

// Probe everything, then move ★ to the fastest server that answered. This is
// the manual counterpart to the url-test group in the generated client configs.
app.post('/api/auto-active', route(async (req, res) => {
  const store = loadStore();
  if (!store.profiles.length) return res.status(404).json({ error: 'No profiles.' });
  const results = await testAll(store, isDeep(req));
  const best = results.find((r) => r.ok === true);
  if (!best) {
    return res.status(409).json({ error: 'Nothing answered a probe — leaving ★ where it is.', results });
  }
  const { idx } = findProfile(store, best.id);
  const changed = idx !== store.active;
  store.active = idx;
  saveStore(store);
  res.json({ ok: true, changed, chose: best.remarks, latencyMs: best.latencyMs, results, ...decorate(store) });
}));

app.get('/api/history', route((req, res) => {
  const hist = loadHistory();
  const store = loadStore();
  res.json({
    profiles: store.profiles.map((p) => ({
      id: p.id,
      remarks: p.remarks,
      summary: summarizeHistory(hist[p.id]),
      samples: hist[p.id] || [],
    })),
  });
}));

// ── Error handling ──────────────────────────────────────────────────────────── //
// Everything here answers in JSON, failures included — express's default
// handler renders an HTML page, which the dashboard can only report as an
// opaque "Request failed (400)".
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err.status || err.statusCode || 500;
  if (status >= 500) console.error(err);
  let message = err.message || 'Internal error';
  if (err.type === 'entity.parse.failed') message = `Request body is not valid JSON: ${err.message}`;
  if (err.type === 'entity.too.large') message = 'Request body is too large (limit 256kb).';
  res.status(status).json({ error: message });
});

const boot = (() => {
  try { return ensureStore(); } catch (err) {
    console.error(`\n⚠  ${err.message}\n`);
    return null;
  }
})();

app.listen(PORT, HOST, () => {
  const displayHost = (HOST === '0.0.0.0' || HOST === '::') ? 'localhost' : HOST;
  const secret = AUTH_REQUIRED ? (process.env.UI_TOKEN || (boot && boot.uiToken)) : null;
  const suffix = secret ? `/?ui_token=${encodeURIComponent(secret)}` : '/';
  console.log(`Airport Web UI running at http://${displayHost}:${PORT}${suffix}`);
  console.log(`Config file: ${CFG_PATH}`);
  if (boot && boot.token) {
    console.log(`Subscription: http://${displayHost}:${PORT}/api/subscription/${boot.token}`);
  }
  if (AUTH_REQUIRED) {
    console.log('');
    console.log('⚠  This dashboard is reachable beyond loopback, so it requires the token above.');
    console.log('   Open that URL once and it is remembered in a cookie. Anyone holding the token');
    console.log('   can read and rewrite every profile — treat it as a password.');
    if (!process.env.UI_TOKEN) {
      console.log('   Pin your own with UI_TOKEN=… to keep it stable if the store is ever reset.');
    }
  }
  const deep = deepTestAvailability();
  console.log(deep.available
    ? `Deep connection test: enabled (${deep.version})`
    : `Deep connection test: disabled — ${deep.reason}`);
});
