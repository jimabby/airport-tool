const express   = require('express');
const fs        = require('fs');
const http      = require('http');
const https     = require('https');
const net       = require('net');
const os        = require('os');
const crypto    = require('crypto');
const path      = require('path');
const { spawnSync } = require('child_process');
const QRCode    = require('qrcode');
const C         = require('../config-gen/lib/configs');
const P         = require('../config-gen/lib/probe');
const H         = require('../config-gen/lib/history');
const A         = require('../config-gen/lib/alert');
// The atomic writer lives with the history helpers, which need it too.
const { writeFileAtomic } = H;

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
const HISTORY_PATH = H.historyPathFor(CFG_PATH);

// Names this UI may legitimately be reached under, beyond localhost and bare IP
// literals — needed if you get here through a DDNS name. Declared up here
// because the Host allow-list and the self-signed certificate below both want
// it, and the certificate is built before the first request arrives.
const EXTRA_HOSTS = (process.env.ALLOWED_HOSTS || '')
  .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

// ── HTTPS ───────────────────────────────────────────────────────────────────── //
// On loopback, plain HTTP never leaves the machine. Off it — a phone fetching
// the subscription URL, a tablet opening the dashboard — the token, every proxy
// password and the whole subscription feed cross the LAN in clear text, where
// any other device on the same Wi-Fi can read them.
//
// TLS_CERT/TLS_KEY use a certificate you already have. TLS_SELFSIGNED=1 mints
// one next to the store instead: browsers will warn about it exactly once, and
// an unverified tunnel still beats no tunnel for a token on a shared network.
const TLS_CERT = process.env.TLS_CERT || '';
const TLS_KEY = process.env.TLS_KEY || '';
const TLS_SELFSIGNED = process.env.TLS_SELFSIGNED === '1';

// Every address the UI might legitimately be reached on, so the certificate
// covers the LAN IP a phone will actually type rather than only "localhost".
function certSubjectAltNames() {
  const names = new Set(['DNS:localhost', 'IP:127.0.0.1', 'IP:::1']);
  for (const host of EXTRA_HOSTS) names.add(net.isIP(host) ? `IP:${host}` : `DNS:${host}`);
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (!a.internal && (a.family === 'IPv4' || a.family === 4)) names.add(`IP:${a.address}`);
    }
  }
  return [...names].join(',');
}

// openssl is the one certificate generator we can count on: setup.sh already
// depends on it, and Node has no API for minting a certificate.
function ensureSelfSignedCert() {
  const dir = path.dirname(CFG_PATH);
  const certPath = path.join(dir, 'ui-cert.pem');
  const keyPath = path.join(dir, 'ui-key.pem');
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) return { certPath, keyPath, created: false };
  fs.mkdirSync(dir, { recursive: true });
  const base = ['req', '-x509', '-nodes', '-newkey', 'rsa:2048',
    '-keyout', keyPath, '-out', certPath,
    // 825 days is the longest a browser will look at without complaining about
    // the lifetime on top of complaining about the issuer.
    '-days', '825', '-subj', '/CN=airport-tool'];
  const withSan = [...base, '-addext', `subjectAltName=${certSubjectAltNames()}`];
  let r = spawnSync('openssl', withSan, { encoding: 'utf8', timeout: 30000 });
  // -addext needs OpenSSL 1.1.1+. Without it the cert still works, it just
  // makes browsers complain harder, which beats not starting.
  if (!r || r.status !== 0) r = spawnSync('openssl', base, { encoding: 'utf8', timeout: 30000 });
  if (!r || r.status !== 0) {
    const why = (r && (r.stderr || r.error?.message)) || 'openssl is not on PATH';
    throw new Error(`TLS_SELFSIGNED=1 but the certificate could not be generated: ${String(why).trim()}`);
  }
  try { fs.chmodSync(keyPath, 0o600); } catch { /* unsupported filesystem/platform */ }
  return { certPath, keyPath, created: true };
}

function resolveTls() {
  if (TLS_CERT && TLS_KEY) {
    return { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY), source: 'TLS_CERT/TLS_KEY' };
  }
  if (TLS_CERT || TLS_KEY) {
    throw new Error('TLS_CERT and TLS_KEY must be set together.');
  }
  if (!TLS_SELFSIGNED) return null;
  const { certPath, keyPath, created } = ensureSelfSignedCert();
  return {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
    source: created ? `a new self-signed certificate at ${certPath}` : `the self-signed certificate at ${certPath}`,
  };
}

// A TLS misconfiguration has to be a sentence, not a stack trace: the whole
// point of asking for TLS is that you did not want to be served in the clear,
// so falling back to HTTP would be the wrong kind of resilient.
const TLS_OPTIONS = (() => {
  try { return resolveTls(); } catch (err) {
    console.error(`\n⚠  ${err.message}\n`);
    console.error('Fix it, or unset TLS_CERT/TLS_KEY/TLS_SELFSIGNED to serve plain HTTP on purpose.');
    process.exit(1);
  }
})();
const SCHEME = TLS_OPTIONS ? 'https' : 'http';

// Thin wrappers so the call sites below stay free of the path argument.
const loadHistory = () => H.loadHistory(HISTORY_PATH);
const recordHistory = (entries) => H.recordHistory(HISTORY_PATH, entries);
const pruneHistory = (store) => H.pruneHistory(HISTORY_PATH, store);
const summarizeHistory = (list) => H.summarizeHistory(list);

app.use(express.json({ limit: '256kb' }));

// ── Host header allow-list (DNS-rebinding defence) ──────────────────────────── //
// Binding to loopback is not enough on its own: any page the user visits can
// point a hostname it controls at 127.0.0.1 and then read this API cross-origin,
// walking off with every proxy credential. Rebinding needs a *name*, so we only
// accept `localhost`, a bare IP literal, or a name explicitly allow-listed via
// ALLOWED_HOSTS (declared above, next to the certificate that has to cover it).

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

// ── Cross-site request forgery ──────────────────────────────────────────────── //
// The Host allow-list above stops another page *reading* this API, and the
// dashboard cookie is SameSite=Strict so it cannot authorise a cross-site write.
// Neither helps on the loopback default, where there is no cookie to gate: any
// page the user happens to have open can post here as a CORS "simple request".
// `Content-Type: text/plain` skips the preflight, express.json() then declines
// to parse the body, and every handler falls back to `req.body || {}` — so
// `POST /api/rotate-token` with no body took its default and silently rotated
// the subscription token, breaking the URL every client polls. The attacker
// cannot read the reply, but the damage does not need a reply.
//
// Browsers label cross-site requests and page script cannot forge the labels;
// non-browsers send neither, so curl, the phone apps and the test suite are
// unaffected.
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function crossSiteRequest(req) {
  // Fetch metadata is the reliable signal where it exists. "none" means the
  // user typed the URL or opened a bookmark.
  const site = req.headers['sec-fetch-site'];
  if (site) return !['same-origin', 'same-site', 'none'].includes(site);
  // Anything older: Origin is still sent on every cross-origin POST, simple
  // requests included.
  const origin = req.headers.origin;
  if (!origin) return false;
  let originHost;
  try { originHost = new URL(origin).host.toLowerCase(); } catch { return true; }
  return originHost !== String(req.headers.host || '').toLowerCase();
}

app.use((req, res, next) => {
  if (SAFE_METHODS.has(req.method) || !crossSiteRequest(req)) return next();
  res.status(403).type('text/plain').send(
    'Refused: this request came from another site.\n' +
    'Every write here rewrites proxy credentials, so it has to come from the dashboard itself.\n',
  );
});

// Responses from this API carry proxy passwords and both tokens. Nothing about
// them should ever sit in a browser or proxy cache, and without an explicit
// header a JSON response is eligible for heuristic caching.
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// ── Store helpers ───────────────────────────────────────────────────────────── //
class ConfigError extends Error {}

function timingSafeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function saveStore(store) {
  // 0600 — holds proxy secrets; keep it owner-only.
  writeFileAtomic(CFG_PATH, JSON.stringify(store, null, 2), 0o600);
}

// Every write here is read-modify-write against one file. Node runs one handler
// at a time, but any `await` inside one (the probes in /api/auto-active, or a
// monitor pass) is a window where a second request can load the store, and the
// slower writer then saves a copy that never saw the other's change. Serialise
// the whole load→mutate→save sequence instead of hoping the window stays shut.
let storeLock = Promise.resolve();

// When each per-device subscription token was last used. In memory on purpose:
// a client polls that feed every few hours, and writing to the file that holds
// every credential you own that often is exactly the churn the probe history
// was split into its own file to avoid. It resets on restart, and the UI says
// so rather than letting "never" read as "this device has never worked".
const clientLastSeen = new Map();

function withStore(fn) {
  const run = storeLock.then(() => fn());
  // Swallow rejections *on the chain only* — the caller still sees them.
  storeLock = run.then(() => {}, () => {});
  return run;
}

// True when the on-disk shape already matches what we'd write back, so a read
// doesn't rewrite the file on every request.
function isCanonical(parsed) {
  if (!parsed || Array.isArray(parsed) || !Array.isArray(parsed.profiles)) return false;
  if (typeof parsed.token !== 'string' || parsed.token.length < 16) return false;
  if (typeof parsed.uiToken !== 'string' || parsed.uiToken.length < 16) return false;
  if (!parsed.monitor || typeof parsed.monitor !== 'object') return false;
  return parsed.profiles.every((p) => p && C.isUuid(p.id));
}

function loadStore() {
  // Normalised even when there is no file: callers reach for store.monitor and
  // store.clients unconditionally, and a hand-rolled literal missing either one
  // turned "the store was deleted while running" into a 500 with a TypeError.
  if (!fs.existsSync(CFG_PATH)) return C.normalizeStore({ active: 0, profiles: [] });
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
  const store = C.normalizeStore({ active: 0, profiles: [], token: C.newToken(), uiToken: C.newToken() });
  saveStore(store);
  return store;
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

// SameSite=Strict is what stops this cookie authorising a cross-site write;
// HttpOnly keeps it out of reach of any script that manages to run on the page.
// Secure is added only under TLS — setting it on a plain-HTTP origin makes the
// browser drop the cookie, which locks you out of your own dashboard.
function setUiCookie(res, value) {
  const flags = ['HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=31536000'];
  if (TLS_OPTIONS) flags.splice(1, 0, 'Secure');
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(value)}; ${flags.join('; ')}`);
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
    if (req.query.ui_token && req.method === 'GET') {
      setUiCookie(res, want);
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
  const enabled = C.enabledProfiles(store.profiles);
  return {
    active: store.active,
    activeId: store.profiles[store.active] ? store.profiles[store.active].id : null,
    subscriptionPath: store.token ? `/api/subscription/${store.token}` : null,
    lanUrls: lanUrls(store.token),
    // The bundles only carry enabled profiles, so the UI has to be able to say
    // "3 of 5" rather than implying every profile is being handed out.
    enabledCount: enabled.length,
    deepTest: P.deepTestAvailability(),
    monitor: { ...store.monitor, state: monitorState() },
    // Per-device subscription tokens. The raw token goes out because the URL is
    // the point and this endpoint already returns every proxy password; last-seen
    // is in-memory only, so polling a feed never rewrites the credential file.
    clients: store.clients.map((c) => ({
      id: c.id,
      name: c.name,
      createdAt: c.createdAt,
      path: `/api/subscription/${c.token}`,
      lastSeen: clientLastSeen.get(c.id) || null,
    })),
    tls: !!TLS_OPTIONS,
    // The dashboard token can be pinned by the environment, in which case
    // rotating the stored one changes nothing — the UI needs to know that
    // before it offers the button.
    uiTokenPinned: !!process.env.UI_TOKEN,
    authRequired: AUTH_REQUIRED,
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
      if (a.family === 'IPv4' && !a.internal) out.push(`${SCHEME}://${a.address}:${PORT}/api/subscription/${token}`);
    }
  }
  return out;
}

function findProfile(store, id) {
  const idx = store.profiles.findIndex((p) => p.id === id);
  return { idx, profile: store.profiles[idx] };
}

// Keep ★ on a profile the generated configs actually carry. It can drift off
// one by deletion or by the profile being disabled; either way, pointing the
// QR and active-uri.txt at something no bundle contains is worse than moving
// it. When nothing is enabled it stays put — there is nowhere honest to go.
function reseatActive(store) {
  if (store.active < 0 || store.active >= store.profiles.length) {
    store.active = Math.max(0, store.profiles.length - 1);
  }
  const current = store.profiles[store.active];
  if (current && C.isEnabled(current)) return;
  const next = store.profiles.findIndex(C.isEnabled);
  if (next !== -1) store.active = next;
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
app.post('/api/profiles', route(async (req, res) => {
  const body = req.body || {};
  const profile = C.normalizeProfile(body);
  const { errors, warnings } = C.validateProfile(profile);
  if (errors.length) {
    return res.status(400).json({ error: errors.join('; ') });
  }
  await withStore(async () => {
    const store = loadStore();
    const { idx } = findProfile(store, body.id);
    if (idx !== -1) {
      profile.id = store.profiles[idx].id; // preserve id on update
      store.profiles[idx] = profile;
      // Editing a profile must not steal the ★ from whichever one is active —
      // switching active is an explicit action (/api/active). Disabling the
      // active one through the form is the exception: ★ has to move off it.
      reseatActive(store);
    } else {
      store.profiles.push(profile);
      if (store.profiles.length === 1) store.active = 0;
    }
    saveStore(store);
    res.json({ ok: true, savedId: profile.id, warnings, ...decorate(store) });
  });
}));

app.delete('/api/profiles/:id', route(async (req, res) => {
  await withStore(async () => {
    const store = loadStore();
    const { idx } = findProfile(store, req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Profile not found.' });
    store.profiles.splice(idx, 1);
    reseatActive(store);
    saveStore(store);
    // The profile is gone; its latency samples are now unreachable clutter.
    pruneHistory(store);
    res.json({ ok: true, ...decorate(store) });
  });
}));

app.post('/api/active', route(async (req, res) => {
  await withStore(async () => {
    const store = loadStore();
    const { idx, profile } = findProfile(store, (req.body || {}).id);
    if (idx === -1) return res.status(404).json({ error: 'Profile not found.' });
    // ★ marks the profile the QR and active-uri.txt describe. Pointing it at a
    // disabled server would hand out a config the bundles deliberately omit.
    if (!C.isEnabled(profile)) {
      return res.status(409).json({ error: `"${profile.remarks}" is disabled — enable it before making it active.` });
    }
    store.active = idx;
    saveStore(store);
    res.json({ ok: true, ...decorate(store) });
  });
}));

// ── Enable / disable ────────────────────────────────────────────────────────── //
// A blocked server should be able to leave the generated configs without being
// deleted: setup.sh cannot reproduce a password it already minted, so deleting
// a profile is not the reversible act it looks like.
app.post('/api/profiles/:id/enabled', route(async (req, res) => {
  const want = (req.body || {}).enabled;
  if (typeof want !== 'boolean') {
    return res.status(400).json({ error: 'Send { "enabled": true } or { "enabled": false }.' });
  }
  await withStore(async () => {
    const store = loadStore();
    const { idx, profile } = findProfile(store, req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Profile not found.' });
    if (!want && idx === store.active) {
      // Move ★ somewhere real rather than leaving it on a profile no bundle
      // carries. Refusing outright would make the last-enabled case unfixable.
      const next = store.profiles.findIndex((p, i) => i !== idx && C.isEnabled(p));
      if (next === -1) {
        return res.status(409).json({
          error: `"${profile.remarks}" is the only enabled profile — disabling it would leave every generated config empty.`,
        });
      }
      store.active = next;
    }
    profile.enabled = want;
    saveStore(store);
    res.json({
      ok: true,
      enabled: want,
      note: want ? null : `"${profile.remarks}" stays in the store but leaves every generated config and the subscription feed.`,
      ...decorate(store),
    });
  });
}));

// ── Import ──────────────────────────────────────────────────────────────────── //
// Accepts a share link (ss:// / vless:// / hysteria2:// / tuic://), several of
// them on separate lines, a base64 subscription blob, or the JSON that setup.sh
// writes to /etc/airport-tool/profile.json. Beats retyping six fields by hand.
app.post('/api/import', route(async (req, res) => {
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

  await withStore(async () => {
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
  });
}));

// ── Restore from a backup ───────────────────────────────────────────────────── //
// /api/download/backup has always existed; this is its other half. Import can
// pick the profiles out of a backup, but it cannot bring back `active` or either
// token — so restoring onto a fresh machine silently handed every client a new
// subscription URL. A restore adopts the file wholesale instead.
app.post('/api/restore', route(async (req, res) => {
  const text = String((req.body || {}).text || '').trim();
  if (!text) return res.status(400).json({ error: 'Nothing to restore.' });
  let parsed;
  try { parsed = JSON.parse(text); } catch (err) {
    return res.status(400).json({ error: `Not a valid backup file: ${err.message}` });
  }
  const restored = C.normalizeStore(parsed);
  if (!restored.profiles.length) {
    return res.status(400).json({ error: 'That backup holds no profiles — refusing to wipe the current store.' });
  }
  const problems = [];
  for (const p of restored.profiles) {
    const { errors } = C.validateProfile(p);
    if (errors.length) problems.push(`${p.remarks}: ${errors.join(', ')}`);
  }

  await withStore(async () => {
    // A backup written before tokens existed gets fresh ones rather than none.
    if (!restored.token) restored.token = C.newToken();
    if (!restored.uiToken) restored.uiToken = C.newToken();
    saveStore(restored);
    pruneHistory(restored);
    applyMonitor();
    // The restored store almost certainly carries a different dashboard token,
    // which would lock the caller out of the page they just clicked. Hand the
    // new one straight back as a cookie.
    if (AUTH_REQUIRED && !process.env.UI_TOKEN) setUiCookie(res, restored.uiToken);
    res.json({ ok: true, restored: restored.profiles.length, problems, ...decorate(restored) });
  });
}));

// ── Token rotation ──────────────────────────────────────────────────────────── //
// The subscription response *is* every credential you own, and its URL ends up
// pasted into phone apps, chat messages and QR codes. Until now the only way to
// revoke a leaked one was to hand-edit servers.json.
app.post('/api/rotate-token', route(async (req, res) => {
  const which = String((req.body || {}).which || 'subscription');
  if (!['subscription', 'dashboard', 'both'].includes(which)) {
    return res.status(400).json({ error: `Unknown token "${which}" — use subscription, dashboard or both.` });
  }
  const wantsUi = which === 'dashboard' || which === 'both';
  const wantsSub = which === 'subscription' || which === 'both';

  await withStore(async () => {
    const store = loadStore();
    const notes = [];
    if (wantsSub) {
      store.token = C.newToken();
      notes.push('Subscription URL changed — every client polling the old one must be re-pointed.');
    }
    if (wantsUi) {
      if (process.env.UI_TOKEN) {
        // Rotating the stored one would be a lie: uiSecret() prefers the env
        // pin, so the old token would keep working and the new one would not.
        return res.status(409).json({
          error: 'The dashboard token is pinned by the UI_TOKEN environment variable. '
            + 'Change UI_TOKEN and restart to rotate it.',
        });
      }
      store.uiToken = C.newToken();
      notes.push('Dashboard token changed — other browsers and devices must sign in again.');
    }
    saveStore(store);
    if (wantsUi && AUTH_REQUIRED) setUiCookie(res, store.uiToken);
    res.json({ ok: true, rotated: which, notes, ...decorate(store) });
  });
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
  const url = `${SCHEME}://${req.headers.host}/api/subscription/${store.token}`;
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

// Every bundle carries only the enabled profiles, so "no profiles" and "none of
// your profiles are switched on" are different failures and get different
// messages — the second one is otherwise very hard to diagnose from a client.
function bundleRefusal(store) {
  if (!store.profiles.length) return { status: 404, message: 'No profiles' };
  if (!C.enabledProfiles(store.profiles).length) {
    return {
      status: 409,
      message: 'Every profile is disabled — enable at least one, or this config would carry no servers.',
    };
  }
  return null;
}

app.get('/api/download/clash', route((req, res) => {
  const store = loadStore();
  const refusal = bundleRefusal(store);
  if (refusal) return res.status(refusal.status).send(refusal.message);
  res.setHeader('Content-Type', 'text/yaml');
  res.setHeader('Content-Disposition', 'attachment; filename="clash-config.yaml"');
  res.send(C.buildClashYaml(store.profiles));
}));

// ?tun=0 drops the VPN interface. The tun inbound needs root/Administrator, so
// `sing-box run -c …` on a laptop dies on the config the phone apps require.
app.get('/api/download/singbox', route((req, res) => {
  const store = loadStore();
  const refusal = bundleRefusal(store);
  if (refusal) return res.status(refusal.status).send(refusal.message);
  const tun = !(req.query.tun === '0' || req.query.tun === 'false');
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition',
    `attachment; filename="${tun ? 'singbox-config.json' : 'singbox-desktop.json'}"`);
  res.send(JSON.stringify(C.buildSingBox(store.profiles, { tun }), null, 2));
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
// Which token was presented: the store-wide one, or one issued to a named
// device. Every candidate is compared even after a match so the time taken does
// not depend on how far down the list the right one sat.
function matchSubscriptionToken(store, presented) {
  let hit = null;
  if (store.token && timingSafeEqual(presented, store.token)) hit = { kind: 'store', name: 'store-wide' };
  for (const c of store.clients) {
    if (timingSafeEqual(presented, c.token) && !hit) hit = { kind: 'client', id: c.id, name: c.name };
  }
  return hit;
}

app.get('/api/subscription/:token', route((req, res) => {
  const store = loadStore();
  const who = matchSubscriptionToken(store, req.params.token);
  if (!who) return res.status(404).type('text/plain').send('Not found\n');
  // Having profiles but none of them enabled is a state you can only reach on
  // purpose, and an empty feed reads to most clients as "the subscription is
  // broken" — some of them then discard the profiles they already had. Say what
  // happened instead. A store with no profiles at all still answers 200 with an
  // empty body: that is the "not set up yet" case, not a mistake to report.
  if (store.profiles.length && !C.enabledProfiles(store.profiles).length) {
    return res.status(409).type('text/plain').send(
      'Every profile is disabled — this subscription would be empty.\n' +
      'Enable a server in the dashboard and poll again.\n',
    );
  }
  // Recorded in memory only. A client polls this every few hours; writing that
  // to the file holding every credential is exactly the churn the history file
  // was split out to avoid.
  if (who.kind === 'client') {
    clientLastSeen.set(who.id, {
      at: Date.now(),
      agent: String(req.headers['user-agent'] || '').slice(0, 120),
    });
  }
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Profile-Update-Interval', '24');
  res.setHeader('Cache-Control', 'no-store');
  res.send(C.buildSubscription(store.profiles));
}));

// ── Per-device subscription tokens ──────────────────────────────────────────── //
// One shared URL means a leak from any device can only be fixed by re-pointing
// every device. A named token per phone/laptop is revocable on its own; the feed
// it serves is byte-identical. (`clientLastSeen` lives up with the other module
// state, next to the note about why it is not persisted.)
app.post('/api/clients', route(async (req, res) => {
  const name = String((req.body || {}).name || '').trim();
  if (!name) return res.status(400).json({ error: 'Give the device a name so you can tell which one to revoke.' });
  await withStore(async () => {
    const store = loadStore();
    if (store.clients.length >= 50) {
      return res.status(409).json({ error: 'That is 50 device tokens already — revoke some before adding more.' });
    }
    const client = { id: crypto.randomUUID(), name: name.slice(0, 60), token: C.newToken(), createdAt: Date.now() };
    store.clients.push(client);
    saveStore(store);
    res.json({ ok: true, created: { id: client.id, name: client.name, path: `/api/subscription/${client.token}` }, ...decorate(store) });
  });
}));

app.delete('/api/clients/:id', route(async (req, res) => {
  await withStore(async () => {
    const store = loadStore();
    const idx = store.clients.findIndex((c) => c.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'No such device token.' });
    const [gone] = store.clients.splice(idx, 1);
    saveStore(store);
    clientLastSeen.delete(gone.id);
    res.json({ ok: true, revoked: gone.name, ...decorate(store) });
  });
}));

// A QR of one device's subscription URL — the whole point of a per-device token
// is that it goes onto exactly one device, and typing it in defeats that.
app.get('/api/qrcode/client/:id', route(async (req, res) => {
  const store = loadStore();
  const client = store.clients.find((c) => c.id === req.params.id);
  if (!client) return res.status(404).json({ error: 'No such device token.' });
  const url = `${SCHEME}://${req.headers.host}/api/subscription/${client.token}`;
  res.json({ qrcode: await QRCode.toDataURL(url, QR_OPTS), uri: url, name: client.name });
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
// The probes themselves live in config-gen/lib/probe.js so `gen.js --test`
// measures the same things this endpoint does. What stays here is the part the
// CLI has no use for: turning a request into a probe, and filing the result.
const isDeep = (req) => req.query.deep === '1' || req.query.deep === 'true';

app.get('/api/test', route(async (req, res) => {
  const p = resolveProfile(loadStore(), req.query.id);
  if (!p) return res.status(404).json({ error: 'No profile found.' });
  const deep = isDeep(req);
  // probeSingle takes the deep slot; a deep probe spawns a proxy, and two
  // batches running at once measure a machine that is busy running the other.
  const result = await P.probeSingle(p, deep);
  const hist = recordHistory([{ id: p.id, ...result }]);
  res.json({ ...result, history: summarizeHistory(hist[p.id]) });
}));

async function testAll(store, deep) {
  const results = await P.probeAll(store.profiles, deep);
  const hist = recordHistory(results);
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
  const probed = loadStore();
  if (!probed.profiles.length) return res.status(404).json({ error: 'No profiles.' });
  const results = await testAll(probed, isDeep(req));
  // A disabled profile is still probed — knowing a blocked server has come back
  // is the reason to look — but ★ must never land on one, because no generated
  // config carries it.
  const best = results.find((r) => r.ok === true && r.enabled !== false);
  if (!best) {
    const anyUp = results.some((r) => r.ok === true);
    return res.status(409).json({
      error: anyUp
        ? 'Only disabled servers answered — leaving ★ where it is. Enable one to use it.'
        : 'Nothing answered a probe — leaving ★ where it is.',
      results,
    });
  }
  // Re-read inside the lock: the probes above took seconds, and a profile may
  // have been added, edited or deleted while they ran.
  await withStore(async () => {
    const store = loadStore();
    const { idx } = findProfile(store, best.id);
    if (idx === -1) {
      return res.status(409).json({ error: `"${best.remarks}" was removed while the probes ran.`, results });
    }
    const changed = idx !== store.active;
    store.active = idx;
    saveStore(store);
    res.json({ ok: true, changed, chose: best.remarks, latencyMs: best.latencyMs, results, ...decorate(store) });
  });
}));

// ── Background health monitor ───────────────────────────────────────────────── //
// The probe history was only ever filled in by hand, so "which server should I
// be on right now?" was a question you had to remember to ask — usually after
// the answer already mattered. This runs the same testAll() on a timer.
//
// Chained setTimeout rather than setInterval: a deep pass over several profiles
// can outlast a short interval, and overlapping passes would spawn a second set
// of proxies on top of the first.
let monitorTimer = null;
let monitorRunning = false;
let monitorLast = null;
let monitorNextAt = null;
// The last state a notification was sent about, so the alert fires on the
// transition rather than on every pass. Deliberately not persisted: after a
// restart the first pass re-establishes the state, and one duplicate alert is a
// better failure than a missed one.
let lastAlertState = null;

function monitorState() {
  return { running: monitorRunning, lastRun: monitorLast, nextAt: monitorNextAt, alertState: lastAlertState };
}

// Fire the webhook if this pass is worth waking somebody for. Never throws:
// a notification that failed must not turn into a monitor pass that failed.
async function maybeAlert(cfg, results, switchedTo) {
  const summary = A.summarize(results);
  const previous = lastAlertState;
  if (summary.state !== 'unknown' && summary.state !== 'empty') lastAlertState = summary.state;
  if (!cfg.alert.enabled) return null;

  // A ★ move always goes out: your clients were just repointed at a different
  // server, which is worth knowing even when the overall state did not change.
  const transition = A.shouldAlert(previous, summary, cfg.alert);
  if (!transition && !switchedTo) return null;

  const text = A.describe(summary) + (switchedTo ? ` ★ moved to ${switchedTo}.` : '');
  const outcome = await A.send(cfg.alert, text, {
    state: summary.state,
    up: summary.up,
    down: summary.down,
    total: summary.total,
    switched: switchedTo || null,
    servers: results.map((r) => ({
      remarks: r.remarks, protocol: r.protocol, ok: r.ok,
      latencyMs: r.latencyMs, enabled: r.enabled !== false, message: r.message,
    })),
  });
  if (!outcome.sent) console.error(`[monitor] alert not delivered: ${outcome.reason}`);
  return outcome;
}

async function monitorPass() {
  monitorRunning = true;
  const startedAt = Date.now();
  try {
    const store = loadStore();
    const cfg = store.monitor;
    if (!store.profiles.length) {
      monitorLast = { at: startedAt, probed: 0, note: 'no profiles' };
      return;
    }
    const results = await testAll(store, cfg.deep);
    const up = results.filter((r) => r.ok === true).length;
    monitorLast = { at: startedAt, probed: results.length, up, deep: cfg.deep, switched: null, alert: null };

    // ★ only ever moves to a profile the generated configs actually carry.
    const best = cfg.autoSwitch
      ? results.find((r) => r.ok === true && r.enabled !== false)
      : null;
    if (cfg.autoSwitch && !best) monitorLast.note = 'nothing usable answered — left ★ alone';
    if (best) {
      await withStore(async () => {
        const fresh = loadStore();
        const { idx, profile } = findProfile(fresh, best.id);
        if (idx === -1 || idx === fresh.active || !C.isEnabled(profile)) return;
        fresh.active = idx;
        saveStore(fresh);
        monitorLast.switched = best.remarks;
        console.log(`[monitor] ★ moved to ${best.remarks} (${best.latencyMs}ms)`);
      });
    }
    // Alerting runs last so the message can mention a ★ move made above.
    monitorLast.alert = await maybeAlert(cfg, results, monitorLast.switched);
  } catch (err) {
    monitorLast = { at: startedAt, error: err.message };
    console.error('[monitor] pass failed:', err.message);
  } finally {
    monitorRunning = false;
  }
}

// Read the schedule back off the store and (re)arm the timer to match.
function applyMonitor() {
  if (monitorTimer) { clearTimeout(monitorTimer); monitorTimer = null; }
  monitorNextAt = null;
  let cfg;
  try { cfg = loadStore().monitor; } catch { return; } // broken store: nothing to schedule
  if (!cfg.enabled) return;
  const everyMs = cfg.intervalMin * 60000;
  const tick = async () => {
    await monitorPass();
    // Re-arm from the *current* settings: a pass may have been the one that
    // disabled the monitor, and rescheduling a cancelled timer here would
    // resurrect it.
    applyMonitor();
  };
  monitorNextAt = Date.now() + everyMs;
  monitorTimer = setTimeout(tick, everyMs);
  // Never hold the process open on the monitor's account.
  if (monitorTimer.unref) monitorTimer.unref();
}

app.get('/api/monitor', route((req, res) => {
  res.json({ ...loadStore().monitor, state: monitorState() });
}));

app.post('/api/monitor', route(async (req, res) => {
  const body = req.body || {};
  await withStore(async () => {
    const store = loadStore();
    // Merge onto what is stored so a partial body (just `enabled`, say) does
    // not silently reset the interval to its default.
    store.monitor = C.normalizeMonitor({ ...store.monitor, ...body });
    saveStore(store);
    applyMonitor();
    res.json({ ok: true, ...decorate(store) });
  });
}));

// Run one pass now, whatever the schedule says — the "check everything" button.
app.post('/api/monitor/run', route(async (req, res) => {
  if (monitorRunning) return res.status(409).json({ error: 'A monitor pass is already running.' });
  await monitorPass();
  res.json({ ok: true, state: monitorState(), last: monitorLast, ...decorate(loadStore()) });
}));

// Send one now, so "did I type the webhook URL correctly?" is answerable
// without waiting for an outage. Accepts an unsaved alert config in the body so
// you can try a URL before committing it to the store.
app.post('/api/monitor/test-alert', route(async (req, res) => {
  const body = req.body || {};
  const cfg = C.normalizeAlert(body.alert ? body.alert : loadStore().monitor.alert);
  if (!cfg.url) {
    return res.status(400).json({ error: 'No webhook URL set — enter an http(s) URL first.' });
  }
  // Force delivery regardless of the enabled flag: pressing "Send test" is a
  // more explicit request than the checkbox is.
  const outcome = await A.send({ ...cfg, enabled: true },
    'Airport: test notification. If you are reading this, the health monitor can reach you.',
    { state: 'test', test: true });
  if (!outcome.sent) return res.status(502).json({ error: `Webhook failed: ${outcome.reason}` });
  res.json({ ok: true, status: outcome.status });
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

const server = TLS_OPTIONS
  ? https.createServer({ cert: TLS_OPTIONS.cert, key: TLS_OPTIONS.key }, app)
  : http.createServer(app);

server.listen(PORT, HOST, () => {
  const displayHost = (HOST === '0.0.0.0' || HOST === '::') ? 'localhost' : HOST;
  const secret = AUTH_REQUIRED ? (process.env.UI_TOKEN || (boot && boot.uiToken)) : null;
  const suffix = secret ? `/?ui_token=${encodeURIComponent(secret)}` : '/';
  console.log(`Airport Web UI running at ${SCHEME}://${displayHost}:${PORT}${suffix}`);
  console.log(`Config file: ${CFG_PATH}`);
  if (TLS_OPTIONS) console.log(`TLS: on, using ${TLS_OPTIONS.source}`);
  if (boot && boot.token) {
    console.log(`Subscription: ${SCHEME}://${displayHost}:${PORT}/api/subscription/${boot.token}`);
  }
  if (boot && boot.clients.length) {
    console.log(`Device tokens: ${boot.clients.length} issued (${boot.clients.map((c) => c.name).join(', ')})`);
  }
  if (AUTH_REQUIRED) {
    console.log('');
    console.log('⚠  This dashboard is reachable beyond loopback, so it requires the token above.');
    console.log('   Open that URL once and it is remembered in a cookie. Anyone holding the token');
    console.log('   can read and rewrite every profile — treat it as a password.');
    if (!process.env.UI_TOKEN) {
      console.log('   Pin your own with UI_TOKEN=… to keep it stable if the store is ever reset.');
    }
    if (!TLS_OPTIONS) {
      // The token, every proxy password and the whole subscription feed are on
      // the wire in clear text at this point, on a network you do not control.
      console.log('   Nothing here is encrypted in transit. Set TLS_SELFSIGNED=1 (or TLS_CERT/TLS_KEY)');
      console.log('   so the token and your credentials do not cross the LAN in the clear.');
    }
  }
  const deep = P.deepTestAvailability();
  console.log(deep.available
    ? `Deep connection test: enabled (${deep.version})`
    : `Deep connection test: disabled — ${deep.reason}`);

  // Arm the background prober last, so nothing schedules against a store the
  // boot above may have just refused to read.
  if (boot) {
    applyMonitor();
    const m = boot.monitor;
    console.log(m.enabled
      ? `Health monitor: every ${m.intervalMin} min (${m.deep ? 'deep' : 'shallow'}${m.autoSwitch ? ', moves ★' : ''})`
      : 'Health monitor: off — turn it on from the dashboard.');
    console.log(m.alert.enabled
      ? `Monitor alerts: ${m.alert.mode} → ${m.alert.url}${m.alert.onEveryPass ? ' (every pass)' : ' (on change)'}`
      : 'Monitor alerts: off — nothing will tell you when a server goes down.');
  }
});
