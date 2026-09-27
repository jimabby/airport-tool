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
const K         = require('../config-gen/lib/clients');
// The atomic writer lives with the history helpers, which need it too.
const { writeFileAtomic } = H;

const app  = express();
// Nothing good comes of announcing the framework and its version to anyone who
// asks, and this is the whole of what it takes to stop.
app.disable('x-powered-by');
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
// Which alert state was last notified about, and when each device token last
// pulled the subscription. Both used to live only in this process's memory, so
// a restart re-sent an alert that had already gone out and made a device that
// had been polling for months read as "never seen".
const STATE_PATH = H.statePathFor(CFG_PATH);

// Names this UI may legitimately be reached under, beyond localhost and bare IP
// literals — needed if you get here through a DDNS name. Declared up here
// because the Host allow-list and the self-signed certificate below both want
// it, and the certificate is built before the first request arrives.
const EXTRA_HOSTS = (process.env.ALLOWED_HOSTS || '')
  .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

// ── Public address ──────────────────────────────────────────────────────────── //
// Behind a reverse proxy (Caddy, nginx, a Cloudflare tunnel) the address a
// phone should use is not the one this process sees: requests arrive over
// plain HTTP from 127.0.0.1, so a subscription QR built from the request came
// out as http://localhost:3000/… — useless on the device it was scanned into,
// and missing the TLS the proxy was put there to add. PUBLIC_URL says what the
// outside world calls this dashboard, and every URL handed to a client is built
// from it.
//
// Only the origin is taken. The page fetches its API from absolute /api/…
// paths, so serving it under a sub-path would break the page itself; refusing
// a path at boot beats a dashboard that loads and then cannot save anything.
const PUBLIC_URL = (() => {
  const raw = (process.env.PUBLIC_URL || '').trim();
  if (!raw) return '';
  let u;
  try { u = new URL(raw); } catch {
    console.error(`\n⚠  PUBLIC_URL=${raw} is not a URL. Use the form https://airport.example.com\n`);
    process.exit(1);
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    console.error(`\n⚠  PUBLIC_URL must be http:// or https:// (got ${u.protocol}//).\n`);
    process.exit(1);
  }
  if (u.pathname.replace(/\/+$/, '') !== '' || u.search || u.hash) {
    console.error(`\n⚠  PUBLIC_URL=${raw} has a path. Serve the dashboard at the root of a host,`);
    console.error('   e.g. https://airport.example.com — the page cannot run under a sub-path.\n');
    process.exit(1);
  }
  return u.origin;
})();
// The proxy normally forwards the public Host header, and the allow-list below
// has to accept it or every request through the proxy is refused.
if (PUBLIC_URL) EXTRA_HOSTS.push(new URL(PUBLIC_URL).hostname.toLowerCase());
const PUBLIC_IS_HTTPS = PUBLIC_URL.startsWith('https:');

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

// ── Response hardening ──────────────────────────────────────────────────────── //
// The dashboard is a single self-contained page: every script and style is
// inline, the only images are the `data:` URIs the QR endpoints return, and the
// only network calls are same-origin fetches to this API. That makes a strict
// policy cheap — `default-src 'none'` and then name the three things the page
// genuinely does, so an injected <img>, <iframe> or fetch to somewhere else has
// nowhere to go even if something ever manages to inject one.
//
// 'unsafe-inline' is unavoidable while the page is one file with inline blocks;
// it is what a nonce would replace if the page were ever split up. The rest of
// the policy still does real work without it.
const CSP = [
  "default-src 'none'",
  "script-src 'unsafe-inline'",
  "style-src 'unsafe-inline'",
  // data: is the QR codes; 'self' is nothing today but costs nothing.
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', CSP);
  // Responses here carry proxy passwords as text/plain and application/json;
  // nosniff stops a browser deciding one of them is really HTML.
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // The dashboard URL can contain ?ui_token= before the redirect swaps it for a
  // cookie. No referrer at all is the only setting that cannot leak it.
  res.setHeader('Referrer-Policy', 'no-referrer');
  // frame-ancestors above covers this for anything current; X-Frame-Options is
  // for the browsers that only understand the old spelling.
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

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
  let parsed;
  try { parsed = new URL(origin); } catch { return true; }
  // Behind a proxy that rewrites Host, the page's own origin is PUBLIC_URL
  // rather than whatever Host this process was handed.
  if (PUBLIC_URL && parsed.origin === PUBLIC_URL) return false;
  return parsed.host.toLowerCase() !== String(req.headers.host || '').toLowerCase();
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

// When each per-device subscription token was last used. Kept out of the
// profile store on purpose — a client polls that feed every few hours, and
// writing the file that holds every credential you own that often is exactly
// the churn the probe history was split out to avoid — but persisted to
// monitor-state.json, so "never seen" now means the device really has never
// arrived rather than that the dashboard was restarted.
const bootState = H.loadState(STATE_PATH);
const clientLastSeen = new Map(Object.entries(bootState.clients || {}));

// Both halves of the persisted state are written together: they are two fields
// of one small file, and neither is worth its own write.
function persistState() {
  H.saveState(STATE_PATH, {
    alertState: lastAlertState,
    downStreak,
    clients: Object.fromEntries(clientLastSeen),
  });
}

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
  // A file that is not in canonical shape — hand-edited, or written before
  // tokens and profile ids existed — has to be repaired on disk: normalizeStore
  // mints a *fresh* token and fresh ids every time it is handed one that lacks
  // them, and the UI tracks the selected profile by id.
  //
  // That repair is a write, and every other write here goes through withStore().
  // It used to happen inline, which put a save on the read path — uiSecret()
  // calls this on every authenticated request — and outside the lock.
  if (!isCanonical(parsed)) return queueRepair(store);
  return store;
}

// The repaired shape waiting to be written back, or null. Handing the same
// object to every reader until the write lands is the point: two reads of a
// token-less file would otherwise each invent their own token, and only one of
// them would ever reach disk.
let pendingRepair = null;

function queueRepair(store) {
  if (pendingRepair) return pendingRepair;
  pendingRepair = store;
  withStore(async () => {
    const repaired = pendingRepair;
    pendingRepair = null;
    try {
      // A real write may have got there first and already fixed the file;
      // writing this snapshot over it would undo whatever it changed.
      const raw = fs.existsSync(CFG_PATH) ? JSON.parse(fs.readFileSync(CFG_PATH, 'utf8')) : null;
      if (isCanonical(raw)) return;
      saveStore(repaired);
    } catch { /* an unreadable file is reported by the next loadStore() */ }
  });
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
// browser drop the cookie, which locks you out of your own dashboard. TLS
// terminated by a proxy in front counts: the browser is on https either way.
function setUiCookie(res, value) {
  const flags = ['HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=31536000'];
  if (TLS_OPTIONS || PUBLIC_IS_HTTPS) flags.splice(1, 0, 'Secure');
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(value)}; ${flags.join('; ')}`);
}

// ── UI_TOKEN has to be long enough to be a password ─────────────────────────── //
// A stored token is 24 random bytes; normalizeStore refuses anything under 16
// characters as "not a token". The environment pin used to skip that check
// entirely, so `UI_TOKEN=x` was accepted as the only thing standing between a
// LAN and every proxy credential in the file — and the service template ships
// `#Environment=UI_TOKEN=change-me` as the example to copy.
//
// Refusing at boot rather than warning: a dashboard that starts and says it is
// protected, while guarded by one character, is worse than one that will not
// start until you fix it.
const MIN_UI_TOKEN = 16;
const UI_TOKEN = process.env.UI_TOKEN || '';
if (UI_TOKEN && UI_TOKEN.length < MIN_UI_TOKEN) {
  console.error(`\n⚠  UI_TOKEN is ${UI_TOKEN.length} character(s) long, and it is the only thing`);
  console.error(`   protecting every proxy credential in the store. Use at least ${MIN_UI_TOKEN}.`);
  console.error('\n   Generate one:  node -e "console.log(require(\'crypto\').randomBytes(24).toString(\'base64url\'))"');
  console.error('   Or unset UI_TOKEN to use the token minted into the store instead.\n');
  process.exit(1);
}

// The token the UI must present. An explicit UI_TOKEN wins so it can be pinned
// in a service file; otherwise it's the one minted into the store.
function uiSecret() {
  if (UI_TOKEN) return UI_TOKEN;
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
    // The same feed rendered as a whole client config rather than a bare URI
    // list — see SUB_TARGETS. Named here so the page cannot offer a target the
    // server does not serve. (Defined below; decorate only ever runs on a
    // request, long after the module has finished evaluating.)
    subscriptionTargets: Object.keys(SUB_TARGETS),
    lanUrls: lanUrls(store.token),
    // What to put in front of every path above when showing it as a URL. null
    // means "wherever the browser already is", which is right unless a proxy
    // sits in front — see PUBLIC_URL.
    publicBase: PUBLIC_URL || null,
    // Your own direct / proxy / block lists, applied in every bundle.
    rules: store.rules,
    // The bundles only carry enabled profiles, so the UI has to be able to say
    // "3 of 5" rather than implying every profile is being handed out.
    enabledCount: enabled.length,
    deepTest: P.deepTestAvailability(),
    monitor: { ...store.monitor, state: monitorState() },
    // Per-device subscription tokens. The raw token goes out because the URL is
    // the point and this endpoint already returns every proxy password;
    // last-seen lives in monitor-state.json, so polling a feed never rewrites
    // the credential file.
    clients: store.clients.map((c) => ({
      id: c.id,
      name: c.name,
      createdAt: c.createdAt,
      path: `/api/subscription/${c.token}`,
      lastSeen: clientLastSeen.get(c.id) || null,
      // null = every server; otherwise the ids this device's feed carries.
      profiles: c.profiles,
    })),
    tls: !!TLS_OPTIONS,
    // The name clients show for this subscription (the `profile-title` header).
    title: store.title,
    // What Surge and Quantumult X can and cannot carry out of this store, so
    // the dashboard can say so beside the download buttons rather than leaving
    // it to be discovered from a file with servers missing.
    clientSupport: K.supportSummary(store.profiles),
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
  // With a public address configured, that is the one to hand out; the raw
  // LAN addresses behind the proxy would bypass the TLS it adds.
  if (!token || IS_LOOPBACK || PUBLIC_URL) return [];
  const out = [];
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === 'IPv4' && !a.internal) out.push(`${SCHEME}://${a.address}:${PORT}/api/subscription/${token}`);
    }
  }
  return out;
}

// The origin a client should be handed: PUBLIC_URL when one is set, otherwise
// the address this request came in on (already vetted by the Host allow-list).
function publicBase(req) {
  return PUBLIC_URL || `${SCHEME}://${req.headers.host}`;
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

// ── Handing out one profile's credentials ───────────────────────────────────── //
// ★ means "the profile the QR code and active-uri.txt describe", which is a
// promise that it is one of the profiles the bundles carry. reseatActive() keeps
// that true whenever it can, but when *every* profile is disabled there is
// nowhere honest to move ★ to, so it stays on a profile no generated config
// contains. /api/download/clash and the subscription feed both refuse in that
// state; /api/qrcode and /api/download/uri used to cheerfully hand over its
// credentials instead, which is the same store answering two different ways.
//
// An explicit ?id= is still served whatever its state: being able to look at a
// disabled profile is the whole reason disabling exists rather than deleting.
function resolveForHandout(store, id) {
  const profile = resolveProfile(store, id);
  if (!profile) return { error: { status: 404, message: 'No profile found.' } };
  if (!id && !C.isEnabled(profile)) {
    return {
      error: {
        status: 409,
        message: `"${profile.remarks}" is the active profile but is disabled, so no generated config carries it. `
          + 'Enable it, or ask for a particular profile with ?id=.',
      },
    };
  }
  return { profile };
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
      // Keep ★ on something real here too, not only on the update path above.
      // With one disabled profile in the store this cannot help — there is
      // nowhere to move to, which is what resolveForHandout() exists to catch —
      // but it does keep an out-of-range `active` from surviving an append.
      reseatActive(store);
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
    const [gone] = store.profiles.splice(idx, 1);
    // Device tokens limited to a subset stop naming it. A device whose list
    // empties out this way is reported by its feed rather than silently
    // widened to every server, which is not what it was given.
    for (const c of store.clients) {
      if (Array.isArray(c.profiles)) c.profiles = c.profiles.filter((id) => id !== gone.id);
    }
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

// ── Reordering ──────────────────────────────────────────────────────────────── //
// Order is not decoration: it is the order the Clash and sing-box selectors list
// their proxies in, the order `uris.txt` comes out in, and the order a client
// walks when the one above does not answer. Until now the only way to change it
// was to hand-edit servers.json.
app.post('/api/profiles/order', route(async (req, res) => {
  const ids = (req.body || {}).ids;
  if (!Array.isArray(ids)) {
    return res.status(400).json({ error: 'Send { "ids": [ … ] } naming every profile in the order you want.' });
  }
  await withStore(async () => {
    const store = loadStore();
    const byId = new Map(store.profiles.map((p) => [p.id, p]));
    // A partial list would silently drop whatever it left out, and a repeated
    // id would duplicate a profile. Both are worth refusing rather than
    // guessing at: this rewrites the file every client is generated from.
    if (ids.length !== byId.size || new Set(ids).size !== ids.length || ids.some((id) => !byId.has(id))) {
      return res.status(400).json({
        error: `The list has to name each of the ${byId.size} profile(s) exactly once.`,
      });
    }
    // ★ is stored as an index, so it has to follow the profile it was pointing
    // at rather than staying at the position that profile used to occupy.
    const activeId = store.profiles[store.active] ? store.profiles[store.active].id : null;
    store.profiles = ids.map((id) => byId.get(id));
    const moved = store.profiles.findIndex((p) => p.id === activeId);
    store.active = moved === -1 ? 0 : moved;
    reseatActive(store);
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
  const { profile: p, error } = resolveForHandout(loadStore(), req.query.id);
  if (error) return res.status(error.status).json({ error: error.message });
  const uri = C.buildUri(p);
  res.json({ qrcode: await QRCode.toDataURL(uri, QR_OPTS), uri });
}));

// A QR of the subscription URL itself. Typing a 32-character token into a phone
// by hand is the worst part of setting a client up.
app.get('/api/qrcode/subscription', route(async (req, res) => {
  const store = loadStore();
  if (!store.profiles.length) return res.status(404).json({ error: 'No profiles yet.' });
  if (!store.token) return res.status(404).json({ error: 'No subscription token.' });
  const url = `${publicBase(req)}/api/subscription/${store.token}`;
  res.json({ qrcode: await QRCode.toDataURL(url, QR_OPTS), uri: url });
}));

// Downloads are named after what they hold — a hysteria2 profile written to
// "ss-uri.txt" is just confusing.
const URI_FILENAME = {
  shadowsocks: 'ss-uri.txt',
  'vless-reality': 'vless-uri.txt',
  hysteria2: 'hysteria2-uri.txt',
  tuic: 'tuic-uri.txt',
  trojan: 'trojan-uri.txt',
  vmess: 'vmess-uri.txt',
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
  res.send(C.buildClashYaml(store.profiles, { rules: store.rules }));
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
  res.send(JSON.stringify(C.buildSingBox(store.profiles, { tun, rules: store.rules }), null, 2));
}));

// ── Surge / Quantumult X ────────────────────────────────────────────────────── //
// Neither client reads Clash or Sing-Box files, and neither can express every
// protocol modelled here. The builders comment each omission into the file they
// produce rather than quietly shortening it — see config-gen/lib/clients.js —
// and `clientSupport` in decorate() tells the dashboard the same thing up front,
// so "Surge: 3 of 5 servers" is visible before the download rather than after.
function sendPlainConfig(res, filename, built) {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(built.text);
}

app.get('/api/download/surge', route((req, res) => {
  const store = loadStore();
  const refusal = bundleRefusal(store);
  if (refusal) return res.status(refusal.status).send(refusal.message);
  sendPlainConfig(res, 'surge.conf', K.buildSurge(store.profiles, { title: store.title, rules: store.rules }));
}));

app.get('/api/download/quantumultx', route((req, res) => {
  const store = loadStore();
  const refusal = bundleRefusal(store);
  if (refusal) return res.status(refusal.status).send(refusal.message);
  sendPlainConfig(res, 'quantumultx.conf', K.buildQuantumultX(store.profiles, { title: store.title, rules: store.rules }));
}));

app.get('/api/download/uri', route((req, res) => {
  const { profile: p, error } = resolveForHandout(loadStore(), req.query.id);
  if (error) return res.status(error.status).send(error.message);
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
  if (store.token && timingSafeEqual(presented, store.token)) hit = { kind: 'store', name: 'store-wide', client: null };
  for (const c of store.clients) {
    if (timingSafeEqual(presented, c.token) && !hit) hit = { kind: 'client', id: c.id, name: c.name, client: c };
  }
  return hit;
}

// ── What the feed hands back ────────────────────────────────────────────────── //
// The default is the base64 URI list every client understands, and it stays the
// default because that is what a QR code scanned into v2rayNG or Shadowrocket
// has to be.
//
// But a URI list is *only* servers. Everything this tool knows about getting
// out of China — the domestic-first DNS split, the DoH fallback that rides the
// tunnel, the fake-ip exemptions, the CN-direct rules, the geo mirrors that are
// reachable from behind the firewall — lives in the bundled Clash and Sing-Box
// configs, and none of it reaches a client that subscribed to the URI list.
// Clash Verge converts that list using its own defaults instead. So the person
// who did the easy thing (paste the subscription URL) got a working proxy with
// the routing this project spent its effort on quietly replaced.
//
// `?target=` closes that: same token, same servers, but the whole config. The
// URL still auto-updates, which the downloaded file does not.
//
// Each builder is handed the profile list separately from the store because a
// device token can be limited to a subset of the servers; the rules and the
// title still come from the store.
const SUB_TARGETS = {
  clash: {
    type: 'text/yaml; charset=utf-8',
    build: (store, profiles) => C.buildClashYaml(profiles, { rules: store.rules }),
  },
  singbox: {
    type: 'application/json; charset=utf-8',
    build: (store, profiles) => JSON.stringify(C.buildSingBox(profiles, { rules: store.rules }), null, 2),
  },
  // The desktop CLI cannot open the tun interface without root, so it needs the
  // same store without one — the same split /api/download/singbox?tun=0 makes.
  'singbox-desktop': {
    type: 'application/json; charset=utf-8',
    build: (store, profiles) => JSON.stringify(C.buildSingBox(profiles, { tun: false, rules: store.rules }), null, 2),
  },
  surge: {
    type: 'text/plain; charset=utf-8',
    build: (store, profiles) => K.buildSurge(profiles, { title: store.title, rules: store.rules }).text,
  },
  quantumultx: {
    type: 'text/plain; charset=utf-8',
    build: (store, profiles) => K.buildQuantumultX(profiles, { title: store.title, rules: store.rules }).text,
  },
};

app.get('/api/subscription/:token', route((req, res) => {
  const store = loadStore();
  const who = matchSubscriptionToken(store, req.params.token);
  if (!who) return res.status(404).type('text/plain').send('Not found\n');
  // Checked before the "every profile is disabled" refusal below, so a typo in
  // the target is answered as a typo rather than as a broken subscription.
  const target = req.query.target === undefined ? '' : String(req.query.target);
  if (target && !SUB_TARGETS[target]) {
    return res.status(400).type('text/plain').send(
      `Unknown target "${target}".\n` +
      `Use one of: ${Object.keys(SUB_TARGETS).join(', ')} — or leave it off for the URI list.\n`,
    );
  }
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
  // A device limited to a subset gets only those servers. If none of them is
  // left enabled (deleted, or switched off) the feed would be empty, which is
  // the same "the subscription is broken" signal as above — say why instead.
  const profiles = C.profilesForClient(store.profiles, who.client);
  if (store.profiles.length && !C.enabledProfiles(profiles).length) {
    return res.status(409).type('text/plain').send(
      `None of the servers "${who.name}" is allowed to use is enabled — this subscription would be empty.\n` +
      'Choose its servers again in the dashboard, or enable one of them.\n',
    );
  }
  // Recorded beside the probe history, never in the profile store. A client
  // polls this every few hours; writing that to the file holding every
  // credential is exactly the churn the history file was split out to avoid.
  if (who.kind === 'client') {
    clientLastSeen.set(who.id, {
      at: Date.now(),
      agent: String(req.headers['user-agent'] || '').slice(0, 120),
    });
    persistState();
  }
  const format = SUB_TARGETS[target];
  res.setHeader('Content-Type', format ? format.type : 'text/plain; charset=utf-8');
  res.setHeader('Profile-Update-Interval', '24');
  // Without a title a client shows the subscription as its raw URL — token and
  // all — in the profile list and in every screenshot of it. base64: is the
  // prefix the clients that read this header expect, and it is what keeps a
  // non-ASCII name intact through a header value.
  res.setHeader('Profile-Title', `base64:${Buffer.from(store.title, 'utf8').toString('base64')}`);
  // Where "open the provider's page" goes in Clash Verge and friends. Pointing
  // it at this dashboard is the only sensible destination.
  res.setHeader('Profile-Web-Page-URL', `${publicBase(req)}/`);
  //
  // Deliberately *not* set: Subscription-Userinfo. Clients render it as a
  // traffic and expiry badge, and this tool is a config generator — it does not
  // sit in the data path and has no idea how many bytes a server has carried.
  // Emitting the zeros it could honestly claim would paint every client with a
  // "0 B of 0 B, expired" badge, which is worse than the header's absence.
  res.setHeader('Cache-Control', 'no-store');
  res.send(format ? format.build(store, profiles) : C.buildSubscription(profiles));
}));

// ── Per-device subscription tokens ──────────────────────────────────────────── //
// One shared URL means a leak from any device can only be fixed by re-pointing
// every device. A named token per phone/laptop is revocable on its own; the feed
// it serves is byte-identical. (`clientLastSeen` lives up with the other module
// state, next to the note about why it is not persisted.)
// ── Which servers a device gets ─────────────────────────────────────────────── //
// `profiles` absent or null: every server, including ones added later. An array:
// exactly those profile ids. An empty array is refused rather than stored — a
// token that can see nothing is a revoked token wearing a disguise, and Revoke
// already exists. Unknown ids are refused too: a typo there would otherwise be
// a server the device silently never receives.
function readClientSubset(store, body) {
  if (!body || !Object.prototype.hasOwnProperty.call(body, 'profiles') || body.profiles === null) {
    return { subset: null };
  }
  if (!Array.isArray(body.profiles)) {
    return { error: 'Send "profiles" as a list of profile ids, or null for every server.' };
  }
  const ids = [...new Set(body.profiles)];
  if (!ids.length) return { error: 'Pick at least one server for this device — or revoke it instead.' };
  const known = new Set(store.profiles.map((p) => p.id));
  const unknown = ids.filter((id) => !known.has(id));
  if (unknown.length) return { error: `No such profile: ${unknown.join(', ')}` };
  return { subset: ids };
}

app.post('/api/clients', route(async (req, res) => {
  const name = String((req.body || {}).name || '').trim();
  if (!name) return res.status(400).json({ error: 'Give the device a name so you can tell which one to revoke.' });
  await withStore(async () => {
    const store = loadStore();
    if (store.clients.length >= 50) {
      return res.status(409).json({ error: 'That is 50 device tokens already — revoke some before adding more.' });
    }
    const { subset, error } = readClientSubset(store, req.body);
    if (error) return res.status(400).json({ error });
    const client = {
      id: crypto.randomUUID(), name: name.slice(0, 60), token: C.newToken(), createdAt: Date.now(), profiles: subset,
    };
    store.clients.push(client);
    saveStore(store);
    res.json({ ok: true, created: { id: client.id, name: client.name, path: `/api/subscription/${client.token}` }, ...decorate(store) });
  });
}));

// Rename a device, or change which servers it receives. The token — and so the
// URL already pasted into that device — stays the same.
app.post('/api/clients/:id', route(async (req, res) => {
  const body = req.body || {};
  await withStore(async () => {
    const store = loadStore();
    const client = store.clients.find((c) => c.id === req.params.id);
    if (!client) return res.status(404).json({ error: 'No such device token.' });
    if (Object.prototype.hasOwnProperty.call(body, 'name')) {
      const name = String(body.name || '').trim();
      if (!name) return res.status(400).json({ error: 'A device needs a name.' });
      client.name = name.slice(0, 60);
    }
    if (Object.prototype.hasOwnProperty.call(body, 'profiles')) {
      const { subset, error } = readClientSubset(store, body);
      if (error) return res.status(400).json({ error });
      client.profiles = subset;
    }
    saveStore(store);
    res.json({ ok: true, updated: { id: client.id, name: client.name, profiles: client.profiles }, ...decorate(store) });
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
    persistState();
    res.json({ ok: true, revoked: gone.name, ...decorate(store) });
  });
}));

// A QR of one device's subscription URL — the whole point of a per-device token
// is that it goes onto exactly one device, and typing it in defeats that.
app.get('/api/qrcode/client/:id', route(async (req, res) => {
  const store = loadStore();
  const client = store.clients.find((c) => c.id === req.params.id);
  if (!client) return res.status(404).json({ error: 'No such device token.' });
  const url = `${publicBase(req)}/api/subscription/${client.token}`;
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

// ── Subscription display name ─────────────────────────────────────────────── //
// Fed to clients as the `profile-title` header above. Its own endpoint because
// it belongs to neither the monitor settings nor a profile.
app.post('/api/title', route(async (req, res) => {
  const want = (req.body || {}).title;
  if (typeof want !== 'string') {
    return res.status(400).json({ error: 'Send { "title": "…" } — the name clients should show for this subscription.' });
  }
  await withStore(async () => {
    const store = loadStore();
    store.title = C.normalizeTitle(want);
    saveStore(store);
    res.json({ ok: true, ...decorate(store) });
  });
}));

// ── Custom routing rules ────────────────────────────────────────────────────── //
// Your own direct / proxy / block lists, applied ahead of the geographic rules
// in every bundle and every subscription target. Each list is an array or the
// text of a textarea. The whole body is validated before anything is saved: a
// half-applied rule set is harder to reason about than a refused one.
app.post('/api/rules', route(async (req, res) => {
  const body = req.body || {};
  const { rules, errors } = C.checkRules(body);
  if (errors.length) {
    return res.status(400).json({ error: errors.slice(0, 10).join('; ') + (errors.length > 10 ? ` (and ${errors.length - 10} more)` : '') });
  }
  await withStore(async () => {
    const store = loadStore();
    store.rules = rules;
    saveStore(store);
    res.json({ ok: true, ...decorate(store) });
  });
}));

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
// How many consecutive passes have found something wrong. Read back from
// monitor-state.json at boot for the same reason lastAlertState is: a restart
// used to reset it, which handed every deploy a fresh grace period and delayed
// exactly the alert the threshold exists to debounce.
let downStreak = bootState.downStreak || 0;
// The last state a notification was sent about, so the alert fires on the
// transition rather than on every pass. Persisted in monitor-state.json — it
// used to reset on restart, which turned every deploy into a repeat alert, and
// it is the same field `gen.js --test --alert` reads so a cron probe and the
// dashboard cannot disagree about what the current state is.
let lastAlertState = bootState.alertState || null;

function monitorState() {
  return {
    running: monitorRunning,
    lastRun: monitorLast,
    nextAt: monitorNextAt,
    alertState: lastAlertState,
    // Surfaced so the dashboard can say "down on 1 of the 3 passes it takes"
    // rather than looking identical to a monitor that found nothing wrong.
    downStreak,
  };
}

// Fire the webhook if this pass is worth waking somebody for. Never throws:
// a notification that failed must not turn into a monitor pass that failed.
async function maybeAlert(cfg, results, switchedTo) {
  const summary = A.summarize(results);
  // One call decides whether to speak, what state to remember and where the
  // failure streak now stands — they cannot be decided separately, because
  // recording a held-back "down" as the current state would consume the
  // transition on the pass that deliberately stayed quiet. `gen.js --test
  // --alert` calls the same function against the same state file. See alert.js.
  const decision = A.evaluate(lastAlertState, downStreak, summary, cfg.alert);
  // Tracked whether or not alerting is armed: turning the webhook on later
  // should not fire on a transition that happened while nobody was listening.
  lastAlertState = decision.state;
  downStreak = decision.streak;
  persistState();
  if (!cfg.alert.enabled) return null;

  // A ★ move always goes out: your clients were just repointed at a different
  // server, which is worth knowing even when the overall state did not change.
  if (!decision.send && !switchedTo) {
    return decision.holding
      ? {
        sent: false,
        reason: `something is down, but on ${decision.streak} of the ${decision.threshold} consecutive passes it takes to report it`,
      }
      : null;
  }

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
    // A pass started by "Run now" may still be going. Running a second on top
    // of it would probe everything twice at once and race the first pass's
    // alert decision, so this tick is skipped and the timer simply re-armed.
    if (monitorRunning) {
      applyMonitor();
      return;
    }
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
  const requested = body.alert ? body.alert : loadStore().monitor.alert;
  const cfg = C.normalizeAlert(requested);
  if (!cfg.url) {
    // normalizeAlert blanks a URL it will not use, which on its own reads as
    // "you left the field empty" even when the field was full. Ask why.
    const why = C.alertUrlProblem(requested && requested.url);
    return res.status(400).json({
      error: why === 'no URL'
        ? 'No webhook URL set — enter an http(s) URL first.'
        : `That webhook URL cannot be used: ${why}.`,
    });
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
// A request to an /api path that matched no route above fell through to
// express's default handler, which renders an HTML page — so a typo in a
// fetch() surfaced in the dashboard as an opaque "Request failed (404)" with
// nothing to go on. Same contract as the error handler below: everything under
// /api answers in JSON, failures included.
//
// Only /api. A missing static file should still 404 the way a static file does.
app.use('/api', (req, res) => {
  res.status(404).json({ error: `No such endpoint: ${req.method} ${req.path}` });
});

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
  if (PUBLIC_URL) console.log(`Public URL: ${PUBLIC_URL} — every link and QR code handed to a client uses it`);
  if (boot && boot.token) {
    console.log(`Subscription: ${PUBLIC_URL || `${SCHEME}://${displayHost}:${PORT}`}/api/subscription/${boot.token}`);
  }
  if (boot && boot.clients.length) {
    console.log(`Device tokens: ${boot.clients.length} issued (${boot.clients.map((c) => c.name).join(', ')})`);
  }
  console.log(`Monitor state: ${STATE_PATH}`);
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
    const when = m.alert.onEveryPass
      ? ' (every pass)'
      : ` (on change, after ${m.alert.afterFailures} consecutive failure${m.alert.afterFailures === 1 ? '' : 's'})`;
    console.log(m.alert.enabled
      ? `Monitor alerts: ${m.alert.mode} → ${m.alert.url}${when}`
      : 'Monitor alerts: off — nothing will tell you when a server goes down.');
  }
});
