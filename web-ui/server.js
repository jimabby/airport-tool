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
const S         = require('../config-gen/lib/sources');
const B = require('../config-gen/lib/storage');
// Shared storage supplies revision checks and encrypted recovery snapshots.

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

// A restore carries a whole store as an escaped JSON string (and a snapshot
// adds base64 on top), so a store that downloads fine can be several times
// 256kb by the time it comes back. Only those two routes get the bigger limit.
const BIG_BODY_PATHS = new Set(['/api/restore', '/api/backups/import']);
const smallJson = express.json({ limit: '256kb' });
const bigJson = express.json({ limit: '8mb' });
app.use((req, res, next) => (BIG_BODY_PATHS.has(req.path.toLowerCase()) ? bigJson : smallJson)(req, res, next));

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
  // Once the browser has reached this dashboard over TLS, never let it fall
  // back to plain HTTP: the token and every credential would cross in clear.
  // Only when TLS is genuinely in play — sending it over http is ignored at
  // best and, behind a proxy that later drops TLS, a lock-out at worst.
  if (TLS_OPTIONS || PUBLIC_IS_HTTPS) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
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
  //
  // "same-site" is *not* ours. A site is the registrable domain, so behind
  // PUBLIC_URL=https://airport.example.com every other *.example.com page is
  // same-site — and SameSite=Strict cookies are still sent to it, so it could
  // make authenticated writes. On the loopback default, any other localhost
  // port (a dev server, a compromised local app) is same-site too. Only the
  // dashboard's own origin counts.
  const site = req.headers['sec-fetch-site'];
  if (site) return !['same-origin', 'none'].includes(site);
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

// Some GETs have side effects too: /api/test-all?deep=1 starts a sing-box per
// profile, and a cross-site <img src> can make that request with no CORS check
// at all. Nothing under /api is meant to be reached from another site — except
// the subscription feed, which is a URL people paste and click from anywhere.
function guarded(req) {
  if (!SAFE_METHODS.has(req.method)) return true;
  // Express routes case-insensitively, so /API/test-all reaches the same
  // handler and has to be guarded the same way.
  const p = req.path.toLowerCase();
  return p.startsWith('/api/') && !p.startsWith('/api/subscription');
}

app.use((req, res, next) => {
  if (!guarded(req) || !crossSiteRequest(req)) return next();
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
  B.save(CFG_PATH, store);
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

// A device token not polled for this long is flagged in the device list.
const CLIENT_STALE_DAYS = 30;

// The record as the page may see it. monitor-state.json is hand-editable and
// shared with the CLI, so whatever is in it is checked rather than trusted —
// the page escapes it either way, but a number where an object belongs should
// read as "never polled", not as the year 1970.
function lastSeenOf(id) {
  const v = clientLastSeen.get(id);
  const at = Number(v && typeof v === 'object' ? v.at : v);
  if (!Number.isFinite(at) || at <= 0) return null;
  const agent = v && typeof v === 'object' && typeof v.agent === 'string' ? v.agent.slice(0, 120) : '';
  return { at, agent };
}

// Both halves of the persisted state are written together: they are two fields
// of one small file, and neither is worth its own write.
function persistState() {
  H.saveState(STATE_PATH, {
    alertState: lastAlertState,
    downStreak,
    clients: Object.fromEntries(clientLastSeen),
    notices: noticesSent,
  });
}

// Heads-up notices already delivered — shared with `gen.js --test --alert`
// through the same file, so a cron run and the monitor do not both send one.
let noticesSent = bootState.notices || {};

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
  if (!fs.existsSync(CFG_PATH)) return B.track(C.normalizeStore({ active: 0, profiles: [] }), null);
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
  const store = B.track(C.normalizeStore(parsed), raw);
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
  const store = B.track(C.normalizeStore({ active: 0, profiles: [], token: C.newToken(), uiToken: C.newToken() }), null);
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
//
// A hostname in ALLOWED_HOSTS counts as off loopback too: on a loopback bind
// the only way a request arrives under a real name is a reverse proxy passing
// it through — and the Host refusal tells you to set ALLOWED_HOSTS, not
// PUBLIC_URL, so following its advice used to publish the dashboard unguarded.
const AUTH_REQUIRED = !IS_LOOPBACK || !!PUBLIC_URL || !!process.env.UI_TOKEN
  || EXTRA_HOSTS.some((h) => !net.isIP(h));
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
function setUiCookie(res, value, maxAge = 31536000) {
  const flags = ['HttpOnly', 'SameSite=Strict', 'Path=/', `Max-Age=${maxAge}`];
  if (TLS_OPTIONS || PUBLIC_IS_HTTPS) flags.splice(1, 0, 'Secure');
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(value)}; ${flags.join('; ')}`);
}

// ── Sign out ────────────────────────────────────────────────────────────────── //
// The cookie lasts a year, which is right for your own laptop and wrong for a
// borrowed one. Clearing it takes the same flags it was set with — a browser
// only replaces a cookie whose name, path and Secure-ness match — and Max-Age=0.
//
// Registered ahead of the token check on purpose: clearing your own cookie is
// harmless, and a browser holding a token that has since been rotated must be
// able to drop it too. It is a POST, so the cross-site guard above applies.
app.post('/api/logout', (req, res) => {
  setUiCookie(res, '', 0);
  res.json({ ok: true, authRequired: AUTH_REQUIRED });
});

// ── Failed-token rate limiting ──────────────────────────────────────────────── //
// The dashboard token is 24 random bytes, so guessing it is hopeless — but
// UI_TOKEN can be pinned to anything 16 characters long, and nothing used to
// stop a script on the LAN trying as many as the socket would carry. After
// AUTH_FAIL_LIMIT wrong tokens inside AUTH_FAIL_WINDOW_MS, an address is told
// 429 with Retry-After, for a minute the first time and twice as long each time
// after, up to an hour. A locked-out address is refused even with the right
// token: letting that through would leave guessing exactly as fast as before,
// with 429 merely meaning "wrong".
//
// Only requests that *present* a token count. Opening the page without one is
// not a guess, and counting it would lock you out for visiting your own
// dashboard. A token rotated away while this process ran is not counted either
// — that is a browser left open on the old one, not an attacker. A success
// clears the address's record; it is never delayed.
//
// The subscription feed has its own token per URL and its own bucket ("sub:"):
// a revoked phone polling a dead URL must not lock its owner out of the
// dashboard from the same Wi-Fi.
const AUTH_FAIL_LIMIT = 10;
const AUTH_FAIL_WINDOW_MS = 15 * 60000;
const AUTH_LOCK_BASE_MS = 60000;
const AUTH_LOCK_MAX_MS = 60 * 60000;
// Bounded: one entry per address seen failing, oldest evicted first, and
// anything idle for a day swept out by the timer below.
const AUTH_TRACK_MAX = 5000;
const AUTH_IDLE_MS = 24 * 3600000;
const authFailures = new Map();
const retiredUiTokens = [];

function retireUiToken(token) {
  if (!token) return;
  retiredUiTokens.push(token);
  while (retiredUiTokens.length > 5) retiredUiTokens.shift();
}

const isLoopbackAddress = (a) => a === '::1' || /^(?:::ffff:)?127\./.test(a);

// An IPv6 client can hold a whole /64 and walk through it, so it is limited as
// one; IPv4 by the single address.
function v6Prefix(addr) {
  const [head, tail] = addr.split('::');
  const h = head ? head.split(':') : [];
  const t = tail === undefined ? [] : (tail ? tail.split(':') : []);
  const groups = tail === undefined ? h : [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t];
  return `${groups.slice(0, 4).map((g) => parseInt(g || '0', 16).toString(16)).join(':')}::/64`;
}

// Who is asking. The socket address, except behind the reverse proxy that
// PUBLIC_URL says is there: then every request arrives from 127.0.0.1 and one
// guesser would lock everybody out, so the address the proxy appended to
// X-Forwarded-For is used instead. Only the *rightmost* entry — the ones to its
// left were written by the client and say whatever it likes — and only when the
// socket really is loopback, so nobody reaching the port directly can choose
// their own bucket. Express's `trust proxy` is not enabled here; req.ip is not
// used for the same reason.
function clientAddress(req) {
  const sock = String(req.socket.remoteAddress || '');
  let addr = sock;
  if (PUBLIC_URL && isLoopbackAddress(sock)) {
    const hops = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
    const last = hops.length ? hops[hops.length - 1].replace(/^\[(.*)\](?::\d+)?$/, '$1') : '';
    if (net.isIP(last)) addr = last;
  }
  addr = addr.replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, '').replace(/%.*$/, '');
  return net.isIPv6(addr) ? v6Prefix(addr.toLowerCase()) : addr;
}

// Milliseconds this key is still locked out for, or 0.
function lockedFor(key, now = Date.now()) {
  const e = authFailures.get(key);
  return e && e.lockedUntil > now ? e.lockedUntil - now : 0;
}

function noteAuthFailure(key, now = Date.now()) {
  let e = authFailures.get(key);
  if (e) authFailures.delete(key); // re-inserted below, so Map order is LRU
  if (!e || now - e.last > AUTH_IDLE_MS) e = { count: 0, windowStart: now, lockedUntil: 0, lockouts: 0, last: now };
  if (now - e.windowStart > AUTH_FAIL_WINDOW_MS) { e.count = 0; e.windowStart = now; }
  e.count += 1;
  e.last = now;
  if (e.count >= AUTH_FAIL_LIMIT) {
    e.lockouts += 1;
    e.lockedUntil = now + Math.min(AUTH_LOCK_MAX_MS, AUTH_LOCK_BASE_MS * 2 ** (e.lockouts - 1));
    e.count = 0;
    e.windowStart = now;
  }
  authFailures.set(key, e);
  while (authFailures.size > AUTH_TRACK_MAX) authFailures.delete(authFailures.keys().next().value);
}

function refuseLocked(res, ms) {
  res.setHeader('Retry-After', String(Math.max(1, Math.ceil(ms / 1000))));
  return res.status(429).type('text/plain').send(
    'Too many wrong tokens from this address. Wait and try again — the wait doubles each time.\n',
  );
}

setInterval(() => {
  const now = Date.now();
  for (const [key, e] of authFailures) if (e.lockedUntil <= now && now - e.last > AUTH_IDLE_MS) authFailures.delete(key);
}, 10 * 60000).unref();

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

  const limitKey = `ui:${clientAddress(req)}`;
  const wait = lockedFor(limitKey);
  if (wait) return refuseLocked(res, wait);

  const want = uiSecret();
  if (!want) {
    return res.status(500).type('text/plain').send('No dashboard token available — check the server log.\n');
  }
  const got = presentedToken(req);
  if (got && timingSafeEqual(got, want)) {
    authFailures.delete(limitKey);
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
  if (got && !retiredUiTokens.some((t) => timingSafeEqual(got, t))) noteAuthFailure(limitKey);
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
    // Provider subscriptions this store follows, with how many servers each
    // currently contributes and whether one is being fetched right now.
    sources: store.sources.map((s) => ({
      ...s,
      count: store.profiles.filter((p) => p.source === s.id).length,
      refreshing: refreshingSources.has(s.id),
    })),
    // The bundles only carry enabled profiles, so the UI has to be able to say
    // "3 of 5" rather than implying every profile is being handed out.
    enabledCount: enabled.length,
    deepTest: P.deepTestAvailability(),
    monitor: { ...store.monitor, state: monitorState() },
    // Per-device subscription tokens. The raw token goes out because the URL is
    // the point and this endpoint already returns every proxy password;
    // last-seen lives in monitor-state.json, so polling a feed never rewrites
    // the credential file.
    clients: store.clients.map((c) => {
      const lastSeen = lastSeenOf(c.id);
      return {
        id: c.id,
        name: c.name,
        createdAt: c.createdAt,
        path: `/api/subscription/${c.token}`,
        // { at, agent }: when the feed was last pulled and by what client
        // software — the User-Agent is often the only clue to which phone a
        // badly named token is on.
        lastSeen,
        // 'never' | 'stale' | 'active'. A token nothing has polled for a month
        // is usually a device you no longer have, and a URL still in the wild.
        status: !lastSeen ? 'never' : (Date.now() - lastSeen.at > CLIENT_STALE_DAYS * 86400000 ? 'stale' : 'active'),
        // null = every server; otherwise the ids this device's feed carries.
        profiles: c.profiles,
      };
    }),
    clientStaleDays: CLIENT_STALE_DAYS,
    // Offered beside the per-source exclude filter as a one-click start.
    sourceExcludeSuggestion: SOURCE_EXCLUDE_SUGGESTION,
    tls: !!TLS_OPTIONS,
    // The name clients show for this subscription (the `profile-title` header).
    title: store.title,
    // What Surge and Quantumult X can and cannot carry out of this store, so
    // the dashboard can say so beside the download buttons rather than leaving
    // it to be discovered from a file with servers missing.
    clientSupport: K.supportSummary(store.profiles),
    backups: listBackups(),
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
      if (err.status === 409) return res.status(409).json({ error: err.message });
      if (err instanceof ConfigError) return res.status(500).json({ error: err.message });
      next(err);
    }
  };
}

// ── Profile CRUD ────────────────────────────────────────────────────────────── //
app.get('/api/config', route((req, res) => {
  res.json(decorate(loadStore()));
}));

// Each snapshot with whether this process's key can open it — a snapshot sealed
// under another key (BACKUP_KEY here, a key file in the CLI) is flagged in the
// list rather than discovered at the moment you need to roll back.
const listBackups = () => B.listBackups(CFG_PATH, { keyStatus: true });

app.get('/api/backups', route((req, res) => res.json({ backups: listBackups() })));
app.post('/api/backups', route(async (req, res) => {
  await withStore(() => {
    const id = B.snapshot(CFG_PATH);
    res.json({ id, backups: listBackups() });
  });
}));
app.get('/api/backups/:id/download', route((req, res) => {
  res.download(B.backupPath(CFG_PATH, req.params.id));
}));

// The snapshot key, as text. It sits beside the snapshots it protects, so a
// disk that loses one loses both — and a downloaded snapshot is useless on a
// new machine without it. It is no more sensitive than /api/download/backup,
// which hands over the store itself in plain text.
app.get('/api/backups/key', route((req, res) => {
  const { key, fingerprint } = B.exportKey(CFG_PATH);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="airport-backup-key.txt"');
  res.send(`${key}\n# fingerprint ${fingerprint} — paste the line above when restoring a snapshot on another machine,\n# or set it as BACKUP_KEY.\n`);
}));

// ── Previewing a restore ────────────────────────────────────────────────────── //
// All three ways back — rolling back to a snapshot, restoring a snapshot file,
// restoring a plain servers.json — replace the whole store, tokens included,
// and used to do it on one confirm() that could only say "everything will be
// replaced". `?preview=1` on any of them answers what *would* change instead,
// writes nothing, and names no secret: profiles by id and by connection
// identity, sources (by name and host — their URLs carry provider tokens),
// devices, and whether either token, the title, the rules or the monitor
// settings would change.
//
// The preview also hands back two digests, the way a source preview carries
// the store's revision: `revision` (the store as it was) and `candidate` (the
// exact bytes previewed). An apply that sends them back is refused with 409 if
// the store has been written since — a monitor moving ★, another tab — or if
// it is not the same backup, so what lands is what was looked at. An apply
// without them is the old unconditional restore, which scripts still rely on.
const sha256 = (text) => crypto.createHash('sha256').update(String(text)).digest('hex');
const isPreview = (req) => req.query.preview === '1' || req.query.preview === 'true';

// The current store for comparison. A store that will not parse is exactly
// when you reach for a backup, so it compares as empty rather than refusing.
function storeForDiff() {
  const raw = B.read(CFG_PATH);
  if (raw === null) return { raw, store: C.normalizeStore({ profiles: [] }), unreadable: false };
  try { return { raw, store: C.normalizeStore(JSON.parse(raw)), unreadable: false }; } catch {
    return { raw, store: C.normalizeStore({ profiles: [] }), unreadable: true };
  }
}

// Top-level keys of two objects whose values differ. Names only, never values:
// half of what is in a profile or a monitor config is a credential.
function changedFields(a, b, skip = []) {
  const keys = new Set([...Object.keys(a || {}), ...Object.keys(b || {})]);
  return [...keys].filter((k) => !skip.includes(k) && JSON.stringify((a || {})[k]) !== JSON.stringify((b || {})[k])).sort();
}

const hostOf = (url) => { try { return new URL(url).host; } catch { return ''; } };

function restoreDiff(current, next) {
  const profileView = (p) => ({ id: p.id, remarks: p.remarks, protocol: p.protocol, server: p.server, port: p.port, enabled: p.enabled !== false });
  const curById = new Map(current.profiles.map((p) => [p.id, p]));
  const nextById = new Map(next.profiles.map((p) => [p.id, p]));
  const curByKey = new Map(current.profiles.map((p) => [S.keyOf(p), p]));
  const nextByKey = new Map(next.profiles.map((p) => [S.keyOf(p), p]));
  const profiles = { added: [], removed: [], changed: [], unchanged: 0 };
  for (const p of next.profiles) {
    const was = curById.get(p.id);
    if (!was) {
      // Same server under another id — an old backup of a profile that has
      // since been re-created. Worth saying: it is not really new.
      const twin = curByKey.get(S.keyOf(p));
      profiles.added.push({ ...profileView(p), sameConnectionAs: twin ? twin.remarks : null });
      continue;
    }
    const fields = changedFields(was, p);
    if (!fields.length) { profiles.unchanged += 1; continue; }
    profiles.changed.push({ ...profileView(p), from: was.remarks, fields, connectionChanged: S.keyOf(was) !== S.keyOf(p) });
  }
  for (const p of current.profiles) {
    if (nextById.has(p.id)) continue;
    const twin = nextByKey.get(S.keyOf(p));
    profiles.removed.push({ ...profileView(p), sameConnectionAs: twin ? twin.remarks : null });
  }

  const byId = (list) => new Map(list.map((x) => [x.id, x]));
  const sourceView = (s) => ({ id: s.id, name: s.name, host: hostOf(s.url) });
  const curSources = byId(current.sources);
  const nextSources = byId(next.sources);
  const sources = {
    added: next.sources.filter((s) => !curSources.has(s.id)).map(sourceView),
    removed: current.sources.filter((s) => !nextSources.has(s.id)).map(sourceView),
    changed: next.sources.filter((s) => curSources.has(s.id))
      .map((s) => ({ ...sourceView(s), fields: changedFields(curSources.get(s.id), s, ['lastFetched', 'lastCount', 'lastError', 'failures', 'usage']) }))
      .filter((s) => s.fields.length),
  };

  const curClients = byId(current.clients);
  const nextClients = byId(next.clients);
  const devices = {
    added: next.clients.filter((c) => !curClients.has(c.id)).map((c) => ({ id: c.id, name: c.name })),
    removed: current.clients.filter((c) => !nextClients.has(c.id)).map((c) => ({ id: c.id, name: c.name })),
    // A changed token is named as a field, never shown: it is that device's URL.
    changed: next.clients.filter((c) => curClients.has(c.id))
      .map((c) => ({ id: c.id, name: c.name, fields: changedFields(curClients.get(c.id), c, ['createdAt']) }))
      .filter((c) => c.fields.length),
  };

  const counts = (r) => ({ direct: (r.direct || []).length, proxy: (r.proxy || []).length, block: (r.block || []).length, ads: r.ads === true, regionGroups: r.regionGroups === true });
  const star = (s) => (s.profiles[s.active] ? s.profiles[s.active].remarks : null);
  return {
    profiles,
    sources,
    devices,
    // A restored store with no token gets a fresh one, which is a change too.
    subscriptionTokenChanges: !next.token || next.token !== current.token,
    uiTokenChanges: !next.uiToken || next.uiToken !== current.uiToken,
    // With UI_TOKEN pinned the stored dashboard token is not the one in use,
    // so replacing it signs nobody out.
    uiTokenPinned: !!UI_TOKEN,
    title: next.title !== current.title ? { from: current.title, to: next.title } : null,
    rules: JSON.stringify(current.rules) !== JSON.stringify(next.rules) ? { from: counts(current.rules), to: counts(next.rules) } : null,
    monitor: changedFields(current.monitor, next.monitor).length ? { fields: changedFields(current.monitor, next.monitor) } : null,
    active: star(current) !== star(next) ? { from: star(current), to: star(next) } : null,
  };
}

// Answer a preview, or refuse an apply whose preview no longer describes what
// would happen. Returns true when the response has been sent.
function previewOrRefuse(req, res, plain, rawCandidate, extra = {}) {
  const candidate = sha256(rawCandidate);
  if (isPreview(req)) {
    const { raw, store, unreadable } = storeForDiff();
    res.json({
      preview: true,
      revision: B.digest(raw),
      candidate,
      currentUnreadable: unreadable,
      count: C.normalizeStore(plain).profiles.length,
      diff: restoreDiff(store, C.normalizeStore(plain)),
      ...extra,
    });
    return true;
  }
  const body = req.body || {};
  if (body.expectCandidate !== undefined && body.expectCandidate !== candidate) {
    res.status(409).json({ error: 'This is not the backup that was previewed. Preview it again.' });
    return true;
  }
  return false;
}

// Inside the store lock: has the store been written since the preview?
function staleSincePreview(req) {
  const body = req.body || {};
  if (body.expectRevision === undefined) return false;
  return body.expectRevision !== B.digest(B.read(CFG_PATH));
}
const STALE_RESTORE = 'Settings changed since this preview. Preview the restore again before applying it.';

// A restore usually swaps the dashboard token; the one it replaces is then a
// browser left open, not a guess (see the failed-token limiter).
function retireCurrentUiToken(next) {
  try {
    const was = JSON.parse(B.read(CFG_PATH) || '{}').uiToken;
    if (typeof was === 'string' && was !== next.uiToken) retireUiToken(was);
  } catch { /* an unreadable store has no token worth remembering */ }
}

// Replace the store with a decrypted snapshot, keeping the caller signed in.
function adoptSnapshot(res, plain) {
  const restored = B.track(C.normalizeStore(plain), B.read(CFG_PATH));
  if (!restored.token) restored.token = C.newToken();
  if (!restored.uiToken) restored.uiToken = C.newToken();
  retireCurrentUiToken(restored);
  saveStore(restored);
  pruneHistory(restored);
  applyMonitor();
  writeAccessFile(restored);
  if (AUTH_REQUIRED && !UI_TOKEN) setUiCookie(res, restored.uiToken);
  return restored;
}

app.post('/api/backups/:id/restore', route(async (req, res) => {
  // The envelope on disk is what gets digested: it is what "this snapshot"
  // means, and reading it also turns a bad id into the 400 backupPath throws.
  let envelope;
  let plain;
  try {
    envelope = fs.readFileSync(B.backupPath(CFG_PATH, req.params.id), 'utf8');
    plain = B.decryptBackup(CFG_PATH, req.params.id);
  } catch (err) {
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'No such snapshot.' });
    return res.status(400).json({ error: err.message });
  }
  if (previewOrRefuse(req, res, plain, envelope)) return;
  await withStore(() => {
    if (staleSincePreview(req)) return res.status(409).json({ error: STALE_RESTORE });
    const restored = adoptSnapshot(res, plain);
    res.json({ ok: true, ...decorate(restored) });
  });
}));

// The other half of "Download encrypted snapshot": a snapshot file carried from
// another machine, opened with the key that sealed it (pasted, or this store's
// own when it was sealed here).
app.post('/api/backups/import', route(async (req, res) => {
  const body = req.body || {};
  const text = String(body.snapshot || '').trim();
  if (!text) return res.status(400).json({ error: 'Choose an encrypted snapshot (.enc) file.' });
  let envelope;
  try { envelope = JSON.parse(text); } catch {
    return res.status(400).json({ error: 'That file is not an encrypted snapshot. A plain servers.json goes through "Restore from Backup…".' });
  }
  let plain;
  try {
    // Only the first line of a pasted key file: the rest is its comment.
    const key = body.key
      ? B.parseKey(String(body.key).split(/\r?\n/)[0], 'The backup key')
      : Buffer.from(B.exportKey(CFG_PATH).key, 'base64');
    plain = B.decryptEnvelope(envelope, key);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
  const check = C.normalizeStore(plain);
  if (!check.profiles.length) return res.status(400).json({ error: 'That snapshot holds no profiles — refusing to wipe the current store.' });
  // The key is part of what was previewed: the same file opened with another
  // key would be another store (or fail), so both are digested together.
  if (previewOrRefuse(req, res, plain, `${text}\n${String(body.key || '').split(/\r?\n/)[0].trim()}`)) return;
  await withStore(() => {
    if (staleSincePreview(req)) return res.status(409).json({ error: STALE_RESTORE });
    const restored = adoptSnapshot(res, plain);
    res.json({ ok: true, restored: restored.profiles.length, ...decorate(restored) });
  });
}));

app.post('/api/profiles/bulk', route(async (req, res) => {
  const { ids, action } = req.body || {};
  if (!Array.isArray(ids) || !ids.length || !['enable', 'disable', 'delete'].includes(action)) {
    return res.status(400).json({ error: 'Choose profiles and enable, disable, or delete.' });
  }
  await withStore(() => {
    const store = loadStore();
    const chosen = new Set(ids);
    if (ids.some((id) => !store.profiles.some((p) => p.id === id))) return res.status(409).json({ error: 'A selected profile no longer exists. Reload first.' });
    const activeId = store.profiles[store.active]?.id;
    // The single toggle refuses to switch off the last enabled server; this
    // used to let a bulk action do exactly that, and every subscription then
    // answered 409. Deleting everything is still fine — an empty store is the
    // "not set up yet" state — but leaving only disabled servers behind is not.
    if (action !== 'enable') {
      const left = store.profiles.filter((p) => !(action === 'delete' && chosen.has(p.id)));
      const enabledLeft = left.filter((p) => C.isEnabled(p) && !(action === 'disable' && chosen.has(p.id)));
      if (left.length && !enabledLeft.length && C.enabledProfiles(store.profiles).length) {
        return res.status(409).json({
          error: `That would ${action} every enabled server and leave each generated config and subscription empty. Keep at least one enabled.`,
        });
      }
    }
    if (action === 'delete') {
      store.profiles = store.profiles.filter((p) => !chosen.has(p.id));
      for (const c of store.clients) if (Array.isArray(c.profiles)) c.profiles = c.profiles.filter((id) => !chosen.has(id));
    } else for (const p of store.profiles) if (chosen.has(p.id)) p.enabled = action === 'enable';
    store.active = store.profiles.findIndex((p) => p.id === activeId);
    reseatActive(store);
    saveStore(store);
    pruneHistory(store);
    res.json({ ok: true, ...decorate(store) });
  });
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
      // The form knows nothing about subscription sources, so a save would
      // otherwise strip the tag and the next refresh would add the server a
      // second time. An edit to a source's server lasts until that refresh.
      if (store.profiles[idx].source) profile.source = store.profiles[idx].source;
      else delete profile.source;
      store.profiles[idx] = profile;
      // Editing a profile must not steal the ★ from whichever one is active —
      // switching active is an explicit action (/api/active). Disabling the
      // active one through the form is the exception: ★ has to move off it.
      reseatActive(store);
    } else {
      // Only a refresh tags a profile with a source; a new one is yours.
      delete profile.source;
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
    const activeId = store.profiles[store.active]?.id;
    const [gone] = store.profiles.splice(idx, 1);
    store.active = store.profiles.findIndex((p) => p.id === activeId);
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
      // A pasted profile is yours, not a subscription's — even if it was
      // copied out of a backup that said otherwise.
      delete p.source;
      const { errors } = C.validateProfile(p);
      if (errors.length) { problems.push(`${p.remarks}: ${errors.join(', ')}`); continue; }
      const dup = store.profiles.find((e) =>
        S.keyOf(e) === S.keyOf(p));
      if (dup) { skipped.push(p.remarks); continue; }
      // A backup's copy of a profile you have since edited keeps its old id.
      if (store.profiles.some((e) => e.id === p.id)) p.id = crypto.randomUUID();
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
  if (previewOrRefuse(req, res, parsed, text, { problems })) return;

  await withStore(async () => {
    if (staleSincePreview(req)) return res.status(409).json({ error: STALE_RESTORE });
    // A backup written before tokens existed gets fresh ones rather than none.
    if (!restored.token) restored.token = C.newToken();
    if (!restored.uiToken) restored.uiToken = C.newToken();
    retireCurrentUiToken(restored);
    B.track(restored, B.read(CFG_PATH));
    saveStore(restored);
    pruneHistory(restored);
    applyMonitor();
    writeAccessFile(restored);
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
      retireUiToken(store.uiToken);
      store.uiToken = C.newToken();
      notes.push('Dashboard token changed — other browsers and devices must sign in again.');
    }
    saveStore(store);
    writeAccessFile(store);
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
  'vless-tls': 'vless-uri.txt',
};

// The ★ profile's id, handed to every bundle builder so ★ leads its failover
// group — see preferredName in configs.js. Without this, moving ★ (by hand,
// "Use Fastest ★" or the monitor) changed nothing a subscribed client did.
function preferredId(store) {
  const p = store.profiles[store.active];
  return p && C.isEnabled(p) ? p.id : null;
}

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
  res.send(C.buildClashYaml(store.profiles, { rules: store.rules, preferred: preferredId(store) }));
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
  res.send(JSON.stringify(C.buildSingBox(store.profiles, { tun, rules: store.rules, preferred: preferredId(store) }), null, 2));
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
  sendPlainConfig(res, 'surge.conf', K.buildSurge(store.profiles, { title: store.title, rules: store.rules, preferred: preferredId(store) }));
}));

app.get('/api/download/quantumultx', route((req, res) => {
  const store = loadStore();
  const refusal = bundleRefusal(store);
  if (refusal) return res.status(refusal.status).send(refusal.message);
  sendPlainConfig(res, 'quantumultx.conf', K.buildQuantumultX(store.profiles, { title: store.title, rules: store.rules, preferred: preferredId(store) }));
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
    build: (store, profiles) => C.buildClashYaml(profiles, { rules: store.rules, preferred: preferredId(store) }),
  },
  singbox: {
    type: 'application/json; charset=utf-8',
    build: (store, profiles) => JSON.stringify(C.buildSingBox(profiles, { rules: store.rules, preferred: preferredId(store) }), null, 2),
  },
  // The desktop CLI cannot open the tun interface without root, so it needs the
  // same store without one — the same split /api/download/singbox?tun=0 makes.
  'singbox-desktop': {
    type: 'application/json; charset=utf-8',
    build: (store, profiles) => JSON.stringify(C.buildSingBox(profiles, { tun: false, rules: store.rules, preferred: preferredId(store) }), null, 2),
  },
  surge: {
    type: 'text/plain; charset=utf-8',
    build: (store, profiles) => K.buildSurge(profiles, { title: store.title, rules: store.rules, preferred: preferredId(store) }).text,
  },
  quantumultx: {
    type: 'text/plain; charset=utf-8',
    build: (store, profiles) => K.buildQuantumultX(profiles, { title: store.title, rules: store.rules, preferred: preferredId(store) }).text,
  },
};

app.get('/api/subscription/:token', route((req, res) => {
  // Its own bucket — see the failed-token limiter next to the auth check.
  const limitKey = `sub:${clientAddress(req)}`;
  const wait = lockedFor(limitKey);
  if (wait) return refuseLocked(res, wait);
  const store = loadStore();
  const who = matchSubscriptionToken(store, req.params.token);
  if (!who) {
    noteAuthFailure(limitKey);
    return res.status(404).type('text/plain').send('Not found\n');
  }
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
// state, next to the note about why it is kept in monitor-state.json.)
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

// ── Remote subscription sources ─────────────────────────────────────────────── //
// A provider's subscription URL, followed: fetched now, then again whenever its
// interval comes round, with its servers merged into the store. The fetch and
// the merge live in config-gen/lib/sources.js so `gen.js --refresh` does
// exactly the same thing. What stays here is the locking and the schedule.
const refreshingSources = new Set();
const sourcePreviews = new Map();

// ── Per-source filters ──────────────────────────────────────────────────────── //
// include / exclude are case-insensitive regexes matched against the provider's
// server names, and prefix is prepended to each — applied on every refresh by
// config-gen (applySourceFilters), which also drops a pattern that does not
// compile to ''. That silent drop is right for a store read off disk and wrong
// for a request: a typo would be saved as "no filter" and the next refresh
// would import exactly the junk servers you were filtering out. So the API
// refuses it with a reason instead.
//
// The limits and the check are config-gen's when it exports them; the
// fallbacks below mirror them so the two cannot disagree in the meantime.
const SOURCE_PATTERN_MAX = C.SOURCE_PATTERN_MAX || 200;
const SOURCE_PREFIX_MAX = C.SOURCE_PREFIX_MAX || 24;
const SOURCE_EXCLUDE_SUGGESTION = C.SOURCE_EXCLUDE_SUGGESTION || '';
const SOURCE_FILTER_FIELDS = ['include', 'exclude', 'prefix'];

function sourcePatternProblem(v) {
  if (typeof C.sourcePatternProblem === 'function') return C.sourcePatternProblem(v);
  if (v === undefined || v === null || v === '') return null;
  if (typeof v !== 'string') return 'a filter has to be a regular expression written as text';
  const s = v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (s.length > SOURCE_PATTERN_MAX) return `a filter can be at most ${SOURCE_PATTERN_MAX} characters`;
  try { new RegExp(s, 'i'); } catch (err) { return `"${s}" is not a valid regular expression (${err.message})`; }
  return null;
}

// The filter fields present in a request body, validated, or { error }.
// Absent fields are left out so an update touches only what it names; null
// means "clear it", the same as ''.
function readSourceFilters(body) {
  const out = {};
  for (const field of SOURCE_FILTER_FIELDS) {
    if (!body || !Object.prototype.hasOwnProperty.call(body, field)) continue;
    const v = body[field] === null ? '' : body[field];
    if (typeof v !== 'string') return { error: `${field} has to be text.` };
    if (field === 'prefix') {
      const p = v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
      if (p.length > SOURCE_PREFIX_MAX) return { error: `The name prefix can be at most ${SOURCE_PREFIX_MAX} characters.` };
      out.prefix = p;
      continue;
    }
    const problem = sourcePatternProblem(v);
    if (problem) return { error: `The ${field} filter cannot be used: ${problem}.` };
    out[field] = v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  }
  return { filters: out };
}

app.post('/api/sources/:id/preview', route(async (req, res) => {
  const source = loadStore().sources.find((s) => s.id === req.params.id);
  if (!source) return res.status(404).json({ error: 'No such source.' });
  const result = await S.fetchSource(source);
  if (result.error) return res.status(502).json({ error: result.error });
  const raw = B.read(CFG_PATH);
  const store = C.normalizeStore(JSON.parse(raw));
  const current = store.sources.find((s) => s.id === source.id);
  if (!current || current.url !== source.url) return res.status(409).json({ error: 'Source changed; preview again.' });
  const preview = S.previewMerge(store, current, result.profiles);
  const id = crypto.randomUUID();
  for (const [key, value] of sourcePreviews) if (Date.now() - value.at > 600000) sourcePreviews.delete(key);
  while (sourcePreviews.size >= 20) sourcePreviews.delete(sourcePreviews.keys().next().value);
  sourcePreviews.set(id, { at: Date.now(), sourceId: source.id, revision: B.digest(raw), result, next: preview.next });
  res.json({ id, changes: preview.changes, skipped: preview.merged.skipped, problems: result.problems, expiresInSeconds: 600 });
}));

app.post('/api/sources/:id/apply', route(async (req, res) => {
  await withStore(() => {
    const preview = sourcePreviews.get(req.body?.previewId);
    if (!preview || preview.sourceId !== req.params.id || Date.now() - preview.at > 600000) {
      return res.status(409).json({ error: 'Preview expired. Preview the subscription again.' });
    }
    const raw = B.read(CFG_PATH);
    if (B.digest(raw) !== preview.revision) return res.status(409).json({ error: 'Settings changed since this preview. Preview again before applying.' });
    const next = B.track(preview.next, raw);
    S.recordResult(next.sources.find((s) => s.id === req.params.id), preview.result);
    reseatActive(next);
    saveStore(next);
    sourcePreviews.delete(req.body.previewId);
    pruneHistory(next);
    res.json({ ok: true, ...decorate(next) });
  });
}));

// The network half runs outside the store lock — a slow provider must not hold
// up every other write — and the merge re-reads the store inside it.
async function refreshSource(id) {
  let snapshot;
  try { snapshot = loadStore().sources.find((s) => s.id === id); } catch (err) { return { error: err.message }; }
  if (!snapshot) return { missing: true };
  if (refreshingSources.has(id)) return { error: `"${snapshot.name}" is already being refreshed.` };
  refreshingSources.add(id);
  try {
    const result = await S.fetchSource(snapshot);
    return await withStore(async () => {
      const store = loadStore();
      const source = store.sources.find((s) => s.id === id);
      if (!source) return { missing: true };
      // Edited while the fetch ran: that response answers a question nobody
      // is asking any more.
      if (source.url !== snapshot.url) return { error: 'The source changed while it was being fetched — refresh it again.' };
      if (source.requireReview) return { error: 'Review is now required. Preview and apply these changes in the dashboard.' };
      S.recordResult(source, result);
      let merged = null;
      if (!result.error) {
        merged = S.mergeSource(store, source, result.profiles);
        reseatActive(store);
      }
      saveStore(store);
      if (merged && merged.removedIds.length) pruneHistory(store);
      return {
        name: source.name,
        error: result.error || null,
        problems: result.problems.slice(0, 10),
        ...(merged ? { added: merged.added, updated: merged.updated, removed: merged.removed, skipped: merged.skipped } : {}),
        store,
      };
    });
  } finally {
    refreshingSources.delete(id);
  }
}

function sourceSummary(r) {
  if (r.error) return r.error;
  return `${r.added} new, ${r.updated} updated, ${r.removed} gone`
    + (r.skipped ? `, ${r.skipped} skipped (already here by hand)` : '');
}

app.post('/api/sources', route(async (req, res) => {
  const body = req.body || {};
  const url = String(body.url || '').trim();
  const problem = C.alertUrlProblem(url);
  if (problem) {
    return res.status(400).json({ error: problem === 'no URL' ? 'Paste the subscription URL your provider gave you.' : `That URL cannot be used: ${problem}.` });
  }
  const { filters, error: filterError } = readSourceFilters(body);
  if (filterError) return res.status(400).json({ error: filterError });
  let source;
  const refusal = await withStore(async () => {
    const store = loadStore();
    if (store.sources.length >= C.SOURCE_LIMIT) return { status: 409, error: `That is ${C.SOURCE_LIMIT} sources already — remove one first.` };
    if (store.sources.some((s) => s.url === url)) return { status: 409, error: 'That subscription is already a source.' };
    [source] = C.normalizeSources([{
      name: body.name || 'Subscription', url, intervalHours: body.intervalHours, requireReview: body.requireReview === true, ...filters,
    }]);
    store.sources.push(source);
    saveStore(store);
    return null;
  });
  if (refusal) return res.status(refusal.status).json({ error: refusal.error });
  if (source.requireReview) return res.json({ ok: true, added: source.name, ...decorate(loadStore()) });
  // Fetched straight away, so adding one shows its servers rather than an
  // empty source that fills in some hours later.
  const r = await refreshSource(source.id);
  res.json({ ok: true, added: source.name, refresh: { error: r.error || null, summary: sourceSummary(r), problems: r.problems || [] }, ...decorate(loadStore()) });
}));

app.post('/api/sources/:id/refresh', route(async (req, res) => {
  if (loadStore().sources.find((s) => s.id === req.params.id)?.requireReview) return res.status(409).json({ error: 'This source requires a preview before applying changes.' });
  const r = await refreshSource(req.params.id);
  if (r.missing) return res.status(404).json({ error: 'No such source.' });
  // The failure is recorded on the source either way; 502 says it was the
  // provider, not this request, that went wrong.
  if (r.error) return res.status(502).json({ error: `${r.name ? `${r.name}: ` : ''}${r.error}` });
  res.json({ ok: true, summary: sourceSummary(r), problems: r.problems, ...decorate(r.store) });
}));

// Rename a source, change how often it is fetched, or change its filters. The
// URL is its identity — a different one is a different source. New filters
// take effect on the next refresh (or preview); servers already imported stay
// until then, so a change can be previewed before anything disappears.
app.post('/api/sources/:id', route(async (req, res) => {
  const body = req.body || {};
  const { filters, error: filterError } = readSourceFilters(body);
  if (filterError) return res.status(400).json({ error: filterError });
  await withStore(async () => {
    const store = loadStore();
    const source = store.sources.find((s) => s.id === req.params.id);
    if (!source) return res.status(404).json({ error: 'No such source.' });
    if (Object.prototype.hasOwnProperty.call(body, 'name')) {
      const name = String(body.name || '').trim();
      if (!name) return res.status(400).json({ error: 'A source needs a name.' });
      source.name = name.slice(0, 60);
    }
    if (Object.prototype.hasOwnProperty.call(body, 'intervalHours')) {
      source.intervalHours = C.normalizeSourceInterval(body.intervalHours);
    }
    if (Object.prototype.hasOwnProperty.call(body, 'requireReview')) source.requireReview = body.requireReview === true;
    Object.assign(source, filters);
    saveStore(store);
    res.json({ ok: true, ...decorate(store) });
  });
}));

// Stop following a source. Its servers go with it unless ?keep=1, in which case
// they stay as ordinary profiles that nothing will refresh or remove.
app.delete('/api/sources/:id', route(async (req, res) => {
  const keep = req.query.keep === '1' || req.query.keep === 'true';
  await withStore(async () => {
    const store = loadStore();
    const idx = store.sources.findIndex((s) => s.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'No such source.' });
    const [gone] = store.sources.splice(idx, 1);
    const activeId = store.profiles[store.active] ? store.profiles[store.active].id : null;
    const removed = new Set();
    store.profiles = store.profiles.filter((p) => {
      if (p.source !== gone.id) return true;
      if (keep) { delete p.source; return true; }
      removed.add(p.id);
      return false;
    });
    for (const c of store.clients) {
      if (Array.isArray(c.profiles)) c.profiles = c.profiles.filter((id) => !removed.has(id));
    }
    const at = store.profiles.findIndex((p) => p.id === activeId);
    store.active = at === -1 ? 0 : at;
    reseatActive(store);
    saveStore(store);
    if (removed.size) pruneHistory(store);
    res.json({ ok: true, removed: removed.size, kept: keep, ...decorate(store) });
  });
}));

// Refresh whatever is due. Checked often and acted on rarely: each source has
// its own interval, and a check that finds nothing due costs one file read.
const SOURCE_CHECK_MS = 10 * 60000;
let sourceCheckRunning = false;
async function refreshDueSources() {
  if (sourceCheckRunning) return;
  sourceCheckRunning = true;
  try {
    let store;
    try { store = loadStore(); } catch { return; }
    for (const source of store.sources) {
      if (source.requireReview) continue;
      if (!S.isDue(source)) continue;
      const r = await refreshSource(source.id);
      if (r.missing) continue;
      if (r.error) console.error(`[sources] ${source.name}: ${r.error}`);
      else console.log(`[sources] ${source.name}: ${sourceSummary(r)}`);
    }
  } catch (err) {
    // Run from a timer: a throw here (a save refused by a lock, a missing
    // backup key) would be an unhandled rejection, which ends the process.
    console.error(`[sources] background refresh failed: ${err.message}`);
  } finally {
    sourceCheckRunning = false;
  }
}

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

// One interactive job at a time, with bounded workers shared by all batch probes.
let probeJob = null;
const jobView = () => probeJob && ({ id: probeJob.id, state: probeJob.state,
  total: probeJob.total, completed: probeJob.results.length, results: probeJob.results, error: probeJob.error });
app.post('/api/tests', route((req, res) => {
  if (probeJob && ['running', 'cancelling'].includes(probeJob.state)) return res.status(409).json({ error: 'A test is already running.', job: jobView() });
  const store = loadStore();
  if (!store.profiles.length) return res.status(400).json({ error: 'No profiles to test.' });
  const job = { id: crypto.randomUUID(), controller: new AbortController(), state: 'running', total: store.profiles.length, results: [] };
  probeJob = job;
  P.probeAll(store.profiles, req.body?.deep === true, {
    signal: job.controller.signal,
    onProgress: ({ result }) => job.results.push(result),
  }).then((results) => {
    job.results = results;
    const hist = recordHistory(results);
    job.results = results.map((r) => ({ ...r, history: summarizeHistory(hist[r.id]) }));
    job.state = job.controller.signal.aborted ? 'cancelled' : 'complete';
  }).catch((err) => { job.error = err.message; job.state = 'failed'; });
  res.status(202).json(jobView());
}));
app.get('/api/tests', route((req, res) => res.json({ job: jobView() })));
app.delete('/api/tests/:id', route((req, res) => {
  if (!probeJob || probeJob.id !== req.params.id) return res.status(404).json({ error: 'No such test.' });
  if (probeJob.state === 'running') { probeJob.state = 'cancelling'; probeJob.controller.abort(); }
  res.json(jobView());
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
  const previous = lastAlertState;
  const decision = A.evaluate(previous, downStreak, summary, cfg.alert);
  downStreak = decision.streak;
  // Tracked whether or not alerting is armed: turning the webhook on later
  // should not fire on a transition that happened while nobody was listening.
  if (!cfg.alert.enabled) {
    lastAlertState = decision.state;
    persistState();
    return null;
  }

  // A ★ move always goes out: your clients were just repointed at a different
  // server, which is worth knowing even when the overall state did not change.
  if (!decision.send && !switchedTo) {
    lastAlertState = decision.state;
    persistState();
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
  // Recorded only now that we know whether the message left: a failed delivery
  // keeps the old state, so the next pass sees the same transition and retries
  // rather than staying quiet about an outage nobody was told about.
  lastAlertState = A.settle(decision, previous, outcome);
  persistState();
  if (!outcome.sent) console.error(`[monitor] alert not delivered (will retry next pass): ${outcome.reason}`);
  return outcome;
}

// Certificates about to run out and provider plans expiring or nearly spent —
// see alert.notices(). Only sent when alerting is armed; until then nothing is
// recorded, so arming it later reports what is already true.
async function maybeNotify(cfg, results, sources) {
  if (!cfg.alert.enabled) return null;
  const current = A.notices({
    servers: results.map((r) => ({ id: r.id, remarks: r.remarks, enabled: r.enabled, cert: r.history && r.history.cert })),
    sources,
  });
  // Re-read: a `gen.js --test --alert` cron run may have sent some since boot.
  const shared = H.loadState(STATE_PATH).notices;
  const { sent, outcome } = await A.deliverNotices(cfg.alert, current, { ...shared, ...noticesSent });
  noticesSent = sent;
  persistState();
  if (outcome && !outcome.sent) console.error(`[monitor] heads-up not delivered (will retry next pass): ${outcome.reason}`);
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
    monitorLast.notices = await maybeNotify(cfg, results, store.sources);
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
  if (err.type === 'entity.too.large') message = `Request body is too large (limit ${BIG_BODY_PATHS.has(req.path.toLowerCase()) ? '8mb' : '256kb'}).`;
  res.status(status).json({ error: message });
});

// ── Where the token-bearing URLs go ─────────────────────────────────────────── //
// They used to be printed to the log unconditionally, which under systemd or
// Docker means the journal or the container log: readable by anyone in the
// `adm` group or with access to the Docker socket, kept for weeks, and shipped
// off by whatever collects logs. They are now written to a 0600 file beside the
// store, and printed in full only to an interactive terminal (or when
// SHOW_TOKEN=1 says the log is private enough).
const ACCESS_PATH = path.join(path.dirname(CFG_PATH), 'dashboard-url.txt');
const SHOW_SECRETS = !!process.stdout.isTTY || process.env.SHOW_TOKEN === '1';
const BASE_URL = (() => {
  const displayHost = (HOST === '0.0.0.0' || HOST === '::') ? 'localhost' : HOST;
  return PUBLIC_URL || `${SCHEME}://${displayHost}:${PORT}`;
})();

function dashboardUrl(store) {
  const secret = AUTH_REQUIRED ? (UI_TOKEN || (store && store.uiToken)) : null;
  return `${BASE_URL}${secret ? `/?ui_token=${encodeURIComponent(secret)}` : '/'}`;
}

function writeAccessFile(store) {
  if (!store) return;
  const lines = [`Dashboard: ${dashboardUrl(store)}`];
  if (store.token) lines.push(`Subscription: ${BASE_URL}/api/subscription/${store.token}`);
  try { H.writeFileAtomic(ACCESS_PATH, `${lines.join('\n')}\n`, 0o600); } catch (err) {
    console.error(`Could not write ${ACCESS_PATH}: ${err.message}`);
  }
}

const mask = (url) => url.replace(/(ui_token=|subscription\/)([^/&\s]{4})[^/&\s]+/g, '$1$2…');

// ── Can we write where the store lives? ─────────────────────────────────────── //
// Under the systemd unit, ProtectSystem=strict makes everything read-only but
// the directories ReadWritePaths= names. Point CFG_PATH (or HISTORY_PATH, or
// MONITOR_STATE_PATH) somewhere else without adding it there and the dashboard
// starts, shows your profiles, and then fails every save with EROFS — which
// reads as a bug in the save, not a line missing from a unit file. Say so once,
// at boot, in words that name the fix. Not fatal: reading the store still works
// and is worth having while you fix it.
function unwritableStoreDirs() {
  const dirs = [...new Set([CFG_PATH, HISTORY_PATH, STATE_PATH].map((p) => path.dirname(path.resolve(p))))];
  const problems = [];
  for (const dir of dirs) {
    // A directory that does not exist yet is created on the first save, so
    // what matters is whether its nearest existing ancestor can be written.
    let d = dir;
    while (!fs.existsSync(d) && path.dirname(d) !== d) d = path.dirname(d);
    try {
      if (!fs.statSync(d).isDirectory()) { problems.push({ dir, why: `${d} is a file, not a directory` }); continue; }
      fs.accessSync(d, fs.constants.W_OK);
    } catch (err) {
      problems.push({ dir, why: err.code === 'EROFS' ? 'read-only file system' : (err.code || err.message) });
    }
  }
  return problems;
}

for (const { dir, why } of unwritableStoreDirs()) {
  console.error(`\n⚠  Cannot write to ${dir} (${why}).`);
  console.error('   The store, its snapshots, the probe history and the monitor state live there,');
  console.error('   so every save from this dashboard will fail until it is fixed.');
  console.error('   Under systemd (ProtectSystem=strict) the directory must be listed in ReadWritePaths= —');
  console.error('   set CFG_PATH / HISTORY_PATH / MONITOR_STATE_PATH in /etc/airport-ui.env and re-run');
  console.error('   web-ui/install-service.sh, which adds them. Otherwise check the directory\'s owner and mode.\n');
}

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
  const show = (url) => (SHOW_SECRETS ? url : mask(url));
  writeAccessFile(boot);
  console.log(`Airport Web UI running at ${show(dashboardUrl(boot))}`);
  if (!SHOW_SECRETS && boot) {
    console.log(`Full URLs, token included: ${ACCESS_PATH} (owner-only; SHOW_TOKEN=1 prints them here)`);
  }
  console.log(`Config file: ${CFG_PATH}`);
  if (TLS_OPTIONS) console.log(`TLS: on, using ${TLS_OPTIONS.source}`);
  if (PUBLIC_URL) console.log(`Public URL: ${PUBLIC_URL} — every link and QR code handed to a client uses it`);
  if (boot && boot.token) {
    console.log(`Subscription: ${show(`${BASE_URL}/api/subscription/${boot.token}`)}`);
  }
  if (boot && boot.clients.length) {
    console.log(`Device tokens: ${boot.clients.length} issued (${boot.clients.map((c) => c.name).join(', ')})`);
  }
  console.log(`Monitor state: ${STATE_PATH}`);
  if (AUTH_REQUIRED) {
    console.log('');
    console.log('⚠  This dashboard is reachable beyond loopback, so it requires the token in the URL above.');
    console.log('   Open that URL once and it is remembered in a cookie. Anyone holding the token');
    console.log('   can read and rewrite every profile — treat it as a password.');
    if (!process.env.UI_TOKEN) {
      console.log('   Pin your own with UI_TOKEN=… to keep it stable if the store is ever reset.');
    }
    if (!TLS_OPTIONS && !PUBLIC_IS_HTTPS) {
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
    // Subscription sources: one look shortly after boot (a source that fell
    // due while the dashboard was down should not wait ten more minutes), then
    // a cheap check on a timer. Neither holds the process open.
    const first = setTimeout(refreshDueSources, 30000);
    if (first.unref) first.unref();
    const every = setInterval(refreshDueSources, SOURCE_CHECK_MS);
    if (every.unref) every.unref();
    if (boot.sources.length) {
      console.log(`Subscription sources: ${boot.sources.length} (${boot.sources.map((s) => `${s.name}, every ${s.intervalHours}h`).join('; ')})`);
    }
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

// Daily recovery point even when no settings changed. Pre-change snapshots are
// also taken by the shared writer used by both the dashboard and CLI.
function scheduledBackup() { try { B.dailySnapshot(CFG_PATH); } catch (err) { console.error('[backup]', err.message); } }
scheduledBackup();
setInterval(scheduledBackup, 3600000).unref();

// ── Shutdown ──────────────────────────────────────────────────────────────── //
// As PID 1 in a container, node has no default SIGTERM action at all: `docker
// stop` waited its ten seconds and then SIGKILLed, mid-save if unlucky, which
// is how a write lock got left behind. Stop taking requests, let any queued
// store write finish, kill the deep-probe proxies (child processes outlive
// their parent), and leave.
let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[shutdown] ${signal} — finishing pending writes`);
  if (monitorTimer) clearTimeout(monitorTimer);
  if (probeJob && probeJob.state === 'running') probeJob.controller.abort();
  P.killAll();
  server.close();
  // Idle keep-alive connections would otherwise hold close() open.
  if (server.closeIdleConnections) server.closeIdleConnections();
  const exit = () => { P.killAll(); process.exit(0); };
  storeLock.then(exit, exit);
  setTimeout(exit, 5000).unref();
}
process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));
