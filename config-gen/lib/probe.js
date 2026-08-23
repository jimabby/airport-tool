// Connectivity probes, shared by the web UI (/api/test) and the CLI
// (gen.js --test) so the two report the same thing about the same server and
// file it in the same history.

'use strict';

const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const tls = require('tls');
const { spawn, spawnSync } = require('child_process');
const C = require('./configs');

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

// ── Certificate expiry ─────────────────────────────────────────────────────── //
// An expired certificate is the failure that arrives on its own while you do
// nothing, and it looks from the client side like the server simply stopped
// working. `setup.sh --show` has warned about it for a while; the probes are
// where the dashboard and the CLI can learn the same thing without an SSH
// session. Anything we can complete a TLS handshake with, we can date.
const CERT_WARN_DAYS = 14;

function readCert(socket) {
  let c;
  try { c = socket.getPeerCertificate(false); } catch { return null; }
  if (!c || !c.valid_to) return null;
  const notAfter = Date.parse(c.valid_to);
  if (!Number.isFinite(notAfter)) return null;
  const subject = (c.subject && c.subject.CN) || '';
  const issuer = (c.issuer && c.issuer.CN) || '';
  const daysLeft = Math.floor((notAfter - Date.now()) / 86400000);
  return {
    subject,
    issuer,
    notAfter,
    daysLeft,
    expired: daysLeft < 0,
    expiring: daysLeft >= 0 && daysLeft <= CERT_WARN_DAYS,
    // A cert that issued itself is the self-signed one setup.sh generates when
    // no DOMAIN was given — clients are expected to skip verification for it,
    // and its ten-year expiry is not news.
    selfSigned: !!issuer && issuer === subject,
  };
}

// One sentence about the certificate, or '' when there is nothing to say.
function certNote(cert) {
  if (!cert) return '';
  if (cert.expired) return `certificate EXPIRED ${-cert.daysLeft}d ago`;
  if (cert.expiring) return `certificate expires in ${cert.daysLeft}d`;
  return '';
}

function tlsProbe(host, port, servername, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    let settled = false;
    let socket;
    const done = (ok, message, cert = null) => {
      if (settled) return;
      settled = true;
      if (socket) socket.destroy();
      resolve({ ok, message, latencyMs: Date.now() - start, cert });
    };
    // rejectUnauthorized:false — Reality intentionally serves a borrowed cert,
    // and we only care that the TLS handshake completes, not that it validates.
    // The certificate is still read back: not validating it is not a reason to
    // stay ignorant of when it runs out.
    socket = tls.connect(
      { host, port: Number(port), servername, rejectUnauthorized: false, timeout: timeoutMs },
      () => {
        const cert = readCert(socket);
        const note = certNote(cert);
        done(true, `TLS handshake OK (${socket.getProtocol()}) with SNI ${servername}${note ? ` — ${note}` : ''}`, cert);
      },
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

// A negative answer is re-checked periodically so installing sing-box while the
// UI is running enables the deep test on its own. A positive one is kept for
// good: `spawnSync` blocks the event loop for up to five seconds, which is not
// something to repeat on every dashboard poll just to confirm what we know.
const SINGBOX_RECHECK_MS = 60000;
let singboxCache = null;
let singboxCheckedAt = 0;

function deepTestAvailability() {
  if (singboxCache && (singboxCache.available || Date.now() - singboxCheckedAt < SINGBOX_RECHECK_MS)) {
    return singboxCache;
  }
  let r;
  try { r = spawnSync(SINGBOX_BIN, singboxArgv('version'), { encoding: 'utf8', timeout: 5000 }); } catch { r = null; }
  singboxCheckedAt = Date.now();
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

// What the certificate a TLS probe would see actually belongs to. Reality
// deliberately serves the *borrowed* site's certificate, so dating it says
// something about the camouflage target rather than about your server — worth
// showing, but not worth confusing with your own ACME renewal.
const CERT_SOURCE = {
  'vless-reality': 'camouflage target',
  shadowsocks: 'server',
};

async function probeProfile(p, timeoutMs, deep) {
  if (deep) return deepProbe(p, timeoutMs);

  // Hysteria2 and TUIC are QUIC over UDP: the port can't be probed without
  // speaking the protocol, and silence is indistinguishable from a drop. The
  // deep test is the only one that means anything for them.
  if (p.protocol === 'hysteria2' || p.protocol === 'tuic') {
    return {
      ok: null, stage: 'skipped', latencyMs: 0,
      cert: null,
      // Say why there is no certificate line rather than leaving a blank the
      // reader has to interpret: it is not that the cert is fine, it is that
      // nothing here can see it. Only the server knows — `setup.sh --show`.
      certNote: `${p.protocol} serves its certificate inside QUIC, which nothing here speaks — run \`setup.sh --show\` on the server to date it.`,
      message: `${p.protocol} runs over UDP/QUIC — reachability can't be probed from here. Use the deep test.`,
    };
  }
  const tcp = await tcpProbe(p.server, p.port, timeoutMs);
  if (!tcp.ok) return { ...tcp, stage: 'tcp', cert: null };

  const usesTls = p.protocol === 'vless-reality' || (p.plugin_opts || '').includes('tls');
  if (!usesTls) return { ...tcp, stage: 'tcp', cert: null };

  const servername = p.sni || (p.plugin_opts || '').match(/host=([^;]+)/)?.[1] || p.server;
  const r = await tlsProbe(p.server, p.port, servername, timeoutMs);
  return { ...r, stage: 'tls', certOf: r.cert ? (CERT_SOURCE[p.protocol] || 'server') : null };
}
// A deep probe has to boot a proxy and complete a real request, so it needs
// more room than a bare connect.
const timeoutFor = (deep) => (deep ? 15000 : 5000);

// ── One deep batch at a time ───────────────────────────────────────────────── //
// A deep probe spawns a sing-box per profile. A scheduled monitor pass landing
// on top of somebody pressing "Test All" doubled that, for no benefit — the
// second batch measures a machine already busy running the first. Queue them
// instead of refusing: the caller waits a little and gets a real measurement.
let deepQueue = Promise.resolve();

function withDeepSlot(fn) {
  const run = deepQueue.then(() => fn());
  // Swallow rejections on the chain only — the caller still sees them.
  deepQueue = run.then(() => {}, () => {});
  return run;
}

// Probe one profile, taking the deep slot when it needs a proxy. This is the
// entry point for a single-profile check; probeProfile() stays unguarded so
// probeAll() can fan out inside one slot rather than deadlocking on itself.
function probeSingle(p, deep) {
  const run = () => probeProfile(p, timeoutFor(deep), deep);
  return deep ? withDeepSlot(run) : run();
}

// Probe every profile at once and rank by latency - turns "is this one up?"
// into "which server should I be on right now?". Reachable first (fastest
// first), then untestable, then failures.
async function probeAll(profiles, deep) {
  const timeout = timeoutFor(deep);
  const run = async () => {
    const results = await Promise.all(profiles.map(async (p) => ({
      id: p.id, remarks: p.remarks, protocol: p.protocol, enabled: C.isEnabled(p),
      ...(await probeProfile(p, timeout, deep)),
    })));
    const rank = (r) => (r.ok === true ? 0 : r.ok === null ? 1 : 2);
    results.sort((a, b) => rank(a) - rank(b) || a.latencyMs - b.latencyMs);
    return results;
  };
  return deep ? withDeepSlot(run) : run();
}

module.exports = {
  SINGBOX_BIN,
  DEEP_TEST_URL,
  CERT_WARN_DAYS,
  deepTestAvailability,
  certNote,
  tcpProbe,
  tlsProbe,
  deepProbe,
  probeProfile,
  probeSingle,
  probeAll,
  withDeepSlot,
  timeoutFor,
};
