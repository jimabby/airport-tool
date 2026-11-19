// Which proxy, if any, carries this process's own outbound requests: fetching a
// provider's subscription, posting an alert, registering a WARP identity.
//
// Wherever the dashboard runs inside China, those hosts are exactly the ones
// that are blocked — a provider's subscription domain, api.telegram.org,
// Cloudflare's WARP API — and every one of those requests used to go out
// directly and fail. Now:
//
//   OUTBOUND_PROXY=http://127.0.0.1:7890     an HTTP proxy (CONNECT), e.g. the
//   OUTBOUND_PROXY=socks5://127.0.0.1:7891   local Clash / sing-box client, or SOCKS5
//   OUTBOUND_PROXY=active                    a sing-box tunnel through ★, started
//                                            on demand and stopped when idle
//   OUTBOUND_PROXY=off                       always direct, whatever else is set
//
// Unset, the conventional HTTPS_PROXY / HTTP_PROXY / ALL_PROXY (either case)
// apply, with NO_PROXY honoured, so a machine already configured for a proxy
// needs nothing new. Loopback and LAN destinations — a self-hosted ntfy, a NAS
// — are always reached directly.

'use strict';

const net = require('net');

const IDLE_MS = 60000;
let activeResolver = null;
let current = null; // { key, tunnel, timer }
let pending = null; // { key, promise }

// The host decides what ★ is: the dashboard and the CLI each hold the store.
// `fn` returns { profile, relay } or null.
function setActiveResolver(fn) { activeResolver = typeof fn === 'function' ? fn : null; }

const env = (name) => process.env[name] || process.env[name.toLowerCase()] || '';

function setting() {
  const raw = String(process.env.OUTBOUND_PROXY || '').trim();
  if (raw) return raw;
  return null;
}

function noProxy(host) {
  const list = env('NO_PROXY').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const h = host.toLowerCase();
  return list.some((e) => e === '*' || h === e.replace(/^\./, '') || h.endsWith(e.startsWith('.') ? e : `.${e}`));
}

// LAN, loopback and the like never need a proxy, and sending a webhook for a
// box on the same network through a server in Tokyo would be absurd.
function isLocal(host) {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.lan') || h.endsWith('.home.arpa')) return true;
  const family = net.isIP(h);
  if (!family) return false;
  const list = new net.BlockList();
  list.addSubnet('10.0.0.0', 8); list.addSubnet('172.16.0.0', 12); list.addSubnet('192.168.0.0', 16);
  list.addSubnet('127.0.0.0', 8); list.addSubnet('100.64.0.0', 10);
  list.addAddress('::1', 'ipv6'); list.addSubnet('fc00::', 7, 'ipv6');
  return list.check(h, family === 4 ? 'ipv4' : 'ipv6');
}

function proxyProblem(raw) {
  let u;
  try { u = new URL(raw); } catch { return `OUTBOUND_PROXY=${raw} is not a URL (use http://host:port, socks5://host:port or "active")`; }
  if (!['http:', 'https:', 'socks5:', 'socks5h:', 'socks:'].includes(u.protocol)) {
    return `OUTBOUND_PROXY must be http://, https://, socks5:// or socks5h:// (got ${u.protocol}//)`;
  }
  return null;
}

// What the dashboard shows about this setting, without starting anything.
function describe() {
  const s = setting();
  if (s && s.toLowerCase() === 'off') return { mode: 'off', label: 'direct (OUTBOUND_PROXY=off)' };
  if (s && s.toLowerCase() === 'active') return { mode: 'active', label: 'through ★ (a local sing-box tunnel, started when needed)' };
  if (s) {
    const problem = proxyProblem(s);
    return problem ? { mode: 'invalid', label: problem } : { mode: 'proxy', label: `through ${redact(s)}` };
  }
  const std = env('HTTPS_PROXY') || env('HTTP_PROXY') || env('ALL_PROXY');
  return std ? { mode: 'env', label: `through ${redact(std)} (from the proxy environment variables)` } : { mode: 'direct', label: 'direct' };
}

const redact = (raw) => { try { const u = new URL(raw); if (u.password) u.password = '***'; return u.toString().replace(/\/$/, ''); } catch { return raw; } };

async function proxyFor(target) {
  const host = target.hostname.replace(/^\[|\]$/g, '');
  if (isLocal(host)) return null;
  const s = setting();
  if (s) {
    const lower = s.toLowerCase();
    if (lower === 'off' || lower === 'direct') return null;
    if (lower === 'active') return activeTunnel();
    const problem = proxyProblem(s);
    if (problem) throw new Error(problem);
    return s;
  }
  if (noProxy(host)) return null;
  const std = (target.protocol === 'https:' ? env('HTTPS_PROXY') : env('HTTP_PROXY')) || env('ALL_PROXY');
  if (!std) return null;
  const problem = proxyProblem(std);
  if (problem) throw new Error(problem.replace('OUTBOUND_PROXY', 'the proxy environment variable'));
  return std;
}

// ── The tunnel through ★ ──────────────────────────────────────────────────── //
function keyOf(pick) { return JSON.stringify([pick.profile, pick.relay || null]); }

function scheduleIdle() {
  if (!current) return;
  clearTimeout(current.timer);
  const mine = current;
  mine.timer = setTimeout(() => { if (current === mine) { current = null; mine.tunnel.close(); } }, IDLE_MS);
  if (mine.timer.unref) mine.timer.unref();
}

async function activeTunnel() {
  const pick = activeResolver ? activeResolver() : null;
  if (!pick || !pick.profile) throw new Error('OUTBOUND_PROXY=active, but there is no enabled ★ profile to tunnel through');
  const key = keyOf(pick);
  if (current && current.key === key && current.tunnel.alive()) {
    scheduleIdle();
    return `http://127.0.0.1:${current.tunnel.port}`;
  }
  if (pending && pending.key === key) return pending.promise;
  if (current) { const old = current; current = null; clearTimeout(old.timer); old.tunnel.close(); }
  const promise = (async () => {
    try {
      const tunnel = await require('./probe').startTunnel(pick.profile, { relay: pick.relay || null });
      current = { key, tunnel, timer: null };
      scheduleIdle();
      return `http://127.0.0.1:${tunnel.port}`;
    } catch (err) {
      throw new Error(`OUTBOUND_PROXY=active could not open a tunnel through "${pick.profile.remarks}": ${err.message}`);
    } finally {
      pending = null;
    }
  })();
  pending = { key, promise };
  return promise;
}

function shutdown() {
  if (!current) return Promise.resolve();
  const old = current;
  current = null;
  clearTimeout(old.timer);
  return old.tunnel.close();
}

module.exports = { setActiveResolver, proxyFor, describe, shutdown, isLocal, IDLE_MS };
