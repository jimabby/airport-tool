// Pushing an encrypted snapshot of the store somewhere other than this disk.
//
// The snapshots beside servers.json protect against a bad edit; they do not
// protect against the disk, the laptop or the container volume going away —
// and losing servers.json means rebuilding every server, because setup.sh
// cannot reproduce a password it already minted. This sends a fresh snapshot
// (the same AES-256-GCM envelope `Download encrypted snapshot` gives you) to a
// WebDAV folder or a webhook on a schedule. The backup key never leaves the
// machine: keep a copy of it apart from both (`Download key`).
//
// Shared by the dashboard (scheduled, plus a "Push now" button) and
// `gen.js --push-backup`, and both record the outcome in monitor-state.json.

'use strict';

const fs = require('fs');
const C = require('./configs');
const B = require('./storage');
const H = require('./history');

const RETRY_MS = 15 * 60000;

function authHeader(auth) {
  const a = String(auth || '').trim();
  if (!a) return {};
  // "Bearer …", "Basic …" or any other scheme is sent as written; a bare
  // "user:password" is what WebDAV servers want, as Basic; anything else is a
  // token.
  if (/\s/.test(a)) return { Authorization: a };
  if (a.includes(':')) return { Authorization: `Basic ${Buffer.from(a).toString('base64')}` };
  return { Authorization: `Bearer ${a}` };
}

const redact = (url) => { try { const u = new URL(url); u.search = u.search ? '?…' : ''; return u.toString(); } catch { return ''; } };

// Whether a scheduled push is due, given the stored settings and the last
// outcome recorded in monitor-state.json.
function isDue(cfg, last, now = Date.now()) {
  if (!cfg || !cfg.enabled || !cfg.url) return false;
  if (!last || !last.at) return true;
  if (!last.ok) return now - last.at >= RETRY_MS;
  return now - last.at >= cfg.everyHours * 3600000;
}

// Take a snapshot of the store as it is now and push it. Never throws; the
// result is also written to the state file. `force` pushes even when nothing
// changed since the last successful push.
async function push(cfgPath, backupCfg, { force = false, statePath = H.statePathFor(cfgPath) } = {}) {
  const cfg = C.normalizeRemoteBackup(backupCfg);
  const record = (r) => {
    H.updateState(statePath, (s) => { s.remoteBackup = { ...r, url: redact(cfg.url) }; });
    return r;
  };
  if (!cfg.url) return { ok: false, at: Date.now(), error: 'no backup URL is set' };
  let raw;
  try { raw = B.read(cfgPath); } catch (err) { return record({ ok: false, at: Date.now(), error: err.message }); }
  if (raw === null) return record({ ok: false, at: Date.now(), error: 'there is no store to back up yet' });
  const digest = B.digest(raw);
  const last = H.loadState(statePath).remoteBackup;
  if (!force && last && last.ok && last.digest === digest) {
    // Nothing changed: say so, and count it as this period's push.
    return record({ ...last, at: Date.now(), unchanged: true });
  }
  let id;
  let envelope;
  try {
    id = B.snapshot(cfgPath, raw);
    envelope = fs.readFileSync(B.backupPath(cfgPath, id), 'utf8');
  } catch (err) {
    return record({ ok: false, at: Date.now(), error: `could not seal a snapshot: ${err.message}` });
  }
  const headers = { 'Content-Type': 'application/json', 'User-Agent': 'airport-tool', ...authHeader(cfg.auth) };
  const target = cfg.mode === 'put' ? `${cfg.url.replace(/\/+$/, '')}/${id}` : cfg.url;
  const body = cfg.mode === 'put'
    ? envelope
    : JSON.stringify({ name: id, at: Date.now(), kid: JSON.parse(envelope).kid || null, snapshot: JSON.parse(envelope) });
  try {
    const res = await require('./network').request(target, { method: cfg.mode === 'put' ? 'PUT' : 'POST', headers, body, timeoutMs: 30000, maxBytes: 65536 });
    if (!res.ok) {
      const why = res.status === 401 || res.status === 403 ? ' — check the credentials' : (res.status >= 300 && res.status < 400 ? ' — redirects are not followed; use the final URL' : '');
      return record({ ok: false, at: Date.now(), status: res.status, id, error: `the server answered ${res.status}${why}` });
    }
    return record({ ok: true, at: Date.now(), status: res.status, id, digest, bytes: Buffer.byteLength(body) });
  } catch (err) {
    return record({ ok: false, at: Date.now(), id, error: err.message });
  }
}

module.exports = { push, isDue, authHeader, RETRY_MS };
