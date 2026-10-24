'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { writeFileAtomic } = require('./history');
const versions = new WeakMap();
const digest = (raw) => raw === null ? null : crypto.createHash('sha256').update(raw).digest('hex');
const read = (file) => { try { return fs.readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; } };
function track(store, raw) { versions.set(store, digest(raw)); return store; }
function conflict(message) { return Object.assign(new Error(message), { status: 409 }); }
const backupDir = (file) => `${file}.backups`;
const BACKUP_NAME = /^\d{13}-[a-f0-9]{16}\.enc$/;

// ── Retention ──────────────────────────────────────────────────────────────── //
// Every save takes a snapshot, so "keep the newest 20" alone meant a busy hour
// (a monitor moving ★, hourly source refreshes, a reorder session) pushed every
// older recovery point out, the daily one included. Keep the recent run *and*
// the newest snapshot of each of the last KEEP_DAYS days that have one.
const KEEP_RECENT = 20;
const KEEP_DAYS = 14;

// ── Key fingerprints ───────────────────────────────────────────────────────── //
// A snapshot names the key it was sealed with, so a snapshot sealed under a
// different key (BACKUP_KEY in one process, a key file in another) is reported
// as such in the list rather than discovered as an authentication failure at
// the moment you need to roll back.
const keyId = (key) => crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);

function parseKey(text, label = 'BACKUP_KEY') {
  const key = Buffer.from(String(text || '').trim(), 'base64');
  if (key.length !== 32) throw new Error(`${label} must be a base64-encoded 32-byte key`);
  return key;
}

function keyFor(file) {
  if (process.env.BACKUP_KEY) return parseKey(process.env.BACKUP_KEY);
  const keyFile = `${file}.backup-key`;
  try { return fs.readFileSync(keyFile); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (listBackups(file).length) {
    throw new Error(`Backup key is missing. Restore the original ${path.basename(keyFile)} or set BACKUP_KEY (the same one every writer of this store uses) before saving.`);
  }
  const key = crypto.randomBytes(32);
  try { fs.writeFileSync(keyFile, key, { flag: 'wx', mode: 0o600 }); }
  catch (e) { if (e.code !== 'EEXIST') throw e; return fs.readFileSync(keyFile); }
  return key;
}

// `keyStatus` adds each snapshot's key fingerprint and whether this process can
// open it: true, false, or null for a snapshot written before fingerprints.
function listBackups(file, { keyStatus = false } = {}) {
  let names;
  try { names = fs.readdirSync(backupDir(file)); } catch (e) { if (e.code === 'ENOENT') return []; throw e; }
  const list = names.filter((n) => BACKUP_NAME.test(n)).sort().reverse()
    .flatMap((id) => {
      try { return [{ id, at: Number(id.slice(0, 13)), bytes: fs.statSync(path.join(backupDir(file), id)).size }]; }
      catch (e) { if (e.code === 'ENOENT') return []; throw e; }
    });
  if (!keyStatus || !list.length) return list;
  let current = null;
  let keyError = null;
  try { current = keyId(keyFor(file)); } catch (e) { keyError = e.message; }
  return list.map((b) => {
    let kid = null;
    try { kid = JSON.parse(fs.readFileSync(path.join(backupDir(file), b.id), 'utf8')).kid || null; } catch { /* unreadable envelope */ }
    return { ...b, kid, readable: keyError ? false : (kid ? kid === current : null), ...(keyError ? { keyError } : {}) };
  });
}

function prune(file) {
  const dir = backupDir(file);
  const list = listBackups(file);
  const keep = new Set(list.slice(0, KEEP_RECENT).map((b) => b.id));
  const days = new Set();
  for (const b of list) {
    const day = Math.floor(b.at / 86400000);
    if (days.has(day) || days.size >= KEEP_DAYS) continue;
    days.add(day);
    keep.add(b.id);
  }
  for (const b of list) {
    if (keep.has(b.id)) continue;
    try { fs.unlinkSync(path.join(dir, b.id)); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
}

function seal(raw, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(raw, 'utf8'), cipher.final()]);
  return { version: 1, kid: keyId(key), iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
}

function snapshot(file, raw = read(file)) {
  if (raw === null) return null;
  // Never replace recoverable snapshots with malformed input.
  JSON.parse(raw);
  const dir = backupDir(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const id = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.enc`;
  writeFileAtomic(path.join(dir, id), JSON.stringify(seal(raw, keyFor(file))), 0o600);
  prune(file);
  return id;
}

function backupPath(file, id) {
  if (!BACKUP_NAME.test(String(id))) throw new Error('Invalid backup ID');
  return path.join(backupDir(file), id);
}

// Open a snapshot envelope with a given key. Shared by rollback (this store's
// key) and importing a snapshot file carried over from another machine.
function decryptEnvelope(envelope, key) {
  const b = typeof envelope === 'string' ? JSON.parse(envelope) : envelope;
  if (!b || b.version !== 1) throw new Error('Not an encrypted snapshot this tool wrote (unsupported version)');
  if (b.kid && b.kid !== keyId(key)) {
    throw new Error(`This snapshot was sealed with a different backup key (fingerprint ${b.kid}; the key in use is ${keyId(key)}). `
      + 'Supply the matching key, restore the original .backup-key file, or set BACKUP_KEY.');
  }
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(b.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(b.tag, 'base64'));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(b.data, 'base64')), decipher.final()]).toString('utf8'));
  } catch (err) {
    if (err instanceof SyntaxError) throw new Error('The snapshot decrypted but does not hold a store');
    throw new Error('The snapshot could not be opened with this key — it was sealed with a different one, or the file is damaged.');
  }
}

function decryptBackup(file, id) {
  return decryptEnvelope(fs.readFileSync(backupPath(file, id), 'utf8'), keyFor(file));
}

// The key as text, for keeping somewhere other than beside the snapshots it
// protects: a disk that loses the store loses the key file with it.
function exportKey(file) {
  const key = keyFor(file);
  return { key: key.toString('base64'), fingerprint: keyId(key) };
}

// ── The write lock ─────────────────────────────────────────────────────────── //
// A save holds the lock for milliseconds. One left behind means its writer died
// mid-save — a SIGKILL, a power cut, `docker stop` timing out — and nothing
// used to clear it, so every later write was refused until someone deleted the
// file by hand.
//
// The lock file says who holds it: a random nonce, the PID, the hostname, the
// PID namespace (Linux) and when it was taken. Whether it is stale:
//
//   older than LOCK_STALE_MS            stale, whoever wrote it — no save takes
//                                       anywhere near that long
//   same host and PID namespace         stale when that PID is gone, or is this
//                                       process (saves are synchronous, so a
//                                       lock naming us is a previous process
//                                       that had our PID)
//   anything else                       held until it ages out
//
// The last line is the one that used to be wrong. Two containers sharing /data
// each see the other's PID as a number in their own namespace: kill(pid, 0)
// says ESRCH (or, with both on PID 1, "that is me"), and a lock held at that
// moment by the other container was deleted out from under it. Only a lock we
// can actually check is judged by its PID.
//
// Releasing is guarded the same way: the lock is unlinked only if it still
// carries our nonce. A writer that stalled past LOCK_STALE_MS and was taken
// over used to delete its successor's lock on the way out.
const LOCK_STALE_MS = 30000;

function pidNamespace() {
  try { return fs.readlinkSync('/proc/self/ns/pid'); } catch { return null; }
}

function lockBody(nonce) {
  return JSON.stringify({ nonce, pid: process.pid, host: os.hostname(), ns: pidNamespace(), at: Date.now() });
}

function parseLock(text) {
  try {
    const v = JSON.parse(text);
    return v && typeof v === 'object' && typeof v.nonce === 'string' ? v : null;
  } catch { return null; }
}

// { stale, text } — the text is handed back so a takeover can check the lock
// it is about to delete is still the one it judged.
function inspectLock(lock) {
  let text;
  let st;
  try { st = fs.statSync(lock); text = fs.readFileSync(lock, 'utf8'); } catch (e) { return { stale: e.code === 'ENOENT', text: null }; }
  const at = parseLock(text)?.at;
  // The older of the two clocks we have: the file's own mtime, and the time the
  // holder wrote into it. A lock from a clock running ahead still ages out on
  // its mtime.
  const age = Date.now() - Math.min(st.mtimeMs, Number.isFinite(at) ? at : Infinity);
  if (age > LOCK_STALE_MS) return { stale: true, text };
  const info = parseLock(text);
  // An old-format lock (a bare PID), an empty one (its writer died between
  // creating and filling it) or garbage: no host to compare, so age only.
  if (!info || info.host !== os.hostname() || (info.ns || null) !== pidNamespace()) return { stale: false, text };
  const pid = Number(info.pid);
  if (!Number.isInteger(pid) || pid <= 0) return { stale: false, text };
  if (pid === process.pid) return { stale: true, text };
  // EPERM means it exists and belongs to someone else; only ESRCH is "gone".
  try { process.kill(pid, 0); return { stale: false, text }; } catch (e) { return { stale: e.code === 'ESRCH', text }; }
}

function lockIsStale(lock) { return inspectLock(lock).stale; }

function acquire(lock) {
  const nonce = crypto.randomBytes(16).toString('hex');
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let fd;
    try { fd = fs.openSync(lock, 'wx', 0o600); }
    catch (e) {
      if (e.code !== 'EEXIST') throw e;
      const seen = attempt === 0 ? inspectLock(lock) : { stale: false };
      if (seen.stale) {
        // Only delete the lock we judged. If it changed in between, someone
        // else took it over first, and theirs is not ours to remove.
        if (seen.text === null || read(lock) === seen.text) {
          try { fs.unlinkSync(lock); } catch (err) { if (err.code !== 'ENOENT') throw err; }
        }
        continue;
      }
      throw conflict(`Store is being written by another process. Retry; if it persists, inspect ${lock} for a stopped writer.`);
    }
    // Filled before anything else happens, so a lock is never seen empty by a
    // process that could judge it.
    try { fs.writeFileSync(fd, lockBody(nonce)); } catch (e) { fs.closeSync(fd); try { fs.unlinkSync(lock); } catch { /* gone */ } throw e; }
    return { fd, nonce };
  }
  throw conflict(`Store is being written by another process. Retry; if it persists, inspect ${lock} for a stopped writer.`);
}

function release(lock, held) {
  fs.closeSync(held.fd);
  let text;
  try { text = read(lock); } catch { return; }
  if (text === null || parseLock(text)?.nonce !== held.nonce) return; // taken over: not ours
  try { fs.unlinkSync(lock); } catch { /* already gone */ }
}

function save(file, store) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const lock = `${file}.lock`;
  const held = acquire(lock);
  try {
    const raw = read(file);
    if (!versions.has(store) || versions.get(store) !== digest(raw)) {
      throw conflict('The store changed since it was read. Reload and retry; no changes were overwritten.');
    }
    const next = JSON.stringify(store, null, 2);
    if (raw === next) return;
    snapshot(file, raw);
    writeFileAtomic(file, next, 0o600);
    track(store, next);
  } finally { release(lock, held); }
}

function dailySnapshot(file) {
  const last = listBackups(file)[0];
  if (!last || Date.now() - last.at >= 86400000) snapshot(file);
}

module.exports = {
  KEEP_RECENT, KEEP_DAYS, LOCK_STALE_MS,
  track, read, digest, save, snapshot, dailySnapshot, listBackups,
  decryptBackup, decryptEnvelope, backupPath, exportKey, keyId, parseKey, lockIsStale, inspectLock,
};
