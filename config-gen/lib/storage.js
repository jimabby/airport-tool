'use strict';

const fs = require('fs');
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
// file by hand. A lock is taken over when the PID it names is gone (or is this
// process: saves are synchronous, so it cannot be ours unless a previous
// process had the same PID — every container's node is PID 1), or when it has
// sat there far longer than any save takes.
const LOCK_STALE_MS = 30000;

function lockIsStale(lock) {
  let text;
  let st;
  try { st = fs.statSync(lock); text = fs.readFileSync(lock, 'utf8').trim(); } catch (e) { return e.code === 'ENOENT'; }
  if (Date.now() - st.mtimeMs > LOCK_STALE_MS) return true;
  if (!/^\d+$/.test(text)) return false;
  const pid = Number(text);
  if (pid === process.pid) return true;
  try { process.kill(pid, 0); return false; } catch (e) { return e.code === 'ESRCH'; }
}

function acquire(lock) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try { return fs.openSync(lock, 'wx', 0o600); }
    catch (e) {
      if (e.code !== 'EEXIST') throw e;
      if (attempt === 0 && lockIsStale(lock)) {
        try { fs.unlinkSync(lock); } catch (err) { if (err.code !== 'ENOENT') throw err; }
        continue;
      }
      throw conflict(`Store is being written by another process. Retry; if it persists, inspect ${lock} for a stopped writer.`);
    }
  }
  throw conflict(`Store is being written by another process. Retry; if it persists, inspect ${lock} for a stopped writer.`);
}

function save(file, store) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const lock = `${file}.lock`;
  const fd = acquire(lock);
  try {
    fs.writeFileSync(fd, String(process.pid));
    const raw = read(file);
    if (!versions.has(store) || versions.get(store) !== digest(raw)) {
      throw conflict('The store changed since it was read. Reload and retry; no changes were overwritten.');
    }
    const next = JSON.stringify(store, null, 2);
    if (raw === next) return;
    snapshot(file, raw);
    writeFileAtomic(file, next, 0o600);
    track(store, next);
  } finally { fs.closeSync(fd); try { fs.unlinkSync(lock); } catch { /* already taken over */ } }
}

function dailySnapshot(file) {
  const last = listBackups(file)[0];
  if (!last || Date.now() - last.at >= 86400000) snapshot(file);
}

module.exports = {
  KEEP_RECENT, KEEP_DAYS, LOCK_STALE_MS,
  track, read, digest, save, snapshot, dailySnapshot, listBackups,
  decryptBackup, decryptEnvelope, backupPath, exportKey, keyId, parseKey, lockIsStale,
};
