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
function keyFor(file) {
  if (process.env.BACKUP_KEY) {
    const key = Buffer.from(process.env.BACKUP_KEY, 'base64');
    if (key.length !== 32) throw new Error('BACKUP_KEY must be a base64-encoded 32-byte key');
    return key;
  }
  const keyFile = `${file}.backup-key`;
  try { return fs.readFileSync(keyFile); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (listBackups(file).length) throw new Error('Backup key is missing. Restore the original .backup-key file or set BACKUP_KEY before saving.');
  const key = crypto.randomBytes(32);
  try { fs.writeFileSync(keyFile, key, { flag: 'wx', mode: 0o600 }); }
  catch (e) { if (e.code !== 'EEXIST') throw e; return fs.readFileSync(keyFile); }
  return key;
}
function listBackups(file) {
  let names;
  try { names = fs.readdirSync(backupDir(file)); } catch (e) { if (e.code === 'ENOENT') return []; throw e; }
  return names.filter((n) => /^\d{13}-[a-f0-9]{16}\.enc$/.test(n)).sort().reverse()
    .flatMap((id) => {
      try { return [{ id, at: Number(id.slice(0, 13)), bytes: fs.statSync(path.join(backupDir(file), id)).size }]; }
      catch (e) { if (e.code === 'ENOENT') return []; throw e; }
    });
}
function snapshot(file, raw = read(file)) {
  if (raw === null) return null;
  // Never replace recoverable snapshots with malformed input.
  JSON.parse(raw);
  const dir = backupDir(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyFor(file), iv);
  const data = Buffer.concat([cipher.update(raw, 'utf8'), cipher.final()]);
  const id = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.enc`;
  writeFileAtomic(path.join(dir, id), JSON.stringify({ version: 1, iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') }), 0o600);
  for (const old of listBackups(file).slice(20)) {
    try { fs.unlinkSync(path.join(dir, old.id)); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  return id;
}
function backupPath(file, id) {
  if (!/^\d{13}-[a-f0-9]{16}\.enc$/.test(String(id))) throw new Error('Invalid backup ID');
  return path.join(backupDir(file), id);
}
function decryptBackup(file, id) {
  const b = JSON.parse(fs.readFileSync(backupPath(file, id), 'utf8'));
  if (b.version !== 1) throw new Error('Unsupported backup version');
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyFor(file), Buffer.from(b.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(b.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(b.data, 'base64')), decipher.final()]).toString('utf8'));
}
function save(file, store) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const lock = `${file}.lock`;
  let fd;
  try { fd = fs.openSync(lock, 'wx', 0o600); }
  catch (e) { if (e.code === 'EEXIST') throw conflict(`Store is being written by another process. Retry; if it persists, inspect ${lock} for a stopped writer.`); throw e; }
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
  } finally { fs.closeSync(fd); fs.unlinkSync(lock); }
}
function dailySnapshot(file) {
  const last = listBackups(file)[0];
  if (!last || Date.now() - last.at >= 86400000) snapshot(file);
}
module.exports = { track, read, digest, save, snapshot, dailySnapshot, listBackups, decryptBackup, backupPath };
