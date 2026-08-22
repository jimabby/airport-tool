// Probe history: how each server has behaved over the last few checks.
//
// It lives in its own file, beside the profile store rather than inside it.
// The samples are written on every probe, and churning a file full of
// credentials that often is a good way to eventually lose it.
//
// Shared by the web UI and `gen.js --test` so a probe from either shows up in
// the other's history.

'use strict';

const fs = require('fs');
const path = require('path');

// Write through a temporary file and rename over the target: a write that dies
// halfway - power cut, disk full, Ctrl-C - would otherwise leave a truncated
// file behind.
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

// Where the history sits, given the profile store's path.
function historyPathFor(cfgPath) {
  return process.env.HISTORY_PATH || path.join(path.dirname(cfgPath), 'test-history.json');
}

// ── Probe history (separate, non-secret file) ───────────────────────────────── //
const HISTORY_LIMIT = 30;

function loadHistory(histPath) {
  try {
    const parsed = JSON.parse(fs.readFileSync(histPath, 'utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    // A missing or corrupt history file is not worth failing a request over —
    // it caches latency numbers, not anything that can't be re-measured.
    return {};
  }
}

function recordHistory(histPath, entries) {
  const hist = loadHistory(histPath);
  const at = Date.now();
  for (const e of entries) {
    if (!e || !e.id) continue;
    const list = Array.isArray(hist[e.id]) ? hist[e.id] : [];
    list.push({ at, ok: e.ok, latencyMs: e.latencyMs, stage: e.stage });
    hist[e.id] = list.slice(-HISTORY_LIMIT);
  }
  try { writeFileAtomic(histPath, JSON.stringify(hist), 0o600); } catch { /* best effort */ }
  return hist;
}

// Drop samples belonging to profiles that no longer exist. Without this a
// deleted profile's latency history sat in the file forever, and every restore
// from a backup piled another set of orphans on top.
function pruneHistory(histPath, store) {
  const keep = new Set(store.profiles.map((p) => p.id));
  const hist = loadHistory(histPath);
  const stale = Object.keys(hist).filter((id) => !keep.has(id));
  if (!stale.length) return;
  for (const id of stale) delete hist[id];
  try { writeFileAtomic(histPath, JSON.stringify(hist), 0o600); } catch { /* best effort */ }
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
    // Probes that returned ok:null never asked the question, so they are
    // reported separately rather than folded into a success rate that would
    // otherwise read as "null% up" in the dashboard.
    attempted: attempted.length,
    lastAt: samples.length ? samples[samples.length - 1].at : null,
    lastOk: samples.length ? samples[samples.length - 1].ok : null,
    bestMs: timed.length ? Math.min(...timed.map((s) => s.latencyMs)) : null,
    avgMs: timed.length ? Math.round(timed.reduce((a, s) => a + s.latencyMs, 0) / timed.length) : null,
    successRate: attempted.length
      ? Math.round((attempted.filter((s) => s.ok === true).length / attempted.length) * 100)
      : null,
  };
}

module.exports = {
  HISTORY_LIMIT,
  writeFileAtomic,
  historyPathFor,
  loadHistory,
  recordHistory,
  pruneHistory,
  summarizeHistory,
};
