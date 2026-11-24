// Probe history: how each server has behaved over the last few checks.
//
// It lives in its own file, beside the profile store rather than inside it.
// The samples are written on every probe, and churning a file full of
// credentials that often is a good way to eventually lose it.
//
// Shared by the web UI and `gen.js --test` so a probe from either shows up in
// the other's history.

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const C = require('./configs');

// Write through a temporary file and rename over the target: a write that dies
// halfway - power cut, disk full, Ctrl-C - would otherwise leave a truncated
// file behind.
//
// The temp name carries a random suffix as well as the PID. The PID alone is
// not unique: every container's node is PID 1, and two containers sharing
// /data (or a dashboard and a `docker compose exec … gen.js`) would otherwise
// write the same temp file at the same moment and rename each other's
// half-written bytes into place. 'wx' makes a collision an error rather than a
// silent share.
function writeFileAtomic(file, data, mode) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  const fd = fs.openSync(tmp, 'wx', mode);
  try {
    try {
      fs.writeFileSync(fd, data, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    // chmod is a no-op on Windows; ignore its errors there.
    try { fs.chmodSync(tmp, mode); } catch { /* unsupported filesystem/platform */ }
    fs.renameSync(tmp, file);
  } catch (err) {
    // A disk-full write must not leave a temp file full of credentials behind.
    try { fs.unlinkSync(tmp); } catch { /* never created, or already renamed */ }
    throw err;
  }
}

// Where the history sits, given the profile store's path.
function historyPathFor(cfgPath) {
  return process.env.HISTORY_PATH || path.join(path.dirname(cfgPath), 'test-history.json');
}

// ── Monitor state (separate, non-secret file) ───────────────────────────────── //
// Two things used to live only in the dashboard process's memory: which alert
// state was last notified about, and when each device token last pulled the
// subscription. Both reset on every restart — so a restart re-sent an alert
// that had already gone out, and a device that had been polling for months
// read as "never seen".
//
// They do not belong in the profile store (that file holds every credential and
// should be written as rarely as possible) and they do not belong in the probe
// history (pruneHistory() deletes every key that is not a profile id, which
// would eat them). So: their own file, beside the other two.
function statePathFor(cfgPath) {
  return process.env.MONITOR_STATE_PATH || path.join(path.dirname(cfgPath), 'monitor-state.json');
}

const emptyState = () => ({ alertState: null, downStreak: 0, clients: {}, notices: {}, remoteBackup: null, doctor: {} });
const plainObject = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

function loadState(statePath) {
  try {
    const parsed = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return emptyState();
    const streak = Number(parsed.downStreak);
    return {
      alertState: typeof parsed.alertState === 'string' ? parsed.alertState : null,
      // How many consecutive passes have found something wrong. Persisted for
      // the same reason alertState is: a restart used to reset it, which turned
      // every deploy into a fresh grace period and delayed the alert that the
      // threshold was only ever meant to debounce.
      downStreak: Number.isFinite(streak) && streak >= 0 ? Math.round(streak) : 0,
      clients: plainObject(parsed.clients),
      // Heads-up notices (certificate, plan expiry, quota) already delivered,
      // by key, so each goes out once. See alert.notices().
      notices: plainObject(parsed.notices),
      // The last off-machine backup push, written by whichever of the two
      // processes made it. See remote-backup.js.
      remoteBackup: parsed.remoteBackup && typeof parsed.remoteBackup === 'object' && !Array.isArray(parsed.remoteBackup)
        ? parsed.remoteBackup : null,
      // What the last `deploy.sh --doctor` found on each server, by host id.
      // Written by hosts.js for deploy.sh; see lib/hosts.js.
      doctor: require('./hosts').normalizeDoctorState(parsed.doctor),
    };
  } catch {
    // Same reasoning as the history file: a missing or corrupt one costs a
    // duplicate alert, not anything that cannot be re-derived.
    return emptyState();
  }
}

// 0600 because the last-seen records carry User-Agent strings, which say more
// about your devices than they look like they do. Best effort, but it says
// whether the write landed: a caller that trusts the file over its own memory
// has to know when the file did not keep up.
function saveState(statePath, state) {
  try {
    writeFileAtomic(statePath, JSON.stringify({
      alertState: state.alertState || null,
      downStreak: Number.isFinite(state.downStreak) ? state.downStreak : 0,
      clients: state.clients || {},
      notices: state.notices || {},
      remoteBackup: state.remoteBackup || null,
      doctor: state.doctor || {},
    }), 0o600);
    return true;
  } catch { return false; }
}

// Read-modify-write of the state file, for a writer that only owns some of it.
//
// Two processes share this file: the dashboard (device last-seen, its own
// alert state and notices) and `gen.js --test --alert` from cron (alert state,
// streak, notices). A writer that loads the state, waits seconds on a webhook
// and then saves what it loaded puts back every field as it was before the
// wait — erasing whichever devices the dashboard saw in between. `mutate`
// receives the state as it is on disk *now* and changes only the fields its
// caller decided; the load and the save are one synchronous step, so nothing
// in this process can interleave, and another process has a window of
// microseconds rather than the length of an HTTP request.
function updateState(statePath, mutate) {
  const state = loadState(statePath);
  mutate(state);
  // Non-enumerable, so a caller that serialises the state never writes it.
  Object.defineProperty(state, 'saved', { value: saveState(statePath, state), enumerable: false });
  return state;
}

// ── Probe history (separate, non-secret file) ───────────────────────────────── //
const HISTORY_LIMIT = 30;

// How many samples summarizeHistory hands back for the dashboard's sparkline.
// Fewer than HISTORY_LIMIT because this rides along on every /api/config poll,
// and twenty points is already more than 120 pixels of chart can distinguish.
const SPARK_LIMIT = 20;

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

// load → mutate → write is synchronous end to end here, so nothing else in this
// process can interleave with it. Two *processes* can (the dashboard and
// `gen.js --test` at the same moment), and the loser's batch of samples is
// dropped. That is deliberately not locked against: these are latency numbers
// that the next probe re-measures, and a lock file left behind by a killed
// process would cost more than the samples it saved.
function recordHistory(histPath, entries) {
  const hist = loadHistory(histPath);
  const at = Date.now();
  for (const e of entries) {
    if (!e || !e.id) continue;
    const list = Array.isArray(hist[e.id]) ? hist[e.id] : [];
    const sample = { at, ok: e.ok, latencyMs: e.latencyMs, stage: e.stage };
    // Keep the certificate's expiry with the sample that observed it, so the
    // dashboard can still say "expires in 9 days" on a page load that has not
    // probed anything yet. Only the date is kept — the subject and issuer are
    // re-read on the next probe and would just bloat a file we rewrite often.
    if (e.cert && Number.isFinite(e.cert.notAfter)) {
      sample.certNotAfter = e.cert.notAfter;
      sample.certSelfSigned = !!e.cert.selfSigned;
      if (e.certOf) sample.certOf = e.certOf;
    }
    list.push(sample);
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
//
// The expiry threshold comes from configs.js so the dashboard, the CLI and
// `setup.sh --show` cannot disagree about when to start worrying.
const { CERT_WARN_DAYS } = C;

function summarizeHistory(list) {
  const samples = Array.isArray(list) ? list : [];
  const timed = samples.filter((s) => s.ok === true && Number.isFinite(s.latencyMs));
  const attempted = samples.filter((s) => s.ok !== null);
  // The most recent sample that actually saw a certificate — not necessarily
  // the most recent sample, since a deep probe never observes one.
  const withCert = samples.filter((s) => Number.isFinite(s.certNotAfter));
  const lastCert = withCert.length ? withCert[withCert.length - 1] : null;
  const daysLeft = lastCert ? Math.floor((lastCert.certNotAfter - Date.now()) / 86400000) : null;
  return {
    samples: samples.length,
    // The last few probes, for the dashboard's sparkline. One probe is weather;
    // the shape of the last twenty is the thing that tells you a server has been
    // getting steadily worse rather than having one bad morning.
    recent: samples.slice(-SPARK_LIMIT).map((s) => ({
      at: s.at, ok: s.ok, latencyMs: Number.isFinite(s.latencyMs) ? s.latencyMs : null,
    })),
    cert: lastCert ? {
      notAfter: lastCert.certNotAfter,
      daysLeft,
      expired: daysLeft < 0,
      expiring: daysLeft >= 0 && daysLeft <= CERT_WARN_DAYS,
      selfSigned: !!lastCert.certSelfSigned,
      of: lastCert.certOf || 'server',
      seenAt: lastCert.at,
    } : null,
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

// ── Reports from probe agents elsewhere ─────────────────────────────────────── //
// Every probe here runs from wherever this process runs — typically outside
// China, where a server whose address the firewall has blocked still answers
// perfectly. `gen.js --agent <subscription URL>` on a machine *inside* China
// probes the servers that subscription carries and posts the results back;
// the latest report from each agent lives here, keyed by the device token it
// used. Not secret, rewritten on every report, and re-derived by the next one,
// so a lost file costs nothing.
const VANTAGE_RESULTS_MAX = 200;

function vantagePathFor(cfgPath) {
  return process.env.VANTAGE_PATH || path.join(path.dirname(cfgPath), 'vantage.json');
}

function loadVantage(vantagePath) {
  try {
    const parsed = JSON.parse(fs.readFileSync(vantagePath, 'utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch { return {}; }
}

// One agent's report, replacing its previous one. `results` are checked and
// trimmed here: they come over the network from a device token.
function recordVantage(vantagePath, reporter, { results, deep = false, agent = '' } = {}) {
  const clean = (Array.isArray(results) ? results : []).slice(0, VANTAGE_RESULTS_MAX).flatMap((r) => {
    if (!r || typeof r !== 'object' || !C.isUuid(r.id)) return [];
    const ok = r.ok === true ? true : r.ok === false ? false : null;
    const latency = Number(r.latencyMs);
    return [{
      id: r.id,
      ok,
      latencyMs: Number.isFinite(latency) && latency >= 0 ? Math.round(latency) : null,
      stage: typeof r.stage === 'string' ? r.stage.slice(0, 20) : '',
      message: typeof r.message === 'string' ? r.message.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 300) : '',
    }];
  });
  const all = loadVantage(vantagePath);
  all[reporter.id] = {
    name: String(reporter.name || 'Agent').slice(0, 60),
    at: Date.now(),
    deep: deep === true,
    agent: String(agent || '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 120),
    results: clean,
  };
  try { writeFileAtomic(vantagePath, JSON.stringify(all), 0o600); } catch { /* best effort */ }
  return all[reporter.id];
}

// Drop the reports of agents whose token no longer exists.
function pruneVantage(vantagePath, keepIds) {
  const all = loadVantage(vantagePath);
  const keep = new Set(keepIds);
  const stale = Object.keys(all).filter((id) => !keep.has(id));
  if (!stale.length) return;
  for (const id of stale) delete all[id];
  try { writeFileAtomic(vantagePath, JSON.stringify(all), 0o600); } catch { /* best effort */ }
}

module.exports = {
  VANTAGE_RESULTS_MAX,
  vantagePathFor,
  loadVantage,
  recordVantage,
  pruneVantage,
  HISTORY_LIMIT,
  SPARK_LIMIT,
  CERT_WARN_DAYS,
  writeFileAtomic,
  historyPathFor,
  statePathFor,
  loadState,
  saveState,
  updateState,
  loadHistory,
  recordHistory,
  pruneHistory,
  summarizeHistory,
};
