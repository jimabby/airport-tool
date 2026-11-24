// ── Servers deploy.sh has set up ───────────────────────────────────────────── //
// A profile says how a *client* reaches a server. Looking after the server
// itself — `--doctor`, `--upgrade`, moving it to a new VPS — needs how *you*
// reach it: the ssh login, port, key and jump host. deploy.sh records those
// here (store.hosts) when it sets a server up, so `deploy.sh --all --doctor`
// can visit every one of them without being told again, and the dashboard can
// show what the last check found.
//
// Every field ends up on an ssh command line on your own computer, and the
// store can arrive from a restored backup, so each one is checked rather than
// trusted. `-o` options above all: `ProxyCommand` and `LocalCommand` run
// arbitrary local commands, so only options from an allow-list are kept.

const crypto = require('crypto');

const MAX_HOSTS = 100;

// ssh -o options that only change how the connection is made. Anything that
// can run a command (ProxyCommand, LocalCommand, KnownHostsCommand), pull in
// other config (Include, Match) or forward something (LocalForward, …) is not
// on it.
const SAFE_SSH_OPTIONS = new Set([
  'stricthostkeychecking', 'userknownhostsfile', 'hostkeyalias', 'connecttimeout',
  'connectionattempts', 'serveraliveinterval', 'serveralivecountmax', 'identitiesonly',
  'addressfamily', 'compression', 'tcpkeepalive', 'preferredauthentications',
  'pubkeyauthentication', 'passwordauthentication', 'batchmode', 'loglevel',
]);

// user@host. The host may be a name, an IPv4 address or a bracket-less IPv6
// one, as ssh takes it. Nothing may start with "-", or ssh would read it as an
// option.
const TARGET_RE = /^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}@[A-Za-z0-9._:][A-Za-z0-9._:-]{0,252}$/;
// [user@]host[:port], comma-separated for a chain of jumps.
const JUMP_RE = /^(?:[A-Za-z0-9._][A-Za-z0-9._-]{0,63}@)?[A-Za-z0-9._\[\]:][A-Za-z0-9._\[\]:-]{0,252}(?:,(?:[A-Za-z0-9._][A-Za-z0-9._-]{0,63}@)?[A-Za-z0-9._\[\]:][A-Za-z0-9._\[\]:-]{0,252})*$/;

function targetProblem(t) {
  return TARGET_RE.test(String(t || '')) ? null : `"${t}" is not a USER@HOST ssh login`;
}

function jumpProblem(j) {
  return !j || (JUMP_RE.test(j) && j.length <= 512) ? null : `"${j}" is not a jump host ([USER@]HOST[:PORT])`;
}

function optionProblem(o) {
  const m = /^([A-Za-z]+)=(.*)$/.exec(String(o || ''));
  if (!m) return `"${o}" is not an ssh option of the form Name=value`;
  if (!SAFE_SSH_OPTIONS.has(m[1].toLowerCase())) return `ssh option ${m[1]} is not one deploy.sh will remember (only connection options are; some others run commands on this computer)`;
  if (!/^[^\s'"`$\\;|&<>]{1,256}$/.test(m[2])) return `ssh option ${m[1]} has a value deploy.sh will not remember: "${m[2]}"`;
  return null;
}

function normalizeHost(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const target = String(raw.target || '').trim();
  if (targetProblem(target)) return null;
  const out = {
    id: typeof raw.id === 'string' && /^[0-9a-f-]{36}$/i.test(raw.id) ? raw.id.toLowerCase() : crypto.randomUUID(),
    target,
  };
  const port = Number(raw.port);
  if (Number.isInteger(port) && port > 0 && port < 65536 && port !== 22) out.port = port;
  // A path on the computer deploy.sh ran on. Only shown and handed back to
  // ssh as -i; never opened here.
  const key = typeof raw.key === 'string' ? raw.key.trim() : '';
  if (key && key.length <= 1024 && !/[\r\n\0]/.test(key) && !key.startsWith('-')) out.key = key;
  const jump = typeof raw.jump === 'string' ? raw.jump.trim() : '';
  if (jump && !jumpProblem(jump)) out.jump = jump;
  const options = Array.isArray(raw.options) ? [...new Set(raw.options.map((o) => String(o).trim()))].filter((o) => !optionProblem(o)) : [];
  if (options.length) out.options = options.slice(0, 10);
  // The addresses its profiles give clients — how a host and its profiles are
  // matched, and what a move to a new server re-points.
  const addrs = Array.isArray(raw.addresses) ? raw.addresses : [];
  out.addresses = [...new Set(addrs.map((a) => String(a || '').trim().toLowerCase()))]
    .filter((a) => a && a.length <= 253 && /^[a-z0-9.:_-]+$/.test(a)).slice(0, 16);
  const at = Number(raw.deployedAt);
  if (Number.isFinite(at) && at > 0) out.deployedAt = Math.round(at);
  return out;
}

function normalizeHosts(raw) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const out = [];
  for (const h of raw.map(normalizeHost)) {
    if (!h || seen.has(h.target.toLowerCase()) || seen.has(h.id)) continue;
    seen.add(h.target.toLowerCase()); seen.add(h.id);
    out.push(h);
    if (out.length >= MAX_HOSTS) break;
  }
  return out;
}

// The server addresses in whatever setup.sh --show --json (or any import
// text) describes. Read with the same parser an import uses.
function addressesIn(text) {
  const C = require('./configs');
  const body = String(text || '').trim();
  let profiles = [];
  if (body.startsWith('{') || body.startsWith('[')) {
    try {
      const json = JSON.parse(body);
      const list = Array.isArray(json) ? json : (json && Array.isArray(json.profiles) ? json.profiles : [json]);
      profiles = list.map(C.normalizeProfile);
    } catch { profiles = []; }
  } else if (body) {
    profiles = C.parseSubscription(body).profiles;
  }
  return [...new Set(profiles.map((p) => String(p.server || '').trim().toLowerCase()).filter(Boolean))];
}

// Add or update the record for `fields.target`. `replaces` names a login whose
// record goes (the old server, after a move). Returns the record.
function recordHost(store, fields, { replaces } = {}) {
  const problem = targetProblem(fields.target) || jumpProblem(fields.jump);
  if (problem) throw Object.assign(new Error(problem), { status: 400 });
  const rejected = (fields.options || []).map(optionProblem).filter(Boolean);
  const hosts = normalizeHosts(store.hosts);
  const lower = String(fields.target).toLowerCase();
  const existing = hosts.find((h) => h.target.toLowerCase() === lower);
  // The connection is taken whole from this deploy, never merged with the last
  // one's: a port or key left off this time is how the server was reached
  // this time. Only the id (which the doctor results are filed under) and,
  // when this run read none, the addresses carry over.
  const next = normalizeHost({
    target: fields.target,
    port: fields.port,
    key: fields.key,
    jump: fields.jump,
    options: fields.options,
    id: existing ? existing.id : undefined,
    addresses: fields.addresses && fields.addresses.length ? fields.addresses : (existing ? existing.addresses : []),
    deployedAt: Date.now(),
  });
  const gone = replaces ? String(replaces).toLowerCase() : null;
  store.hosts = hosts.filter((h) => h.target.toLowerCase() !== lower && (!gone || h.target.toLowerCase() !== gone));
  store.hosts.push(next);
  return { host: next, rejected };
}

function findHost(store, target) {
  const lower = String(target || '').toLowerCase();
  return normalizeHosts(store.hosts).find((h) => h.target.toLowerCase() === lower || h.id === lower) || null;
}

function forgetHost(store, idOrTarget) {
  const lower = String(idOrTarget || '').toLowerCase();
  const before = normalizeHosts(store.hosts);
  store.hosts = before.filter((h) => h.id !== lower && h.target.toLowerCase() !== lower);
  return before.length !== store.hosts.length;
}

// ── What a `setup.sh --doctor` run found ───────────────────────────────────── //
// The report is for people: "── reality" section headers, then ✓ / ✗ / •
// lines. This keeps what the dashboard needs — the failures and the notes,
// labelled by section — and whether the run as a whole passed.
const LINE_MAX = 300;
const LIST_MAX = 40;

function parseDoctor(text, exitCode) {
  const lines = String(text || '').replace(/\x1b\[[0-9;]*m/g, '').replace(/\r/g, '').split('\n');
  let section = '';
  let passed = 0;
  const failures = [];
  const notes = [];
  for (const raw of lines) {
    const line = raw.trim();
    const head = /^──\s*(.+)$/.exec(line);
    if (head) { section = head[1].trim(); continue; }
    const m = /^([✓✗•])\s+(.*)$/.exec(line);
    if (!m) continue;
    const said = `${section ? `${section}: ` : ''}${m[2]}`.slice(0, LINE_MAX);
    if (m[1] === '✓') passed += 1;
    else if (m[1] === '✗') { if (failures.length < LIST_MAX) failures.push(said); }
    else if (notes.length < LIST_MAX) notes.push(said);
  }
  const code = Number.isInteger(Number(exitCode)) ? Number(exitCode) : null;
  const out = { at: Date.now(), ok: code === 0 && failures.length === 0, exitCode: code, passed, failures, notes };
  // No report at all: ssh never got there, or setup.sh stopped before it began.
  // The last thing said is the most useful line to keep.
  if (!passed && !failures.length && !notes.length) {
    const last = lines.map((l) => l.trim()).filter(Boolean).pop() || `no report (exit ${code})`;
    out.ok = false;
    out.error = last.slice(0, LINE_MAX);
  }
  return out;
}

function normalizeDoctorState(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  for (const [id, r] of Object.entries(raw)) {
    if (!/^[0-9a-f-]{36}$/i.test(id) || !r || typeof r !== 'object') continue;
    const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string').map((x) => x.slice(0, LINE_MAX)).slice(0, LIST_MAX) : []);
    out[id] = {
      at: Number(r.at) || 0,
      ok: r.ok === true,
      exitCode: Number.isInteger(r.exitCode) ? r.exitCode : null,
      passed: Number(r.passed) || 0,
      failures: list(r.failures),
      notes: list(r.notes),
      ...(typeof r.error === 'string' ? { error: r.error.slice(0, LINE_MAX) } : {}),
    };
  }
  return out;
}

module.exports = {
  MAX_HOSTS,
  SAFE_SSH_OPTIONS,
  targetProblem,
  jumpProblem,
  optionProblem,
  normalizeHost,
  normalizeHosts,
  addressesIn,
  recordHost,
  findHost,
  forgetHost,
  parseDoctor,
  normalizeDoctorState,
};
