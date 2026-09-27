#!/usr/bin/env node
// Generates client config files + QR codes for all configured server profiles.
// Supports Shadowsocks (v2ray-plugin), VLESS + Reality (tcp/grpc/xhttp),
// Hysteria2, TUIC v5, Trojan and VMess.
//
// Outputs, all into output/: clash-config.yaml, singbox-config.json,
// surge.conf, quantumultx.conf, subscription-base64.txt, uris.txt,
// active-uri.txt, qrcode.png and summary.json.
//
// Usage:
//   node gen.js [--config servers.json]
//   node gen.js --add "vless://…"                 import a share link, then generate
//   node gen.js --add /etc/airport-tool/profile.json   import setup.sh's output
//   node gen.js --add -                           import whatever is on stdin
//   node gen.js --export backup.json              write a copy of the store and stop
//   node gen.js --test [--deep] [--json] [--alert]   probe every server and stop
//
// --export exists because setup.sh cannot reproduce a password it generated
// once: if servers.json is lost, so are those servers.
//
// --test runs the same probes as the web UI's Test All button and files the
// results in the same test-history.json, so the two agree about which servers
// are up. --deep dials through each server with a local sing-box, which is the
// only check that proves the credentials work — and the only one that means
// anything at all for the QUIC protocols.
//
// --alert POSTs the result to the webhook configured under monitor.alert, so a
// cron entry can do the job the dashboard's health monitor does without the
// dashboard having to be running. Like the monitor it speaks on a transition
// rather than on every run, and holds a transition back until it has repeated
// `monitor.alert.afterFailures` times; both the last state and the current
// failure streak live in monitor-state.json beside the store, so a cron probe
// and the dashboard cannot disagree about either.

const fs   = require('fs');
const path = require('path');
const QRCode = require('qrcode');
const C = require('./lib/configs');
const P = require('./lib/probe');
const H = require('./lib/history');
const A = require('./lib/alert');
const K = require('./lib/clients');

// ── Load config ────────────────────────────────────────────────────────────── //
// Accept either `node gen.js --config path` or `node gen.js path`.
function flagValue(argv, flag) {
  const i = argv.indexOf(flag);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : null;
}

function resolveConfigPath(argv) {
  const flagged = flagValue(argv, '--config');
  if (flagged) return flagged;
  const flags = new Set(['--config', '--add', '--import', '--export']);
  // Skip both the flags themselves and the values that follow them.
  const rest = argv.slice(2);
  const positional = rest.find((a, i) => !a.startsWith('--') && !flags.has(rest[i - 1]));
  if (positional) return positional;
  // Prefer servers.json, fall back to legacy server.json.
  const multi = path.join(__dirname, 'servers.json');
  const single = path.join(__dirname, 'server.json');
  return fs.existsSync(multi) ? multi : single;
}
const configPath = resolveConfigPath(process.argv);
const importArg = flagValue(process.argv, '--add') || flagValue(process.argv, '--import');
const exportArg = flagValue(process.argv, '--export');
const testMode = process.argv.includes('--test');
const deepMode = process.argv.includes('--deep');
// --json turns --test into something a cron job or a monitoring agent can read.
// The decorated output is for humans and is deliberately unstable; this is the
// contract.
const jsonMode = process.argv.includes('--json');
// Notify the configured webhook about this probe. Off unless asked for: a
// generate run should never send anything anywhere — which is also why asking
// for it without --test is refused rather than quietly ignored. A cron entry
// that silently never notifies is worse than one that fails on the first run.
const alertMode = process.argv.includes('--alert');
if (alertMode && !testMode) {
  console.error('--alert reports the result of a probe, so it needs --test: node gen.js --test --alert');
  process.exit(1);
}

function readStore(p) {
  if (!fs.existsSync(p)) return C.normalizeStore({ active: 0, profiles: [], token: null });
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (err) {
    // Refuse rather than continue from an empty store — a later write would
    // otherwise overwrite a merely-malformed file and lose every credential.
    console.error(`${p} is not valid JSON: ${err.message}`);
    console.error('Fix the file (or move it aside) and re-run.');
    process.exit(1);
  }
  const store = C.normalizeStore(raw);
  // normalizeStore drops a routing rule it cannot read. Say which, or a typo in
  // a hand-edited list just quietly stops routing that site the way you meant.
  if (raw && !Array.isArray(raw) && raw.rules) {
    for (const problem of C.checkRules(raw.rules).errors) {
      console.warn(`⚠  Routing rule ignored — ${problem}`);
    }
  }
  // A hand-written servers.json carries no profile ids, so normalizeStore mints
  // fresh ones on every read. Persist them: they key the probe history and
  // summary.json, and regenerating them each run means neither can accumulate
  // anything — every probe would file itself under a brand-new server.
  const rawProfiles = Array.isArray(raw) ? raw : (Array.isArray(raw.profiles) ? raw.profiles : [raw]);
  if (store.profiles.some((prof, i) => !rawProfiles[i] || rawProfiles[i].id !== prof.id)) {
    // …but not into a template. `--config servers.json.example` is a natural
    // thing to type while working out what the file should look like, and this
    // is a write on the *read* path: it would mint ids and a token into the
    // example, and strip every `_comment_*` line out of it on the way past,
    // for a command that only meant to look. Copy it first, as the README says.
    if (/\.example$/i.test(p)) {
      console.warn(`⚠  ${p} is a template — leaving it alone rather than writing profile ids into it.`);
      console.warn('   Probe results will not accumulate under a stable id. Copy it to servers.json to keep them.');
    } else {
      writeStore(p, store);
    }
  }
  return store;
}

// Write through a temp file and rename over the target: a write that dies
// halfway would otherwise leave a truncated file full of credentials.
function writeStore(p, store) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = `${p}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2), { encoding: 'utf8', mode: 0o600 });
  try { fs.chmodSync(tmp, 0o600); } catch { /* unsupported filesystem/platform */ }
  fs.renameSync(tmp, p);
}

// ── --add: import a share link or a profile.json before generating ─────────── //
// The argument is either a literal URI or a path to a file holding one (or the
// JSON profile that setup.sh writes on the server).
function importInto(store, arg) {
  // "-" is stdin, so piping setup.sh --show --json straight in works and the
  // credentials never touch a file on the way over.
  let text;
  if (arg === '-') text = fs.readFileSync(0, 'utf8').trim();
  else text = fs.existsSync(arg) ? fs.readFileSync(arg, 'utf8').trim() : arg.trim();
  let candidates;
  if (text.startsWith('{') || text.startsWith('[')) {
    let json;
    try { json = JSON.parse(text); } catch (err) {
      console.error(`Import failed — not valid JSON: ${err.message}`);
      process.exit(1);
    }
    const list = Array.isArray(json) ? json : (Array.isArray(json.profiles) ? json.profiles : [json]);
    candidates = list.map(C.normalizeProfile);
  } else {
    const { profiles, errors } = C.parseSubscription(text);
    errors.forEach((e) => console.warn(`⚠  ${e}`));
    candidates = profiles;
  }
  if (!candidates.length) {
    console.error('Import failed — nothing recognisable in that input.');
    process.exit(1);
  }
  let added = 0;
  for (const p of candidates) {
    const { errors } = C.validateProfile(p);
    if (errors.length) {
      console.error(`✗ Skipped "${p.remarks}": ${errors.join(', ')}`);
      continue;
    }
    const dup = store.profiles.find((e) =>
      e.protocol === p.protocol && e.server === p.server && Number(e.port) === Number(p.port));
    if (dup) {
      console.log(`•  Already have ${p.protocol} ${p.server}:${p.port} — skipped`);
      continue;
    }
    store.profiles.push(p);
    added += 1;
    console.log(`✓  Imported ${p.protocol} ${p.server}:${p.port} as "${p.remarks}"`);
  }
  if (!added) {
    console.error('Nothing was imported.');
    process.exit(1);
  }
  if (!store.token) store.token = C.newToken();
  writeStore(configPath, store);
  console.log(`   Saved to ${configPath}\n`);
}

// ── --alert: tell the webhook what this run found ──────────────────────────── //
// The dashboard's monitor already does this, but only while it is running. A
// cron entry calling `gen.js --test --alert` is the version that survives the
// laptop being closed, and the two share both the config and the state file so
// they never disagree about what the current state is.
async function runAlert(alertCfg, statePath, summary, results, deep) {
  if (!alertCfg.url) {
    return {
      sent: false,
      reason: 'no webhook URL is configured — set one under Background Health Monitor in the dashboard, or monitor.alert.url in the store',
    };
  }
  const state = H.loadState(statePath);
  // Passing --alert *is* the request to send, so the stored enabled flag — which
  // arms the dashboard's own monitor — does not gate it.
  const armed = { ...alertCfg, enabled: true };
  // One call decides all three things: whether to speak, what state to remember
  // and where the failure streak now stands. They cannot be decided separately —
  // recording a held-back "down" as the current state would consume the
  // transition on the pass that deliberately stayed quiet. See alert.js.
  const decision = A.evaluate(state.alertState, state.downStreak, summary, armed);
  state.alertState = decision.state;
  state.downStreak = decision.streak;
  H.saveState(statePath, state);
  if (!decision.send) {
    return {
      sent: false,
      reason: decision.holding
        ? `something is down, but on ${decision.streak} of the ${decision.threshold} consecutive passes it takes to report it`
        : `nothing changed since the last run (still "${summary.state}")`,
    };
  }
  return A.send(armed, A.describe(summary), {
    state: summary.state,
    up: summary.up,
    down: summary.down,
    total: summary.total,
    deep: !!deep,
    source: 'gen.js --test --alert',
    servers: results.map((r) => ({
      remarks: r.remarks, protocol: r.protocol, ok: r.ok,
      latencyMs: r.latencyMs, enabled: r.enabled !== false, message: r.message,
    })),
  });
}

// ── What --test tells the shell ────────────────────────────────────────────── //
// A cron entry reads this, so the two states it must not confuse are "every
// server is down" and "nothing here could be checked". A store holding only
// Hysteria2 or TUIC profiles probed without --deep produces no successes at
// all — QUIC over UDP cannot be reached from outside the protocol — and used
// to exit 1 on every single run, which is an alarm that is always on and
// therefore never read. `unknown` means the probe never got to ask; that is
// not a failure of the servers.
//
// `empty` (every profile disabled) is the same kind of non-answer, and the
// generate path already treats it as a state you reached deliberately.
function probeExitCode(summary) {
  if (summary.state === 'unknown' || summary.state === 'empty') return 0;
  return summary.up ? 0 : 1;
}

const store = readStore(configPath);

if (importArg) {
  importInto(store, importArg);
} else if (!fs.existsSync(configPath)) {
  console.error(`Config file not found: ${configPath}`);
  console.error('Create servers.json (see servers.json.example), or import one:');
  console.error('  node gen.js --add "vless://…"');
  console.error('  node gen.js --add /path/to/profile.json');
  process.exit(1);
}

if (!store.profiles.length) {
  console.error('No profiles found in config.');
  process.exit(1);
}

// --test is a diagnostic, not a generation step. It runs before validation so
// you can still probe a store that has one broken profile in it.
if (testMode) {
  const historyPath = H.historyPathFor(configPath);
  const avail = P.deepTestAvailability();
  if (deepMode && !avail.available) {
    console.error(`✗ ${avail.reason}`);
    process.exit(1);
  }
  if (!jsonMode) {
    console.log(`Probing ${store.profiles.length} server(s)${deepMode ? ` through ${P.SINGBOX_BIN}` : ''}…\n`);
  }
  P.probeAll(store.profiles, deepMode).then(async (results) => {
    const hist = H.recordHistory(historyPath, results);
    const summary = A.summarize(results);
    const alert = alertMode
      ? await runAlert(store.monitor.alert, H.statePathFor(configPath), summary, results, deepMode)
      : null;

    // ── Machine-readable output ───────────────────────────────────────────── //
    if (jsonMode) {
      const payload = {
        at: new Date().toISOString(),
        deep: deepMode,
        state: summary.state,
        up: summary.up,
        down: summary.down,
        untestable: summary.untestable,
        total: results.length,
        historyPath,
        alert,
        servers: results.map((r) => {
          const h = H.summarizeHistory(hist[r.id]);
          return {
            id: r.id,
            remarks: r.remarks,
            protocol: r.protocol,
            enabled: r.enabled !== false,
            active: !!(store.profiles[store.active] && store.profiles[store.active].id === r.id),
            ok: r.ok,
            stage: r.stage,
            latencyMs: r.latencyMs,
            message: r.message,
            cert: h.cert,
            avgMs: h.avgMs,
            successRate: h.successRate,
            samples: h.samples,
          };
        }),
      };
      console.log(JSON.stringify(payload, null, 2));
      process.exit(probeExitCode(summary));
    }

    const mark = (ok) => (ok === true ? '✓' : ok === null ? '—' : '✗');
    for (const r of results) {
      const star = store.profiles[store.active] && store.profiles[store.active].id === r.id ? ' ★' : '';
      const off = r.enabled === false ? ' (disabled)' : '';
      const h = H.summarizeHistory(hist[r.id]);
      // One probe is weather; twenty are climate. Show the run of them when
      // there is a run to show — including for a server that has only ever
      // failed, where the record is the whole point.
      let trend = '';
      if (h.samples > 1) {
        const bits = [];
        if (h.avgMs !== null) bits.push(`avg ${h.avgMs}ms`);
        if (h.successRate !== null) bits.push(`${h.successRate}% up`);
        bits.push(`over ${h.samples}`);
        trend = `  [${bits.join(', ')}]`;
      }
      console.log(`${mark(r.ok)} ${r.remarks}${star}${off} (${r.protocol})`);
      console.log(`    ${r.ok === true ? `${r.latencyMs}ms · ` : ''}${r.message}${trend}`);
      // An expiring certificate is the failure that happens while you do
      // nothing, so it gets its own line rather than being buried in the probe
      // message — this is the run you would actually notice it on.
      if (h.cert && !h.cert.selfSigned && (h.cert.expired || h.cert.expiring)) {
        const whose = h.cert.of === 'camouflage target' ? "the camouflage target's " : '';
        console.log(h.cert.expired
          ? `    ⚠  ${whose}certificate EXPIRED ${-h.cert.daysLeft}d ago — clients will refuse it`
          : `    ⚠  ${whose}certificate expires in ${h.cert.daysLeft}d`);
      }
      if (r.certNote && !h.cert) console.log(`    ·  ${r.certNote}`);
    }
    const up = results.filter((r) => r.ok === true).length;
    const untestable = results.filter((r) => r.ok === null).length;
    const disabled = results.filter((r) => r.enabled === false).length;
    console.log(`\n${up}/${results.length} reachable` +
      (untestable ? ` (${untestable} untestable without --deep)` : '') +
      (disabled ? ` · ${disabled} disabled, and left out of every generated config` : '') +
      `. History: ${historyPath}`);
    if (alert) {
      console.log(alert.sent
        ? `Alert delivered (${alert.status}) — ${A.describe(summary)}`
        : `Alert not sent: ${alert.reason}`);
    }
    // Nothing reachable is a failure worth reporting to a shell script.
    process.exit(probeExitCode(summary));
  }).catch((err) => {
    console.error(`Probe failed: ${err.message}`);
    process.exit(1);
  });
  return;
}

// --export is a backup, not a generation step: write the store somewhere safe
// and stop, without touching output/.
if (exportArg) {
  writeStore(exportArg, store);
  console.log(`✓  Backed up ${store.profiles.length} profile(s) to ${exportArg}`);
  console.log('   It holds every credential in plain text (mode 0600) — keep it somewhere safe.');
  process.exit(0);
}

// Validate every profile before writing anything. A *disabled* profile's errors
// are reported but do not block the run: nothing generated here will carry it,
// and "switch the broken one off" should be a way out of a blocked generate
// rather than another thing that has to be fixed first.
let hasError = false;
store.profiles.forEach((p, i) => {
  const enabled = C.isEnabled(p);
  const { errors, warnings } = C.validateProfile(p);
  errors.forEach((e) => {
    if (enabled) {
      console.error(`✗ Profile #${i + 1} (${p.remarks}): ${e}`);
      hasError = true;
    } else {
      console.warn(`⚠  Disabled profile "${p.remarks}": ${e} (not generated, so not fatal)`);
    }
  });
  if (enabled) warnings.forEach((w) => console.warn(`⚠  Profile "${p.remarks}": ${w}`));
});
if (hasError) process.exit(1);

// Everything below writes client configs, and those only ever carry enabled
// profiles — so there has to be one.
const live = C.enabledProfiles(store.profiles);
if (!live.length) {
  console.error('Every profile is disabled — there is nothing to generate.');
  console.error('Re-enable one (set "enabled": true, or use the dashboard) and re-run.');
  process.exit(1);
}
// ★ names the profile the QR and active-uri.txt describe, so it has to be one
// of the profiles that made it into the bundles.
if (!C.isEnabled(store.profiles[store.active])) {
  const moved = store.profiles.findIndex(C.isEnabled);
  console.warn(`⚠  The active profile "${store.profiles[store.active].remarks}" is disabled — using "${store.profiles[moved].remarks}" for the QR code instead.`);
  store.active = moved;
}

// Everything written below is a client config, and a client config *is* the
// credential — uris.txt, the subscription blob and summary.json each carry
// every password in plain text, and even the QR encodes one. The store is 0600
// and so are the probe's temp files; these used to be whatever the umask said,
// which on a shared machine is world-readable.
const outDir = path.join(__dirname, 'output');
fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
// mkdirSync's mode applies only when it creates the directory, so an output/
// left over from before this existed keeps its old permissions until told.
try { fs.chmodSync(outDir, 0o700); } catch { /* unsupported filesystem/platform */ }

const secretMode = (outPath) => {
  try { fs.chmodSync(outPath, 0o600); } catch { /* unsupported filesystem/platform */ }
};

const write = (name, data) => {
  const outPath = path.join(outDir, name);
  fs.writeFileSync(outPath, data, { encoding: 'utf8', mode: 0o600 });
  secretMode(outPath);
  console.log('✓', name.padEnd(22), '→', outPath);
};

(async () => {
  const { profiles, active } = store;
  const activeProfile = profiles[active];
  const skipped = profiles.length - live.length;

  console.log(`\nGenerating configs for ${live.length} profile(s). Active: ${activeProfile.remarks}`);
  if (skipped) {
    console.log(`${skipped} disabled profile(s) kept in the store and left out of every file below.`);
  }
  console.log('');

  // ── Bundled configs (enabled profiles) ──────────────────────────────────── //
  // The builders filter to enabled themselves; `live` is used here so the URI
  // list and the de-duplicated names agree with what they produced.
  const names = C.uniqueNames(live);
  // Your own direct / proxy / block lists ride along in every bundle.
  const { rules } = store;
  if (C.hasRules(rules)) {
    const counts = C.RULE_LISTS.map((l) => `${rules[l].length} ${l}`).join(', ');
    console.log(`Custom routing rules: ${counts}\n`);
  }
  write('clash-config.yaml', C.buildClashYaml(profiles, { rules }));
  write('singbox-config.json', JSON.stringify(C.buildSingBox(profiles, { rules }), null, 2));
  write('subscription-base64.txt', C.buildSubscription(profiles) + '\n');

  // ── Surge / Quantumult X ────────────────────────────────────────────────── //
  // Neither client can express every protocol here, and a file that silently
  // dropped the server you needed would only be discovered at the worst moment.
  // Both builders comment the omissions into the file and report them back, so
  // they get said out loud here too.
  const surge = K.buildSurge(profiles, { title: store.title, rules });
  write('surge.conf', surge.text);
  const qx = K.buildQuantumultX(profiles, { title: store.title, rules });
  write('quantumultx.conf', qx.text);
  for (const [label, built] of [['surge.conf', surge], ['quantumultx.conf', qx]]) {
    if (!built.skipped.length) continue;
    console.log(`   ${label}: ${built.usable}/${built.total} server(s) — left out ${built.skipped.map((s) => s.name).join(', ')}`);
    for (const s of built.skipped) console.log(`     · ${s.name}: ${s.reason}`);
  }
  // Pass the de-duplicated label explicitly. `live.map(C.buildUri)` would
  // hand map's index across as the label, tagging every line after the first
  // with "#1", "#2", … instead of the profile's name.
  write('uris.txt', live.map((p, i) => C.buildUri(p, names[i])).join('\n') + '\n');

  // ── Active profile URI + QR ─────────────────────────────────────────────── //
  const activeUri = C.buildUri(activeProfile);
  write('active-uri.txt', activeUri + '\n');

  const pngPath = path.join(outDir, 'qrcode.png');
  await QRCode.toFile(pngPath, activeUri, { errorCorrectionLevel: 'M', width: 512 });
  // The PNG is written by the qrcode library, which takes no mode — and
  // scanning it hands over the active profile's credentials just as readily as
  // reading active-uri.txt would.
  secretMode(pngPath);
  console.log('✓', 'qrcode.png'.padEnd(22), '→', pngPath);

  // ── Summary (used by tooling) ───────────────────────────────────────────── //
  // Every profile is listed, disabled ones included, with a flag saying which
  // actually reached the bundles. The de-duplicated display name is looked up
  // by id rather than by index: `names` covers the enabled profiles only, so
  // indexing it with a position in `profiles` mislabels everything after the
  // first disabled entry.
  const displayName = new Map(live.map((p, i) => [p.id, names[i]]));
  const summary = {
    generatedAt: new Date().toISOString(),
    active: activeProfile.id,
    enabledCount: live.length,
    profiles: profiles.map((p) => ({
      id: p.id, remarks: p.remarks, protocol: p.protocol,
      server: p.server, port: p.port, enabled: C.isEnabled(p),
      uri: C.buildUri(p, displayName.get(p.id)),
    })),
  };
  write('summary.json', JSON.stringify(summary, null, 2));

  // ── Terminal QR for the active profile ──────────────────────────────────── //
  const termQr = await QRCode.toString(activeUri, { type: 'terminal', small: true });
  console.log(`\nScan the active profile (${activeProfile.remarks}):\n`);
  console.log(termQr);
  console.log(`All files written to: ${outDir}\n`);
})();
