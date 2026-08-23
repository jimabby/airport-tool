#!/usr/bin/env node
// Generates client config files + QR codes for all configured server profiles.
// Supports Shadowsocks (v2ray-plugin), VLESS + Reality (tcp/grpc/xhttp),
// Hysteria2 and TUIC v5.
//
// Usage:
//   node gen.js [--config servers.json]
//   node gen.js --add "vless://…"                 import a share link, then generate
//   node gen.js --add /etc/airport-tool/profile.json   import setup.sh's output
//   node gen.js --export backup.json              write a copy of the store and stop
//   node gen.js --test [--deep] [--json]          probe every server and stop
//
// --export exists because setup.sh cannot reproduce a password it generated
// once: if servers.json is lost, so are those servers.
//
// --test runs the same probes as the web UI's Test All button and files the
// results in the same test-history.json, so the two agree about which servers
// are up. --deep dials through each server with a local sing-box, which is the
// only check that proves the credentials work — and the only one that means
// anything at all for the QUIC protocols.

const fs   = require('fs');
const path = require('path');
const QRCode = require('qrcode');
const C = require('./lib/configs');
const P = require('./lib/probe');
const H = require('./lib/history');
const A = require('./lib/alert');

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
  // A hand-written servers.json carries no profile ids, so normalizeStore mints
  // fresh ones on every read. Persist them: they key the probe history and
  // summary.json, and regenerating them each run means neither can accumulate
  // anything — every probe would file itself under a brand-new server.
  const rawProfiles = Array.isArray(raw) ? raw : (Array.isArray(raw.profiles) ? raw.profiles : [raw]);
  if (store.profiles.some((prof, i) => !rawProfiles[i] || rawProfiles[i].id !== prof.id)) {
    writeStore(p, store);
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
  const text = fs.existsSync(arg) ? fs.readFileSync(arg, 'utf8').trim() : arg.trim();
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
  P.probeAll(store.profiles, deepMode).then((results) => {
    const hist = H.recordHistory(historyPath, results);

    // ── Machine-readable output ───────────────────────────────────────────── //
    if (jsonMode) {
      const summary = A.summarize(results);
      const payload = {
        at: new Date().toISOString(),
        deep: deepMode,
        state: summary.state,
        up: summary.up,
        down: summary.down,
        untestable: summary.untestable,
        total: results.length,
        historyPath,
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
      process.exit(summary.up ? 0 : 1);
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
    // Nothing reachable is a failure worth reporting to a shell script.
    process.exit(up ? 0 : 1);
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

const outDir = path.join(__dirname, 'output');
fs.mkdirSync(outDir, { recursive: true });

const write = (name, data) => {
  const outPath = path.join(outDir, name);
  fs.writeFileSync(outPath, data, 'utf8');
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
  write('clash-config.yaml', C.buildClashYaml(profiles));
  write('singbox-config.json', JSON.stringify(C.buildSingBox(profiles), null, 2));
  write('subscription-base64.txt', C.buildSubscription(profiles) + '\n');
  // Pass the de-duplicated label explicitly. `live.map(C.buildUri)` would
  // hand map's index across as the label, tagging every line after the first
  // with "#1", "#2", … instead of the profile's name.
  write('uris.txt', live.map((p, i) => C.buildUri(p, names[i])).join('\n') + '\n');

  // ── Active profile URI + QR ─────────────────────────────────────────────── //
  const activeUri = C.buildUri(activeProfile);
  write('active-uri.txt', activeUri + '\n');

  const pngPath = path.join(outDir, 'qrcode.png');
  await QRCode.toFile(pngPath, activeUri, { errorCorrectionLevel: 'M', width: 512 });
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
