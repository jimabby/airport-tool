#!/usr/bin/env node
// The servers deploy.sh looks after: their ssh logins (in the store, under
// `hosts`) and what `setup.sh --doctor` last found on each (in
// monitor-state.json, beside the store). deploy.sh is the caller; nothing here
// opens a network connection. See lib/hosts.js.
//
//   node hosts.js list                 one line per server, fields split by \x1f
//   node hosts.js show                 the same, for people, with the last doctor result
//   node hosts.js lookup USER@HOST     that server's line, or exit 1
//   node hosts.js record --target USER@HOST [--port N] [--key FILE] [--jump J]
//                        [--option Name=value …] [--replaces USER@OLD]  < profiles
//   node hosts.js doctor ID --exit N   < the --doctor report
//   node hosts.js addresses            < profiles: the server addresses in them
//   node hosts.js forget USER@HOST|ID
//
// Every command takes --config FILE; otherwise the store is the one gen.js
// and the dashboard use (CFG_PATH, or servers.json beside this file).

const fs = require('fs');
const path = require('path');
const C = require('./lib/configs');
const B = require('./lib/storage');
const H = require('./lib/history');
const T = require('./lib/hosts');

const argv = process.argv.slice(2);
const cmd = argv[0];

function values(flag) {
  const out = [];
  argv.forEach((a, i) => { if (a === flag && argv[i + 1] !== undefined) out.push(argv[i + 1]); });
  return out;
}
const value = (flag) => values(flag)[0];

function configPath() {
  if (value('--config')) return value('--config');
  if (process.env.CFG_PATH) return process.env.CFG_PATH;
  const multi = path.join(__dirname, 'servers.json');
  const single = path.join(__dirname, 'server.json');
  return fs.existsSync(multi) ? multi : (fs.existsSync(single) ? single : multi);
}

function die(message) {
  console.error(`✗ ${message}`);
  process.exit(1);
}

function load(file) {
  if (!fs.existsSync(file)) return B.track(C.normalizeStore({ active: 0, profiles: [] }), null);
  const raw = fs.readFileSync(file, 'utf8');
  let parsed;
  try { parsed = JSON.parse(raw); } catch (err) {
    die(`${file} is not valid JSON (${err.message}) — fix it before deploy.sh can record anything in it.`);
  }
  return B.track(C.normalizeStore(parsed), raw);
}

function save(file, store) {
  if (!store.token) store.token = C.newToken();
  try { B.save(file, store); } catch (err) { die(err.message); }
}

const stdin = () => { try { return fs.readFileSync(0, 'utf8'); } catch { return ''; } };
const SEP = '\x1f';
const line = (h) => [h.id, h.target, h.port || '', h.key || '', h.jump || '', (h.options || []).join('\x1e')].join(SEP);

function ago(ms) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 129600) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

const file = configPath();
const statePath = H.statePathFor(file);

switch (cmd) {
  case 'list': {
    for (const h of load(file).hosts) console.log(line(h));
    break;
  }
  case 'show': {
    const store = load(file);
    const doctor = H.loadState(statePath).doctor;
    if (!store.hosts.length) {
      console.log('No servers recorded yet. deploy.sh records each one it sets up:');
      console.log('  bash server/deploy.sh USER@HOST PROTOCOL=reality');
      break;
    }
    for (const h of store.hosts) {
      const how = [h.port && `port ${h.port}`, h.key && `key ${h.key}`, h.jump && `via ${h.jump}`].filter(Boolean).join(', ');
      console.log(`${h.target}${how ? `  (${how})` : ''}`);
      if (h.addresses.length) console.log(`    serves clients at ${h.addresses.join(', ')}`);
      const d = doctor[h.id];
      if (!d) console.log('    doctor: never run — bash server/deploy.sh --all --doctor');
      else if (d.error) console.log(`    doctor ${ago(d.at)}: ✗ ${d.error}`);
      else console.log(`    doctor ${ago(d.at)}: ${d.ok ? '✓' : '✗'} ${d.passed} passed, ${d.failures.length} failed${d.notes.length ? `, ${d.notes.length} note(s)` : ''}`);
      if (d) for (const f of d.failures) console.log(`      ✗ ${f}`);
    }
    break;
  }
  case 'lookup': {
    const h = T.findHost(load(file), argv[1]);
    if (!h) process.exit(1);
    console.log(line(h));
    break;
  }
  case 'record': {
    const store = load(file);
    const addresses = T.addressesIn(stdin());
    let result;
    try {
      result = T.recordHost(store, {
        target: value('--target'),
        port: value('--port'),
        key: value('--key'),
        jump: value('--jump'),
        options: values('--option'),
        addresses,
      }, { replaces: value('--replaces') });
    } catch (err) { die(err.message); }
    save(file, store);
    for (const r of result.rejected) console.error(`⚠  Not remembered: ${r}`);
    console.log(`✓  Recorded ${result.host.target} for deploy.sh --all${addresses.length ? ` (serves ${addresses.join(', ')})` : ''}`);
    break;
  }
  case 'doctor': {
    const store = load(file);
    const h = T.findHost(store, argv[1]);
    if (!h) die(`No recorded server ${argv[1]}.`);
    const report = T.parseDoctor(stdin(), value('--exit'));
    H.updateState(statePath, (s) => { s.doctor[h.id] = report; });
    break;
  }
  case 'addresses': {
    console.log(T.addressesIn(stdin()).join(','));
    break;
  }
  case 'forget': {
    const store = load(file);
    const h = T.findHost(store, argv[1]);
    if (!h) die(`No recorded server ${argv[1]}.`);
    T.forgetHost(store, h.id);
    save(file, store);
    H.updateState(statePath, (s) => { delete s.doctor[h.id]; });
    console.log(`✓  Forgot ${h.target}. Its profiles are untouched.`);
    break;
  }
  default:
    console.error('Usage: node hosts.js list|show|lookup|record|doctor|addresses|forget … (see the top of this file)');
    process.exit(1);
}
