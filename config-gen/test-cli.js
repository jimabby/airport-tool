#!/usr/bin/env node
// CLI-level tests for gen.js: the two things that only exist at the process
// boundary and so cannot be reached from test.js.
//
//   --add -            reading a profile off stdin, which is what makes
//                      `setup.sh --show --json | gen.js --add -` one command
//   --test --alert     the cron half of the health monitor: it has to fire
//                      once on the change and then stay quiet, or it becomes
//                      the notification people learn to swipe away
//
// Run: node test-cli.js
'use strict';

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

const GEN = path.join(__dirname, 'gen.js');

let passed = 0;
let failed = 0;
function check(name, cond, detail) {
  if (cond) { passed += 1; console.log('  ✓', name); return; }
  failed += 1;
  console.error('  ✗', name);
  if (detail !== undefined) console.error('     ', String(detail).slice(0, 400));
}

// gen.js exits non-zero when nothing is reachable, which is the normal case
// here — every profile points at a documentation address on purpose. Resolve
// with the output either way and let each test decide what that means.
function runGen(args, { stdin } = {}) {
  return new Promise((resolve) => {
    const child = execFile(process.execPath, [GEN, ...args], { encoding: 'utf8' },
      (err, stdout, stderr) => resolve({ code: err ? err.code : 0, stdout, stderr }));
    if (stdin !== undefined) child.stdin.end(stdin);
    else child.stdin.end();
  });
}

// A server that is guaranteed not to answer: 203.0.113.0/24 is reserved for
// documentation, so the probe times out rather than reaching anything real.
const NOWHERE = {
  protocol: 'shadowsocks', server: '203.0.113.99', port: 8388,
  password: 'p', method: 'aes-256-gcm', remarks: 'Nowhere',
};

async function testStdinImport(dir) {
  console.log('\n── --add - reads a profile off stdin');
  const cfg = path.join(dir, 'servers.json');
  const profile = {
    protocol: 'vless-reality', server: '203.0.113.9', port: 443,
    uuid: '11111111-2222-3333-4444-555555555555',
    publicKey: 'PUBKEYBBB', shortId: 'abcd', sni: 'www.microsoft.com', remarks: 'Piped',
  };
  const r = await runGen(['--add', '-', '--config', cfg], { stdin: JSON.stringify(profile) });
  check('the pipe is accepted', /Imported vless-reality/.test(r.stdout), r.stdout + r.stderr);
  const store = JSON.parse(fs.readFileSync(cfg, 'utf8'));
  check('and the profile landed in the store',
    store.profiles.length === 1 && store.profiles[0].remarks === 'Piped', JSON.stringify(store.profiles));

  // setup.sh --show --json emits an array, so that shape has to work too.
  const cfg2 = path.join(dir, 'array.json');
  const two = await runGen(['--add', '-', '--config', cfg2], {
    stdin: JSON.stringify([profile, { ...NOWHERE, remarks: 'Second' }]),
  });
  const store2 = JSON.parse(fs.readFileSync(cfg2, 'utf8'));
  check('an array of profiles — what --show --json emits — imports too',
    store2.profiles.length === 2, two.stdout + two.stderr);
}

async function testAlerting(dir) {
  console.log('\n── --test --alert speaks on the change and then keeps quiet');
  const received = [];
  const hook = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => { received.push(body); res.writeHead(204).end(); });
  });
  await new Promise((r) => hook.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${hook.address().port}/hook`;

  try {
    const cfg = path.join(dir, 'alerting.json');
    fs.writeFileSync(cfg, JSON.stringify({
      active: 0,
      profiles: [NOWHERE],
      // enabled:false on purpose — passing --alert is the explicit request, and
      // the stored checkbox arms the dashboard's monitor rather than this.
      monitor: { enabled: false, alert: { enabled: false, url, mode: 'json' } },
    }));

    const first = await runGen(['--test', '--alert', '--config', cfg]);
    check('the first run reports a delivery', /Alert delivered/.test(first.stdout), first.stdout + first.stderr);
    check('and the webhook got exactly one message', received.length === 1, received.length);
    if (received.length) {
      check('which says everything is unreachable',
        /unreachable/i.test(JSON.parse(received[0]).text), received[0]);
      check('and names its source, so a cron alert is tellable from the dashboard\'s',
        JSON.parse(received[0]).source === 'gen.js --test --alert', received[0]);
    }

    const second = await runGen(['--test', '--alert', '--config', cfg]);
    check('the second run stays quiet', /nothing changed/.test(second.stdout), second.stdout);
    check('and sends nothing', received.length === 1, received.length);

    // The state is what makes the second run quiet, so it has to be on disk —
    // in memory it would reset on every cron invocation and alert every time.
    const state = JSON.parse(fs.readFileSync(path.join(dir, 'monitor-state.json'), 'utf8'));
    check('the transition state is persisted beside the store',
      state.alertState === 'down', JSON.stringify(state));

    // --json is the machine-readable contract; the alert outcome belongs in it.
    const asJson = await runGen(['--test', '--alert', '--json', '--config', cfg]);
    const payload = JSON.parse(asJson.stdout);
    check('--json carries the alert outcome', payload.alert && payload.alert.sent === false,
      JSON.stringify(payload.alert));

    // Asking to alert with nowhere to send is a mistake worth naming rather
    // than silently doing nothing about.
    const noHook = path.join(dir, 'no-hook.json');
    fs.writeFileSync(noHook, JSON.stringify({ active: 0, profiles: [NOWHERE] }));
    const quiet = await runGen(['--test', '--alert', '--config', noHook]);
    check('an unconfigured webhook is reported, not ignored',
      /no webhook URL is configured/.test(quiet.stdout), quiet.stdout);
  } finally {
    hook.close();
  }
}

// Reading a store rewrites it when the profiles carry no ids — they key the
// probe history, and re-minting them every run means nothing can accumulate.
// That is a write on the read path, and pointing it at the shipped template is
// a very easy thing to type: it would mint ids and a token into the example and
// strip its `_comment_*` lines on the way past, for a command that only looked.
async function testTemplateIsNotRewritten(dir) {
  console.log('\n── a .example store is read but never rewritten');
  const tpl = path.join(dir, 'servers.json.example');
  const body = JSON.stringify({
    _comment: 'kept',
    active: 0,
    profiles: [NOWHERE],
  }, null, 2);
  fs.writeFileSync(tpl, body);
  const r = await runGen(['--test', '--config', tpl]);
  check('the file is byte-identical afterwards', fs.readFileSync(tpl, 'utf8') === body,
    fs.readFileSync(tpl, 'utf8'));
  check('and it says why the ids will not stick',
    /is a template/.test(r.stderr), r.stderr);

  // The same store under its real name is still repaired in place.
  const real = path.join(dir, 'servers.json');
  fs.writeFileSync(real, body);
  await runGen(['--test', '--config', real]);
  const after = JSON.parse(fs.readFileSync(real, 'utf8'));
  check('a real store still gets its profile ids', typeof after.profiles[0].id === 'string',
    fs.readFileSync(real, 'utf8'));
}

// A cron entry reads the exit code, so "everything is down" and "nothing here
// could be checked" must not look the same. A QUIC-only store probed without
// --deep has no successes at all and used to fail on every single run.
async function testExitCodes(dir) {
  console.log('\n── the exit code separates "down" from "unaskable"');
  const quic = path.join(dir, 'quic.json');
  fs.writeFileSync(quic, JSON.stringify({
    active: 0,
    profiles: [{
      id: '11111111-1111-4111-8111-111111111111',
      protocol: 'hysteria2', server: '203.0.113.7', port: 443,
      password: 'p', insecure: true, remarks: 'QUIC only',
    }],
  }));
  const untestable = await runGen(['--test', '--config', quic]);
  check('a QUIC-only store exits 0 — nothing failed, nothing was asked',
    untestable.code === 0, `exit ${untestable.code}: ${untestable.stdout}`);

  const down = path.join(dir, 'down.json');
  fs.writeFileSync(down, JSON.stringify({
    active: 0,
    profiles: [{ id: '22222222-2222-4222-8222-222222222222', ...NOWHERE }],
  }));
  const failed = await runGen(['--test', '--config', down]);
  check('a store whose only server is unreachable still exits 1',
    failed.code === 1, `exit ${failed.code}: ${failed.stdout}`);
}

(async () => {
  const dirs = [];
  const mk = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-cli-')); dirs.push(d); return d; };
  try {
    await testStdinImport(mk());
    await testTemplateIsNotRewritten(mk());
    await testExitCodes(mk());
    await testAlerting(mk());
  } catch (err) {
    console.error('✗ harness error:', err.message);
    failed += 1;
  } finally {
    for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* temp dir */ } }
  }
  console.log(failed ? `\n${passed} passed, ${failed} FAILED` : `\n${passed} passed`);
  process.exit(failed ? 1 : 0);
})();
