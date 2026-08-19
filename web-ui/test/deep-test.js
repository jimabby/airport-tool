#!/usr/bin/env node
// End-to-end check of the deep connection test: boot the web UI with a stub in
// place of sing-box and a local origin in place of gstatic, then confirm the
// probe reports a real end-to-end success — and a real failure when the proxy
// refuses to start.
//
// The deep test is the only check that says anything about whether credentials
// work, so the plumbing around it (config generation, port allocation, spawn,
// wait, fetch, cleanup) is worth covering even without a real proxy.
'use strict';

const assert = require('assert');
const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const HERE = __dirname;
const PORT = 3311;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-deep-'));
const cfgPath = path.join(dir, 'servers.json');

let origin;
let server;
let failed = 0;

function get(pathname) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: PORT, path: pathname }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    }).on('error', reject);
  });
}

function post(pathname, payload) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const req = http.request({
      host: '127.0.0.1', port: PORT, path: pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end(data);
  });
}

async function waitUp(deadline) {
  for (;;) {
    try { await get('/api/config'); return true; } catch {
      if (Date.now() > deadline) return false;
      await new Promise((r) => setTimeout(r, 150));
    }
  }
}

function check(name, cond, detail) {
  if (cond) { console.log('✓', name); return; }
  console.error('✗', name);
  if (detail) console.error('  ', detail);
  failed += 1;
}

(async () => {
  // A local stand-in for the 204 endpoint the probe fetches.
  origin = http.createServer((req, res) => { res.writeHead(204); res.end(); });
  await new Promise((r) => origin.listen(0, '127.0.0.1', r));
  const originPort = origin.address().port;

  server = spawn(process.execPath, [path.join(HERE, '..', 'server.js')], {
    env: {
      ...process.env,
      CFG_PATH: cfgPath,
      HISTORY_PATH: path.join(dir, 'history.json'),
      PORT: String(PORT),
      HOST: '127.0.0.1',
      // Reached through SINGBOX_ARGS so the stub needs no shebang, exec bit
      // or .cmd shim to be spawnable on every platform CI runs on.
      SINGBOX_BIN: process.execPath,
      SINGBOX_ARGS: JSON.stringify([path.join(HERE, 'fake-sing-box.js')]),
      FAKE_ORIGIN: String(originPort),
      DEEP_TEST_URL: `http://127.0.0.1:${originPort}/generate_204`,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverErr = '';
  server.stderr.on('data', (b) => { serverErr += b.toString(); });

  assert.ok(await waitUp(Date.now() + 15000), `server never came up: ${serverErr}`);

  const cfg = JSON.parse((await get('/api/config')).body);
  check('deep test reports itself available', cfg.deepTest.available, JSON.stringify(cfg.deepTest));

  await post('/api/profiles', {
    protocol: 'tuic', server: '203.0.113.9', port: 443,
    uuid: '11111111-2222-3333-4444-555555555555', password: 'pw',
    sni: 'www.bing.com', insecure: true, remarks: 'Deep',
  });

  const res = JSON.parse((await get('/api/test?deep=1')).body);
  check('deep probe carries traffic end to end', res.ok === true && res.stage === 'deep', JSON.stringify(res));
  check('deep probe records a latency', Number.isFinite(res.latencyMs), JSON.stringify(res));
  check('deep probe is written to history', res.history && res.history.samples >= 1, JSON.stringify(res.history));

  // A QUIC profile has no shallow probe, so the deep test is the only thing
  // that can ever return ok:true for it — that is the whole point.
  const auto = JSON.parse((await post('/api/auto-active?deep=1', {})).body);
  check('auto-active picks the profile the deep test proved', auto.ok === true && auto.chose === 'Deep', JSON.stringify(auto).slice(0, 200));

  // A proxy that refuses to start must surface as a failure with sing-box's own
  // complaint attached, not as a timeout with no explanation.
  const bad = JSON.parse((await post('/api/profiles', {
    protocol: 'tuic', server: '198.51.100.254', port: 443,
    uuid: '11111111-2222-3333-4444-555555555555', password: 'pw',
    sni: 'www.bing.com', insecure: true, remarks: 'Broken',
  })).body);
  const badRes = JSON.parse((await get(`/api/test?deep=1&id=${bad.savedId}`)).body);
  check('a proxy that will not start reports why', badRes.ok === false && /did not start/.test(badRes.message), JSON.stringify(badRes));

  const shallow = JSON.parse((await get('/api/test')).body);
  check('without deep, a QUIC profile is untestable', shallow.ok === null && shallow.stage === 'skipped', JSON.stringify(shallow));
})()
  .catch((err) => { console.error('✗ harness error:', err.message); failed += 1; })
  .finally(async () => {
    if (server) server.kill();
    if (origin) origin.close();
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* temp dir */ }
    console.log(failed ? `\ndeep test: ${failed} failure(s)` : '\ndeep test: all checks passed');
    process.exit(failed ? 1 : 0);
  });
