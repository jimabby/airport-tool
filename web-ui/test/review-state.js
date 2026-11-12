'use strict';

// Review-required sources checked in the background, the shared monitor state
// file, and the pin / HTTPUpgrade fields through the dashboard API.
//
//   - A source set to require review is fetched on its own, nothing is applied,
//     the dashboard says how many changes are waiting, and a WeCom-shaped
//     webhook is told once.
//   - A device polling its subscription no longer rewrites what a cron
//     `gen.js --test --alert` run recorded in monitor-state.json.
//   - A profile saved with a certificate pin and the httpupgrade transport
//     reaches the Clash download intact.

const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { spawn } = require('child_process');
const C = require('../../config-gen/lib/configs');
const B = require('../../config-gen/lib/storage');
const H = require('../../config-gen/lib/history');

const root = path.resolve(__dirname, '../..');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-review-'));
const cfg = path.join(dir, 'servers.json');
const statePath = H.statePathFor(cfg);
const token = 'test-only-dashboard-token';
const subToken = 'test-only-subscription-token';
const deviceToken = 'test-only-device-token-0001';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let app, provider, hook;

async function listen(server) {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server.address().port;
}

async function waitFor(what, fn, ms = 15000) {
  const until = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await sleep(150);
  }
}

async function main() {
  const sourceId = '22222222-2222-4222-8222-222222222222';
  const kept = C.normalizeProfile({ protocol: 'trojan', server: 'old.example.com', port: 443, password: 'pw', sni: 'old.example.com', remarks: 'Old', source: sourceId });
  const fresh = C.normalizeProfile({ protocol: 'trojan', server: 'new.example.com', port: 443, password: 'pw', sni: 'new.example.com', remarks: 'New' });
  // The provider now lists one new server alongside the old one.
  provider = http.createServer((_req, res) => res.end([C.buildUri(kept), C.buildUri(fresh)].join('\n')));
  const providerPort = await listen(provider);

  // A WeCom-shaped robot: answers 200 with errcode 0, as the real one does.
  const hookBodies = [];
  hook = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => { b += c; });
    req.on('end', () => { hookBodies.push(JSON.parse(b)); res.end('{"errcode":0,"errmsg":"ok"}'); });
  });
  const hookPort = await listen(hook);

  const deviceId = '33333333-3333-4333-8333-333333333333';
  B.save(cfg, B.track(C.normalizeStore({
    profiles: [kept],
    token: subToken,
    uiToken: token,
    clients: [{ id: deviceId, name: 'Phone', token: deviceToken, createdAt: 1 }],
    sources: [{ id: sourceId, name: 'Acme', url: `http://127.0.0.1:${providerPort}/sub`, requireReview: true }],
    monitor: { enabled: false, alert: { enabled: true, url: `http://127.0.0.1:${hookPort}/cgi-bin/webhook/send?key=K`, mode: 'wecom' } },
  }), null));
  // The state as the dashboard finds it at boot.
  H.saveState(statePath, { alertState: 'ok', downStreak: 0, clients: {}, notices: {} });

  const reservation = http.createServer();
  const port = await listen(reservation);
  await new Promise((r) => reservation.close(r));
  app = spawn(process.execPath, [path.join(root, 'web-ui/server.js')], {
    env: { ...process.env, CFG_PATH: cfg, PORT: String(port), HOST: '127.0.0.1', UI_TOKEN: token,
      PUBLIC_URL: '', TLS_CERT: '', TLS_KEY: '', TLS_SELFSIGNED: '', SHOW_TOKEN: '',
      HISTORY_PATH: '', MONITOR_STATE_PATH: '', SOURCE_FIRST_CHECK_MS: '200' },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  const call = async (url, method = 'GET', body, { auth = true } = {}) => {
    const res = await fetch(`http://127.0.0.1:${port}${url}`, {
      method,
      headers: { ...(auth ? { 'X-UI-Token': token } : {}), 'Content-Type': 'application/json' },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const text = await res.text();
    let data; try { data = JSON.parse(text); } catch { data = text; }
    return { status: res.status, data };
  };
  for (let i = 0; ; i++) { try { await call('/api/config'); break; } catch (e) { if (i > 100) throw e; await sleep(100); } }
  const storeBefore = fs.readFileSync(cfg, 'utf8');

  // ── A review-required source is checked without being applied ──
  const pending = await waitFor('the background review check', async () => {
    const r = await call('/api/config');
    const p = r.data.sources[0].pendingReview;
    return p && p.count ? p : null;
  });
  assert.equal(pending.count, 1);
  assert.equal(pending.added, 1);
  assert.equal(pending.error, null);
  assert.equal(fs.readFileSync(cfg, 'utf8'), storeBefore, 'a review check must not write the store');
  await waitFor('the review notice', async () => hookBodies.length);
  assert.equal(hookBodies.length, 1);
  assert.equal(hookBodies[0].msgtype, 'text');
  assert.match(hookBodies[0].text.content, /"Acme" subscription has 1 server change\(s\) waiting for your review/);
  console.log('✓ a review-required source is checked in the background, applied by nobody, and announced once to a WeCom robot');

  // ── A device poll leaves cron's alert state alone ──
  // What a cron `gen.js --test --alert` run records while the dashboard is
  // up — written the way gen.js writes it, on top of the file as it is.
  H.updateState(statePath, (s) => {
    s.alertState = 'down';
    s.downStreak = 4;
    s.notices = { ...s.notices, 'cert:cron:1:expiring': 123 };
  });
  const sub = await fetch(`http://127.0.0.1:${port}/api/subscription/${deviceToken}`, { headers: { 'User-Agent': 'clash-verge/2' } });
  assert.equal(sub.status, 200);
  const state = H.loadState(statePath);
  assert.equal(state.alertState, 'down');
  assert.equal(state.downStreak, 4);
  assert.ok(state.notices['cert:cron:1:expiring'], 'cron\'s notice was erased');
  assert.ok(Object.keys(state.notices).some((k) => k.startsWith(`review:${sourceId}:`)), 'the review notice is remembered');
  assert.equal(state.clients[deviceId].agent, 'clash-verge/2');
  console.log('✓ a device poll records itself without rewriting the alert state and notices a cron run left');

  // ── Preview and apply clear the pending count ──
  let r = await call(`/api/sources/${sourceId}/preview`, 'POST', {});
  assert.equal(r.status, 200, JSON.stringify(r.data));
  r = await call(`/api/sources/${sourceId}/apply`, 'POST', { previewId: r.data.id });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.profiles.length, 2);
  assert.equal(r.data.sources[0].pendingReview.count, 0);
  // Switching to automatic drops the review state altogether.
  r = await call(`/api/sources/${sourceId}`, 'POST', { requireReview: false });
  assert.equal(r.data.sources[0].pendingReview, null);
  console.log('✓ applying the preview clears what was waiting; automatic refresh drops it');

  // ── Pin and HTTPUpgrade through the API ──
  const pin = 'AB:'.repeat(31) + 'AB';
  r = await call('/api/profiles', 'POST', {
    protocol: 'trojan', server: 'hu.example.com', port: 443, password: 'pw', sni: 'hu.example.com', insecure: true,
    pinSha256: pin, network: 'httpupgrade', path: '/up', host: 'cdn.example.com', remarks: 'HU',
  });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.ok(!r.data.warnings.some((w) => /nothing is pinned/.test(w)));
  const saved = r.data.profiles.find((p) => p.id === r.data.savedId);
  assert.equal(saved.pinSha256, 'ab'.repeat(32));
  assert.equal(saved.network, 'httpupgrade');
  const clash = await fetch(`http://127.0.0.1:${port}/api/download/clash`, { headers: { 'X-UI-Token': token } }).then((x) => x.text());
  const doc = require('js-yaml').load(clash);
  const px = doc.proxies.find((p) => p.name === 'HU');
  assert.equal(px.fingerprint, 'ab'.repeat(32));
  assert.equal(px['ws-opts']['v2ray-http-upgrade'], true);
  r = await call('/api/profiles', 'POST', { protocol: 'tuic', server: 'x.example.com', port: 443, uuid: '11111111-1111-4111-8111-111111111111', password: 'p', pinSha256: 'not-a-pin' });
  assert.equal(r.status, 400);
  assert.match(r.data.error, /pinSha256 must be/);
  console.log('✓ a pinned httpupgrade profile saves, and reaches the Clash download with both');

  console.log('Review and state tests passed');
}

main().catch((err) => {
  console.error('✗', err.stack || err.message);
  process.exitCode = 1;
}).finally(() => {
  if (app) app.kill();
  for (const s of [provider, hook]) if (s) s.close();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* temp */ }
});
