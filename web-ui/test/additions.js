#!/usr/bin/env node
// API tests for the dashboard fixes and additions: the shared import path, the
// last-enabled guard on the profile form, ★ following an enable, relays, the
// Loon and Stash targets, probe agents (gen.js --agent end to end), off-machine
// backups and the outbound-proxy status.
'use strict';

const assert = require('assert');
const http = require('http');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
let passed = 0;

const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => r(port)); }); });

function request(port, method, p, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers: { ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}), ...headers } }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => { let json = null; try { json = JSON.parse(text); } catch { /* not JSON */ } resolve({ status: res.statusCode, headers: res.headers, text, json }); });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function boot(env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-additions-'));
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(ROOT, 'web-ui', 'server.js')], {
    env: {
      ...process.env, PORT: String(port), CFG_PATH: path.join(dir, 'servers.json'),
      SOURCE_FIRST_CHECK_MS: '600000', SHOW_TOKEN: '', OUTBOUND_PROXY: '', HTTPS_PROXY: '', HTTP_PROXY: '', ALL_PROXY: '', ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  child.stdout.on('data', (b) => { log += b; });
  child.stderr.on('data', (b) => { log += b; });
  for (let i = 0; i < 100 && !/running at/.test(log); i += 1) await new Promise((r) => setTimeout(r, 100));
  if (!/running at/.test(log)) throw new Error(`server did not start:\n${log}`);
  const call = (method, p, body, headers) => request(port, method, p, body, headers);
  return { dir, port, call, log: () => log, stop: () => { child.kill(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

const trojan = (over = {}) => ({ protocol: 'trojan', server: 't.example.com', port: 443, password: 'pw-trojan', sni: 't.example.com', remarks: 'T', ...over });

async function check(name, fn) {
  try { await fn(); passed += 1; console.log('  ✓', name); } catch (err) { console.error('  ✗', name); console.error('    ', err.stack || err.message); process.exitCode = 1; }
}

(async () => {
  // ── The fixes ────────────────────────────────────────────────────────────── //
  console.log('── fixes');
  let s = await boot();
  try {
    await check('the Import box reads a pasted sing-box config (it used to fail as one broken profile)', async () => {
      const text = JSON.stringify({ outbounds: [{ type: 'trojan', tag: 'From sing-box', server: 'sb.example.com', server_port: 443, password: 'pw-sb', tls: { enabled: true, server_name: 'sb.example.com' } }] });
      const r = await s.call('POST', '/api/import', { text });
      assert.strictEqual(r.status, 200, r.text);
      assert.deepStrictEqual(r.json.added, ['From sing-box']);
      assert.strictEqual(r.json.format, 'singbox');
    });

    await check('the Import box reads SIP008', async () => {
      const text = JSON.stringify({ version: 1, servers: [{ server: 'sip.example.com', server_port: 8388, password: 'pw', method: 'aes-256-gcm', remarks: 'SIP' }] });
      const r = await s.call('POST', '/api/import', { text });
      assert.strictEqual(r.status, 200, r.text);
      assert.deepStrictEqual(r.json.added, ['SIP']);
    });

    await check('saving the form cannot switch off the last enabled server; the toggle moves ★ back onto an enabled one', async () => {
      // Two servers; disable every one except "From sing-box".
      let cfg = (await s.call('GET', '/api/config')).json;
      const [a, b] = cfg.profiles;
      assert.strictEqual((await s.call('POST', `/api/profiles/${b.id}/enabled`, { enabled: false })).status, 200);
      const refused = await s.call('POST', '/api/profiles', { ...a, enabled: false });
      assert.strictEqual(refused.status, 409);
      assert.match(refused.json.error, /only enabled profile/);
      // Strand ★ the way an older store could: every profile off, ★ on one.
      const store = JSON.parse(fs.readFileSync(path.join(s.dir, 'servers.json'), 'utf8'));
      store.profiles.forEach((p) => { p.enabled = false; });
      store.active = 0;
      fs.writeFileSync(path.join(s.dir, 'servers.json'), JSON.stringify(store, null, 2));
      cfg = (await s.call('POST', `/api/profiles/${b.id}/enabled`, { enabled: true })).json;
      assert.strictEqual(cfg.activeId, b.id, '★ follows the server that was just enabled');
      assert.strictEqual((await s.call('GET', '/api/qrcode')).status, 200);
    });
  } finally { s.stop(); }

  // ── Relays and the new targets ───────────────────────────────────────────── //
  console.log('── relays, Loon and Stash');
  s = await boot();
  try {
    let relayId;
    let farId;
    await check('a relay is saved, validated against the store, and reaches the Clash and Surge files', async () => {
      relayId = (await s.call('POST', '/api/profiles', trojan({ remarks: 'Relay', server: 'relay.example.com' }))).json.savedId;
      const missing = await s.call('POST', '/api/profiles', trojan({ remarks: 'Far', server: 'far.example.com', via: '00000000-0000-4000-8000-000000000000' }));
      assert.strictEqual(missing.status, 400);
      assert.match(missing.json.error, /no longer exists/);
      const far = await s.call('POST', '/api/profiles', trojan({ remarks: 'Far', server: 'far.example.com', via: relayId }));
      assert.strictEqual(far.status, 200, far.text);
      farId = far.json.savedId;
      // A relay cannot itself be relayed, nor can a relayed server be a relay.
      const loop = await s.call('POST', '/api/profiles', { ...far.json.profiles.find((p) => p.id === relayId), via: farId });
      assert.strictEqual(loop.status, 400);
      const clash = await s.call('GET', '/api/download/clash');
      assert.match(clash.text, /name: "Far"[\s\S]*?dialer-proxy: "Relay"/);
      const surge = await s.call('GET', '/api/download/surge');
      assert.match(surge.text, /^Far = trojan, .*underlying-proxy=Relay$/m);
    });

    await check('the URI feed leaves a relayed server out; a broken relay is explained in /api/config', async () => {
      const cfg = (await s.call('GET', '/api/config')).json;
      const feed = await s.call('GET', `${cfg.subscriptionPath}`);
      const links = Buffer.from(feed.text, 'base64').toString();
      assert.ok(links.includes('relay.example.com') && !links.includes('far.example.com'));
      assert.strictEqual((await s.call('POST', '/api/profiles', trojan({ remarks: 'Spare', server: 'spare.example.com' }))).status, 200);
      await s.call('POST', `/api/profiles/${relayId}/enabled`, { enabled: false });
      const after = (await s.call('GET', '/api/config')).json;
      assert.match(after.relayProblems[farId], /is disabled/);
      assert.ok(after.clientSupport.clash.skipped.some((x) => x.name === 'Far'));
      await s.call('POST', `/api/profiles/${relayId}/enabled`, { enabled: true });
    });

    await check('Loon and Stash are downloadable and subscribable', async () => {
      const cfg = (await s.call('GET', '/api/config')).json;
      assert.ok(cfg.subscriptionTargets.includes('loon') && cfg.subscriptionTargets.includes('stash'));
      assert.ok(cfg.clientSupport.loon && cfg.clientSupport.stash);
      const loon = await s.call('GET', '/api/download/loon');
      assert.strictEqual(loon.status, 200);
      assert.match(loon.headers['content-disposition'], /loon\.conf/);
      assert.match(loon.text, /^Relay = Trojan,relay\.example\.com,443,"pw-trojan"/m);
      assert.match(loon.text, /# Far: skipped — Loon cannot dial one server through another/);
      const stash = await s.call('GET', `${cfg.subscriptionPath}?target=stash`);
      assert.strictEqual(stash.status, 200);
      assert.match(stash.headers['content-type'], /yaml/);
      const doc = require(path.join(ROOT, 'web-ui', 'node_modules', 'js-yaml')).load(stash.text);
      assert.ok(doc.proxies.some((p) => p.name === 'Relay'));
      assert.strictEqual((await s.call('GET', `${cfg.subscriptionPath}?target=loon`)).status, 200);
    });
  } finally { s.stop(); }

  // ── Probe agents ─────────────────────────────────────────────────────────── //
  console.log('── probe agents');
  const hooks = [];
  const hook = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { hooks.push(JSON.parse(b)); res.writeHead(200); res.end('{}'); }); });
  await new Promise((r) => hook.listen(0, '127.0.0.1', r));
  // A TCP port that answers, standing in for a reachable server.
  const alive = net.createServer((sock) => sock.end());
  await new Promise((r) => alive.listen(0, '127.0.0.1', r));
  s = await boot();
  try {
    let token;
    let deviceId;
    let upId;
    let downId;
    await check('a device token lists its servers for an agent, and a report is stored and shown', async () => {
      upId = (await s.call('POST', '/api/profiles', { protocol: 'shadowsocks', server: '127.0.0.1', port: alive.address().port, password: 'p', method: 'aes-256-gcm', plugin: '', remarks: 'Up' })).json.savedId;
      downId = (await s.call('POST', '/api/profiles', { protocol: 'shadowsocks', server: '127.0.0.1', port: 9, password: 'p', method: 'aes-256-gcm', plugin: '', remarks: 'Down' })).json.savedId;
      await s.call('POST', '/api/monitor', { alert: { enabled: true, url: `http://127.0.0.1:${hook.address().port}/hook`, mode: 'json' } });
      const dev = await s.call('POST', '/api/clients', { name: 'Home in Shanghai' });
      token = dev.json.created.path.split('/').pop();
      deviceId = dev.json.created.id;
      const list = await s.call('GET', `/api/subscription/${token}/profiles`);
      assert.strictEqual(list.status, 200);
      assert.strictEqual(list.json.reporter, 'Home in Shanghai');
      assert.deepStrictEqual(list.json.profiles.map((p) => p.remarks).sort(), ['Down', 'Up']);
      assert.strictEqual((await s.call('GET', '/api/subscription/wrong-token-0000000000/profiles')).status, 404);
    });

    await check('gen.js --agent probes from its own machine and reports back; a down server is a heads-up, once', async () => {
      const url = `http://127.0.0.1:${s.port}/api/subscription/${token}`;
      const run = spawnSync(process.execPath, [path.join(ROOT, 'config-gen', 'gen.js'), '--agent', url], {
        encoding: 'utf8', timeout: 60000, env: { ...process.env, CFG_PATH: path.join(s.dir, 'nothing-here.json'), OUTBOUND_PROXY: '' },
      });
      assert.match(run.stdout, /1\/2 reachable from here — reported to the dashboard/, run.stdout + run.stderr);
      const cfg = (await s.call('GET', '/api/config')).json;
      const v = cfg.vantage.find((x) => x.id === deviceId);
      assert.ok(v, 'the report is in /api/config');
      assert.strictEqual(v.name, 'Home in Shanghai');
      assert.strictEqual(v.results.find((r) => r.id === upId).ok, true);
      assert.strictEqual(v.results.find((r) => r.id === downId).ok, false);
      for (let i = 0; i < 50 && !hooks.length; i += 1) await new Promise((r) => setTimeout(r, 100));
      assert.strictEqual(hooks.length, 1);
      assert.match(hooks[0].text, /"Down" is unreachable from Home in Shanghai/);
      // A second identical report says nothing new.
      spawnSync(process.execPath, [path.join(ROOT, 'config-gen', 'gen.js'), '--agent', url], { encoding: 'utf8', timeout: 60000, env: { ...process.env, OUTBOUND_PROXY: '' } });
      await new Promise((r) => setTimeout(r, 500));
      assert.strictEqual(hooks.length, 1);
    });

    await check('a report cannot name servers outside its token, and revoking the token drops its reports', async () => {
      const r = await s.call('POST', `/api/subscription/${token}/report`, { results: [{ id: '00000000-0000-4000-8000-000000000000', ok: false }] });
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.json.stored, 0);
      assert.strictEqual((await s.call('POST', `/api/subscription/${token}/report`, { nope: 1 })).status, 400);
      await s.call('DELETE', `/api/clients/${deviceId}`);
      const cfg = (await s.call('GET', '/api/config')).json;
      assert.ok(!cfg.vantage.some((x) => x.id === deviceId));
    });
  } finally { s.stop(); }

  // ── Off-machine backups and the outbound proxy ───────────────────────────── //
  console.log('── off-machine backup, outbound proxy');
  const puts = [];
  let davStatus = 201;
  const dav = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { puts.push({ method: req.method, url: req.url, auth: req.headers.authorization, body: b }); res.writeHead(davStatus); res.end(); }); });
  await new Promise((r) => dav.listen(0, '127.0.0.1', r));
  s = await boot({ OUTBOUND_PROXY: 'http://127.0.0.1:7890' });
  try {
    await check('backup settings save without echoing the credential; Push now lands an encrypted snapshot', async () => {
      await s.call('POST', '/api/profiles', trojan());
      const bad = await s.call('POST', '/api/backup-remote', { url: 'http://169.254.169.254/' });
      assert.strictEqual(bad.status, 400);
      const saved = await s.call('POST', '/api/backup-remote', { enabled: true, url: `http://127.0.0.1:${dav.address().port}/dav/`, mode: 'put', auth: 'me:secret', everyHours: 12 });
      assert.strictEqual(saved.status, 200, saved.text);
      assert.strictEqual(saved.json.remoteBackup.authSet, true);
      assert.ok(!JSON.stringify(saved.json.remoteBackup).includes('secret'));
      // A save that leaves auth out keeps it.
      const again = await s.call('POST', '/api/backup-remote', { everyHours: 6 });
      assert.strictEqual(again.json.remoteBackup.authSet, true);
      assert.strictEqual(again.json.remoteBackup.everyHours, 6);
      const pushed = await s.call('POST', '/api/backup-remote/push');
      assert.strictEqual(pushed.status, 200, pushed.text);
      assert.strictEqual(puts[0].method, 'PUT');
      assert.match(puts[0].url, /^\/dav\/\d{13}-[0-9a-f]{16}\.enc$/);
      assert.strictEqual(puts[0].auth, `Basic ${Buffer.from('me:secret').toString('base64')}`);
      assert.ok(!puts[0].body.includes('pw-trojan'));
      assert.strictEqual(pushed.json.remoteBackup.last.ok, true);
      davStatus = 500;
      const failed = await s.call('POST', '/api/backup-remote/push');
      assert.strictEqual(failed.status, 502);
      assert.match(failed.json.error, /answered 500/);
    });

    await check('/api/config says how outbound requests leave', async () => {
      const cfg = (await s.call('GET', '/api/config')).json;
      assert.strictEqual(cfg.outbound.mode, 'proxy');
      assert.match(cfg.outbound.label, /127\.0\.0\.1:7890/);
    });
  } finally { s.stop(); dav.close(); hook.close(); alive.close(); }

  // ── Servers deploy.sh looks after ─────────────────────────────────────────── //
  console.log('── deploy.sh servers');
  s = await boot();
  try {
    const hostId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
    await check('/api/config shows each recorded server, the profiles behind it and its last --doctor', async () => {
      const added = await s.call('POST', '/api/import', { text: 'hysteria2://pw-host@203.0.113.9:443/?insecure=1#Airport%20Hysteria2' });
      assert.strictEqual(added.status, 200, added.text);
      // Written the way hosts.js writes them for deploy.sh, while the dashboard runs.
      const file = path.join(s.dir, 'servers.json');
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      raw.hosts = [{ id: hostId, target: 'ubuntu@203.0.113.9', port: 2222, addresses: ['203.0.113.9'], options: ['ProxyCommand=id'] }];
      fs.writeFileSync(file, JSON.stringify(raw));
      fs.writeFileSync(path.join(s.dir, 'monitor-state.json'), JSON.stringify({ doctor: { [hostId]: { at: Date.now(), ok: false, exitCode: 1, passed: 4, failures: ['host: a reboot is pending'], notes: [] } } }));
      const cfg = (await s.call('GET', '/api/config')).json;
      assert.strictEqual(cfg.hosts.length, 1);
      const h = cfg.hosts[0];
      assert.strictEqual(h.target, 'ubuntu@203.0.113.9');
      assert.strictEqual(h.options, undefined, 'an option that runs commands never reaches the page, or deploy.sh');
      assert.deepStrictEqual(h.profiles.map((p) => p.remarks), ['Airport Hysteria2']);
      assert.strictEqual(h.doctor.ok, false);
      assert.deepStrictEqual(h.doctor.failures, ['host: a reboot is pending']);
    });

    await check('forgetting a server drops its record and its doctor result, and leaves its profiles', async () => {
      const gone = await s.call('DELETE', `/api/hosts/${hostId}`);
      assert.strictEqual(gone.status, 200, gone.text);
      assert.strictEqual(gone.json.forgotten, 'ubuntu@203.0.113.9');
      assert.deepStrictEqual(gone.json.hosts, []);
      assert.strictEqual(gone.json.profiles.length, 1);
      const state = JSON.parse(fs.readFileSync(path.join(s.dir, 'monitor-state.json'), 'utf8'));
      assert.deepStrictEqual(state.doctor, {});
      assert.strictEqual((await s.call('DELETE', `/api/hosts/${hostId}`)).status, 404);
    });

    await check('forgetting is a write, so another site cannot do it', async () => {
      const r = await s.call('DELETE', `/api/hosts/${hostId}`, undefined, { 'Sec-Fetch-Site': 'cross-site' });
      assert.strictEqual(r.status, 403);
    });
  } finally { s.stop(); }

  console.log(`\n${passed} passed${process.exitCode ? ', with failures' : ''}`);
})().catch((err) => { console.error(err); process.exit(1); });
