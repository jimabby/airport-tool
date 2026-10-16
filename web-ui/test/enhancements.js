'use strict';

const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const dns = require('dns');
const { spawn, execFile } = require('child_process');
const C = require('../../config-gen/lib/configs');
const S = require('../../config-gen/lib/sources');
const B = require('../../config-gen/lib/storage');
const N = require('../../config-gen/lib/network');
const P = require('../../config-gen/lib/probe');

const root = path.resolve(__dirname, '../..');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-enhancements-'));
const cfg = path.join(dir, 'servers.json');
const token = 'test-only-dashboard-token';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const profile = (remarks, extra = {}) => C.normalizeProfile({ protocol: 'trojan', server: 'example.com', port: 443, password: remarks, sni: 'example.com', remarks, ...extra });
let app, provider, origin;

async function main() {
  // Literal and DNS aliases are validated at the socket lookup boundary.
  for (const address of ['169.254.169.254', '::ffff:169.254.169.254', 'fe90::1', 'fd00:ec2::254']) assert.ok(N.addressProblem(address));
  assert.equal(N.addressProblem('127.0.0.1'), null);
  assert.equal(N.addressProblem('192.168.1.1'), null);
  const lookup = dns.lookup;
  dns.lookup = (_host, _opts, cb) => cb(null, [{ address: '169.254.169.254', family: 4 }]);
  try {
    await assert.rejects(new Promise((resolve, reject) => N.safeLookup('alias.example', {}, (e, a) => e ? reject(e) : resolve(a))), /metadata/);
    await assert.rejects(N.request('http://alias.example/'), /metadata/);
  } finally { dns.lookup = lookup; }
  console.log('✓ metadata literals and DNS aliases blocked; LAN destinations preserved');

  const a = profile('A'), b = profile('B');
  assert.equal(S.parseSourceBody([C.buildUri(a), C.buildUri(b), C.buildUri(a)].join('\n')).profiles.length, 2);
  const source = C.normalizeSources([{ url: 'http://127.0.0.1/test' }])[0];
  const model = C.normalizeStore({ profiles: [{ ...a, source: source.id }], sources: [source] });
  const preview = S.previewMerge(model, source, [{ ...a, password: 'rotated' }]);
  assert.equal(preview.next.profiles[0].id, a.id);
  assert.deepEqual(preview.changes[0].fields, ['password']);
  assert.equal(model.profiles[0].password, 'A');
  assert.throws(() => C.buildSingBox([profile('X', { protocol: 'vless-reality', network: 'xhttp' })]), /XHTTP/);
  console.log('✓ account deduplication, credential-rotation previews and incompatible export refusal');

  const initial = C.normalizeStore({ profiles: [a, b, profile('C')], active: 1, token: 'test-only-subscription-token', uiToken: token });
  B.save(cfg, B.track(initial, null));
  const raw = B.read(cfg);
  const first = B.track(JSON.parse(raw), raw), stale = B.track(JSON.parse(raw), raw);
  first.title = 'New title'; B.save(cfg, first);
  stale.title = 'Lost update';
  assert.throws(() => B.save(cfg, stale), /changed since/);
  assert.equal(JSON.parse(B.read(cfg)).title, 'New title');
  fs.writeFileSync(`${cfg}.lock`, 'test writer');
  try { assert.throws(() => B.save(cfg, first), /another process/); }
  finally { fs.unlinkSync(`${cfg}.lock`); }
  const snapshot = B.listBackups(cfg)[0];
  assert.equal(B.decryptBackup(cfg, snapshot.id).title, initial.title);
  assert.ok(!fs.readFileSync(B.backupPath(cfg, snapshot.id), 'utf8').includes(token));
  const envelope = JSON.parse(fs.readFileSync(B.backupPath(cfg, snapshot.id), 'utf8'));
  envelope.tag = Buffer.alloc(16).toString('base64');
  fs.writeFileSync(B.backupPath(cfg, snapshot.id), JSON.stringify(envelope));
  assert.throws(() => B.decryptBackup(cfg, snapshot.id));
  assert.throws(() => B.backupPath(cfg, '../servers.json'), /Invalid/);
  for (let i = 0; i < 24; i++) B.snapshot(cfg);
  assert.equal(B.listBackups(cfg).length, 20);
  console.log('✓ stale writes refused, snapshots encrypted/authenticated, retention bounded');

  let active = 0, peak = 0, started = 0;
  const controller = new AbortController();
  const results = await P.mapBounded(Array.from({ length: 50 }), 4, async () => {
    started++; peak = Math.max(peak, ++active); await sleep(20); active--; return { ok: true };
  }, { signal: controller.signal, onProgress: () => controller.abort() });
  assert.equal(peak, 4); assert.equal(started, 4); assert.equal(results.length, 1);
  let release;
  const occupying = P.withDeepSlot(() => new Promise((r) => { release = r; }));
  await sleep(0);
  const queuedAbort = new AbortController();
  let ran = false;
  const queued = P.withDeepSlot(() => { ran = true; }, queuedAbort.signal);
  queuedAbort.abort();
  try {
    await Promise.race([queued, sleep(100).then(() => { throw new Error('Queued cancellation waited for the previous job'); })]);
    assert.equal(ran, false);
  } finally { release(); await occupying; }
  console.log('✓ worker concurrency bounded and cancellation stops queued work');

  let feed = [C.buildUri(profile('Provider'))].join('\n');
  let requests = 0;
  let editDuringFetch = false;
  provider = http.createServer((_req, res) => {
    if (_req.url === '/compressed') {
      res.writeHead(200, { 'Content-Encoding': 'gzip' });
      return res.end(require('zlib').gzipSync(Buffer.from('x'.repeat(1024))));
    }
    requests++;
    if (editDuringFetch) {
      const current = JSON.parse(B.read(cfg)); current.title = 'Concurrent dashboard edit';
      fs.writeFileSync(cfg, JSON.stringify(current)); editDuringFetch = false;
    }
    res.writeHead(200, { 'subscription-userinfo': 'upload=1073741824; download=2147483648; total=10737418240; expire=4102444800' });
    res.end(feed);
  });
  await new Promise((r) => provider.listen(0, '127.0.0.1', r));
  const compressedUrl = `http://127.0.0.1:${provider.address().port}/compressed`;
  assert.equal((await N.request(compressedUrl)).text.length, 1024);
  await assert.rejects(N.request(compressedUrl, { maxBytes: 100 }), /larger than/);
  origin = http.createServer((_req, res) => setTimeout(() => res.writeHead(204).end(), 250));
  await new Promise((r) => origin.listen(0, '127.0.0.1', r));
  const reservation = http.createServer(); await new Promise((r) => reservation.listen(0, '127.0.0.1', r));
  const port = reservation.address().port; await new Promise((r) => reservation.close(r));
  app = spawn(process.execPath, [path.join(root, 'web-ui/server.js')], {
    env: { ...process.env, CFG_PATH: cfg, PORT: String(port), HOST: '127.0.0.1', UI_TOKEN: token,
      PUBLIC_URL: '', TLS_CERT: '', TLS_KEY: '', TLS_SELFSIGNED: '',
      SINGBOX_BIN: process.execPath, SINGBOX_ARGS: JSON.stringify([path.join(__dirname, 'fake-sing-box.js')]),
      FAKE_ORIGIN: String(origin.address().port), DEEP_TEST_URL: 'http://test.invalid/', SHOW_TOKEN: '' }, stdio: ['ignore', 'pipe', 'ignore'],
  });
  let appLog = '';
  app.stdout.on('data', (b) => { appLog += b; });
  const call = async (url, method = 'GET', body, auth = true) => {
    const res = await fetch(`http://127.0.0.1:${port}${url}`, { method, headers: { ...(auth ? { 'X-UI-Token': token } : {}), 'Content-Type': 'application/json' }, ...(body && method !== 'GET' ? { body: JSON.stringify(body) } : {}) });
    const text = await res.text(); let data; try { data = JSON.parse(text); } catch { data = text; }
    return { status: res.status, data };
  };
  for (let i = 0; ; i++) { try { await call('/api/config'); break; } catch (e) { if (i > 100) throw e; await sleep(100); } }
  for (const [url, method] of [['/api/backups', 'GET'], ['/api/backups', 'POST'], ['/api/backups/x/restore', 'POST'], ['/api/profiles/bulk', 'POST'], ['/api/sources/x/preview', 'POST'], ['/api/sources/x/apply', 'POST'], ['/api/tests', 'GET'], ['/api/tests', 'POST'], ['/api/tests/x', 'DELETE']]) assert.equal((await call(url, method, {}, false)).status, 401);
  let response = await call(`/api/profiles/${a.id}`, 'DELETE');
  assert.equal(response.data.activeId, b.id);
  const baseline = (await call('/api/backups', 'POST')).data.id;
  response = await call('/api/profiles/bulk', 'POST', { ids: [b.id], action: 'disable' });
  assert.equal(response.data.profiles.find((p) => p.id === b.id).enabled, false);
  response = await call(`/api/backups/${baseline}/restore`, 'POST');
  assert.equal(response.status, 200); assert.equal(response.data.profiles.find((p) => p.id === b.id).enabled, true);
  assert.equal(response.data.activeId, b.id);
  console.log('✓ new endpoints require auth; deletion preserves preference; bulk edits roll back');

  // The log is not a terminal here, so the tokens stay out of it and go to a
  // 0600 file beside the store instead.
  for (let i = 0; i < 50 && !/Full URLs/.test(appLog); i++) await sleep(100);
  assert.ok(!appLog.includes(token), 'the dashboard token is not in a non-TTY log');
  assert.match(appLog, /dashboard-url\.txt/);
  const access = fs.readFileSync(path.join(dir, 'dashboard-url.txt'), 'utf8');
  assert.match(access, new RegExp(`ui_token=${token}`));
  assert.match(access, /Subscription: http:\/\/127\.0\.0\.1:\d+\/api\/subscription\/test-only-subscription-token/);
  console.log('✓ tokens kept out of a non-interactive log and written to an owner-only file');

  // A bulk action may not switch off (or delete) every enabled server.
  const ids = (await call('/api/config')).data.profiles.map((p) => p.id);
  response = await call('/api/profiles/bulk', 'POST', { ids, action: 'disable' });
  assert.equal(response.status, 409); assert.match(response.data.error, /every enabled server/);
  await call('/api/profiles/bulk', 'POST', { ids: [ids[0]], action: 'disable' });
  response = await call('/api/profiles/bulk', 'POST', { ids: [ids[1]], action: 'delete' });
  assert.equal(response.status, 409);
  await call('/api/profiles/bulk', 'POST', { ids: [ids[0]], action: 'enable' });
  assert.equal((await call('/api/config')).data.enabledCount, ids.length);
  response = await call('/api/import', 'POST', { text: '[null]' });
  assert.equal(response.status, 400); assert.match(response.data.error, /missing server/);
  console.log('✓ bulk actions cannot empty every bundle; a null import is a 400, not a 500');

  // Snapshots: key status, key export, and restoring a snapshot file with it.
  const sealed = (await call('/api/backups', 'POST')).data;
  assert.equal(sealed.backups.find((x) => x.id === sealed.id).readable, true);
  const keyText = (await call('/api/backups/key')).data;
  assert.match(keyText, /^[A-Za-z0-9+/=]{44}\n# fingerprint [0-9a-f]{16}/);
  const sealedFile = fs.readFileSync(B.backupPath(cfg, sealed.id), 'utf8');
  await call('/api/title', 'POST', { title: 'After the snapshot' });
  response = await call('/api/backups/import', 'POST', { snapshot: sealedFile, key: Buffer.alloc(32, 7).toString('base64') });
  assert.equal(response.status, 400); assert.match(response.data.error, /different backup key/);
  response = await call('/api/backups/import', 'POST', { snapshot: '{"plain":"store"}' });
  assert.equal(response.status, 400);
  response = await call('/api/backups/import', 'POST', { snapshot: sealedFile, key: keyText });
  assert.equal(response.status, 200); assert.notEqual(response.data.title, 'After the snapshot');
  response = await call('/api/backups/import', 'POST', { snapshot: sealedFile });
  assert.equal(response.status, 200, 'this machine\'s own key is the default');
  console.log('✓ snapshots report their key; the key exports; a snapshot file restores with it');

  // Ad blocking rides through the rules endpoint into the bundles.
  response = await call('/api/rules', 'POST', { direct: '', proxy: '', block: '', ads: true });
  assert.equal(response.data.rules.ads, true);
  assert.match((await call('/api/download/clash')).data, /GEOSITE,category-ads-all,REJECT/);
  await call('/api/rules', 'POST', { direct: '', proxy: '', block: '', ads: false });
  console.log('✓ the ad-block switch reaches the Clash bundle');

  response = await call('/api/sources', 'POST', { url: `http://127.0.0.1:${provider.address().port}/feed`, requireReview: true });
  const sourceId = response.data.sources[0].id;
  assert.equal(requests, 0);
  const beforePreview = B.read(cfg);
  const plan = (await call(`/api/sources/${sourceId}/preview`, 'POST')).data;
  assert.equal(B.read(cfg), beforePreview);
  assert.ok(plan.changes.some((c) => c.kind === 'added'));
  await call('/api/title', 'POST', { title: 'Changed after preview' });
  assert.equal((await call(`/api/sources/${sourceId}/apply`, 'POST', { previewId: plan.id })).status, 409);
  const nextPlan = (await call(`/api/sources/${sourceId}/preview`, 'POST')).data;
  const beforeApplyRequests = requests;
  response = await call(`/api/sources/${sourceId}/apply`, 'POST', { previewId: nextPlan.id });
  assert.equal(response.status, 200); assert.equal(requests, beforeApplyRequests);
  const imported = response.data.profiles.find((p) => p.source === sourceId);
  assert.deepEqual(response.data.sources.find((s) => s.id === sourceId).usage,
    { upload: 1073741824, download: 2147483648, total: 10737418240, expire: 4102444800000 });
  feed = C.buildUri({ ...imported, password: 'changed-password' });
  const credentialPlan = (await call(`/api/sources/${sourceId}/preview`, 'POST')).data;
  assert.ok(credentialPlan.changes.some((c) => c.fields.includes('password')));
  assert.ok(!JSON.stringify(credentialPlan).includes('changed-password'));
  assert.equal((await call(`/api/sources/${sourceId}/refresh`, 'POST')).status, 409);
  console.log('✓ preview is read-only, stale previews refused, exact reviewed response applied, secrets redacted');

  // Run a copied CLI so its output directory is isolated from real user exports.
  const cli = path.join(dir, 'cli'); fs.mkdirSync(cli);
  fs.copyFileSync(path.join(root, 'config-gen/gen.js'), path.join(cli, 'gen.js'));
  fs.cpSync(path.join(root, 'config-gen/lib'), path.join(cli, 'lib'), { recursive: true });
  await call(`/api/sources/${sourceId}`, 'POST', { requireReview: false });
  editDuringFetch = true;
  await new Promise((resolve, reject) => execFile(process.execPath, [path.join(cli, 'gen.js'), '--config', cfg, '--refresh'], {
    env: { ...process.env, NODE_PATH: path.join(root, 'config-gen/node_modules') }, timeout: 30000,
  }, (err) => err ? reject(err) : resolve()));
  assert.equal(JSON.parse(B.read(cfg)).title, 'Concurrent dashboard edit');
  console.log('✓ CLI refresh preserves edits made during the network request');

  // The monitor sends one heads-up when a provider plan is about to expire.
  const notices = [];
  const hook = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => { b += c; });
    req.on('end', () => { const j = JSON.parse(b); if (j.state === 'notice') notices.push(j); res.end('ok'); });
  });
  await new Promise((r) => hook.listen(0, '127.0.0.1', r));
  try {
    const onDisk = JSON.parse(B.read(cfg));
    onDisk.sources[0].usage = { upload: 0, download: 0, total: null, expire: Date.now() + 2 * 86400000 };
    fs.writeFileSync(cfg, JSON.stringify(onDisk));
    await call('/api/monitor', 'POST', { deep: true, alert: { enabled: true, url: `http://127.0.0.1:${hook.address().port}/` } });
    response = await call('/api/monitor/run', 'POST');
    assert.equal(response.status, 200);
    assert.equal(notices.length, 1, JSON.stringify(response.data.last));
    assert.match(notices[0].text, /plan expires in 2d/);
    await call('/api/monitor/run', 'POST');
    assert.equal(notices.length, 1, 'the same heads-up is not repeated');
    await call('/api/monitor', 'POST', { alert: { enabled: false, url: '' } });
  } finally { hook.close(); }
  console.log('✓ the monitor sends a provider-plan heads-up once');

  for (let i = 0; i < 8; i++) await call('/api/profiles', 'POST', profile(`Probe ${i}`));
  response = await call('/api/tests', 'POST', { deep: true });
  assert.equal(response.status, 202);
  const job = response.data;
  assert.equal((await call('/api/tests', 'POST', { deep: true })).status, 409);
  await sleep(100);
  await call(`/api/tests/${job.id}`, 'DELETE');
  for (let i = 0; ; i++) {
    const current = (await call('/api/tests')).data.job;
    if (current.state === 'cancelled') { assert.ok(current.completed < current.total); break; }
    if (i > 100) throw new Error('Cancellation did not finish');
    await sleep(100);
  }
  console.log('✓ test jobs report progress, reject overlap and cancel active deep probes');

  // SIGTERM finishes cleanly — as PID 1 in a container there is no default
  // action, so without a handler `docker stop` waited and then SIGKILLed.
  // Windows has no catchable SIGTERM, so this is checked where it exists.
  if (process.platform !== 'win32') {
    const exited = new Promise((r) => app.once('exit', (code, signal) => r({ code, signal })));
    app.kill('SIGTERM');
    const { code, signal } = await Promise.race([exited, sleep(6000).then(() => ({ code: 'timeout' }))]);
    assert.equal(code, 0, `exit ${code} ${signal}`);
    assert.ok(!fs.existsSync(`${cfg}.lock`));
    console.log('✓ SIGTERM shuts down cleanly and leaves no lock');
  }
}

main().then(() => console.log('Enhancement regression tests passed')).catch((err) => { console.error(err); process.exitCode = 1; }).finally(async () => {
  if (app && app.exitCode === null) { app.kill(); await new Promise((r) => app.once('exit', r)); }
  for (const server of [provider, origin]) if (server) { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
  const resolved = path.resolve(dir);
  assert.ok(resolved.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(resolved).startsWith('airport-enhancements-'));
  fs.rmSync(resolved, { recursive: true, force: true });
});
