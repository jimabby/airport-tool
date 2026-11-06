'use strict';

// The dashboard side of AnyTLS, ShadowTLS, mux, the WARP exit and the provider
// usage badge: what the API stores, what the feed hands out, and that a rules
// save never throws away a WARP identity. Cloudflare is never contacted — the
// registration goes to a local stand-in through WARP_API_URL.

const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { spawn } = require('child_process');
const C = require('../../config-gen/lib/configs');
const B = require('../../config-gen/lib/storage');

const root = path.resolve(__dirname, '../..');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-features-'));
const cfg = path.join(dir, 'servers.json');
const token = 'test-only-dashboard-token';
const subToken = 'test-only-subscription-token';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let app, provider, warpApi;

async function listen(server) {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server.address().port;
}

async function main() {
  // A provider feed with a plan, and a fake WARP registration endpoint.
  const feedProfile = C.normalizeProfile({ protocol: 'anytls', server: 'p.example.com', port: 443, password: 'pw', sni: 'p.example.com', remarks: 'Prov' });
  provider = http.createServer((_req, res) => {
    res.writeHead(200, { 'subscription-userinfo': 'upload=100; download=200; total=1000; expire=4102444800' });
    res.end(C.buildUri(feedProfile));
  });
  const providerPort = await listen(provider);
  let warpCalls = 0;
  warpApi = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      warpCalls += 1;
      const key = JSON.parse(body).key;
      assert.ok(C.wgKeyOk(key));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ config: {
        client_id: Buffer.from([4, 5, 6]).toString('base64'),
        peers: [{ public_key: C.WARP_PUBLIC_KEY }],
        interface: { addresses: { v4: '172.16.0.2', v6: '2606:4700:110:8a1a::1' } },
      } }));
    });
  });
  const warpPort = await listen(warpApi);

  B.save(cfg, B.track(C.normalizeStore({ profiles: [], token: subToken, uiToken: token }), null));
  const reservation = http.createServer();
  const port = await listen(reservation);
  await new Promise((r) => reservation.close(r));
  app = spawn(process.execPath, [path.join(root, 'web-ui/server.js')], {
    env: { ...process.env, CFG_PATH: cfg, PORT: String(port), HOST: '127.0.0.1', UI_TOKEN: token,
      PUBLIC_URL: '', TLS_CERT: '', TLS_KEY: '', TLS_SELFSIGNED: '', SHOW_TOKEN: '',
      WARP_API_URL: `http://127.0.0.1:${warpPort}/reg` },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  const call = async (url, method = 'GET', body, { auth = true, raw = false } = {}) => {
    const res = await fetch(`http://127.0.0.1:${port}${url}`, {
      method,
      headers: { ...(auth ? { 'X-UI-Token': token } : {}), 'Content-Type': 'application/json' },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    if (raw) return res;
    const text = await res.text();
    let data; try { data = JSON.parse(text); } catch { data = text; }
    return { status: res.status, data };
  };
  for (let i = 0; ; i++) { try { await call('/api/config'); break; } catch (e) { if (i > 100) throw e; await sleep(100); } }

  // ── Profiles: AnyTLS, ShadowTLS, mux ──
  let r = await call('/api/profiles', 'POST', { protocol: 'anytls', server: 'a.example.com', port: 443, password: 'pw', insecure: true, remarks: 'Mine' });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  const key = Buffer.alloc(16, 1).toString('base64');
  r = await call('/api/profiles', 'POST', {
    protocol: 'shadowsocks', server: '1.2.3.4', port: 443, method: '2022-blake3-aes-128-gcm', password: key,
    plugin: 'shadow-tls', plugin_opts: 'server;host=www.microsoft.com;password=st;version=3', mux: true, remarks: 'STLS',
  });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  const stls = r.data.profiles.find((p) => p.remarks === 'STLS');
  assert.equal(stls.mux, true);
  r = await call('/api/profiles', 'POST', { protocol: 'hysteria2', server: 'h.example.com', port: 443, password: 'x', mux: true });
  assert.equal(r.status, 400);
  assert.match(r.data.error, /QUIC/);
  let res = await call('/api/download/singbox', 'GET', undefined, { raw: true });
  const sb = JSON.parse(await res.text());
  assert.ok(sb.outbounds.some((o) => o.type === 'shadowtls'));
  assert.ok(sb.outbounds.some((o) => o.type === 'anytls'));
  res = await call('/api/download/clash', 'GET', undefined, { raw: true });
  assert.match(await res.text(), /type: "anytls"/);
  console.log('✓ AnyTLS and ShadowTLS profiles save and export; mux is refused where it cannot work');

  // ── Usage badge: only for a feed that is all one provider ──
  res = await call(`/api/subscription/${subToken}`, 'GET', undefined, { auth: false, raw: true });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('subscription-userinfo'), null);
  r = await call('/api/sources', 'POST', { name: 'Prov', url: `http://127.0.0.1:${providerPort}/sub` });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  // Mixed with my own servers: no single plan to describe.
  res = await call(`/api/subscription/${subToken}`, 'GET', undefined, { auth: false, raw: true });
  assert.equal(res.headers.get('subscription-userinfo'), null);
  // A device limited to the provider's server gets the provider's figures.
  const provId = r.data.profiles.find((p) => p.source).id;
  r = await call('/api/clients', 'POST', { name: 'Phone', profiles: [provId] });
  const devicePath = r.data.created.path;
  res = await call(devicePath, 'GET', undefined, { auth: false, raw: true });
  assert.equal(res.headers.get('subscription-userinfo'), 'upload=100; download=200; total=1000; expire=4102444800');
  console.log('✓ the provider plan reaches the client badge only when the feed is all that provider');

  // ── WARP ──
  r = await call('/api/warp/register', 'POST', {});
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(warpCalls, 1);
  assert.equal(r.data.rules.warp.enabled, true);
  assert.deepEqual(r.data.rules.warp.reserved, [4, 5, 6]);
  const privateKey = r.data.rules.warp.privateKey;
  assert.ok(C.wgKeyOk(privateKey));
  // A rules save from an older page, without `warp`, keeps the identity.
  r = await call('/api/rules', 'POST', { direct: 'mybank.com' });
  assert.equal(r.status, 200);
  assert.equal(r.data.rules.warp.privateKey, privateKey);
  // The page's save — sites, domains, switch, no key — merges into it.
  r = await call('/api/rules', 'POST', { warp: { enabled: true, sites: 'netflix', domains: 'claude.ai' } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.rules.warp.privateKey, privateKey);
  assert.deepEqual(r.data.rules.warp.sites, ['netflix']);
  r = await call('/api/rules', 'POST', { warp: { enabled: true, sites: 'not a list' } });
  assert.equal(r.status, 400);
  res = await call('/api/download/clash', 'GET', undefined, { raw: true });
  const clash = await res.text();
  assert.match(clash, /dialer-proxy: "PROXY"/);
  assert.match(clash, /"DOMAIN-SUFFIX,claude\.ai,Unlock"/);
  res = await call(`/api/subscription/${subToken}?target=singbox`, 'GET', undefined, { auth: false, raw: true });
  const feed = JSON.parse(await res.text());
  assert.equal(feed.endpoints[0].detour, 'proxy');
  // Switching it off keeps the key for later.
  r = await call('/api/rules', 'POST', { warp: { enabled: false } });
  assert.equal(r.data.rules.warp.enabled, false);
  assert.equal(r.data.rules.warp.privateKey, privateKey);
  assert.equal((await call('/api/warp/register', 'POST', {}, { auth: false })).status, 401);
  console.log('✓ WARP registers, survives rules saves, reaches both bundles and switches off without losing its key');
}

main().then(() => console.log('Feature tests passed')).catch((err) => { console.error(err); process.exitCode = 1; }).finally(async () => {
  if (app && app.exitCode === null) { app.kill(); await new Promise((r) => app.once('exit', r)); }
  for (const server of [provider, warpApi]) if (server) { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
  const resolved = path.resolve(dir);
  assert.ok(resolved.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(resolved).startsWith('airport-features-'));
  fs.rmSync(resolved, { recursive: true, force: true });
});
