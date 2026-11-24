#!/usr/bin/env node
// Tests for the shared import path, relays, Loon / Stash output, SIP008, share-
// link pins, scoped notices, probe agents' storage, off-machine backups, the
// outbound proxy and the deep probe's certificate reading.
//
// Same harness as test.js: built-in assert, no framework.
'use strict';

const path = require('path');
// The deep probe reads these when probe.js loads, so they are set first: a
// stand-in sing-box (web-ui/test/fake-sing-box.js) run through node.
process.env.SINGBOX_BIN = process.execPath;
process.env.SINGBOX_ARGS = JSON.stringify([path.join(__dirname, '..', 'web-ui', 'test', 'fake-sing-box.js')]);
delete process.env.OUTBOUND_PROXY;
for (const k of ['HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'https_proxy', 'http_proxy', 'all_proxy', 'NO_PROXY', 'no_proxy']) delete process.env[k];

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const yaml = require('js-yaml');
const C = require('./lib/configs');
const K = require('./lib/clients');
const S = require('./lib/sources');
const A = require('./lib/alert');
const H = require('./lib/history');

let passed = 0;
const queue = [];
const test = (name, fn) => queue.push([name, fn]);

const uuid = () => crypto.randomUUID();
const trojan = (over = {}) => C.normalizeProfile({ protocol: 'trojan', server: 't.example.com', port: 443, password: 'pw-trojan', sni: 't.example.com', remarks: 'T', ...over });
const reality = (over = {}) => C.normalizeProfile({
  protocol: 'vless-reality', server: 'r.example.com', port: 443, uuid: uuid(), publicKey: 'A'.repeat(43), shortId: 'abcd', sni: 'www.microsoft.com', remarks: 'R', ...over,
});

// ── Import (dashboard and CLI share it) ────────────────────────────────────── //
test('importText: a pasted sing-box config is read for its outbounds, not taken for a profile', () => {
  const store = C.normalizeStore({ profiles: [] });
  const text = JSON.stringify({ outbounds: [
    { type: 'trojan', tag: 'T1', server: 'a.example.com', server_port: 443, password: 'pw-123456', tls: { enabled: true, server_name: 'a.example.com' } },
    { type: 'direct', tag: 'direct' },
  ] });
  const r = S.importText(store, text);
  assert.deepStrictEqual(r.added, ['T1']);
  assert.strictEqual(r.format, 'singbox');
  assert.strictEqual(store.profiles[0].protocol, 'trojan');
});

test('importText: SIP008 imports every Shadowsocks server, plugin options and all', () => {
  const store = C.normalizeStore({ profiles: [] });
  const text = JSON.stringify({ version: 1, servers: [
    { id: uuid(), remarks: 'S1', server: 's1.example.com', server_port: 8388, password: 'pw-1', method: 'chacha20-ietf-poly1305' },
    { id: uuid(), remarks: 'S2', server: 's2.example.com', server_port: 443, password: 'pw-2', method: 'aes-256-gcm', plugin: 'obfs-local', plugin_opts: 'obfs=tls;obfs-host=x.example.com' },
  ] });
  const r = S.importText(store, text);
  assert.strictEqual(r.format, 'sip008');
  assert.deepStrictEqual(r.added, ['S1', 'S2']);
  assert.strictEqual(store.profiles[1].plugin, 'obfs-local');
  assert.match(store.profiles[1].plugin_opts, /^server;obfs=tls;obfs-host=x\.example\.com$/);
  // The SIP008 entry's own id is not adopted.
  assert.notStrictEqual(store.profiles[0].id, JSON.parse(text).servers[0].id);
});

test('importText: strips a stale source tag, re-ids a clash and keeps ★ on an enabled profile', () => {
  const keep = trojan({ remarks: 'Mine' });
  const store = C.normalizeStore({ profiles: [keep] });
  const copy = trojan({ id: keep.id, server: 'other.example.com', remarks: 'Copy', source: uuid() });
  const r = S.importText(store, JSON.stringify([copy]));
  assert.deepStrictEqual(r.added, ['Copy']);
  const added = store.profiles[1];
  assert.notStrictEqual(added.id, keep.id);
  assert.strictEqual(added.source, undefined);

  // A first import whose leading profile is disabled puts ★ on the enabled one.
  const empty = C.normalizeStore({ profiles: [] });
  S.importText(empty, JSON.stringify([trojan({ remarks: 'Off', enabled: false }), trojan({ remarks: 'On', server: 'on.example.com' })]));
  assert.strictEqual(empty.profiles[empty.active].remarks, 'On');
});

test('importText: a relay in the same paste follows its new id; a dangling one is dropped and said', () => {
  const relay = trojan({ remarks: 'Relay', server: 'relay.example.com' });
  const target = reality({ remarks: 'Target', via: relay.id });
  const store = C.normalizeStore({ profiles: [relay] });
  // Same connection as the stored relay → skipped, but the target still finds it.
  const r = S.importText(store, JSON.stringify([relay, target]));
  assert.deepStrictEqual(r.added, ['Target']);
  assert.strictEqual(store.profiles[1].via, relay.id);

  const lonely = C.normalizeStore({ profiles: [] });
  const r2 = S.importText(lonely, JSON.stringify([reality({ remarks: 'Orphan', via: uuid() })]));
  assert.strictEqual(lonely.profiles[0].via, undefined);
  assert.ok(r2.problems.some((p) => /imported without its relay/.test(p)));
});

test('importText: malformed JSON is a 400-shaped error, not a crash', () => {
  assert.throws(() => S.importText(C.normalizeStore({ profiles: [] }), '{ nope'), (e) => e.status === 400 && /Not valid JSON/.test(e.message));
});

// ── Relays ─────────────────────────────────────────────────────────────────── //
function relayStore() {
  const relay = trojan({ remarks: 'Relay', server: 'relay.example.com' });
  const target = reality({ remarks: 'Target', via: relay.id });
  return { relay, target, profiles: [relay, target] };
}

test('relay: Clash dials through dialer-proxy, Sing-Box through detour, Surge through underlying-proxy', () => {
  const { relay, target, profiles } = relayStore();
  const clash = yaml.load(C.buildClashYaml(profiles));
  const px = clash.proxies.find((p) => p.name === 'Target');
  assert.strictEqual(px['dialer-proxy'], 'Relay');
  const sb = C.buildSingBox(profiles);
  assert.strictEqual(sb.outbounds.find((o) => o.tag === 'Target').detour, 'Relay');
  assert.strictEqual(sb.outbounds.find((o) => o.tag === 'Relay').detour, undefined);
  // Reality cannot be in Surge at all, so chain a Trojan through the Trojan.
  const t2 = trojan({ remarks: 'T2', server: 't2.example.com', via: relay.id });
  const surge = K.buildSurge([relay, t2]).text;
  assert.match(surge, /^T2 = trojan, t2\.example\.com, 443, .*underlying-proxy=Relay$/m);
  assert.ok(target.via);
});

test('relay: a ShadowTLS profile chains its ShadowTLS outbound, not the Shadowsocks one', () => {
  const relay = trojan({ remarks: 'Relay', server: 'relay.example.com' });
  const st = C.normalizeProfile({
    protocol: 'shadowsocks', server: 's.example.com', port: 443, method: '2022-blake3-aes-128-gcm', password: Buffer.alloc(16, 1).toString('base64'),
    plugin: 'shadow-tls', plugin_opts: 'host=www.microsoft.com;password=stpw;version=3', remarks: 'ST', via: relay.id,
  });
  const sb = C.buildSingBox([relay, st]);
  assert.strictEqual(sb.outbounds.find((o) => o.tag === 'ST').detour, 'ST-shadowtls');
  assert.strictEqual(sb.outbounds.find((o) => o.tag === 'ST-shadowtls').detour, 'Relay');
});

test('relay: share links, Quantumult X, Loon and Stash leave a relayed server out, by name', () => {
  const relay = trojan({ remarks: 'Relay', server: 'relay.example.com' });
  const t2 = trojan({ remarks: 'T2', server: 't2.example.com', via: relay.id });
  const links = Buffer.from(C.buildSubscription([relay, t2]), 'base64').toString();
  assert.ok(!/t2\.example\.com/.test(links));
  for (const built of [K.buildQuantumultX([relay, t2]), K.buildLoon([relay, t2]), K.buildStash([relay, t2])]) {
    assert.strictEqual(built.usable, 1);
    assert.match(built.skipped[0].reason, /cannot dial one server through another/);
  }
});

test('relay: a missing, disabled or chained relay keeps the server out of every bundle', () => {
  const relay = trojan({ remarks: 'Relay', server: 'relay.example.com', enabled: false });
  const keep = trojan({ remarks: 'Keep', server: 'keep.example.com' });
  const t = trojan({ remarks: 'Chained', server: 'c.example.com', via: relay.id });
  assert.match(C.relayProblem([relay, keep, t], t), /is disabled/);
  assert.ok(!C.buildClashConfig([relay, keep, t]).proxies.some((p) => p.name === 'Chained'));
  assert.match(C.relayProblem([keep, t], t), /no longer exists/);
  const hop = trojan({ remarks: 'Hop', server: 'h.example.com', via: keep.id });
  const deep = trojan({ remarks: 'Deep', server: 'd.example.com', via: hop.id });
  assert.match(C.relayProblem([keep, hop, deep], deep), /only one hop/);
  const sum = K.supportSummary([keep, hop, deep]);
  assert.ok(sum.clash.skipped.some((s) => s.name === 'Deep'));
  // normalizeProfile never lets a profile relay through itself.
  const self = C.normalizeProfile({ ...keep, via: keep.id });
  assert.strictEqual(self.via, undefined);
});

test('relay: a QUIC server through a TCP-only relay is warned about', () => {
  const ws = C.normalizeProfile({ protocol: 'shadowsocks', server: 'w.example.com', port: 80, password: 'p', method: 'chacha20-ietf-poly1305', plugin: 'v2ray-plugin', plugin_opts: 'server', remarks: 'WS' });
  const hy = C.normalizeProfile({ protocol: 'hysteria2', server: 'h.example.com', port: 443, password: 'p', insecure: true, remarks: 'HY', via: ws.id });
  assert.match(C.relayWarnings([ws, hy], hy)[0], /carries TCP only/);
});

// ── Share-link certificate pins ────────────────────────────────────────────── //
test('pins: Trojan and VLESS + TLS links carry pcs, and read it back', () => {
  const pin = 'ab'.repeat(32);
  const t = trojan({ pinSha256: pin, insecure: true });
  const link = C.buildUri(t);
  assert.match(link, new RegExp(`[?&]pcs=${pin}`));
  assert.strictEqual(C.parseUri(link).pinSha256, pin);
  const v = C.normalizeProfile({ protocol: 'vless-tls', server: 'v.example.com', port: 443, uuid: uuid(), sni: 'v.example.com', pinSha256: pin, remarks: 'V' });
  assert.strictEqual(C.parseUri(C.buildUri(v)).pinSha256, pin);
  // A provider's unusable pin is dropped rather than making the link fail.
  const odd = C.parseUri('trojan://pw@t.example.com:443?security=tls&sni=t.example.com&pcs=not-a-pin#X');
  assert.strictEqual(odd.pinSha256, undefined);
  assert.deepStrictEqual(C.validateProfile(odd).errors, []);
});

// ── Surge / Quantumult X names a parser would read as a comment ─────────────── //
test('line formats: a name starting with # or ; is refused by name instead of vanishing', () => {
  const p = trojan({ remarks: '# Tokyo' });
  const q = trojan({ remarks: '; Osaka', server: 'o.example.com' });
  const surge = K.buildSurge([p, q]);
  assert.strictEqual(surge.usable, 0);
  assert.match(surge.skipped[0].reason, /comment character/);
  const qx = K.buildQuantumultX([p, q]);
  assert.strictEqual(qx.usable, 0);
});

// ── Loon ───────────────────────────────────────────────────────────────────── //
test('Loon: writes each protocol it documents, quotes secrets, and names what it cannot carry', () => {
  const ss = C.normalizeProfile({ protocol: 'shadowsocks', server: 's.example.com', port: 8388, password: 'pa,ss', method: 'aes-256-gcm', plugin: '', remarks: 'SS' });
  const hy = C.normalizeProfile({ protocol: 'hysteria2', server: 'h.example.com', port: 443, password: 'hp', sni: 'h.example.com', obfs: 'salamander', obfsPassword: 'op', ports: '20000-30000', down: 100, remarks: 'HY' });
  const r = reality({ remarks: 'R' });
  const tu = C.normalizeProfile({ protocol: 'tuic', server: 'u.example.com', port: 443, uuid: uuid(), password: 'x', insecure: true, remarks: 'TU' });
  const out = K.buildLoon([ss, hy, r, trojan({ pinSha256: 'cd'.repeat(32) }), tu], { title: 'Mine' });
  assert.match(out.text, /^SS = Shadowsocks,s\.example\.com,8388,aes-256-gcm,"pa,ss",udp=true$/m);
  assert.match(out.text, /^HY = Hysteria2,h\.example\.com,443,"hp",sni=h\.example\.com,skip-cert-verify=false,salamander-password="op",server-ports="20000:30000",hop-interval=30,download-bandwidth=100,udp=true$/m);
  assert.match(out.text, /^R = VLESS,r\.example\.com,443,"[0-9a-f-]+",transport=tcp,flow=xtls-rprx-vision,public-key="A+",short-id=abcd,over-tls=true,sni=www\.microsoft\.com,udp=true$/m);
  assert.match(out.text, /tls-cert-sha256=(cd){32}/);
  assert.strictEqual(out.usable, 4);
  assert.match(out.skipped[0].reason, /TUIC/);
  assert.match(out.text, /^Auto = url-test,SS,HY,R,T,url=http:\/\/www\.gstatic\.com\/generate_204,interval=300,tolerance=50$/m);
  assert.match(out.text, /^PROXY = select,Auto,Fallback,SS,HY,R,T,DIRECT$/m);
  assert.match(out.text, /^FINAL,PROXY$/m);
  // A double quote in a quoted value cannot be escaped in Loon's format.
  const bad = K.buildLoon([trojan({ password: 'a"b' })]);
  assert.match(bad.skipped[0].reason, /double quote/);
});

// ── Stash ──────────────────────────────────────────────────────────────────── //
test('Stash: Clash YAML with Stash spellings, no mux, and no transport it lacks', () => {
  const hy = C.normalizeProfile({ protocol: 'hysteria2', server: 'h.example.com', port: 443, password: 'hp', insecure: true, up: 20, down: 100, remarks: 'HY' });
  const tu = C.normalizeProfile({ protocol: 'tuic', server: 'u.example.com', port: 443, uuid: uuid(), password: 'x', insecure: true, remarks: 'TU' });
  const pinned = trojan({ pinSha256: 'ef'.repeat(32), mux: true });
  const hu = trojan({ remarks: 'HU', server: 'hu.example.com', network: 'httpupgrade', path: '/x' });
  const out = K.buildStash([hy, tu, pinned, hu], { rules: { ads: true } });
  const doc = yaml.load(out.text);
  const byName = Object.fromEntries(doc.proxies.map((p) => [p.name, p]));
  assert.strictEqual(byName.HY.auth, 'hp');
  assert.strictEqual(byName.HY.password, undefined);
  assert.strictEqual(byName.HY['down-speed'], 100);
  assert.strictEqual(byName.TU.version, 5);
  assert.strictEqual(byName.T['server-cert-fingerprint'], 'ef'.repeat(32));
  assert.strictEqual(byName.T.fingerprint, undefined);
  assert.strictEqual(byName.T.smux, undefined);
  assert.ok(!byName.HU);
  assert.match(out.skipped[0].reason, /HTTPUpgrade/);
  assert.ok(doc.rules.includes('GEOSITE,category-ads-all,REJECT'));
  assert.strictEqual(doc.rules[doc.rules.length - 1], 'MATCH,PROXY');
  assert.ok(!('geox-url' in doc) && !('sniffer' in doc));
  assert.deepStrictEqual(doc['proxy-groups'].map((g) => g.name), ['PROXY', 'Auto', 'Fallback']);
});

// ── Notices are settled only within the caller's own kinds ─────────────────── //
test('notices: a scoped settle keeps the kinds it did not compute', () => {
  const sent = { 'review:s1:abc': 1, 'vantage:d1:p1': 2, 'cert:p1:1:expiring': 3, 'plan:s1:9:expiring': 4 };
  const kept = A.settleNotices([], sent, [], 5, ['cert', 'plan', 'quota']);
  assert.deepStrictEqual(Object.keys(kept).sort(), ['review:s1:abc', 'vantage:d1:p1']);
  // Unscoped is the old full settle: nothing current, nothing kept.
  assert.deepStrictEqual(A.settleNotices([], sent, []), {});
});

test('notices: a server a probe agent cannot reach is a heads-up, once per agent and server', () => {
  const n = A.notices({ vantage: [{ id: 'd1', name: 'Home in Shanghai', at: Date.UTC(2026, 10, 19), results: [
    { id: 'p1', remarks: 'Tokyo', ok: false, enabled: true },
    { id: 'p2', remarks: 'Osaka', ok: true, enabled: true },
    { id: 'p3', remarks: 'Old', ok: false, enabled: false },
  ] }] });
  assert.strictEqual(n.length, 1);
  assert.strictEqual(n[0].key, 'vantage:d1:p1');
  assert.match(n[0].text, /"Tokyo" is unreachable from Home in Shanghai \(reported 2026-11-19\)/);
});

// ── Probe-agent reports ────────────────────────────────────────────────────── //
test('vantage: reports are checked, trimmed and pruned with their token', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-vantage-'));
  const p = path.join(dir, 'vantage.json');
  const good = uuid();
  const v = H.recordVantage(p, { id: 'd1', name: 'Pi' }, { deep: true, results: [
    { id: good, ok: true, latencyMs: 41.6, stage: 'tcp', message: 'fine\nreally' },
    { id: 'not-a-uuid', ok: false },
    null,
  ] });
  assert.strictEqual(v.results.length, 1);
  assert.deepStrictEqual(v.results[0], { id: good, ok: true, latencyMs: 42, stage: 'tcp', message: 'fine really' });
  assert.strictEqual(H.loadVantage(p).d1.deep, true);
  H.recordVantage(p, { id: 'd2', name: 'Other' }, { results: [] });
  H.pruneVantage(p, ['d2']);
  assert.deepStrictEqual(Object.keys(H.loadVantage(p)), ['d2']);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ── Off-machine backups ────────────────────────────────────────────────────── //
test('remote backup: settings are normalised, and a metadata URL is never kept', () => {
  assert.deepStrictEqual(C.normalizeRemoteBackup({ enabled: true, url: 'http://169.254.169.254/x' }),
    { enabled: false, url: '', mode: 'put', auth: '', everyHours: 24 });
  const ok = C.normalizeRemoteBackup({ enabled: 'true', url: ' https://dav.example.com/a/ ', mode: 'post', auth: 'u:p\n', everyHours: 999 });
  assert.deepStrictEqual(ok, { enabled: true, url: 'https://dav.example.com/a/', mode: 'post', auth: 'u:p', everyHours: 168 });
  assert.ok('backup' in C.normalizeStore({ profiles: [] }));
});

test('remote backup: PUT lands an encrypted snapshot with Basic auth; unchanged is not re-sent; failure is recorded', async () => {
  const R = require('./lib/remote-backup');
  const B = require('./lib/storage');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-remote-'));
  const cfgPath = path.join(dir, 'servers.json');
  const statePath = path.join(dir, 'monitor-state.json');
  fs.writeFileSync(cfgPath, JSON.stringify(C.normalizeStore({ profiles: [trojan()], token: C.newToken(), uiToken: C.newToken() }), null, 2));
  const seen = [];
  let status = 201;
  const dav = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => { seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, body }); res.writeHead(status); res.end(); });
  });
  await new Promise((r) => dav.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${dav.address().port}/airport/`;
  try {
    const r1 = await R.push(cfgPath, { enabled: true, url, auth: 'me:secret' }, { statePath });
    assert.strictEqual(r1.ok, true, r1.error);
    assert.strictEqual(seen[0].method, 'PUT');
    assert.match(seen[0].url, /^\/airport\/\d{13}-[0-9a-f]{16}\.enc$/);
    assert.strictEqual(seen[0].auth, `Basic ${Buffer.from('me:secret').toString('base64')}`);
    const env = JSON.parse(seen[0].body);
    assert.strictEqual(env.version, 1);
    assert.ok(!seen[0].body.includes('pw-trojan'), 'the snapshot must be encrypted');
    // It opens with this store's key.
    assert.strictEqual(B.decryptEnvelope(env, Buffer.from(B.exportKey(cfgPath).key, 'base64')).profiles[0].password, 'pw-trojan');
    const r2 = await R.push(cfgPath, { enabled: true, url }, { statePath });
    assert.strictEqual(r2.unchanged, true);
    assert.strictEqual(seen.length, 1);
    assert.strictEqual(R.isDue({ enabled: true, url, everyHours: 24 }, H.loadState(statePath).remoteBackup), false);
    status = 403;
    const r3 = await R.push(cfgPath, { enabled: true, url, mode: 'post', auth: 'Bearer abc' }, { statePath, force: true });
    assert.strictEqual(r3.ok, false);
    assert.match(r3.error, /403 — check the credentials/);
    assert.strictEqual(seen[1].method, 'POST');
    assert.strictEqual(seen[1].auth, 'Bearer abc');
    assert.strictEqual(JSON.parse(seen[1].body).snapshot.version, 1);
    assert.strictEqual(H.loadState(statePath).remoteBackup.ok, false);
    // A failed push is retried after the short wait, not a whole period.
    assert.strictEqual(R.isDue({ enabled: true, url, everyHours: 24 }, { ok: false, at: Date.now() - R.RETRY_MS - 1 }), true);
  } finally { dav.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

// ── The outbound proxy ─────────────────────────────────────────────────────── //
test('outbound: OUTBOUND_PROXY, the standard variables, NO_PROXY and local destinations', async () => {
  const O = require('./lib/outbound');
  const u = (s) => new URL(s);
  try {
    assert.strictEqual(await O.proxyFor(u('https://sub.example.com/')), null);
    process.env.HTTPS_PROXY = 'http://127.0.0.1:7890';
    assert.strictEqual(await O.proxyFor(u('https://sub.example.com/')), 'http://127.0.0.1:7890');
    assert.strictEqual(await O.proxyFor(u('http://sub.example.com/')), null, 'HTTPS_PROXY is for https targets');
    process.env.NO_PROXY = '.example.com';
    assert.strictEqual(await O.proxyFor(u('https://sub.example.com/')), null);
    delete process.env.NO_PROXY;
    process.env.OUTBOUND_PROXY = 'socks5://127.0.0.1:7891';
    assert.strictEqual(await O.proxyFor(u('http://sub.example.com/')), 'socks5://127.0.0.1:7891');
    // A webhook on the LAN never takes a detour through a server abroad.
    assert.strictEqual(await O.proxyFor(u('http://192.168.1.5:8080/')), null);
    assert.strictEqual(await O.proxyFor(u('http://localhost/')), null);
    process.env.OUTBOUND_PROXY = 'off';
    assert.strictEqual(await O.proxyFor(u('https://sub.example.com/')), null);
    process.env.OUTBOUND_PROXY = 'ftp://x';
    await assert.rejects(O.proxyFor(u('https://sub.example.com/')), /must be http/);
    assert.strictEqual(O.describe().mode, 'invalid');
    process.env.OUTBOUND_PROXY = 'http://u:hunter2@127.0.0.1:1';
    assert.ok(!O.describe().label.includes('hunter2'));
    process.env.OUTBOUND_PROXY = 'active';
    O.setActiveResolver(() => null);
    await assert.rejects(O.proxyFor(u('https://sub.example.com/')), /no enabled ★ profile/);
  } finally {
    for (const k of ['OUTBOUND_PROXY', 'HTTPS_PROXY', 'NO_PROXY']) delete process.env[k];
  }
});

function origin() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end(`hello ${req.method} ${req.url} ${req.headers.host}`); });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}

test('network: a request rides an HTTP CONNECT proxy, with Proxy-Authorization', async () => {
  const N = require('./lib/network');
  const target = await origin();
  let auth = null;
  let connectTo = null;
  const proxy = http.createServer();
  proxy.on('connect', (req, socket) => {
    auth = req.headers['proxy-authorization'];
    connectTo = req.url;
    const up = net.connect(target.address().port, '127.0.0.1', () => { socket.write('HTTP/1.1 200 OK\r\n\r\n'); up.pipe(socket); socket.pipe(up); });
  });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  try {
    const res = await N.request('http://sub.example.com/feed?x=1', { proxy: `http://me:pw@127.0.0.1:${proxy.address().port}` });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.text, 'hello GET /feed?x=1 sub.example.com');
    assert.strictEqual(connectTo, 'sub.example.com:80');
    assert.strictEqual(auth, `Basic ${Buffer.from('me:pw').toString('base64')}`);
  } finally { proxy.close(); target.close(); }
});

test('network: a request rides a SOCKS5 proxy, the name resolved by the proxy', async () => {
  const N = require('./lib/network');
  const target = await origin();
  let asked = null;
  const socks = net.createServer((sock) => {
    sock.once('data', () => {
      sock.write(Buffer.from([5, 0]));
      sock.once('data', (req) => {
        const len = req[4];
        asked = `${req.subarray(5, 5 + len).toString()}:${req.readUInt16BE(5 + len)}`;
        const up = net.connect(target.address().port, '127.0.0.1', () => {
          sock.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
          up.pipe(sock); sock.pipe(up);
        });
      });
    });
  });
  await new Promise((r) => socks.listen(0, '127.0.0.1', r));
  try {
    const res = await N.request('http://feed.example.com/x', { proxy: `socks5h://127.0.0.1:${socks.address().port}` });
    assert.strictEqual(res.text, 'hello GET /x feed.example.com');
    assert.strictEqual(asked, 'feed.example.com:80');
    // A metadata literal is refused before any proxy is involved.
    await assert.rejects(N.request('http://169.254.169.254/', { proxy: `socks5h://127.0.0.1:${socks.address().port}` }), /metadata/);
  } finally { socks.close(); target.close(); }
});

test('outbound: "active" tunnels through ★ with a local sing-box, reuses it, and shuts it down', async () => {
  const O = require('./lib/outbound');
  const N = require('./lib/network');
  const target = await origin();
  process.env.FAKE_ORIGIN = String(target.address().port);
  process.env.OUTBOUND_PROXY = 'active';
  const star = trojan();
  O.setActiveResolver(() => ({ profile: star, relay: null }));
  try {
    const first = await O.proxyFor(new URL('https://sub.example.com/'));
    assert.match(first, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.strictEqual(await O.proxyFor(new URL('https://sub.example.com/')), first, 'the tunnel is reused while warm');
    const res = await N.request('http://sub.example.com/through-star');
    assert.strictEqual(res.text, 'hello GET /through-star sub.example.com');
  } finally {
    await O.shutdown();
    delete process.env.OUTBOUND_PROXY;
    target.close();
  }
});

// ── The deep probe reads certificates, fails fast, and dials relays ─────────── //
function selfSigned() {
  const cp = require('child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-deepcert-'));
  const key = path.join(dir, 'k.pem');
  const cert = path.join(dir, 'c.pem');
  const r = cp.spawnSync('openssl', ['req', '-x509', '-nodes', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-keyout', key, '-out', cert, '-subj', '/CN=deep.test', '-days', '10'], { encoding: 'utf8', env: { ...process.env, MSYS2_ARG_CONV_EXCL: '/CN' } });
  return r.status === 0 ? { key: fs.readFileSync(key), cert: fs.readFileSync(cert) } : null;
}

test('probe: a deep probe also dates the certificate, so a deep monitor still warns about expiry', async () => {
  const P = require('./lib/probe');
  const pair = selfSigned();
  if (!pair) { console.log('  (skipped: openssl not available)'); return; }
  const target = await origin();
  process.env.FAKE_ORIGIN = String(target.address().port);
  const srv = require('tls').createServer(pair, (s) => s.end());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const p = C.normalizeProfile({ protocol: 'anytls', server: '127.0.0.1', port: srv.address().port, password: 'p', sni: 'deep.test', insecure: true });
    const r = await P.probeProfile(p, 8000, true);
    assert.strictEqual(r.stage, 'deep');
    assert.strictEqual(r.ok, true, r.message);
    assert.ok(r.cert && r.cert.daysLeft <= 10 && r.cert.expiring, 'the certificate was read alongside the deep probe');
    assert.strictEqual(r.certOf, 'server');
    const pinned = await P.probeProfile(C.normalizeProfile({ ...p, pinSha256: 'aa'.repeat(32) }), 8000, true);
    assert.strictEqual(pinned.ok, false);
    assert.strictEqual(pinned.pinMismatch, true);
  } finally { srv.close(); target.close(); }
});

test('probe: a sing-box that exits on its config is reported at once, not after the full wait', async () => {
  const P = require('./lib/probe');
  const p = trojan({ server: '198.51.100.254' }); // the fake's "reject this config" address
  const started = Date.now();
  const r = await P.probeProfile(p, 15000, true);
  assert.strictEqual(r.ok, false);
  assert.match(r.message, /sing-box did not start: FATAL decode config/);
  assert.ok(Date.now() - started < 5000, `took ${Date.now() - started}ms`);
});

test('probe: a relayed profile is deep-probed through its relay', async () => {
  const P = require('./lib/probe');
  const target = await origin();
  process.env.FAKE_ORIGIN = String(target.address().port);
  const dump = path.join(os.tmpdir(), `airport-dump-${process.pid}.json`);
  process.env.FAKE_CONFIG_DUMP = dump;
  try {
    const relay = trojan({ remarks: 'Relay', server: 'relay.example.com' });
    const t = trojan({ remarks: 'Far', server: 'far.example.com', via: relay.id });
    const [r] = await P.probeAll([t], true, { context: [relay, t] });
    assert.strictEqual(r.ok, true, r.message);
    const cfg = JSON.parse(fs.readFileSync(dump, 'utf8'));
    assert.strictEqual(cfg.outbounds[0].detour, 'probe-relay');
    assert.strictEqual(cfg.outbounds[1].server, 'relay.example.com');
    const missing = await P.probeProfile(trojan({ via: uuid() }), 5000, true, null, { profiles: [] });
    assert.strictEqual(missing.ok, null);
  } finally {
    delete process.env.FAKE_CONFIG_DUMP;
    try { fs.unlinkSync(dump); } catch { /* not written */ }
    target.close();
  }
});

// ── Servers deploy.sh looks after (hosts.js) ───────────────────────────────── //
const T = require('./lib/hosts');

test('a stored host keeps only connection ssh options — never one that runs commands', () => {
  const [h] = C.normalizeStore({ profiles: [], hosts: [{
    target: 'ubuntu@203.0.113.9', port: '2222', key: '/home/me/.ssh/k', jump: 'admin@bastion:2200',
    options: ['StrictHostKeyChecking=accept-new', 'ProxyCommand=nc %h %p', 'LocalCommand=id', 'ConnectTimeout=10 ; rm'],
    addresses: ['203.0.113.9', 'bad address'],
  }] }).hosts;
  assert.strictEqual(h.target, 'ubuntu@203.0.113.9');
  assert.strictEqual(h.port, 2222);
  assert.strictEqual(h.jump, 'admin@bastion:2200');
  assert.deepStrictEqual(h.options, ['StrictHostKeyChecking=accept-new']);
  assert.deepStrictEqual(h.addresses, ['203.0.113.9']);
  assert.match(T.optionProblem('ProxyCommand=x'), /only connection options/);
});

test('a login or jump host that ssh would read as an option is dropped', () => {
  const hosts = C.normalizeStore({ profiles: [], hosts: [
    { target: '-oProxyCommand=x@h' }, { target: 'root@-oProxyCommand=x' }, { target: 'ok@h', jump: '-oProxyCommand=x' }, { target: 'ok@h' },
  ] }).hosts;
  assert.deepStrictEqual(hosts.map((h) => [h.target, h.jump]), [['ok@h', undefined]]);
  assert.throws(() => T.recordHost({ hosts: [] }, { target: 'nobody' }), /USER@HOST/);
});

test('recording the same login again updates one record; --replaces drops the old server', () => {
  const store = { hosts: [] };
  const a = T.recordHost(store, { target: 'ubuntu@203.0.113.9', port: 2222, addresses: ['203.0.113.9'] }).host;
  const again = T.recordHost(store, { target: 'UBUNTU@203.0.113.9', addresses: [] }).host;
  assert.strictEqual(store.hosts.length, 1);
  assert.strictEqual(again.id, a.id);
  assert.strictEqual(again.port, undefined, 'a redeploy without -p reached it on 22');
  assert.deepStrictEqual(again.addresses, ['203.0.113.9'], 'kept when the redeploy read none');
  T.recordHost(store, { target: 'root@198.51.100.4', addresses: ['198.51.100.4'] }, { replaces: 'ubuntu@203.0.113.9' });
  assert.deepStrictEqual(store.hosts.map((h) => h.target), ['root@198.51.100.4']);
});

test('addressesIn reads setup.sh --show --json and share links alike', () => {
  const json = JSON.stringify([{ protocol: 'hysteria2', server: '203.0.113.9', port: 443, password: 'p' }, { protocol: 'anytls', server: '203.0.113.9', port: 8443, password: 'q' }]);
  assert.deepStrictEqual(T.addressesIn(json), ['203.0.113.9']);
  assert.deepStrictEqual(T.addressesIn('hysteria2://pw@198.51.100.4:443/?insecure=1#x'), ['198.51.100.4']);
  assert.deepStrictEqual(T.addressesIn('not json {'), []);
});

test('a --doctor report keeps its failures and notes, labelled by section', () => {
  const report = '\n\x1b[0;32m── host\x1b[0m\n  ✓ no reboot pending\n  • MPTCP is enabled\n\n── reality\n  ✓ service xray is active\n  ✗ nothing is listening on 443/tcp\n\x1b[0;31m1 check(s) failed.\x1b[0m\n';
  const d = T.parseDoctor(report, 1);
  assert.strictEqual(d.ok, false);
  assert.strictEqual(d.passed, 2);
  assert.deepStrictEqual(d.failures, ['reality: nothing is listening on 443/tcp']);
  assert.deepStrictEqual(d.notes, ['host: MPTCP is enabled']);
  assert.strictEqual(T.parseDoctor('── host\n  ✓ no reboot pending\n', 0).ok, true);
  const down = T.parseDoctor('ssh: connect to host 203.0.113.9 port 22: Connection timed out\n', 255);
  assert.strictEqual(down.ok, false);
  assert.match(down.error, /Connection timed out/);
  assert.strictEqual(T.parseDoctor('── host\n  ✓ fine\n', 1).ok, false, 'a non-zero exit is never ok');
});

test('the doctor results survive the state file, and junk in it is dropped', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-doctor-'));
  const file = path.join(dir, 'monitor-state.json');
  try {
    const id = uuid();
    H.updateState(file, (s) => { s.doctor[id] = T.parseDoctor('── host\n  ✗ a reboot is pending\n', 1); s.notices = { x: 1 }; });
    H.updateState(file, (s) => { s.alertState = 'up'; });
    const st = H.loadState(file);
    assert.deepStrictEqual(st.doctor[id].failures, ['host: a reboot is pending']);
    assert.deepStrictEqual(st.notices, { x: 1 });
    fs.writeFileSync(file, JSON.stringify({ doctor: { 'not-an-id': {}, [id]: { failures: [1, 'x'.repeat(999)] } } }));
    const junk = H.loadState(file).doctor;
    assert.deepStrictEqual(Object.keys(junk), [id]);
    assert.strictEqual(junk[id].failures.length, 1);
    assert.strictEqual(junk[id].failures[0].length, 300);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('an import with movedFrom re-points the same server instead of adding a second one', () => {
  const p = C.normalizeProfile({ protocol: 'hysteria2', server: '203.0.113.9', port: 443, password: 'pw-move', remarks: 'Airport Hysteria2' });
  const other = C.normalizeProfile({ protocol: 'hysteria2', server: '192.0.2.1', port: 443, password: 'pw-move', remarks: 'Same password, other box' });
  const store = C.normalizeStore({ profiles: [p, other] });
  const link = 'hysteria2://pw-move@198.51.100.4:443/#Airport%20Hysteria2';
  const r = S.importText(store, link, { movedFrom: ['203.0.113.9'] });
  assert.deepStrictEqual(r.added, []);
  assert.deepStrictEqual(r.moved.map((m) => [m.from, m.to]), [['203.0.113.9', '198.51.100.4']]);
  assert.strictEqual(store.profiles[0].id, p.id);
  assert.strictEqual(store.profiles[0].server, '198.51.100.4');
  assert.strictEqual(store.profiles[1].server, '192.0.2.1', 'only the address that was left is re-pointed');
  // Without movedFrom the same import is a new server, as before.
  const fresh = C.normalizeStore({ profiles: [p] });
  const r2 = S.importText(fresh, link);
  assert.strictEqual(r2.added.length, 1);
  assert.strictEqual(fresh.profiles.length, 2);
});

(async () => {
  for (const [name, fn] of queue) {
    try {
      await fn();
      passed += 1;
      console.log('✓', name);
    } catch (err) {
      console.error('✗', name);
      console.error('  ', err.stack || err.message);
      process.exitCode = 1;
    }
  }
  console.log(`\n${passed} passed${process.exitCode ? ', with failures' : ''}`);
})();
