#!/usr/bin/env node
// Tests for the shared config model + builders. No test framework — just the
// built-in assert module, so `npm test` needs no extra dependencies.
// Run: node test.js  (or: npm test)

'use strict';

const assert = require('assert');
const C = require('./lib/configs');

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log('✓', name);
  } catch (err) {
    console.error('✗', name);
    console.error('  ', err.message);
    process.exitCode = 1;
  }
}

// ── normalizeStore accepts all supported shapes ──────────────────────────────── //
test('normalizeStore: canonical multi-profile store', () => {
  const s = C.normalizeStore({ active: 1, profiles: [{ server: 'a', port: 1 }, { server: 'b', port: 2 }] });
  assert.strictEqual(s.profiles.length, 2);
  assert.strictEqual(s.active, 1);
});

test('normalizeStore: bare array', () => {
  const s = C.normalizeStore([{ server: 'a', port: 1 }]);
  assert.strictEqual(s.profiles.length, 1);
  assert.strictEqual(s.active, 0);
});

test('normalizeStore: legacy single object', () => {
  const s = C.normalizeStore({ server: 'a', port: 1, password: 'p' });
  assert.strictEqual(s.profiles.length, 1);
  assert.strictEqual(s.profiles[0].protocol, 'shadowsocks');
});

test('normalizeStore: out-of-range active is clamped to 0', () => {
  assert.strictEqual(C.normalizeStore({ active: 9, profiles: [{ server: 'a', port: 1 }] }).active, 0);
  assert.strictEqual(C.normalizeStore({ active: -3, profiles: [{ server: 'a', port: 1 }] }).active, 0);
});

test('normalizeProfile: infers vless-reality from uuid', () => {
  assert.strictEqual(C.normalizeProfile({ uuid: 'x' }).protocol, 'vless-reality');
});

// ── missingFields ────────────────────────────────────────────────────────────── //
test('missingFields: reports empty reality fields', () => {
  const p = C.normalizeProfile({ protocol: 'vless-reality', server: 's', port: 443 });
  assert.deepStrictEqual(C.missingFields(p).sort(), ['publicKey', 'sni', 'uuid']);
});

test('missingFields: complete SS profile is valid', () => {
  const p = C.normalizeProfile({ server: 's', port: 8388, password: 'p', method: 'aes-256-gcm' });
  assert.deepStrictEqual(C.missingFields(p), []);
});

// ── clientPluginOpts strips server-only tokens ───────────────────────────────── //
test('clientPluginOpts: drops server/cert/key, keeps tls/host/path', () => {
  const out = C.clientPluginOpts('server;tls;host=ex.com;cert=/a;key=/b;path=/ws');
  assert.strictEqual(out, 'tls;host=ex.com;path=/ws');
});

// ── SS URI conforms to SIP002 (base64url userinfo, no padding) ───────────────── //
test('buildSsUri: userinfo is base64url without padding', () => {
  const p = C.normalizeProfile({ server: '1.1.1.1', port: 8388, password: 'p+w/x=y', method: 'aes-256-gcm' });
  const uri = C.buildSsUri(p);
  const userinfo = uri.slice('ss://'.length, uri.indexOf('@'));
  assert.ok(!/[+/=]/.test(userinfo), `userinfo must not contain +, / or =: ${userinfo}`);
  assert.strictEqual(Buffer.from(userinfo, 'base64url').toString(), 'aes-256-gcm:p+w/x=y');
});

// ── uniqueNames de-duplicates collisions ─────────────────────────────────────── //
test('uniqueNames: suffixes duplicate labels in order', () => {
  const profiles = [{ remarks: 'Airport' }, { remarks: 'Airport' }, { remarks: 'Tokyo' }, { remarks: 'Airport' }];
  assert.deepStrictEqual(C.uniqueNames(profiles), ['Airport', 'Airport 2', 'Tokyo', 'Airport 3']);
});

// ── bundled configs never emit duplicate names/tags ──────────────────────────── //
const dupProfiles = [
  C.normalizeProfile({ server: '1.1.1.1', port: 8388, password: 'p', method: 'aes-256-gcm' }),
  C.normalizeProfile({ protocol: 'vless-reality', server: '2.2.2.2', port: 443, uuid: 'u', publicKey: 'k', sni: 'www.microsoft.com' }),
];

test('buildClashConfig: unique proxy names and valid group', () => {
  const cfg = C.buildClashConfig(dupProfiles);
  const names = cfg.proxies.map((p) => p.name);
  assert.strictEqual(new Set(names).size, names.length, `duplicate names: ${names}`);
  // Every name the PROXY group references (except DIRECT) must be a real proxy.
  cfg['proxy-groups'][0].proxies.filter((n) => n !== 'DIRECT')
    .forEach((n) => assert.ok(names.includes(n), `group references missing proxy ${n}`));
});

test('buildSingBox: unique tags and selector default resolves', () => {
  const sb = C.buildSingBox(dupProfiles);
  const tags = sb.outbounds.filter((o) => o.type === 'vless' || o.type === 'shadowsocks').map((o) => o.tag);
  assert.strictEqual(new Set(tags).size, tags.length, `duplicate tags: ${tags}`);
  const selector = sb.outbounds.find((o) => o.type === 'selector');
  assert.ok(tags.includes(selector.default), 'selector default must be a real outbound');
});

test('buildSubscription: decodes to unique per-line labels', () => {
  const decoded = Buffer.from(C.buildSubscription(dupProfiles), 'base64').toString('utf8');
  const labels = decoded.split('\n').map((u) => decodeURIComponent(u.split('#')[1]));
  assert.strictEqual(new Set(labels).size, labels.length, `duplicate labels: ${labels}`);
});

console.log(`\n${passed} passed`);
