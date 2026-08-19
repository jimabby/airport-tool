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

test('normalizeStore: keeps a usable token, drops a junk one', () => {
  const tok = C.newToken();
  assert.strictEqual(C.normalizeStore({ profiles: [], token: tok }).token, tok);
  assert.strictEqual(C.normalizeStore({ profiles: [], token: 'short' }).token, null);
  assert.strictEqual(C.normalizeStore({ profiles: [], token: 42 }).token, null);
});

test('normalizeProfile: infers vless-reality from uuid', () => {
  assert.strictEqual(C.normalizeProfile({ uuid: 'x' }).protocol, 'vless-reality');
});

test('normalizeProfile: unknown protocol falls back to shadowsocks', () => {
  assert.strictEqual(C.normalizeProfile({ protocol: 'wireguard' }).protocol, 'shadowsocks');
  assert.strictEqual(C.normalizeProfile({ protocol: 'hy2', password: 'p' }).protocol, 'hysteria2');
});

// A profile id is interpolated into the web UI's DOM and used as an API key, so
// anything that isn't a real UUID must be replaced rather than trusted.
test('normalizeProfile: rejects a non-UUID id', () => {
  const evil = "x'); alert(1); ('";
  const p = C.normalizeProfile({ id: evil, server: 's', port: 1, password: 'p' });
  assert.notStrictEqual(p.id, evil);
  assert.ok(C.isUuid(p.id), `expected a UUID, got ${p.id}`);
});

test('normalizeProfile: preserves a valid UUID id', () => {
  const id = '6f1e3b7c-2a44-4c9d-8f10-1b2c3d4e5f60';
  assert.strictEqual(C.normalizeProfile({ id, server: 's', port: 1, password: 'p' }).id, id);
});

// ── missingFields / validateProfile ──────────────────────────────────────────── //
test('missingFields: reports empty reality fields', () => {
  const p = C.normalizeProfile({ protocol: 'vless-reality', server: 's', port: 443 });
  assert.deepStrictEqual(C.missingFields(p).sort(), ['publicKey', 'sni', 'uuid']);
});

test('missingFields: complete SS profile is valid', () => {
  const p = C.normalizeProfile({ server: 's', port: 8388, password: 'p', method: 'aes-256-gcm' });
  assert.deepStrictEqual(C.missingFields(p), []);
});

test('missingFields: hysteria2 needs server, port and password', () => {
  const p = C.normalizeProfile({ protocol: 'hysteria2', server: 's' });
  assert.deepStrictEqual(C.missingFields(p).sort(), ['password', 'port']);
});

test('validateProfile: rejects an out-of-range port', () => {
  const p = C.normalizeProfile({ server: 's', port: 70000, password: 'p', method: 'aes-256-gcm' });
  assert.ok(C.validateProfile(p).errors.some((e) => /out of range/.test(e)));
});

test('validateProfile: rejects an IP as a Reality SNI', () => {
  const p = C.normalizeProfile({
    protocol: 'vless-reality', server: 's', port: 443,
    uuid: 'u', publicKey: 'k', sni: '1.2.3.4',
  });
  assert.ok(C.validateProfile(p).errors.some((e) => /sni must be a real domain/.test(e)));
});

test('validateProfile: warns about TLS without a host', () => {
  const p = C.normalizeProfile({
    server: 's', port: 8388, password: 'p', method: 'aes-256-gcm', plugin_opts: 'server;tls',
  });
  const { errors, warnings } = C.validateProfile(p);
  assert.deepStrictEqual(errors, []);
  assert.ok(warnings.some((w) => /no host=/.test(w)));
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

test('buildUri: brackets a bare IPv6 literal', () => {
  const p = C.normalizeProfile({ server: '2001:db8::1', port: 8388, password: 'p', method: 'aes-256-gcm' });
  assert.ok(C.buildSsUri(p).includes('@[2001:db8::1]:8388'), C.buildSsUri(p));
});

// ── uniqueNames de-duplicates collisions ─────────────────────────────────────── //
test('uniqueNames: suffixes duplicate labels in order', () => {
  const profiles = [{ remarks: 'Airport' }, { remarks: 'Airport' }, { remarks: 'Tokyo' }, { remarks: 'Airport' }];
  assert.deepStrictEqual(C.uniqueNames(profiles), ['Airport', 'Airport 2', 'Tokyo', 'Airport 3']);
});

// Regression: gen.js used to write `profiles.map(C.buildUri)`, which hands map's
// index in as the display name — every line after the first was labelled "#1",
// "#2", … instead of the profile's own remarks.
test('buildUri: a numeric name argument never becomes the label', () => {
  const profiles = [
    C.normalizeProfile({ server: '1.1.1.1', port: 8388, password: 'p', method: 'aes-256-gcm', remarks: 'Tokyo' }),
    C.normalizeProfile({ server: '2.2.2.2', port: 8389, password: 'q', method: 'aes-256-gcm', remarks: 'Osaka' }),
  ];
  const names = C.uniqueNames(profiles);
  const uris = profiles.map((p, i) => C.buildUri(p, names[i]));
  assert.deepStrictEqual(uris.map((u) => decodeURIComponent(u.split('#')[1])), ['Tokyo', 'Osaka']);
});

// ── Hysteria2 ────────────────────────────────────────────────────────────────── //
const hy2 = C.normalizeProfile({
  protocol: 'hysteria2', server: '3.3.3.3', port: 443, password: 'pw/+=',
  sni: 'www.bing.com', insecure: true, obfs: 'salamander', obfsPassword: 'ob s',
  remarks: 'HK',
});

test('buildHy2Uri: percent-encodes the password and carries every option', () => {
  const uri = C.buildHy2Uri(hy2);
  const u = new URL(uri);
  assert.strictEqual(u.protocol, 'hysteria2:');
  assert.strictEqual(decodeURIComponent(u.username), 'pw/+=');
  assert.strictEqual(u.searchParams.get('sni'), 'www.bing.com');
  assert.strictEqual(u.searchParams.get('insecure'), '1');
  assert.strictEqual(u.searchParams.get('obfs'), 'salamander');
  assert.strictEqual(u.searchParams.get('obfs-password'), 'ob s');
});

test('buildHy2Uri: omits obfs-password when obfs is off', () => {
  const plain = C.normalizeProfile({ protocol: 'hysteria2', server: 's', port: 443, password: 'p' });
  const u = new URL(C.buildHy2Uri(plain));
  assert.strictEqual(u.searchParams.get('obfs'), null);
  assert.strictEqual(u.searchParams.get('insecure'), null);
});

// ── URI parsing round-trips ──────────────────────────────────────────────────── //
const roundTrip = [
  ['shadowsocks', C.normalizeProfile({
    server: '1.1.1.1', port: 8388, password: 'p@ss w/+=', method: 'aes-256-gcm',
    plugin_opts: 'server;tls;host=ex.com;path=/ws', remarks: 'Tokyo SS',
  })],
  ['vless-reality', C.normalizeProfile({
    protocol: 'vless-reality', server: '2.2.2.2', port: 443,
    uuid: '11111111-2222-3333-4444-555555555555', publicKey: 'PUBKEY', shortId: 'ab12',
    sni: 'www.microsoft.com', remarks: 'SG Reality',
  })],
  ['hysteria2', hy2],
];

for (const [label, original] of roundTrip) {
  test(`parseUri: ${label} survives build → parse`, () => {
    const back = C.parseUri(C.buildUri(original));
    assert.strictEqual(back.protocol, original.protocol);
    assert.strictEqual(back.server, original.server);
    assert.strictEqual(back.port, original.port);
    assert.strictEqual(back.remarks, original.remarks);
    if (original.protocol === 'shadowsocks') {
      assert.strictEqual(back.password, original.password);
      assert.strictEqual(back.method, original.method);
      // The parsed profile describes the server again, so `server` comes back.
      assert.strictEqual(back.plugin_opts, original.plugin_opts);
    } else if (original.protocol === 'vless-reality') {
      assert.strictEqual(back.uuid, original.uuid);
      assert.strictEqual(back.publicKey, original.publicKey);
      assert.strictEqual(back.shortId, original.shortId);
      assert.strictEqual(back.sni, original.sni);
    } else {
      assert.strictEqual(back.password, original.password);
      assert.strictEqual(back.insecure, original.insecure);
      assert.strictEqual(back.obfs, original.obfs);
      assert.strictEqual(back.obfsPassword, original.obfsPassword);
    }
  });
}

test('parseUri: accepts the legacy all-base64 ss:// form', () => {
  const legacy = 'ss://' + Buffer.from('aes-256-gcm:hunter2@9.9.9.9:8388').toString('base64') + '#Old';
  const p = C.parseUri(legacy);
  assert.strictEqual(p.server, '9.9.9.9');
  assert.strictEqual(p.port, 8388);
  assert.strictEqual(p.method, 'aes-256-gcm');
  assert.strictEqual(p.password, 'hunter2');
  assert.strictEqual(p.remarks, 'Old');
});

test('parseUri: accepts the hy2:// alias', () => {
  assert.strictEqual(C.parseUri('hy2://pw@1.2.3.4:443/#X').protocol, 'hysteria2');
});

test('parseUri: rejects an unknown scheme and a non-Reality vless', () => {
  assert.throws(() => C.parseUri('trojan://x@y:443'), /Unsupported URI scheme/);
  assert.throws(() => C.parseUri('vless://u@h:443?security=tls'), /not supported/);
});

test('parseSubscription: decodes base64 and reports bad lines', () => {
  const profiles = roundTrip.map(([, p]) => p);
  const blob = C.buildSubscription(profiles);
  const parsed = C.parseSubscription(blob);
  assert.strictEqual(parsed.profiles.length, 3);
  assert.deepStrictEqual(parsed.errors, []);

  const mixed = C.parseSubscription('ss://bogus\nnot-a-uri');
  assert.strictEqual(mixed.profiles.length, 0);
  assert.strictEqual(mixed.errors.length, 2);
});

test('parseSubscription: accepts a plain multi-line paste', () => {
  const text = roundTrip.map(([, p]) => C.buildUri(p)).join('\n');
  assert.strictEqual(C.parseSubscription(text).profiles.length, 3);
});

// ── bundled configs never emit duplicate names/tags ──────────────────────────── //
const dupProfiles = [
  C.normalizeProfile({ server: '1.1.1.1', port: 8388, password: 'p', method: 'aes-256-gcm' }),
  C.normalizeProfile({ protocol: 'vless-reality', server: '2.2.2.2', port: 443, uuid: 'u', publicKey: 'k', sni: 'www.microsoft.com' }),
  hy2,
];

test('buildClashConfig: unique proxy names and valid groups', () => {
  const cfg = C.buildClashConfig(dupProfiles);
  const names = cfg.proxies.map((p) => p.name);
  assert.strictEqual(new Set(names).size, names.length, `duplicate names: ${names}`);
  // Every proxy a group references must be a real proxy or another group.
  const groupNames = cfg['proxy-groups'].map((g) => g.name);
  const known = new Set([...names, ...groupNames, 'DIRECT']);
  for (const g of cfg['proxy-groups']) {
    for (const ref of g.proxies) assert.ok(known.has(ref), `group ${g.name} references unknown ${ref}`);
  }
});

test('buildClashConfig: emits a url-test group only when it can fail over', () => {
  const many = C.buildClashConfig(dupProfiles)['proxy-groups'];
  assert.ok(many.some((g) => g.type === 'url-test'), 'expected an Auto group for multiple servers');
  const one = C.buildClashConfig([dupProfiles[0]])['proxy-groups'];
  assert.ok(!one.some((g) => g.type === 'url-test'), 'a single server needs no Auto group');
  assert.ok(!one[0].proxies.includes('Auto'), 'PROXY must not reference a group that was not emitted');
});

// LAN traffic must never be tunnelled: without this rule, router admin pages and
// local dev servers get shipped to the VPS.
test('buildClashConfig: keeps private ranges direct, before the CN rule', () => {
  const rules = C.buildClashConfig(dupProfiles).rules;
  const priv = rules.findIndex((r) => /^GEOIP,PRIVATE,DIRECT/.test(r));
  assert.ok(priv !== -1, `no private rule in ${rules}`);
  assert.ok(priv < rules.indexOf('MATCH,PROXY'));
});

// Resolvers must be reachable from behind the firewall, or nothing resolves and
// the GEOIP rules never get a chance to classify anything.
test('buildClashConfig: primary DNS is domestic, foreign resolvers are fallback', () => {
  const dns = C.buildClashConfig(dupProfiles).dns;
  assert.ok(!dns.nameserver.some((n) => /8\.8\.8\.8|1\.1\.1\.1/.test(n)),
    `blocked resolvers must not be primary: ${dns.nameserver}`);
  assert.ok(dns.fallback.includes('8.8.8.8'));
});

test('buildClashProxy: hysteria2 carries password, sni and obfs', () => {
  const proxy = C.buildClashProxy(hy2, 'HK');
  assert.strictEqual(proxy.type, 'hysteria2');
  assert.strictEqual(proxy.password, 'pw/+=');
  assert.strictEqual(proxy['skip-cert-verify'], true);
  assert.strictEqual(proxy.obfs, 'salamander');
});

test('buildSingBox: unique tags and selector default resolves', () => {
  const sb = C.buildSingBox(dupProfiles);
  const proxyTypes = new Set(['vless', 'shadowsocks', 'hysteria2']);
  const tags = sb.outbounds.filter((o) => proxyTypes.has(o.type)).map((o) => o.tag);
  assert.strictEqual(new Set(tags).size, tags.length, `duplicate tags: ${tags}`);
  const all = new Set(sb.outbounds.map((o) => o.tag));
  const selector = sb.outbounds.find((o) => o.type === 'selector');
  assert.ok(all.has(selector.default), 'selector default must be a real outbound');
  selector.outbounds.forEach((t) => assert.ok(all.has(t), `selector references unknown ${t}`));
});

test('buildSingBox: urltest group appears only with multiple servers', () => {
  assert.ok(C.buildSingBox(dupProfiles).outbounds.some((o) => o.type === 'urltest'));
  const one = C.buildSingBox([dupProfiles[0]]);
  assert.ok(!one.outbounds.some((o) => o.type === 'urltest'));
  assert.strictEqual(one.outbounds.find((o) => o.type === 'selector').default, one.outbounds[1].tag);
});

// The pre-1.11 schema (a `dns` outbound, inline geoip route rules, split
// socks/http inbounds) is deprecated upstream and removed in newer releases.
test('buildSingBox: uses the modern 1.11+ schema', () => {
  const sb = C.buildSingBox(dupProfiles);
  assert.ok(!sb.outbounds.some((o) => o.type === 'dns'), 'the dns outbound type is removed upstream');
  assert.ok(sb.inbounds.some((i) => i.type === 'mixed'));
  assert.ok(sb.route.rules.some((r) => r.action === 'hijack-dns'));
  assert.ok(sb.route.rules.some((r) => r.ip_is_private === true));
  assert.ok(!sb.route.rules.some((r) => r.geoip), 'inline geoip rules are deprecated');
  // Every rule_set referenced by a route or DNS rule must actually be defined.
  const defined = new Set(sb.route.rule_set.map((r) => r.tag));
  const referenced = [...sb.route.rules, ...sb.dns.rules]
    .flatMap((r) => (Array.isArray(r.rule_set) ? r.rule_set : r.rule_set ? [r.rule_set] : []));
  referenced.forEach((t) => assert.ok(defined.has(t), `undefined rule_set ${t}`));
  // Rule sets are fetched through the proxy — they're unreachable directly from
  // inside the firewall, which is the only place this config gets used.
  sb.route.rule_set.forEach((rs) => assert.strictEqual(rs.download_detour, 'proxy'));
});

test('buildSubscription: decodes to unique per-line labels', () => {
  const decoded = Buffer.from(C.buildSubscription(dupProfiles), 'base64').toString('utf8');
  const labels = decoded.split('\n').map((u) => decodeURIComponent(u.split('#')[1]));
  assert.strictEqual(new Set(labels).size, labels.length, `duplicate labels: ${labels}`);
});

// ── YAML emitter ─────────────────────────────────────────────────────────────── //
test('toYaml: skips null and undefined, keeps false and 0', () => {
  const out = C.toYaml({ a: null, b: undefined, c: false, d: 0 });
  assert.ok(!/a:/.test(out) && !/b:/.test(out));
  assert.ok(/c: false/.test(out) && /d: 0/.test(out));
});

test('toYaml: nests maps inside list items', () => {
  const yaml = C.buildClashYaml([dupProfiles[0]]);
  assert.ok(/ {4}plugin-opts:\n {6}mode: "websocket"/.test(yaml), yaml);
});


// ── base64url subscriptions ──────────────────────────────────────────────────── //
// Regression: the base64 detector's character class omitted `_`, so any blob
// using the URL-safe alphabet fell through to line-by-line URI parsing and
// failed as a whole. Plenty of providers hand out exactly that alphabet.
test('parseSubscription: decodes a base64url blob containing "_"', () => {
  let urlsafe = null;
  for (let i = 0; i < 500 && !urlsafe; i += 1) {
    const p = C.normalizeProfile({ server: '9.9.9.9', port: 8388, password: `pw${i}`, method: 'aes-256-gcm', remarks: `X${i}` });
    const b = C.buildSubscription([p]).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    if (b.includes('_')) urlsafe = b;
  }
  assert.ok(urlsafe, 'could not construct a blob containing "_"');
  const parsed = C.parseSubscription(urlsafe);
  assert.deepStrictEqual(parsed.errors, []);
  assert.strictEqual(parsed.profiles.length, 1);
});

// ── TUIC v5 ──────────────────────────────────────────────────────────────────── //
const tuic = C.normalizeProfile({
  protocol: 'tuic', server: '4.4.4.4', port: 443,
  uuid: '22222222-3333-4444-5555-666666666666', password: 'pw/+= x',
  sni: 'www.bing.com', insecure: true, remarks: 'TUIC HK',
});

test('buildTuicUri: encodes both halves of the credential', () => {
  const u = new URL(C.buildTuicUri(tuic));
  assert.strictEqual(u.protocol, 'tuic:');
  assert.strictEqual(decodeURIComponent(u.username), tuic.uuid);
  assert.strictEqual(decodeURIComponent(u.password), 'pw/+= x');
  assert.strictEqual(u.searchParams.get('congestion_control'), 'bbr');
  assert.strictEqual(u.searchParams.get('udp_relay_mode'), 'native');
  assert.strictEqual(u.searchParams.get('allow_insecure'), '1');
});

test('parseUri: tuic survives build → parse', () => {
  const back = C.parseUri(C.buildUri(tuic));
  assert.strictEqual(back.protocol, 'tuic');
  assert.strictEqual(back.uuid, tuic.uuid);
  assert.strictEqual(back.password, tuic.password);
  assert.strictEqual(back.sni, tuic.sni);
  assert.strictEqual(back.insecure, true);
  assert.strictEqual(back.remarks, tuic.remarks);
});

test('missingFields: tuic needs a uuid and a password', () => {
  const p = C.normalizeProfile({ protocol: 'tuic', server: 's', port: 443 });
  assert.deepStrictEqual(C.missingFields(p).sort(), ['password', 'uuid']);
});

test('buildClashProxy / buildSingBoxOutbound: tuic carries both credentials', () => {
  const proxy = C.buildClashProxy(tuic, 'HK');
  assert.strictEqual(proxy.type, 'tuic');
  assert.strictEqual(proxy.uuid, tuic.uuid);
  assert.strictEqual(proxy.password, tuic.password);
  assert.strictEqual(proxy['skip-cert-verify'], true);
  assert.deepStrictEqual(proxy.alpn, ['h3']);

  const out = C.buildSingBoxOutbound(tuic, 'HK');
  assert.strictEqual(out.type, 'tuic');
  assert.strictEqual(out.uuid, tuic.uuid);
  assert.strictEqual(out.password, tuic.password);
  assert.strictEqual(out.tls.insecure, true);
});

// ── VLESS transports ─────────────────────────────────────────────────────────── //
// xtls-rprx-vision is a raw-TCP flow. Xray rejects it on grpc/xhttp outright, so
// a profile carrying both is one the client silently fails to connect with.
test('normalizeProfile: the Vision flow is dropped on non-tcp transports', () => {
  const base = { protocol: 'vless-reality', server: 's', port: 443, uuid: 'u', publicKey: 'k', sni: 'www.microsoft.com' };
  assert.strictEqual(C.normalizeProfile({ ...base }).flow, 'xtls-rprx-vision');
  assert.strictEqual(C.normalizeProfile({ ...base, network: 'grpc' }).flow, '');
  assert.strictEqual(C.normalizeProfile({ ...base, network: 'xhttp' }).flow, '');
  assert.strictEqual(C.normalizeProfile({ ...base, network: 'quic' }).network, 'tcp');
});

test('validateProfile: rejects a flow a non-tcp transport cannot use', () => {
  // A hand-written store can still carry the illegal pair; validation catches it.
  const p = {
    ...C.normalizeProfile({
      protocol: 'vless-reality', server: 's', port: 443, uuid: 'u', publicKey: 'k',
      sni: 'www.microsoft.com', network: 'grpc', serviceName: 'x',
    }),
    flow: 'xtls-rprx-vision',
  };
  assert.ok(C.validateProfile(p).errors.some((e) => /only works over tcp/.test(e)));
});

for (const [network, extra] of [['grpc', { serviceName: 'svc' }], ['xhttp', { path: '/abc' }]]) {
  test(`parseUri: vless over ${network} survives build → parse`, () => {
    const p = C.normalizeProfile({
      protocol: 'vless-reality', server: '2.2.2.2', port: 443, uuid: 'u',
      publicKey: 'k', shortId: 'ab12', sni: 'www.microsoft.com', network, remarks: 'T', ...extra,
    });
    const back = C.parseUri(C.buildUri(p));
    assert.strictEqual(back.network, network);
    assert.strictEqual(back.flow, '');
    if (network === 'grpc') assert.strictEqual(back.serviceName, 'svc');
    else assert.strictEqual(back.path, '/abc');
  });
}

test('buildClashProxy: a vless transport never emits an empty flow', () => {
  const p = C.normalizeProfile({
    protocol: 'vless-reality', server: 's', port: 443, uuid: 'u', publicKey: 'k',
    sni: 'www.microsoft.com', network: 'grpc', serviceName: 'svc',
  });
  const proxy = C.buildClashProxy(p, 'G');
  assert.ok(!('flow' in proxy), 'mihomo reads an empty flow as a flow it does not know');
  assert.strictEqual(proxy.network, 'grpc');
  assert.strictEqual(proxy['grpc-opts']['grpc-service-name'], 'svc');
  const out = C.buildSingBoxOutbound(p, 'G');
  assert.ok(!('flow' in out));
  assert.strictEqual(out.transport.type, 'grpc');
});

// ── Client configs must work on the devices the README points at ─────────────── //
// The mobile Sing-Box apps route system traffic through a tun inbound. With only
// a loopback mixed inbound the app connects and carries nothing.
test('buildSingBox: includes a tun inbound with auto_route', () => {
  const inbounds = C.buildSingBox(dupProfiles).inbounds;
  const tun = inbounds.find((i) => i.type === 'tun');
  assert.ok(tun, `no tun inbound in ${inbounds.map((i) => i.type)}`);
  assert.strictEqual(tun.auto_route, true);
  assert.ok(inbounds.some((i) => i.type === 'mixed'), 'the desktop mixed inbound must survive too');
});

// GEOIP/GEOSITE rules are dead weight until the database exists, and mihomo's
// default download URLs are on GitHub — unreachable from inside the firewall.
test('buildClashConfig: geo databases come from a reachable mirror', () => {
  const cfg = C.buildClashConfig(dupProfiles);
  const urls = Object.values(cfg['geox-url']);
  assert.strictEqual(urls.length, 3);
  urls.forEach((u) => assert.ok(!/github\.com|githubusercontent\.com/.test(u), `unreachable geo source: ${u}`));
});

// ── Store secrets ────────────────────────────────────────────────────────────── //
// The subscription token and the dashboard token are deliberately separate: one
// hands a client your servers, the other hands it write access to them.
test('normalizeStore: keeps subscription and dashboard tokens apart', () => {
  const sub = C.newToken();
  const ui = C.newToken();
  const s = C.normalizeStore({ profiles: [], token: sub, uiToken: ui });
  assert.strictEqual(s.token, sub);
  assert.strictEqual(s.uiToken, ui);
  assert.notStrictEqual(sub, ui);
  assert.strictEqual(C.normalizeStore({ profiles: [], uiToken: 'short' }).uiToken, null);
});

console.log(`\n${passed} passed`);
