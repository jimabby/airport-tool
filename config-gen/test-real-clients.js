#!/usr/bin/env node
// Runs the generated bundles through the real clients.
//
// The unit tests check that the builders emit what we *believe* each client
// wants. This checks what the client actually accepts, which is the only
// opinion that matters and the one that changes underneath us: sing-box 1.14
// started refusing to boot a bundle whose servers were named by hostname
// without a domain resolver, and refusing a DNS server that detoured through
// the empty `direct` outbound — both on a config every unit test passed.
//
// Binaries come from SINGBOX_BIN / MIHOMO_BIN, or `sing-box` / `mihomo` on PATH.
// A missing one is skipped with a note, unless REQUIRE_REAL_CLIENTS=1 (CI),
// where a missing binary is a failure rather than a silent pass.
//
// Run: node test-real-clients.js

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const C = require('./lib/configs');

const REQUIRE = process.env.REQUIRE_REAL_CLIENTS === '1';
const SINGBOX = process.env.SINGBOX_BIN || 'sing-box';
const MIHOMO = process.env.MIHOMO_BIN || 'mihomo';

// Every protocol and transport the builders emit, with key material a client
// will actually parse — a placeholder public key fails before the part under
// test is reached. Plus custom rules and a server named after a group, so the
// rule emitters and the reserved-name guard are exercised too.
function fixture() {
  const { publicKey } = crypto.generateKeyPairSync('x25519');
  const pbk = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
  const uuid = () => crypto.randomUUID();
  const ss2022 = crypto.randomBytes(32).toString('base64');
  const profiles = [
    { protocol: 'vless-reality', server: 'r.example.com', port: 443, uuid: uuid(), publicKey: pbk, shortId: 'abcd1234', sni: 'www.microsoft.com', remarks: 'Reality' },
    { protocol: 'vless-reality', server: '198.51.100.2', port: 8443, uuid: uuid(), publicKey: pbk, shortId: 'ab', sni: 'www.microsoft.com', network: 'grpc', serviceName: 'svc', remarks: 'Reality gRPC' },
    { protocol: 'hysteria2', server: 'h.example.com', port: 443, password: 'pw', sni: 'www.bing.com', insecure: true, obfs: 'salamander', obfsPassword: 'op', ports: '20000-25000,30000', up: 50, down: 200, remarks: 'HY2' },
    { protocol: 'tuic', server: '198.51.100.4', port: 443, uuid: uuid(), password: 'pw', sni: 'www.bing.com', insecure: true, remarks: 'TUIC' },
    { protocol: 'trojan', server: 't.example.com', port: 443, password: 'pw', sni: 't.example.com', network: 'ws', path: '/ws', host: 't.example.com', remarks: 'Trojan' },
    { protocol: 'vmess', server: 'v.example.com', port: 443, uuid: uuid(), tls: true, sni: 'v.example.com', network: 'grpc', serviceName: 'g', remarks: 'VMess' },
    { protocol: 'shadowsocks', server: '198.51.100.7', port: 8388, password: 'pw', method: 'chacha20-ietf-poly1305', plugin: '', remarks: 'SS' },
    { protocol: 'shadowsocks', server: '198.51.100.8', port: 8389, password: ss2022, method: '2022-blake3-aes-256-gcm', plugin: '', remarks: 'Auto' },
    { protocol: 'vless-tls', server: 'vt.example.com', port: 443, uuid: uuid(), sni: 'vt.example.com', flow: 'xtls-rprx-vision', remarks: 'VLESS TLS' },
    { protocol: 'vless-tls', server: '198.51.100.9', port: 443, uuid: uuid(), sni: 'cdn.example.com', network: 'ws', path: '/ray', host: 'cdn.example.com', alpn: 'http/1.1', remarks: 'VLESS WS' },
  ].map(C.normalizeProfile);
  const rules = C.normalizeRules({
    direct: ['bank.example.com', '10.8.0.0/16'],
    proxy: ['foreign.cn', '2001:db8::/32'],
    block: ['ads.example.com'],
  });
  // ★ on a server in the middle, so the reordered failover groups are what the
  // clients get to parse.
  return { profiles, rules, preferred: profiles[2].id };
}

let failures = 0;
const ok = (msg) => console.log(`✓ ${msg}`);
const bad = (msg, detail) => {
  failures += 1;
  console.error(`✗ ${msg}`);
  if (detail) console.error(String(detail).trim().split('\n').slice(-12).map((l) => `    ${l}`).join('\n'));
};

function available(bin, args) {
  const r = spawnSync(bin, args, { encoding: 'utf8', timeout: 15000 });
  return r.status === 0 ? (r.stdout || '').split('\n')[0].trim() : null;
}

function skipOrFail(name, bin) {
  if (REQUIRE) bad(`${name} is required (REQUIRE_REAL_CLIENTS=1) but \`${bin}\` did not run`);
  else console.log(`- ${name} not found (\`${bin}\`) — skipped. Set ${name === 'sing-box' ? 'SINGBOX_BIN' : 'MIHOMO_BIN'} to run it.`);
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

// `sing-box check` validates the schema but not start-up: the empty-direct
// detour error, for one, is raised only when the DNS transport starts. So the
// desktop bundle is also run for a few seconds — still alive means it started.
// Run in the temp dir: sing-box writes its cache_file to the working directory.
function runFor(bin, args, ms, cwd) {
  return new Promise((resolve) => {
    const child = spawn(bin, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let log = '';
    child.stdout.on('data', (b) => { log += b; });
    child.stderr.on('data', (b) => { log += b; });
    let exited = null;
    child.on('exit', (code) => { exited = code; });
    child.on('error', (err) => { log += err.message; exited = -1; });
    setTimeout(() => {
      const alive = exited === null;
      if (alive) child.kill();
      resolve({ alive, code: exited, log });
    }, ms);
  });
}

async function main() {
  const { profiles, rules, preferred } = fixture();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-real-'));
  try {
    const sbVersion = available(SINGBOX, ['version']);
    if (!sbVersion) {
      skipOrFail('sing-box', SINGBOX);
    } else {
      console.log(`sing-box: ${sbVersion}`);
      const mobile = path.join(dir, 'singbox.json');
      fs.writeFileSync(mobile, JSON.stringify(C.buildSingBox(profiles, { rules, preferred }), null, 2));
      const r = spawnSync(SINGBOX, ['check', '-c', mobile], { encoding: 'utf8', timeout: 60000 });
      if (r.status === 0) ok('sing-box accepts the mobile bundle (tun, every protocol, custom rules)');
      else bad('sing-box rejects the mobile bundle', r.stderr || r.stdout);

      const desktopCfg = C.buildSingBox(profiles, { tun: false, rules, preferred });
      const mixed = desktopCfg.inbounds.find((i) => i.type === 'mixed');
      mixed.listen_port = await freePort();
      const desktop = path.join(dir, 'singbox-desktop.json');
      fs.writeFileSync(desktop, JSON.stringify(desktopCfg, null, 2));
      const c = spawnSync(SINGBOX, ['check', '-c', desktop], { encoding: 'utf8', timeout: 60000 });
      if (c.status !== 0) {
        bad('sing-box rejects the desktop bundle', c.stderr || c.stdout);
      } else {
        // Long enough to fetch the rule sets and bring the DNS transports up.
        const run = await runFor(SINGBOX, ['run', '-c', desktop], 12000, dir);
        if (run.alive) ok('sing-box starts the desktop bundle and keeps running');
        else bad(`sing-box exited (${run.code}) while starting the desktop bundle`, run.log);
      }

      // The deep probe writes its own one-outbound config (probe.js), with no
      // DNS section at all. Nothing used to check that one against a real
      // sing-box; a release that refused it would turn every deep probe into
      // a "down" result.
      const probeBad = [];
      for (const p of profiles) {
        if (p.protocol === 'vless-reality' && p.network === 'xhttp') continue; // never deep-probed
        const outbound = C.buildSingBoxOutbound(p, 'probe');
        const cfg = {
          log: { level: 'error' },
          inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: 1080 }],
          outbounds: [outbound],
          route: { final: outbound.tag },
        };
        const f = path.join(dir, `probe-${p.id}.json`);
        fs.writeFileSync(f, JSON.stringify(cfg));
        const pc = spawnSync(SINGBOX, ['check', '-c', f], { encoding: 'utf8', timeout: 60000 });
        if (pc.status !== 0) probeBad.push(`${p.remarks}: ${(pc.stderr || pc.stdout).trim()}`);
      }
      if (!probeBad.length) ok('sing-box accepts the deep probe config for every protocol');
      else bad('sing-box rejects a deep probe config', probeBad.join('\n'));
    }

    const mhVersion = available(MIHOMO, ['-v']);
    if (!mhVersion) {
      skipOrFail('mihomo', MIHOMO);
    } else {
      console.log(`mihomo: ${mhVersion}`);
      const yaml = path.join(dir, 'clash.yaml');
      fs.writeFileSync(yaml, C.buildClashYaml(profiles, { rules, preferred }));
      const home = path.join(dir, 'mihomo-home');
      fs.mkdirSync(home);
      // mihomo downloads its geo databases before it will validate a rule that
      // uses them. On a slow link that times out and reads as a config error,
      // so GEODATA_DIR can hand it files fetched earlier (GeoIP.dat, GeoSite.dat).
      if (process.env.GEODATA_DIR) {
        for (const f of fs.readdirSync(process.env.GEODATA_DIR)) {
          fs.copyFileSync(path.join(process.env.GEODATA_DIR, f), path.join(home, f));
        }
      }
      const r = spawnSync(MIHOMO, ['-t', '-d', home, '-f', yaml], { encoding: 'utf8', timeout: 120000 });
      const out = `${r.stdout || ''}${r.stderr || ''}`;
      if (r.status === 0 && /test is successful/.test(out)) ok('mihomo accepts the Clash bundle (every protocol, custom rules)');
      else bad('mihomo rejects the Clash bundle', out);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  console.log(failures ? `\n${failures} real-client check(s) failed` : '\nreal clients: all checks passed');
  process.exit(failures ? 1 : 0);
}

main();
