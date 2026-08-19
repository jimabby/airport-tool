#!/usr/bin/env node
// API-level tests for the web UI: authentication, profile CRUD, import,
// downloads and the subscription gate.
//
// The dashboard is an admin panel for a file full of proxy credentials, and
// most of what can go wrong here is a route that forgets to be guarded — which
// is exactly what nothing used to check.
'use strict';

const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

let failed = 0;
let passed = 0;

function check(name, cond, detail) {
  if (cond) { passed += 1; console.log('  ✓', name); return; }
  failed += 1;
  console.error('  ✗', name);
  if (detail !== undefined) console.error('     ', String(detail).slice(0, 220));
}

function request(port, method, pathname, { headers = {}, body, host } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const req = http.request({
      host: '127.0.0.1', port, method, path: pathname,
      headers: {
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
        ...(host ? { Host: host } : {}),
        ...headers,
      },
    }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* not every response is JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// A raw request, so a body express's JSON parser will reject can be sent.
function rawPost(port, pathname, raw, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, method: 'POST', path: pathname,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(raw), ...headers },
    }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* html error page */ }
        resolve({ status: res.statusCode, text, json });
      });
    });
    req.on('error', reject);
    req.write(raw);
    req.end();
  });
}

async function boot(port, env, dir) {
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: {
      ...process.env,
      PORT: String(port),
      CFG_PATH: path.join(dir, 'servers.json'),
      HISTORY_PATH: path.join(dir, 'history.json'),
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let err = '';
  child.stderr.on('data', (b) => { err += b.toString(); });
  const deadline = Date.now() + 15000;
  for (;;) {
    try { await request(port, 'GET', '/'); return child; } catch {
      if (Date.now() > deadline) { child.kill(); throw new Error(`server ${port} never came up: ${err}`); }
      await new Promise((r) => setTimeout(r, 150));
    }
  }
}

const SS = {
  protocol: 'shadowsocks', server: '203.0.113.10', port: 8388,
  password: 'hunter2', method: 'aes-256-gcm', remarks: 'Tokyo',
};

async function testLoopback(dir) {
  console.log('\n── loopback: usable without a token, still guarded against rebinding');
  const port = 3321;
  const child = await boot(port, { HOST: '127.0.0.1' }, dir);
  try {
    const cfg = await request(port, 'GET', '/api/config');
    check('GET /api/config needs no token on loopback', cfg.status === 200, cfg.status);

    const rebind = await request(port, 'GET', '/api/config', { host: 'evil.example' });
    check('a rebinding Host header is still refused', rebind.status === 403, rebind.status);

    // ── CRUD ──
    const created = await request(port, 'POST', '/api/profiles', { body: SS });
    check('POST /api/profiles creates a profile', created.status === 200 && created.json.profiles.length === 1, created.text);
    const id = created.json.savedId;

    const renamed = await request(port, 'POST', '/api/profiles', { body: { ...SS, id, remarks: 'Tokyo 2' } });
    check('POST with an existing id updates in place', renamed.json.profiles.length === 1 && renamed.json.profiles[0].remarks === 'Tokyo 2', renamed.text);
    check('an update keeps the profile id', renamed.json.savedId === id, renamed.json.savedId);

    const invalid = await request(port, 'POST', '/api/profiles', { body: { protocol: 'shadowsocks', server: '1.1.1.1' } });
    check('an incomplete profile is rejected with a reason', invalid.status === 400 && /missing/.test(invalid.json.error), invalid.text);

    const second = await request(port, 'POST', '/api/profiles', {
      body: { protocol: 'hysteria2', server: '203.0.113.11', port: 443, password: 'pw', insecure: true, remarks: 'Osaka' },
    });
    check('a second profile does not steal ★', second.json.activeId === id, second.json.activeId);

    const activated = await request(port, 'POST', '/api/active', { body: { id: second.json.savedId } });
    check('POST /api/active moves ★', activated.json.activeId === second.json.savedId, activated.text);
    const missing = await request(port, 'POST', '/api/active', { body: { id: 'nope' } });
    check('POST /api/active 404s on an unknown id', missing.status === 404, missing.status);

    // ── Import ──
    const imported = await request(port, 'POST', '/api/import', {
      body: { text: 'tuic://11111111-2222-3333-4444-555555555555:pw@203.0.113.12:443?sni=www.bing.com&allow_insecure=1#Imported' },
    });
    check('POST /api/import accepts a tuic:// link', imported.status === 200 && imported.json.added[0] === 'Imported', imported.text);

    const dupe = await request(port, 'POST', '/api/import', {
      body: { text: 'tuic://11111111-2222-3333-4444-555555555555:pw@203.0.113.12:443?sni=www.bing.com#Again' },
    });
    check('re-importing the same endpoint is refused, not duplicated', dupe.status === 400 && /Already have/.test(dupe.json.error), dupe.text);

    const junk = await request(port, 'POST', '/api/import', { body: { text: 'not-a-uri' } });
    check('unparseable import input reports the bad line', junk.status === 400 && /line 1/.test(junk.json.error), junk.text);

    // ── Downloads ──
    const clash = await request(port, 'GET', '/api/download/clash');
    check('clash download is YAML with every proxy', clash.status === 200 && /proxies:/.test(clash.text) && /hunter2/.test(clash.text), clash.status);
    const singbox = await request(port, 'GET', '/api/download/singbox');
    check('singbox download parses and carries a tun inbound',
      singbox.status === 200 && JSON.parse(singbox.text).inbounds.some((i) => i.type === 'tun'), singbox.status);
    const uri = await request(port, 'GET', `/api/download/uri?id=${encodeURIComponent(id)}`);
    check('uri download is named after its protocol', /ss-uri\.txt/.test(uri.headers['content-disposition'] || ''), uri.headers['content-disposition']);
    const backup = await request(port, 'GET', '/api/download/backup');
    check('backup download returns the whole store', backup.status === 200 && JSON.parse(backup.text).profiles.length === 3, backup.status);

    // ── Deletion ──
    const deleted = await request(port, 'DELETE', `/api/profiles/${encodeURIComponent(id)}`);
    check('DELETE removes the profile', deleted.status === 200 && deleted.json.profiles.length === 2, deleted.text);
    const gone = await request(port, 'DELETE', `/api/profiles/${encodeURIComponent(id)}`);
    check('DELETE 404s on an unknown id', gone.status === 404, gone.status);

    // ── Error shape ──
    const broken = await rawPost(port, '/api/profiles', '{not json');
    check('a malformed body answers in JSON, not HTML', broken.status === 400 && broken.json && /not valid JSON/.test(broken.json.error), broken.text);

    // ── Subscription ──
    const store = JSON.parse(fs.readFileSync(path.join(dir, 'servers.json'), 'utf8'));
    const good = await request(port, 'GET', `/api/subscription/${store.token}`);
    check('the subscription token serves the feed', good.status === 200 && /:\/\//.test(Buffer.from(good.text, 'base64').toString()), good.status);
    const wrong = await request(port, 'GET', '/api/subscription/deadbeefdeadbeefdeadbeef');
    check('a wrong subscription token 404s', wrong.status === 404, wrong.status);
    const untokenized = await request(port, 'GET', '/api/subscription');
    check('the old untokenized path explains itself', untokenized.status === 401, untokenized.status);
    check('the subscription and dashboard tokens are different', store.token !== store.uiToken);
  } finally {
    child.kill();
  }
}

// Once the UI is off loopback, everything that reads or writes credentials must
// demand the dashboard token. Gating only the subscription feed left
// /api/config — which returns the same credentials *plus* that token — open to
// anyone on the network.
async function testAuthRequired(dir) {
  console.log('\n── non-loopback: every credential route demands the dashboard token');
  const port = 3322;
  const child = await boot(port, { HOST: '0.0.0.0' }, dir);
  try {
    const store = JSON.parse(fs.readFileSync(path.join(dir, 'servers.json'), 'utf8'));
    const tok = store.uiToken;
    check('a dashboard token was minted', typeof tok === 'string' && tok.length >= 16, tok);

    const guarded = [
      ['GET', '/'],
      ['GET', '/api/config'],
      ['GET', '/api/qrcode'],
      ['GET', '/api/qrcode/subscription'],
      ['GET', '/api/download/clash'],
      ['GET', '/api/download/singbox'],
      ['GET', '/api/download/uri'],
      ['GET', '/api/download/backup'],
      ['GET', '/api/test'],
      ['GET', '/api/test-all'],
      ['GET', '/api/history'],
      ['POST', '/api/profiles'],
      ['POST', '/api/active'],
      ['POST', '/api/import'],
      ['POST', '/api/auto-active'],
      ['DELETE', '/api/profiles/abc'],
    ];
    for (const [method, pathname] of guarded) {
      const res = await request(port, method, pathname, { body: method === 'GET' ? undefined : {} });
      check(`${method} ${pathname} is refused without a token`, res.status === 401, res.status);
    }

    for (const [label, headers] of [
      ['X-UI-Token', { 'X-UI-Token': tok }],
      ['Authorization: Bearer', { Authorization: `Bearer ${tok}` }],
      ['Cookie', { Cookie: `airport_ui=${tok}` }],
    ]) {
      const res = await request(port, 'GET', '/api/config', { headers });
      check(`${label} is accepted`, res.status === 200, res.status);
    }

    const wrong = await request(port, 'GET', '/api/config', { headers: { 'X-UI-Token': 'x'.repeat(tok.length) } });
    check('a wrong token of the right length is refused', wrong.status === 401, wrong.status);

    // ?ui_token= is traded for a cookie and redirected away, so the secret stops
    // travelling in Referer headers, history and screenshots.
    const viaQuery = await request(port, 'GET', `/?ui_token=${encodeURIComponent(tok)}`);
    check('?ui_token= redirects', viaQuery.status === 302 && viaQuery.headers.location === '/', `${viaQuery.status} ${viaQuery.headers.location}`);
    const cookie = String(viaQuery.headers['set-cookie'] || '');
    check('the cookie it sets is HttpOnly and SameSite=Strict', /HttpOnly/i.test(cookie) && /SameSite=Strict/i.test(cookie), cookie);

    // Clients polling the subscription feed hold neither a cookie nor a header.
    const sub = await request(port, 'GET', `/api/subscription/${store.token}`);
    check('the subscription feed still needs only its own token', sub.status === 200, sub.status);
  } finally {
    child.kill();
  }
}

// UI_TOKEN also turns authentication on for a loopback bind, for anyone sharing
// the machine.
async function testPinnedToken(dir) {
  console.log('\n── UI_TOKEN pins the secret and forces auth on loopback');
  const port = 3323;
  const child = await boot(port, { HOST: '127.0.0.1', UI_TOKEN: 'pinned-token-value-1234567890' }, dir);
  try {
    const denied = await request(port, 'GET', '/api/config');
    check('loopback now requires a token too', denied.status === 401, denied.status);
    const allowed = await request(port, 'GET', '/api/config', { headers: { 'X-UI-Token': 'pinned-token-value-1234567890' } });
    check('the pinned token is what works', allowed.status === 200, allowed.status);
    const storeToken = JSON.parse(fs.readFileSync(path.join(dir, 'servers.json'), 'utf8')).uiToken;
    const stale = await request(port, 'GET', '/api/config', { headers: { 'X-UI-Token': storeToken } });
    check('the stored token does not override UI_TOKEN', stale.status === 401, stale.status);
  } finally {
    child.kill();
  }
}

(async () => {
  const dirs = [];
  const mk = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'airport-api-')); dirs.push(d); return d; };
  try {
    await testLoopback(mk());
    await testAuthRequired(mk());
    await testPinnedToken(mk());
  } catch (err) {
    console.error('✗ harness error:', err.message);
    failed += 1;
  } finally {
    for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* temp dir */ } }
  }
  console.log(failed ? `\n${passed} passed, ${failed} FAILED` : `\n${passed} passed`);
  process.exit(failed ? 1 : 0);
})();
