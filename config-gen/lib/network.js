'use strict';

const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');
const tls = require('tls');
const zlib = require('zlib');

const blocked = new net.BlockList();
blocked.addSubnet('169.254.0.0', 16, 'ipv4');
blocked.addAddress('100.100.100.200', 'ipv4');
blocked.addSubnet('fe80::', 10, 'ipv6');
blocked.addAddress('fd00:ec2::254', 'ipv6');
const metadataNames = new Set(['metadata.google.internal', 'metadata.goog']);
function addressProblem(address) {
  const family = net.isIP(address);
  return family && blocked.check(address, family === 4 ? 'ipv4' : 'ipv6')
    ? 'cloud metadata endpoint or link-local address is not allowed' : null;
}
function urlProblem(raw) {
  if (!String(raw || '').trim()) return 'no URL';
  let u;
  try { u = new URL(raw); } catch { return 'that is not a URL this tool can parse'; }
  if (!['http:', 'https:'].includes(u.protocol)) return 'only http:// and https:// URLs can be used';
  if (u.username || u.password) return 'URL userinfo is not supported';
  const host = u.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (metadataNames.has(host)) return 'cloud metadata endpoint is not allowed';
  return addressProblem(host);
}

// Validate the addresses actually handed to the socket, not an earlier DNS
// lookup that could change before connecting. LAN/loopback webhooks remain usable.
function safeLookup(host, options, callback) {
  dns.lookup(host, { all: true, verbatim: true }, (err, addresses) => {
    if (err) return callback(err);
    if (!addresses.length || addresses.some((a) => addressProblem(a.address))) {
      return callback(new Error('DNS resolved to a cloud metadata endpoint or link-local address'));
    }
    const family = typeof options === 'number' ? options : options.family;
    const usable = family ? addresses.filter((a) => a.family === family) : addresses;
    if (!usable.length) return callback(new Error('No address for the requested family'));
    if (options.all) callback(null, usable);
    else callback(null, usable[0].address, usable[0].family);
  });
}

// Read a response into { status, ok, headers.get, text }, bounded in size.
function collect(req, res, { maxBytes, timer, resolve, fail }) {
  const chunks = [];
  let size = 0;
  const encoding = String(res.headers['content-encoding'] || '').toLowerCase();
  const decoder = encoding === 'gzip' || encoding === 'deflate' ? zlib.createUnzip()
    : encoding === 'br' ? zlib.createBrotliDecompress() : null;
  if (encoding && encoding !== 'identity' && !decoder) {
    req.destroy(new Error('Unsupported response content encoding')); return;
  }
  const bodyStream = decoder ? res.pipe(decoder) : res;
  if (decoder) decoder.on('error', (err) => { req.destroy(err); fail(err); });
  res.on('error', fail);
  bodyStream.on('data', (chunk) => {
    size += chunk.length;
    if (size > maxBytes) {
      const err = new Error(`the response is larger than ${maxBytes} bytes`);
      if (decoder) decoder.destroy();
      req.destroy(err); fail(err); return;
    }
    chunks.push(chunk);
  });
  bodyStream.on('end', () => {
    clearTimeout(timer);
    resolve({ status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300,
      headers: { get: (name) => res.headers[name.toLowerCase()] || null },
      text: Buffer.concat(chunks).toString('utf8') });
  });
}

// ── Through a proxy ────────────────────────────────────────────────────────── //
// From inside China the provider's subscription host, Telegram and Cloudflare's
// WARP API are often unreachable directly, so these requests can go through a
// proxy (see outbound.js for which one). Two kinds are spoken:
//   http(s)://[user:pass@]host:port   CONNECT tunnel (TLS to the proxy for https://)
//   socks5://… / socks5h://…          SOCKS5, the name handed to the proxy to resolve
// Every target is tunnelled, plain-http ones included, so the request bytes are
// built here the same way whichever kind of proxy carries them.
// One listener for the whole handshake. Attaching and detaching a 'data'
// listener per step loses whatever arrives in between — a flowing socket
// emits to nobody — which is how a SOCKS5 reply split across two reads hung.
function reader(socket, limit = 65536) {
  let buf = Buffer.alloc(0);
  let waiter = null;
  let error = null;
  const check = () => {
    if (!waiter) return;
    const got = waiter.take();
    if (got !== undefined) { const w = waiter; waiter = null; w.resolve(got); } else if (error) { const w = waiter; waiter = null; w.reject(error); }
  };
  const onData = (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (buf.length > limit) error = new Error('the proxy sent an oversized reply');
    check();
  };
  const onEnd = () => { error = error || new Error('the proxy closed the connection'); check(); };
  const onError = (err) => { error = err; check(); };
  socket.on('data', onData); socket.on('end', onEnd); socket.on('error', onError);
  const wait = (take) => new Promise((resolve, reject) => { waiter = { take, resolve, reject }; check(); });
  return {
    bytes: (n) => wait(() => {
      if (buf.length < n) return undefined;
      const out = buf.subarray(0, n); buf = buf.subarray(n); return out;
    }),
    until: (marker) => wait(() => {
      const at = buf.indexOf(marker);
      if (at === -1) return undefined;
      const out = buf.subarray(0, at); buf = buf.subarray(at + marker.length); return out;
    }),
    // Hand the socket on, with anything read past the handshake put back.
    done: () => {
      socket.off('data', onData); socket.off('end', onEnd); socket.off('error', onError);
      if (buf.length) socket.unshift(buf);
    },
  };
}

function connected(socket, event) {
  return new Promise((resolve, reject) => {
    socket.once(event, () => { socket.off('error', reject); resolve(socket); });
    socket.once('error', reject);
  });
}

async function socksConnect(socket, proxy, host, port) {
  const r = reader(socket);
  try { await socksHandshake(socket, r, proxy, host, port); } finally { r.done(); }
  return socket;
}

async function socksHandshake(socket, r, proxy, host, port) {
  const readBytes = (_, n) => r.bytes(n);
  const user = decodeURIComponent(proxy.username || '');
  const pass = decodeURIComponent(proxy.password || '');
  socket.write(Buffer.from(user ? [5, 2, 0, 2] : [5, 1, 0]));
  const choice = await readBytes(socket, 2);
  if (choice[0] !== 5) throw new Error('the proxy is not a SOCKS5 proxy');
  if (choice[1] === 2) {
    const u = Buffer.from(user); const p = Buffer.from(pass);
    socket.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([p.length]), p]));
    const auth = await readBytes(socket, 2);
    if (auth[1] !== 0) throw new Error('the SOCKS5 proxy refused the username/password');
  } else if (choice[1] !== 0) {
    throw new Error('the SOCKS5 proxy wants an authentication method this tool does not speak');
  }
  const family = net.isIP(host);
  let addr;
  if (family === 4) addr = Buffer.from([1, ...host.split('.').map(Number)]);
  else if (family === 6) {
    const [a, b] = host.includes('::') ? host.split('::') : [host, undefined];
    const head = a ? a.split(':') : [];
    const tail = b ? b.split(':') : [];
    const groups = b === undefined ? head : [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail];
    addr = Buffer.concat([Buffer.from([4]), Buffer.from(groups.flatMap((g) => { const v = parseInt(g || '0', 16); return [v >> 8, v & 255]; }))]);
  } else {
    const name = Buffer.from(host);
    addr = Buffer.concat([Buffer.from([3, name.length]), name]);
  }
  socket.write(Buffer.concat([Buffer.from([5, 1, 0]), addr, Buffer.from([port >> 8, port & 255])]));
  const head = await readBytes(socket, 4);
  if (head[1] !== 0) throw new Error(`the SOCKS5 proxy could not reach ${host}:${port} (reply ${head[1]})`);
  const rest = head[3] === 1 ? 4 : head[3] === 4 ? 16 : (await readBytes(socket, 1))[0];
  await readBytes(socket, rest + 2);
}

async function httpConnect(socket, proxy, host, port) {
  const authority = `${net.isIPv6(host) ? `[${host}]` : host}:${port}`;
  const lines = [`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`];
  if (proxy.username) {
    const cred = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password || '')}`;
    lines.push(`Proxy-Authorization: Basic ${Buffer.from(cred).toString('base64')}`);
  }
  socket.write(`${lines.join('\r\n')}\r\n\r\n`);
  const r = reader(socket);
  let head;
  try { head = (await r.until('\r\n\r\n')).toString('latin1'); } finally { r.done(); }
  const m = /^HTTP\/1\.[01] (\d{3})/.exec(head);
  if (!m || m[1] !== '200') throw new Error(`the proxy refused to connect to ${authority} (${m ? m[1] : 'no status'})`);
  return socket;
}

// A socket to host:port through `proxyUrl`, TLS-wrapped when the target is https.
async function tunnel(proxyUrl, target) {
  const proxy = new URL(proxyUrl);
  const pport = Number(proxy.port) || (proxy.protocol === 'https:' ? 443 : proxy.protocol.startsWith('socks') ? 1080 : 8080);
  const phost = proxy.hostname.replace(/^\[|\]$/g, '');
  let socket = proxy.protocol === 'https:'
    ? await connected(tls.connect({ host: phost, port: pport, servername: net.isIP(phost) ? undefined : phost }), 'secureConnect')
    : await connected(net.connect(pport, phost), 'connect');
  const host = target.hostname.replace(/^\[|\]$/g, '');
  const port = Number(target.port) || (target.protocol === 'https:' ? 443 : 80);
  try {
    if (proxy.protocol.startsWith('socks')) await socksConnect(socket, proxy, host, port);
    else await httpConnect(socket, proxy, host, port);
    if (target.protocol === 'https:') {
      socket = await connected(tls.connect({ socket, servername: net.isIP(host) ? undefined : host, ALPNProtocols: ['http/1.1'] }), 'secureConnect');
    }
    return socket;
  } catch (err) {
    socket.destroy();
    throw err;
  }
}

// The metadata check, made locally before a name is handed to a proxy to
// resolve. A lookup that fails here (the name is blocked or poisoned locally —
// the reason for the proxy) is not a reason to refuse; only an answer that
// points at a metadata address is.
function lookupProblem(host) {
  if (net.isIP(host)) return Promise.resolve(addressProblem(host));
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), 3000);
    dns.lookup(host, { all: true, verbatim: true }, (err, addresses) => {
      clearTimeout(timer);
      if (err || !addresses) return resolve(null);
      resolve(addresses.some((a) => addressProblem(a.address)) ? 'DNS resolved to a cloud metadata endpoint or link-local address' : null);
    });
  });
}

function request(raw, { method = 'GET', headers = {}, body, timeoutMs = 15000, maxBytes = 2 * 1024 * 1024, proxy } = {}) {
  const problem = urlProblem(raw);
  if (problem) return Promise.reject(new Error(problem));
  const u = new URL(raw);
  return (async () => {
    // `proxy: null` forces a direct connection; undefined asks outbound.js.
    const via = proxy === undefined ? await require('./outbound').proxyFor(u) : proxy;
    if (!via) return direct(u, { method, headers, body, timeoutMs, maxBytes });
    return proxied(u, via, { method, headers, body, timeoutMs, maxBytes });
  })();
}

function direct(u, { method, headers, body, timeoutMs, maxBytes }) {
  return new Promise((resolve, reject) => {
    const req = (u.protocol === 'https:' ? https : http).request(u, {
      method, headers, lookup: safeLookup, agent: false,
    });
    const timer = setTimeout(() => req.destroy(new Error(`no response in ${timeoutMs}ms`)), timeoutMs);
    const fail = (err) => { clearTimeout(timer); reject(err); };
    req.on('error', fail);
    req.on('response', (res) => collect(req, res, { maxBytes, timer, resolve, fail }));
    req.end(body);
  });
}

async function proxied(u, proxyUrl, { method, headers, body, timeoutMs, maxBytes }) {
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const bad = await lookupProblem(host);
  if (bad) throw new Error(bad);
  let socket;
  const deadline = new Promise((_, reject) => setTimeout(() => reject(new Error(`no response in ${timeoutMs}ms`)), timeoutMs).unref());
  try {
    socket = await Promise.race([tunnel(proxyUrl, u), deadline]);
  } catch (err) {
    throw new Error(`through the proxy: ${err.message}`);
  }
  return new Promise((resolve, reject) => {
    const req = http.request({
      protocol: 'http:', host: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: `${u.pathname}${u.search}`, method, headers: { Host: u.host, ...headers },
      createConnection: () => socket,
    });
    const timer = setTimeout(() => req.destroy(new Error(`no response in ${timeoutMs}ms`)), timeoutMs);
    const fail = (err) => { clearTimeout(timer); socket.destroy(); reject(err); };
    req.on('error', fail);
    req.on('response', (res) => collect(req, res, {
      maxBytes, timer, fail, resolve: (r) => { socket.destroy(); resolve(r); },
    }));
    req.end(body);
  });
}

module.exports = { addressProblem, urlProblem, safeLookup, request, tunnel };
