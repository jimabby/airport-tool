'use strict';

const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');
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

function request(raw, { method = 'GET', headers = {}, body, timeoutMs = 15000, maxBytes = 2 * 1024 * 1024 } = {}) {
  const problem = urlProblem(raw);
  if (problem) return Promise.reject(new Error(problem));
  return new Promise((resolve, reject) => {
    const u = new URL(raw);
    const req = (u.protocol === 'https:' ? https : http).request(u, {
      method, headers, lookup: safeLookup, agent: false,
    });
    const timer = setTimeout(() => req.destroy(new Error(`no response in ${timeoutMs}ms`)), timeoutMs);
    const fail = (err) => { clearTimeout(timer); reject(err); };
    req.on('error', fail);
    req.on('response', (res) => {
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
    });
    req.end(body);
  });
}
module.exports = { addressProblem, urlProblem, safeLookup, request };
