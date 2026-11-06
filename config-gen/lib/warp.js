// Registering a Cloudflare WARP device, for the WARP exit (see checkWarp in
// configs.js).
//
// WARP's consumer API hands a WireGuard identity to anyone who presents a
// public key: an address inside Cloudflare's range, the peer's public key, and
// a client id whose first three bytes go into WireGuard's `reserved` field —
// without them some Cloudflare edges silently drop the handshake. This is what
// wgcf does, minus the binary: the key pair is made here and the private half
// never leaves this machine.
//
// Do this *before* travelling. From inside China the registration endpoint is
// itself often unreachable; the identity it returns keeps working afterwards,
// because the WireGuard traffic is chained through your own server.

'use strict';

const crypto = require('crypto');
const C = require('./configs');

const WARP_API = 'https://api.cloudflareclient.com/v0a1922/reg';
const WARP_TIMEOUT_MS = 15000;

const b64 = (b64url) => Buffer.from(b64url, 'base64url').toString('base64');

// An X25519 key pair as WireGuard writes it: base64 of the raw 32 bytes.
function wgKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    privateKey: b64(privateKey.export({ format: 'jwk' }).d),
    publicKey: b64(publicKey.export({ format: 'jwk' }).x),
  };
}

// The `reserved` triple from a registration's client id (base64).
function reservedFrom(clientId) {
  const bytes = Buffer.from(String(clientId || ''), 'base64');
  return bytes.length >= 3 ? [bytes[0], bytes[1], bytes[2]] : [];
}

// The answer → the rules.warp shape. Throws with a readable message when the
// API answered something this cannot use.
function warpFromRegistration(json, privateKey) {
  const cfg = json && json.config;
  const peer = cfg && Array.isArray(cfg.peers) ? cfg.peers[0] : null;
  const addrs = cfg && cfg.interface && cfg.interface.addresses;
  if (!peer || !peer.public_key || !addrs || !addrs.v4) {
    throw new Error('Cloudflare answered, but without a WireGuard peer and address — try again later');
  }
  const v6 = addrs.v6 ? `${addrs.v6}/128` : '';
  const { warp, errors } = C.checkWarp({
    enabled: true,
    privateKey,
    publicKey: peer.public_key,
    address4: `${addrs.v4}/32`,
    address6: v6,
    // The fixed anycast address rather than the hostname: the name needs a DNS
    // lookup at the far end of a chain that has not come up yet.
    endpoint: C.WARP_ENDPOINT,
    reserved: reservedFrom(cfg.client_id),
  });
  if (errors.length) throw new Error(`Cloudflare's answer did not validate: ${errors.join('; ')}`);
  return warp;
}

// Register a fresh device. `fetchImpl` and WARP_API_URL are there so tests
// never reach Cloudflare. Keeps the existing site and domain lists when
// handed them.
async function registerWarp({
  fetchImpl = globalThis.fetch, keep = null, timeoutMs = WARP_TIMEOUT_MS,
  url = process.env.WARP_API_URL || WARP_API,
} = {}) {
  const { privateKey, publicKey } = wgKeyPair();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res;
  try {
    res = await fetchImpl(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'okhttp/3.12.1',
        'CF-Client-Version': 'a-6.3-1922',
      },
      body: JSON.stringify({
        key: publicKey,
        install_id: '',
        fcm_token: '',
        tos: new Date().toISOString(),
        model: 'PC',
        serial_number: '',
        locale: 'en_US',
      }),
      signal: ctrl.signal,
    });
  } catch (err) {
    const why = err && err.name === 'AbortError' ? `no answer in ${timeoutMs / 1000}s` : (err && err.message) || String(err);
    throw new Error(`Could not reach Cloudflare's WARP registration (${why}). From inside China it is often blocked — register before you travel.`);
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw new Error(`Cloudflare refused the WARP registration (HTTP ${res.status})`);
  let json;
  try { json = await res.json(); } catch { throw new Error('Cloudflare answered the WARP registration with something that is not JSON'); }
  const warp = warpFromRegistration(json, privateKey);
  if (keep && typeof keep === 'object') {
    if (Array.isArray(keep.sites)) warp.sites = keep.sites;
    if (Array.isArray(keep.domains)) warp.domains = keep.domains;
  }
  return warp;
}

module.exports = {
  WARP_API,
  wgKeyPair,
  reservedFrom,
  warpFromRegistration,
  registerWarp,
};
