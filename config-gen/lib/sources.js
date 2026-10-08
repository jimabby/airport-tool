// Remote subscription sources: a provider's subscription URL, fetched and
// merged into the store so its servers stay current without being re-pasted.
//
// Shared by the web UI (which refreshes them on a schedule) and gen.js
// (`--refresh`), so both fetch, vet and merge exactly the same way.
//
// The merge is deliberately narrow. Every profile a source produced carries its
// id in `source`; a refresh replaces those profiles and touches nothing else.
// A server that is still in the feed keeps its id — so its probe history, its
// place in a device's subset and ★ all survive — and its enabled flag, so a
// server you switched off stays off however often the provider re-lists it.

'use strict';

const C = require('./configs');

const FETCH_TIMEOUT_MS = 15000;
// A subscription is a list of links. Anything past this is not one, and
// buffering it all to find out is not a good use of the dashboard's memory.
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_REDIRECTS = 3;
// Providers decide what to send by User-Agent: a Clash-looking client gets
// Clash YAML, which this does not read. v2rayN is the client every provider
// answers with the base64 link list that parseSubscription understands.
const USER_AGENT = 'v2rayN/7.0 (airport-tool)';

// Fetch a subscription body as text. Redirects are followed by hand, a few at
// most, and every hop is vetted the way the first URL was — the same reason
// alert.js refuses to follow one blindly: a 302 to a metadata endpoint would
// otherwise walk straight past the check.
async function fetchText(rawUrl, { timeoutMs = FETCH_TIMEOUT_MS, maxBytes = MAX_BYTES } = {}) {
  let url = String(rawUrl || '').trim();
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const problem = C.alertUrlProblem(url);
    if (problem) throw new Error(problem);
    const res = await require('./network').request(url, { timeoutMs, maxBytes, headers: { 'User-Agent': USER_AGENT, Accept: 'text/plain, */*' } });
    if (res.status >= 300 && res.status < 400) {
      const where = res.headers.get('location');
      if (!where) throw new Error(`redirect (${res.status}) with nowhere to go`);
      url = new URL(where, url).toString();
      continue;
    }
    if (!res.ok) throw new Error(`the provider answered ${res.status}`);
    return res.text;
  }
  throw new Error(`more than ${MAX_REDIRECTS} redirects`);
}

const endpointKey = (p) => JSON.stringify([p.protocol, String(p.server || '').toLowerCase(), Number(p.port), p.network || 'tcp', p.path || '', p.serviceName || '', p.host || '', p.sni || '', p.plugin || '', p.plugin_opts || '']);
// Connection identity includes credentials/options, but never display metadata.
const keyOf = (p) => C.buildUri({ ...p, server: String(p.server || '').toLowerCase() }, 'identity');

// Turn a fetched body into the profiles it describes, keeping only the ones
// that would pass validation — an invalid entry would block every generate run.
function parseSourceBody(text) {
  const { profiles, errors } = C.parseSubscription(text);
  const usable = [];
  const problems = [...errors];
  const seen = new Set();
  for (const p of profiles) {
    const { errors: bad } = C.validateProfile(p);
    if (bad.length) { problems.push(`${p.remarks}: ${bad.join(', ')}`); continue; }
    const k = keyOf(p);
    if (seen.has(k)) continue; // a provider listing one server twice
    seen.add(k);
    usable.push(p);
  }
  return { profiles: usable, problems };
}

// Merge one source's freshly fetched profiles into the store, in place.
// Returns what changed, including the ids that disappeared so the caller can
// prune their probe history.
function mergeSource(store, source, fetched) {
  const activeId = store.profiles[store.active] ? store.profiles[store.active].id : null;
  const mine = store.profiles.filter((p) => p.source === source.id);
  const byConnection = new Map();
  const byEndpoint = new Map();
  for (const p of mine) {
    for (const [map, key] of [[byConnection, keyOf(p)], [byEndpoint, endpointKey(p)]]) {
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(p);
    }
  }
  const used = new Set();
  const counts = new Map();
  for (const p of fetched) counts.set(endpointKey(p), (counts.get(endpointKey(p)) || 0) + 1);
  // Servers you already have by hand win: importing a duplicate of one would
  // put the same server in every bundle twice.
  const others = new Set(store.profiles.filter((p) => p.source !== source.id).map(keyOf));

  const replacement = new Map();
  const added = [];
  let skipped = 0;
  for (const p of fetched) {
    const k = keyOf(p);
    if (others.has(k)) { skipped += 1; continue; }
    let old = (byConnection.get(k) || []).find((o) => !used.has(o.id));
    if (!old) {
      const candidates = byEndpoint.get(endpointKey(p)) || [];
      // A unique endpoint can rotate its credentials without losing its ID.
      // Ambiguous accounts are never guessed or silently merged.
      if (candidates.length === 1 && !used.has(candidates[0].id) && counts.get(endpointKey(p)) === 1) old = candidates[0];
    }
    if (old) used.add(old.id);
    const next = C.normalizeProfile({
      ...p,
      id: old ? old.id : undefined,
      enabled: old ? old.enabled : true,
      source: source.id,
    });
    if (old) replacement.set(old.id, next);
    else added.push(next);
  }

  const removedIds = [];
  const profiles = [];
  for (const p of store.profiles) {
    if (p.source !== source.id) { profiles.push(p); continue; }
    if (replacement.has(p.id)) profiles.push(replacement.get(p.id));
    else removedIds.push(p.id);
  }
  profiles.push(...added);
  store.profiles = profiles;

  // ★ follows its profile; if the provider dropped it, it moves to the first
  // enabled server rather than onto whatever slid into its old position.
  const at = profiles.findIndex((p) => p.id === activeId);
  if (at !== -1) store.active = at;
  else {
    const first = profiles.findIndex(C.isEnabled);
    store.active = first === -1 ? 0 : first;
  }
  // A device limited to a subset stops naming servers that no longer exist.
  if (removedIds.length && Array.isArray(store.clients)) {
    const gone = new Set(removedIds);
    for (const c of store.clients) {
      if (Array.isArray(c.profiles)) c.profiles = c.profiles.filter((id) => !gone.has(id));
    }
  }
  return { added: added.length, updated: replacement.size, removed: removedIds.length, skipped, removedIds };
}

// Record the outcome of a refresh on the source itself, so the dashboard can
// say when it last worked and why it last did not.
function recordResult(source, result) {
  source.lastFetched = Date.now();
  source.lastError = result.error || null;
  if (!result.error) source.lastCount = result.count;
}

function previewMerge(store, source, fetched) {
  const next = JSON.parse(JSON.stringify(store));
  const merged = mergeSource(next, source, fetched);
  const before = new Map(store.profiles.map((p) => [p.id, p]));
  const after = new Map(next.profiles.map((p) => [p.id, p]));
  const changes = [];
  for (const p of next.profiles) {
    const old = before.get(p.id);
    if (!old) changes.push({ kind: 'added', name: p.remarks, fields: [] });
    else {
      const fields = [...new Set([...Object.keys(old), ...Object.keys(p)])]
        .filter((k) => !['id', 'source'].includes(k) && JSON.stringify(old[k]) !== JSON.stringify(p[k]));
      if (fields.length) changes.push({ kind: 'changed', name: p.remarks, fields });
    }
  }
  for (const p of store.profiles) if (!after.has(p.id)) changes.push({ kind: 'removed', name: p.remarks, fields: [] });
  return { next, merged, changes };
}

// Fetch and parse one source. Never touches a store: the network half runs
// outside any lock, and the caller merges the result in afterwards. A feed
// that yields nothing usable is an error, not an instruction to delete every
// server the source contributed — providers fail in exactly that shape.
async function fetchSource(source) {
  try {
    const text = await fetchText(source.url);
    const { profiles, problems } = parseSourceBody(text);
    if (!profiles.length) {
      const why = problems.length ? ` (${problems.slice(0, 3).join('; ')})` : '';
      return { error: `nothing usable in the response${why} — kept the servers from the last good fetch`, profiles: [], problems };
    }
    return { profiles, problems, count: profiles.length };
  } catch (err) {
    return { error: `${err.message} — kept the servers from the last good fetch`, profiles: [], problems: [] };
  }
}

// Whether a source is due for its scheduled refresh.
function isDue(source, now = Date.now()) {
  if (!source.lastFetched) return true;
  return now - source.lastFetched >= C.normalizeSourceInterval(source.intervalHours) * 3600000;
}

module.exports = {
  previewMerge,
  keyOf, endpointKey,
  FETCH_TIMEOUT_MS,
  MAX_BYTES,
  USER_AGENT,
  fetchText,
  parseSourceBody,
  mergeSource,
  recordResult,
  fetchSource,
  isDue,
};
