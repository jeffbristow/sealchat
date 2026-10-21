/* =====================================================================
 * Seal Chat — names.js   (name@domain — easy-to-share names, 1.8.0)
 * ---------------------------------------------------------------------
 * Instead of the long Seal Chat ID you can give people a name like
 *     ann@example.com
 * if you (or a friend) have a website. Nobody runs a central list: each
 * website answers only for its own names, in one small file:
 *
 *     https://example.com/.well-known/sealchat.json
 *     { "v": 1, "names": { "ann": "sealchat:<onion>:<fingerprint>",
 *                          "sam": { "id": "sealchat:…", "name": "Sam" } } }
 *
 * Seal Chat Web's setup page (Names) writes that file for you.
 *
 * How it stays safe:
 *   - the name only FINDS the ID; the ID (with its key fingerprint) is
 *     what is trusted, and Seal Chat shows the fingerprint before adding
 *   - the answer is remembered when you add someone ("pinned"); Seal Chat
 *     looks again once a day and warns if the name now points to a
 *     different person — it never switches by itself
 *   - looked up through Tor (the website doesn't see your IP address);
 *     directly only if you allow that for websites that block Tor
 *
 * Sections:
 *   1. Reading a name
 *   2. Looking it up
 *   3. The file format (for Seal Chat Web's Names panel and tests)
 * ===================================================================== */

const { request } = require('./webhttp');
const { parseId } = require('./peer');

/* =================================================================
 * 1. READING A NAME
 * ================================================================= */
const NAME_RE = /^@?([a-z0-9][a-z0-9._-]{0,39})@((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$/i;

/** "Ann@Example.com" → { name: 'ann', domain: 'example.com', handle: 'ann@example.com' }, or null. */
function parseHandle(text) {
  const m = NAME_RE.exec(String(text || '').trim());
  if (!m) return null;
  const name = m[1].toLowerCase(), domain = m[2].toLowerCase();
  if (/^(localhost|.*\.onion)$/.test(domain)) return null;
  return { name, domain, handle: name + '@' + domain };
}
const looksLikeHandle = t => !!parseHandle(t);

/* =================================================================
 * 2. LOOKING IT UP
 * ================================================================= */
/**
 * @param text  "ann@example.com"
 * @param opt   { socksPort (Tor), direct (allow without Tor if Tor is blocked), http (tests), base (tests: http://127.0.0.1:port/) }
 * @returns { handle, id, onion, fp, display }
 */
async function lookup(text, opt = {}) {
  const h = parseHandle(text);
  if (!h) throw new Error('That is not a name like ann@example.com');
  const url = (opt.base || `https://${h.domain}/`) + '.well-known/sealchat.json';
  // Tor → (blocked, and allowed) directly
  const { viaFallbacks, looksBlocked } = require('./webhttp');
  const get = u => viaFallbacks(u, { method: 'GET', socksPort: opt.socksPort || null, direct: !!opt.direct,
    http: opt.http, allowHttp: !!opt.base, timeoutMs: 60e3, maxBytes: 256 * 1024, headers: { Accept: 'application/json' } });
  let r;
  try { r = await get(url); }
  catch (e) {
    if (e.code === 'TOR_BLOCKED') throw new Error(`${h.domain} blocks visitors that come through Tor. (Settings → Privacy can allow contacting such websites directly.)`);
    throw new Error(`Couldn't reach ${h.domain}: ${e.message}`);
  }
  // example.com → www.example.com (or the other way round), https only, at most twice
  for (let hop = 0; hop < 2 && [301, 302, 307, 308].includes(r.status) && r.headers && r.headers.location; hop++) {
    let next; try { next = new URL(String(r.headers.location), url); } catch { break; }
    const host = next.hostname.toLowerCase(), bare = h.domain.replace(/^www\./, '');
    if (!(next.protocol === 'https:' || opt.base) || !(host === bare || host === 'www.' + bare)) break;
    r = await get(next.href);
  }
  if (r.via === 'blocked' || looksBlocked(r)) throw new Error(`${h.domain} blocks visitors that come through Tor. (Settings → Privacy can allow contacting such websites directly.)`);
  if (r.status === 404) throw new Error(`${h.domain} has no Seal Chat names (no /.well-known/sealchat.json there)`);
  if (r.status !== 200) throw new Error(`${h.domain} answered ${r.status}`);
  let j;
  try { j = JSON.parse(r.body.toString('utf8')); } catch { throw new Error(`${h.domain}'s Seal Chat names file is not readable`); }
  const entry = j && j.names && typeof j.names === 'object' ? j.names[h.name] : null;
  if (!entry) throw new Error(`${h.domain} has no Seal Chat name "${h.name}"`);
  const idText = typeof entry === 'string' ? entry : entry.id;
  let id;
  try { id = parseId(idText); } catch { throw new Error(`The ID listed for ${h.handle} is not a valid Seal Chat ID`); }
  const display = typeof entry === 'object' && entry.name ? String(entry.name).replace(/[\x00-\x1f]/g, '').slice(0, 80) : '';
  return { handle: h.handle, id: `sealchat:${id.onion}:${id.fp}`, onion: id.onion, fp: id.fp, display };
}

/* =================================================================
 * 3. FILE FORMAT
 * ================================================================= */
/** The JSON a website publishes, from { name: id | {id, name} }. */
function buildFile(names) {
  const out = {};
  for (const [n, v] of Object.entries(names || {})) {
    const name = String(n).toLowerCase();
    if (!/^[a-z0-9][a-z0-9._-]{0,39}$/.test(name)) continue;
    const idText = typeof v === 'string' ? v : v && v.id;
    try { const p = parseId(idText); out[name] = v && v.name ? { id: `sealchat:${p.onion}:${p.fp}`, name: String(v.name).slice(0, 80) } : `sealchat:${p.onion}:${p.fp}`; } catch { /* skip */ }
  }
  return { v: 1, names: out, updated: new Date().toISOString() };
}

module.exports = { parseHandle, looksLikeHandle, lookup, buildFile };
