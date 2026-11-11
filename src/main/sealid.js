/* =====================================================================
 * Seal Chat — sealid.js   (Seal ID: proven identities, 1.10.0)
 * ---------------------------------------------------------------------
 * Seal ID (github.com/jeffbristow/SealID) is a self-hosted identity page:
 * a chain of statements signed with an OpenPGP key that claims websites,
 * domains and accounts (GitHub, X, Mastodon …) — each claim proven by the
 * account itself. Seal Chat uses it two ways:
 *
 *   YOUR SEAL ID       Settings → Seal ID. Your address goes to your
 *                      contacts inside your (signed, encrypted) profile.
 *   THEIR SEAL ID      When a contact shares one, Seal Chat fetches it
 *                      through Tor, verifies every signature itself and
 *                      checks that it really belongs to THIS contact:
 *                        • same key — the Seal ID is signed by the contact's
 *                          own Seal Chat key (nothing else needed), or
 *                        • signed — the Seal ID claims the contact's Seal Chat
 *                          ID (a "sealchat" proof) and the contact's Seal Chat
 *                          key signed that claim back (an "attestation").
 *                      It remembers what it saw ("pinned") and warns if the
 *                      Seal ID is later replaced instead of extended.
 *   ADD BY SEAL ID     Add contact → "id.example.com" or a domain the person
 *                      proved in their Seal ID ("example.com") → the Seal Chat
 *                      ID their Seal ID proves.
 *
 * Nothing here trusts the Seal ID's web server: the chain is verified here,
 * and a domain only counts as an alias if Seal Chat itself finds the proof.
 * The proof statuses for other accounts (GitHub, X …) are shown as the Seal ID
 * reported them.
 *
 * Sections:
 *   1. Addresses, tokens
 *   2. Fetching (through Tor) and aliases
 *   3. Verifying a Seal ID chain
 *   4. Does it belong to this Seal Chat ID?
 *   5. Summary + pin
 * ===================================================================== */

const crypto = require('crypto');
const openpgp = require('openpgp');
const { viaFallbacks, looksBlocked } = require('./webhttp');

/* =================================================================
 * 1. ADDRESSES, TOKENS
 * ================================================================= */
const TYPES = new Set(['eldest', 'profile', 'proof', 'revoke', 'vouch', 'mirrors', 'rotate']);
const HEX = /^[0-9A-F]{40}$|^[0-9A-F]{64}$/;

/** "ID.example.com/" → "https://id.example.com"; null if it isn't a usable address. opt.allowHttp: tests. */
function normUrl(input, opt = {}) {
  let u = String(input || '').trim();
  if (!u || /\s/.test(u)) return null;
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  let p;
  try { p = new URL(u); } catch { return null; }
  if (p.protocol !== 'https:' && !(opt.allowHttp && p.protocol === 'http:')) return null;
  if (p.search || p.hash || p.username || p.password) return null;
  if (p.port && !opt.allowHttp) return null;
  const host = p.hostname.toLowerCase();
  if (!opt.allowHttp && !/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/.test(host)) return null;
  let path = p.pathname.replace(/\/+$/, '').replace(/\/(index|admin|api)\.php$/, '');
  if (path && !/^(\/[A-Za-z0-9._~-]+)+$/.test(path)) return null;
  return p.protocol + '//' + host + (p.port ? ':' + p.port : '') + path;
}
/** Does the text look like a web address / domain (and not a Seal Chat ID, name or code)? */
const looksLikeAddress = t => /^(https?:\/\/)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(:\d+)?(\/[\w.~-]*)*\/?$/i.test(String(t || '').trim());

const sha256hex = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
/** The proof token for a proof statement: sid1:<22 characters>. */
const token = payload => 'sid1:' + crypto.createHash('sha256').update(payload, 'utf8').digest('base64url').slice(0, 22);
const proofText = (url, tok) => `Verifying my Seal ID ${url} ${tok}`;

/** "sealchat:<onion>:<FP>" → { onion, fp } or null */
function parseSealChat(h) {
  const m = /^sealchat:([a-z2-7]{55}d):([0-9A-F]{40}|[0-9A-F]{64})$/.exec(String(h || ''));
  return m ? { onion: m[1], fp: m[2] } : null;
}

/* =================================================================
 * 2. FETCHING (THROUGH TOR) AND ALIASES
 * net: { socksPort, direct, http (tests), allowHttp (tests), doh (tests: DNS-over-HTTPS base) }
 * ================================================================= */
function get(url, net, accept = 'application/json') {
  return viaFallbacks(url, { method: 'GET', socksPort: net.socksPort || null, direct: !!net.direct, http: net.http,
    allowHttp: !!net.allowHttp, timeoutMs: 60e3, maxBytes: 2 * 1024 * 1024, headers: { Accept: accept, 'Cache-Control': 'no-cache' } });
}

const BLOCKED_HELP = 'Settings → Privacy can allow contacting such websites directly, or the Seal ID\'s owner can add a mirror (Seal ID admin → Settings → Mirrors) and list it in their DNS key record.';

/**
 * The Seal ID's bundle (its signed chain + keys): the API first, then the static file,
 * then mirrors — from the Seal ID's DNS key record (_seal-id.<host>: "v=sealid1; …;
 * mirror=…") and any remembered from earlier. Many web hosts block visitors that
 * come through Tor; a mirror (e.g. on GitHub) still works, and can't be forged:
 * everything in it is signed. Returns { bundle, via, dns }.
 */
async function fetchBundle(url, net, known = []) {
  let last = '', blocked = false;
  const tryOne = async src => {
    let r;
    try { r = await get(src, net); }
    catch (e) { if (e.code === 'TOR_BLOCKED') blocked = true; last = e.code === 'TOR_BLOCKED' ? 'blocks visitors that come through Tor' : e.message; return null; }
    if (r.via === 'blocked' || looksBlocked(r)) { blocked = true; last = 'blocks visitors that come through Tor'; return null; }
    if (r.status !== 200) { last = 'answered ' + r.status; return null; }
    let b;
    try { b = JSON.parse(r.body.toString('utf8')); } catch { last = 'is not a Seal ID'; return null; }
    if (!b || b.seal_id !== 1 || !Array.isArray(b.chain) || !b.keys) { last = 'is not a Seal ID'; return null; }
    if (b.url !== url) { last = `is the Seal ID of ${String(b.url).slice(0, 100)}`; return null; }
    return b;
  };
  for (const src of [url + '/api.php?a=bundle&t=' + Date.now(), url + '/.well-known/seal-id.json?t=' + Date.now()]) {
    const b = await tryOne(src);
    if (b) return { bundle: b, via: 'site', dns: null };
  }
  const siteErr = last, siteBlocked = blocked;
  const dns = await dnsKeyRecord(url, net);
  for (const m of [...new Set([...(dns ? dns.mirrors : []), ...known])]) {
    if (!/^https:\/\//.test(m) && !net.allowHttp) continue;
    const b = await tryOne(m + (m.includes('?') ? '&' : '?') + 't=' + Date.now());
    if (b) return { bundle: b, via: 'mirror', mirror: m, dns };
  }
  const e = new Error(siteBlocked
    ? `${new URL(url).host} blocks visitors that come through Tor, so Seal Chat can't check this Seal ID${dns && dns.mirrors.length ? ' (and its mirrors did not answer)' : ''}. ${BLOCKED_HELP}`
    : `No Seal ID at ${url} (it ${siteErr || 'did not answer'})`);
  e.notFound = !siteBlocked;
  e.blocked = siteBlocked;
  throw e;
}

/** The Seal ID's DNS key record: { fp, mirrors } or null. Same rule as Seal ID: "id=" names the identity; without it, only the host's root identity. */
async function dnsKeyRecord(url, net) {
  const u = new URL(url);
  const root = u.pathname === '/' || u.pathname === '';
  let fallback = null;
  for (const t of await dnsTxt('_seal-id.' + u.hostname, net)) {
    if (!/^\s*v=sealid1\b/i.test(t)) continue;
    const rec = { fp: null, mirrors: [], id: null };
    for (const part of t.split(/\s*;\s*/)) {
      let m;
      if ((m = /^fp=([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$/.exec(part))) rec.fp = m[1].toUpperCase();
      if ((m = /^mirror=(https?:\/\/\S+)$/.exec(part))) rec.mirrors.push(m[1]);
      if ((m = /^id=(https?:\/\/\S+)$/.exec(part))) rec.id = normUrl(m[1], net);
    }
    if (rec.id === url) return rec;
    if (rec.id === null && root && !fallback) fallback = rec;
  }
  return fallback;
}

/** TXT records through DNS-over-HTTPS (through Tor, like everything else). [] if none. */
async function dnsTxt(name, net) {
  const bases = net.doh ? [net.doh] : ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
  for (const base of bases) {
    try {
      const r = await get(`${base}?name=${encodeURIComponent(name)}&type=TXT`, net, 'application/dns-json');
      if (r.status !== 200) continue;
      const j = JSON.parse(r.body.toString('utf8'));
      return (j.Answer || []).filter(a => a.type === 16).map(a => String(a.data || '').replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
    } catch { /* next resolver */ }
  }
  return [];
}

/** Seal IDs a domain points to (its proof file and its _seal-id TXT record): [{ url, token, how }]. */
async function aliasTargets(domain, net) {
  const out = [];
  try {
    const r = await get(`${net.allowHttp ? 'http' : 'https'}://${domain}/.well-known/seal-id.txt?sealid=${Date.now()}`, net, 'text/plain');
    if (r.status === 200) {
      const re = /Verifying my Seal ID (https?:\/\/\S+) (sid1:[A-Za-z0-9_-]{22})/g;
      let m;
      while ((m = re.exec(r.body.toString('utf8')))) { const u = normUrl(m[1], net); if (u) out.push({ url: u, token: m[2], how: 'web' }); }
    }
  } catch { /* no website file */ }
  for (const t of await dnsTxt('_seal-id.' + domain, net)) {
    const m = /\bid=(https?:\/\/[^\s;]+)/.exec(t);
    const u = m && normUrl(m[1], net);
    const tk = /sid1:[A-Za-z0-9_-]{22}/.exec(t);
    if (u) out.push({ url: u, token: tk ? tk[0] : null, how: 'dns' });
  }
  return out;
}

/**
 * Whatever the user typed: a Seal ID address, or a domain that is a verified
 * alias of one. Returns { url, alias, state, bundle }.
 */
async function resolve(input, net, opt = {}) {
  const url = normUrl(input, net);
  if (!url) throw new Error('That is not a web address');
  let firstErr;
  try {
    return await load(url, net, opt.mirrors);
  } catch (e) {
    if (!e.notFound) throw e;
    firstErr = e;
  }
  const host = new URL(url).host;
  if (new URL(url).pathname !== '/') throw firstErr;
  const seen = new Set();
  let blockedErr = null;
  for (const t of await aliasTargets(host, net)) {
    if (seen.has(t.url) || t.url === url) continue;
    seen.add(t.url);
    let r;
    try { r = await load(t.url, net, opt.mirrors); } catch (e) { if (e.blocked) blockedErr = Object.assign(new Error(`${host} points to the Seal ID ${t.url}, but ${e.message}`), { blocked: true }); continue; }
    // The domain only counts if the signed chain claims it with this very token — which we just saw published.
    const p = Object.values(r.state.proofs).find(x => x.service === t.how && x.handle === host && (t.token === null || x.token === t.token));
    if (p && t.token) return { ...r, alias: host };
  }
  if (blockedErr) throw blockedErr;
  throw new Error(`${host} is not a Seal ID, and it doesn't point to one`);
}

/** Fetch + verify one Seal ID; its DNS key record (if any) must name the same key. */
async function load(url, net, mirrors) {
  const f = await fetchBundle(url, net, mirrors || []);
  const state = await verifyChain(f.bundle, url);
  const dns = f.dns || await dnsKeyRecord(url, net).catch(() => null);
  if (dns && dns.fp && !state.fps.includes(dns.fp)) {
    throw new Error(`The DNS key record of ${new URL(url).hostname} names a different key (${prettyFp(dns.fp)}) — someone may be impersonating this Seal ID`);
  }
  return { url, alias: null, state, bundle: f.bundle, via: f.via, mirror: f.mirror || null, dnsConfirmed: !!(dns && dns.fp && dns.fp === state.fp) };
}

/* =================================================================
 * 3. VERIFYING A SEAL ID CHAIN (same rules as Seal ID's lib/chain.php)
 * ================================================================= */
async function readKeyFp(armored, fp) {
  const k = await openpgp.readKey({ armoredKey: String(armored) });
  if (k.getFingerprint().toUpperCase() !== fp) throw new Error('key does not match its fingerprint');
  return k;
}

/** Is sigText (detached armored signature, or a clear-signed message of exactly payload) valid for one of keys? */
async function verifySig(payload, sigText, keys, ts) {
  // Old statements stay valid after a key expires: check as of shortly after the statement was made.
  const date = new Date(Math.min(Date.now() + 2 * 86400e3, (ts + 30 * 86400) * 1000));
  try {
    let res;
    if (/-----BEGIN PGP SIGNED MESSAGE-----/.test(sigText)) {
      const msg = await openpgp.readCleartextMessage({ cleartextMessage: sigText });
      if (msg.getText().replace(/\r\n/g, '\n') !== payload) return false;
      res = await openpgp.verify({ message: msg, verificationKeys: keys, date });
    } else {
      const message = await openpgp.createMessage({ binary: Buffer.from(payload, 'utf8') });
      const signature = await openpgp.readSignature({ armoredSignature: sigText });
      res = await openpgp.verify({ message, signature, verificationKeys: keys, date });
    }
    for (const s of res.signatures) { try { if (await s.verified) return true; } catch { /* next */ } }
  } catch { /* unreadable */ }
  return false;
}

/** Verifies a whole chain. Throws "Seal ID: link N: …" on any problem. */
async function verifyChain(bundle, url) {
  const links = bundle.chain || [], keys = bundle.keys || {};
  if (!links.length || links.length > 5000) throw new Error('Seal ID: the chain is empty or too long');
  const st = { url, fp: null, fps: [], name: '', bio: '', avatar: null, proofs: {}, seq: 0, hash: null, hashes: {}, created: 0, updated: 0, resetFrom: null, mirrors: [], mirrorsSeq: 0 };
  let cur = [], prevHash = null, prevTs = 0;
  const types = {};
  for (let i = 0; i < links.length; i++) {
    const seq = i + 1, L = links[i] || {};
    const bad = why => new Error(`Seal ID: link ${seq}: ${why}`);
    const payload = L.payload, sig = L.sig;
    if (typeof payload !== 'string' || typeof sig !== 'string' || payload.length > 20000 || /[\r\n]/.test(payload) || payload !== payload.trimEnd()) throw bad('malformed');
    let p;
    try { p = JSON.parse(payload); } catch { throw bad('not JSON'); }
    if (p.v !== 1 || p.seq !== seq) throw bad('out of order');
    if (!('prev' in p) || p.prev !== prevHash) throw bad('does not follow the previous link');
    if (p.url !== url) throw bad('belongs to a different identity');
    if (!Number.isInteger(p.ts) || p.ts < prevTs || p.ts > Date.now() / 1000 + 3600) throw bad('bad time stamp');
    if (!TYPES.has(p.type) || !p.body || typeof p.body !== 'object') throw bad('unknown statement');
    if (typeof p.fp !== 'string' || !HEX.test(p.fp)) throw bad('bad fingerprint');
    if (seq === 1) {
      if (p.type !== 'eldest') throw bad('the first link must be "eldest"');
      if (typeof keys[p.fp] !== 'string') throw bad('its key is missing');
      cur = [await readKeyFp(keys[p.fp], p.fp)];
      st.fp = p.fp; st.fps.push(p.fp); st.created = p.ts;
      if (await cur[0].isRevoked()) throw bad('the key has been revoked');
    } else if (p.type === 'eldest') throw bad('"eldest" may only come first');
    if (p.fp !== st.fp) throw bad('signed with the wrong key');
    if (!(await verifySig(payload, sig, cur, p.ts))) throw bad('bad signature');
    const b = p.body;
    if (p.type === 'eldest' || p.type === 'profile') {
      if (typeof (b.name ?? '') !== 'string' || typeof (b.bio ?? '') !== 'string') throw bad('bad profile');
      st.name = String(b.name || '').slice(0, 80); st.bio = String(b.bio || '').slice(0, 500);
      st.avatar = typeof b.avatar === 'string' && /^[0-9a-f]{64}$/.test(b.avatar) ? b.avatar : null;
      if (p.type === 'eldest' && b.reset_from) st.resetFrom = String(b.reset_from);
    } else if (p.type === 'proof') {
      if (typeof b.service !== 'string' || !/^[a-z0-9_-]{1,24}$/.test(b.service) || typeof b.handle !== 'string' || !b.handle || b.handle.length > 200) throw bad('bad proof');
      st.proofs[seq] = { seq, service: b.service, handle: b.handle, token: token(payload), ts: p.ts };
    } else if (p.type === 'revoke') {
      if (!Array.isArray(b.seqs) || !b.seqs.length) throw bad('bad revoke');
      for (const r of b.seqs) {
        if (!Number.isInteger(r) || r < 1 || r >= seq || !['proof', 'vouch', 'mirrors'].includes(types[r])) throw bad('revoke points at an unknown link');
        delete st.proofs[r];
        if (r === st.mirrorsSeq) { st.mirrors = []; st.mirrorsSeq = 0; }
      }
    } else if (p.type === 'mirrors') {
      st.mirrors = Array.isArray(b.urls) ? b.urls.filter(u => typeof u === 'string' && /^https:\/\/\S{4,300}$/.test(u)).slice(0, 10) : [];
      st.mirrorsSeq = seq;
    } else if (p.type === 'rotate') {
      if (typeof b.new_fp !== 'string' || !HEX.test(b.new_fp) || typeof b.new_key !== 'string') throw bad('bad key rotation');
      let nk;
      try { nk = await readKeyFp(b.new_key, b.new_fp); } catch { throw bad('the new key does not match'); }
      const newKeys = [nk];
      if (typeof keys[b.new_fp] === 'string') { try { newKeys.push(await readKeyFp(keys[b.new_fp], b.new_fp)); } catch { /* ignore */ } }
      if (!(await verifySig(payload, String(L.sig_new || ''), newKeys, p.ts))) throw bad('the new key did not sign the rotation');
      cur = newKeys; st.fp = b.new_fp; st.fps.push(b.new_fp);
    }
    prevHash = sha256hex(payload); prevTs = p.ts; types[seq] = p.type;
    st.seq = seq; st.hash = prevHash; st.hashes[seq] = prevHash; st.updated = p.ts;
  }
  return st;
}

/* =================================================================
 * 4. DOES IT BELONG TO THIS SEAL CHAT ID?
 * ================================================================= */
/**
 * @returns { ok, how: 'same-key' | 'signed' | null, why, handle }
 * fp: the contact's (or your own) Seal Chat key fingerprint.
 */
async function sealChatLink(state, bundle, fp) {
  const claims = Object.values(state.proofs).filter(p => p.service === 'sealchat' && (parseSealChat(p.handle) || {}).fp === fp);
  if (state.fps.includes(fp)) return { ok: true, how: 'same-key', why: null, handle: claims[0] ? claims[0].handle : null };
  if (!claims.length) return { ok: false, how: null, why: 'This Seal ID does not name this Seal Chat ID', handle: null };
  for (const p of claims) {
    const att = bundle.attestations && bundle.attestations[String(p.seq)];
    if (!att || typeof att.key !== 'string' || typeof att.sig !== 'string') continue;
    try {
      const k = await readKeyFp(att.key, fp);
      if (await verifySig(proofText(state.url, p.token), att.sig, [k], Math.floor(Date.now() / 1000))) return { ok: true, how: 'signed', why: null, handle: p.handle };
    } catch { /* next */ }
  }
  return { ok: false, how: null, why: 'This Seal ID names this Seal Chat ID, but Seal Chat has not signed it yet', handle: claims[0].handle };
}

/** The Seal Chat IDs a Seal ID proves (for "add contact by Seal ID"). */
async function provenSealChatIds(state, bundle) {
  const out = [];
  for (const p of Object.values(state.proofs)) {
    const id = p.service === 'sealchat' && parseSealChat(p.handle);
    if (!id) continue;
    const l = await sealChatLink(state, bundle, id.fp);
    if (l.ok) out.push({ id: p.handle, onion: id.onion, fp: id.fp, how: l.how });
  }
  return out;
}

/**
 * Two keys: sign the Seal ID's claim of your Seal Chat ID with your Seal Chat key and
 * hand the signature to the Seal ID (api.php?a=attest — it checks it before keeping it).
 * identity: { fp, pubArmored, signArmored(text) }.
 */
async function attest(r, handle, identity, net) {
  const p = Object.values(r.state.proofs).find(x => x.service === 'sealchat' && x.handle === handle);
  if (!p) throw new Error('Your Seal ID has no Seal Chat proof for this Seal Chat ID yet');
  const sig = await identity.signArmored(proofText(r.state.url, p.token));
  const body = JSON.stringify({ sealchat: handle, key: identity.pubArmored, sig });
  let res;
  try {
    res = await viaFallbacks(r.state.url + '/api.php?a=attest', { method: 'POST', socksPort: net.socksPort || null, direct: !!net.direct, http: net.http,
      allowHttp: !!net.allowHttp, timeoutMs: 60e3, maxBytes: 64 * 1024, body, headers: { 'Content-Type': 'application/json', Accept: 'application/json' } });
  } catch (e) { throw new Error(`Couldn't reach your Seal ID: ${e.code === 'TOR_BLOCKED' ? 'it blocks visitors that come through Tor' : e.message}`); }
  let j = null;
  try { j = JSON.parse(res.body.toString('utf8')); } catch { /* not JSON */ }
  if (res.status !== 200 || !j || !j.ok) throw new Error(`Your Seal ID refused the signature: ${(j && j.error) || 'HTTP ' + res.status}`);
  return true;
}

/* =================================================================
 * 5. SUMMARY + PIN
 * ================================================================= */
const prettyFp = fp => String(fp || '').replace(/(.{4})/g, '$1 ').trim();

/** What the window shows about a Seal ID. Proof statuses are as the Seal ID reported them. */
function summary(r, link) {
  const { state, bundle } = r;
  const checks = bundle.checks || {};
  const proofs = Object.values(state.proofs).filter(p => p.service !== 'sealchat').map(p => ({
    service: p.service, handle: p.handle, status: (checks[String(p.seq)] || {}).status || 'unknown'
  }));
  return {
    url: state.url, alias: r.alias || null, name: state.name, bio: state.bio, fp: state.fp, prettyFp: prettyFp(state.fp),
    proofs, aliases: Array.isArray(bundle.aliases) ? bundle.aliases.filter(a => typeof a === 'string').slice(0, 20) : [],
    ok: !!(link && link.ok), how: link ? link.how : null, why: link ? link.why : null, checked: Date.now(),
    via: r.via || 'site', mirror: r.mirror || null, dnsConfirmed: !!r.dnsConfirmed
  };
}
/** What to remember: the key, the newest link seen and every link's hash (so an older copy can be recognised). */
const pinOf = state => ({ url: state.url, fp: state.fp, seq: state.seq, hash: state.hash, hashes: { ...state.hashes }, mirrors: state.mirrors || [] });
/**
 * 'new' | 'match' | 'behind' | 'changed'. A Seal ID may only grow; a replaced chain or
 * key is a warning. 'behind': an older copy of the same chain (a mirror not updated yet).
 */
function pinCheck(pin, state) {
  if (!pin || pin.url !== state.url) return 'new';
  if (pin.seq <= state.seq) return state.hashes[pin.seq] === pin.hash ? 'match' : 'changed';
  return pin.hashes && pin.hashes[state.seq] === state.hash ? 'behind' : 'changed';
}

module.exports = { normUrl, looksLikeAddress, token, proofText, parseSealChat, fetchBundle, aliasTargets, resolve, verifyChain, verifySig, attest,
  sealChatLink, provenSealChatIds, summary, pinOf, pinCheck };
