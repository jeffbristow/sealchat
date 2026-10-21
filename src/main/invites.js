/* =====================================================================
 * Seal Chat — invites.js   (invite codes, 1.8.0)
 * ---------------------------------------------------------------------
 * An invite code is something you can read out over the phone or write
 * on paper instead of sending the long Seal Chat ID:
 *
 *       482-crystal-orange-river          (1 hour, 24 hours or 7 days)
 *       482-crystal-orange-river-lemon    (30 days: one more word)
 *
 * How it works (nobody in the middle, no server):
 *   - "482-crystal" picks a temporary .onion address. Your Seal Chat
 *     publishes it through Tor while the invite is open; the other person's
 *     Seal Chat works out the same address from the code.
 *   - the remaining words are a password that never travels over the
 *     network. Both sides prove they know it with SPAKE2 (a PAKE, on the
 *     ristretto255 curve) and get a shared secret key from it. Someone who
 *     only guesses gets ONE guess per try; after 3 wrong tries the invite
 *     is closed.
 *   - over that secret both sides swap their real Seal Chat IDs. From then
 *     on it is an ordinary contact (key fingerprint checked as always).
 *   - single use: you are both added at once (no request to accept).
 *     Several uses (a group, a club): each person's request waits for you
 *     to accept it, marked with the invite's label.
 *
 * Your Seal Chat has to be open and online for someone to use your code.
 *
 * Sections:
 *   1. Codes (make / read)
 *   2. The temporary .onion address from a code
 *   3. SPAKE2 (password-authenticated key exchange)
 *   4. Sealing the IDs with the shared key
 *   5. Invites you made (open / list / cancel; the listener)
 *   6. Using someone's code
 * ===================================================================== */

const net = require('net');
const crypto = require('crypto');
const { wordlist } = require('@scure/bip39/wordlists/english');
const { ristretto255, ristretto255_hasher: H } = require('@noble/curves/ed25519');
const { FrameSocket, socksConnect } = require('./wire');
const { sha3_256 } = require('./sha3');                     // 1.9.2: "Digest method not supported" in Electron

const P = ristretto255.Point;
const ORDER = P.Fn.ORDER;
const LIFETIMES = { '1h': 3600e3, '24h': 24 * 3600e3, '7d': 7 * 24 * 3600e3, '30d': 30 * 24 * 3600e3 };
const MAX_TRIES = 3;               // wrong codes before an invite closes
const MAX_OPEN = 5;                // invites open at the same time
const MAX_USES = 100;              // for "several people" invites
const VPORT = 80;
const STEP_TIMEOUT = 60e3;
const V = 'sealchat-invite-v1';
const WORDS = new Map(wordlist.map((w, i) => [w, i]));
const BY_PREFIX = new Map(wordlist.map(w => [w.slice(0, 4), w]));   // BIP39 words differ in their first 4 letters

/* =================================================================
 * 1. CODES
 * ================================================================= */
const pick = () => wordlist[crypto.randomInt(wordlist.length)];

/** A new code: "NNN-word-word-word" (+ one more word past 7 days). */
function makeCode(lifetimeMs) {
  const n = String(crypto.randomInt(1000)).padStart(3, '0');
  const words = [pick(), pick(), pick()];
  if (lifetimeMs > LIFETIMES['7d']) words.push(pick());
  return [n, ...words].join('-');
}

/**
 * Reads a code typed by a person: any case, spaces/dashes/dots between
 * parts, and each word may be shortened to its first 4 letters.
 * Returns { code, num, words } or null.
 */
function parseCode(text) {
  const parts = String(text || '').toLowerCase().trim().split(/[^a-z0-9]+/).filter(Boolean);
  if (parts.length < 4 || parts.length > 5 || !/^\d{3}$/.test(parts[0])) return null;
  const words = [];
  for (const p of parts.slice(1)) {
    const w = WORDS.has(p) ? p : (p.length >= 4 ? BY_PREFIX.get(p.slice(0, 4)) : null);
    if (!w) return null;
    words.push(w);
  }
  return { code: [parts[0], ...words].join('-'), num: parts[0], words };
}
const looksLikeCode = t => !!parseCode(t);

/* =================================================================
 * 2. THE TEMPORARY .ONION ADDRESS
 * "482-crystal" → an Ed25519 key → a v3 .onion address. Checked against
 * Tor itself: Tor reports the same address for the key we hand it.
 * ================================================================= */
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
function base32(buf) {
  let bits = 0, v = 0, out = '';
  for (const b of buf) { v = ((v << 8) | b) & 0xffff; bits += 8; while (bits >= 5) { out += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits) out += B32[(v << (5 - bits)) & 31];
  return out;
}
/** { onion, key } — key is what Tor's ADD_ONION takes (ED25519-V3:<expanded secret key>). */
function onionFor(c) { return onionFromSeed(crypto.createHash('sha256').update(`${V}|onion|${c.num}|${c.words[0]}`).digest()); }
/** 1.9.0: the same from any 32-byte seed (a new device's own address is made this way, before Tor sees it). */
function onionFromSeed(seed) {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const pub = Buffer.from(crypto.createPublicKey(priv).export({ format: 'jwk' }).x, 'base64url');
  const ver = Buffer.from([3]);
  const chk = sha3_256(Buffer.concat([Buffer.from('.onion checksum'), pub, ver])).subarray(0, 2);   // 1.9.2: our own SHA3 (Electron's crypto has none)
  const h = crypto.createHash('sha512').update(seed).digest();
  h[0] &= 248; h[31] &= 127; h[31] |= 64;
  return { onion: base32(Buffer.concat([pub, chk, ver])), key: 'ED25519-V3:' + h.toString('base64') };
}

/* =================================================================
 * 3. SPAKE2 on ristretto255
 * Joiner (A):  X = x·G + w·M        Inviter (B):  Y = y·G + w·N
 * A: K = x·(Y − w·N)                B: K = y·(X − w·M)
 * The JOINER proves first (macA). The inviter only answers with its
 * proof after a correct macA, so every try costs a guess on its side.
 * ================================================================= */
const enc = s => Buffer.from(s, 'utf8');
const M = H.hashToCurve(enc(V + ' M'), { DST: V + '-M' });
const N = H.hashToCurve(enc(V + ' N'), { DST: V + '-N' });
const scalarOf = buf => { let n = 0n; for (let i = buf.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(buf[i]); return n % ORDER; };
const randScalar = () => { let s; do s = scalarOf(crypto.randomBytes(64)); while (s === 0n); return s; };
const pointFrom = b64 => {
  const b = Buffer.from(String(b64 || ''), 'base64');
  if (b.length !== 32) throw new Error('bad point');
  const p = P.fromHex(b.toString('hex'));
  if (p.equals(P.ZERO)) throw new Error('bad point');
  return p;
};
const pw = (onion, c) => H.hashToScalar(enc(`${V}|${onion}|${c.words.slice(1).join(' ')}`), { DST: V + '-w' });

/** One side of the exchange. role 'A' (joiner) or 'B' (inviter). */
function spake(role, onion, c) {
  const w = pw(onion, c);
  const s = randScalar();
  const mine = P.BASE.multiply(s).add((role === 'A' ? M : N).multiply(w));
  return {
    msg: Buffer.from(mine.toBytes()).toString('base64'),
    /** Their message → { keys } (or throws for a bad point). */
    finish(theirB64) {
      const theirs = pointFrom(theirB64);
      const K = theirs.subtract((role === 'A' ? N : M).multiply(w)).multiply(s);
      if (K.equals(P.ZERO)) throw new Error('bad point');
      const X = role === 'A' ? mine : theirs, Y = role === 'A' ? theirs : mine;
      const wb = Buffer.alloc(32); let t = w; for (let i = 0; i < 32; i++) { wb[i] = Number(t & 255n); t >>= 8n; }
      const tr = Buffer.concat([enc(V + '|' + onion + '|'), Buffer.from(X.toBytes()), Buffer.from(Y.toBytes()), Buffer.from(K.toBytes()), wb]);
      const sk = crypto.createHash('sha256').update(tr).digest();
      const kdf = label => crypto.createHmac('sha256', sk).update(label).digest();
      const th = crypto.createHash('sha256').update(tr.subarray(0, tr.length - 64)).digest();   // X|Y
      return {
        macA: crypto.createHmac('sha256', kdf('confirm A')).update(th).digest('base64'),
        macB: crypto.createHmac('sha256', kdf('confirm B')).update(th).digest('base64'),
        keyA: kdf('seal A'), keyB: kdf('seal B')
      };
    }
  };
}
const same = (a, b) => { const x = Buffer.from(String(a || '')), y = Buffer.from(String(b || '')); return x.length === y.length && crypto.timingSafeEqual(x, y); };

/* =================================================================
 * 4. SEALING THE IDS (AES-256-GCM with a key from SPAKE2)
 * ================================================================= */
function seal(key, obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function unseal(key, b64) {
  const b = Buffer.from(String(b64 || ''), 'base64');
  if (b.length < 29 || b.length > 4096) throw new Error('bad box');
  const d = crypto.createDecipheriv('aes-256-gcm', key, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'));
}

/* =================================================================
 * 5. INVITES YOU MADE
 * Kept in the encrypted vault (vault.invites) — the code is a secret
 * until it is used. Each open invite has its own small listener on
 * 127.0.0.1 that Tor publishes as the invite's .onion address.
 * ================================================================= */
class Invites {
  /** @param peer the Peer (store, identity, tor, addContact, myId, emit) */
  constructor(peer) {
    this.peer = peer;
    this.live = new Map();           // invite id → { server, port, onion, busy }
    this.timer = null;
  }
  get store() { return this.peer.store; }
  _all() { const v = this.store.vault; if (!Array.isArray(v.invites)) v.invites = []; return v.invites; }
  _save() { this.store.saveVault(); this.peer.emit('invites'); }

  /** What the app shows (the code too: it is your own invite). */
  list() {
    const now = Date.now();
    return this._all().map(i => ({ id: i.id, code: i.code, label: i.label, multi: !!i.multi, created: i.created, expires: i.expires,
      triesLeft: Math.max(0, MAX_TRIES - (i.tries || 0)), uses: i.uses || 0, open: this.live.has(i.id) && i.expires > now }));
  }

  /** New invite: { lifetime: '1h'|'24h'|'7d'|'30d', multi, label } → its list entry. */
  async create({ lifetime = '24h', multi = false, label = '' } = {}) {
    const ms = LIFETIMES[lifetime];
    if (!ms) throw new Error('Choose how long the code works: 1 hour, 24 hours, 7 days or 30 days');
    if (!this.peer.running || !this.peer.myId()) throw new Error('Wait until Seal Chat is connected to Tor');
    if (this._all().length >= MAX_OPEN) throw new Error(`You can have ${MAX_OPEN} invite codes open at once — cancel one first`);
    let code, onion;
    for (let n = 0; n < 20; n++) {                      // a code whose address isn't one of ours already
      code = makeCode(ms); onion = onionFor(parseCode(code)).onion;
      if (!this._all().some(i => i.onion === onion)) break;
    }
    const inv = { id: crypto.randomBytes(8).toString('hex'), code, onion, multi: !!multi, label: String(label || '').replace(/[\x00-\x1f]/g, '').trim().slice(0, 60),
      created: Date.now(), expires: Date.now() + ms, tries: 0, uses: 0 };
    this._all().push(inv);
    this.store.saveVault();
    try { await this._open(inv); } catch (e) { this._remove(inv.id); throw new Error('Tor could not publish the invite: ' + e.message); }
    this._save();
    return this.list().find(i => i.id === inv.id);
  }

  async cancel(id) { await this._close(id); this._remove(id); this._save(); }
  _remove(id) { const v = this.store.vault; v.invites = this._all().filter(i => i.id !== id); }

  /** Peer started (Tor ready): publish every invite that is still valid. */
  async resume() {
    clearInterval(this.timer);
    this.timer = setInterval(() => this._expire(), 60e3);
    if (this.timer.unref) this.timer.unref();
    this._expire();
    for (const inv of this._all()) {
      if (this.live.has(inv.id)) continue;
      try { await this._open(inv); } catch (e) { this.peer.log('invite publish: ' + e.message); }
    }
    this.peer.emit('invites');
  }
  /** Peer stopping: take every invite offline (they stay saved). */
  async pause() {
    clearInterval(this.timer); this.timer = null;
    for (const id of [...this.live.keys()]) await this._close(id);
  }
  _expire() {
    const now = Date.now(); let changed = false;
    for (const inv of [...this._all()]) if (inv.expires <= now) { this._close(inv.id); this._remove(inv.id); changed = true; }
    if (changed) this._save();
  }

  async _open(inv) {
    const live = { server: null, port: 0, onion: inv.onion, busy: false, socks: new Set() };
    live.server = net.createServer(s => this._incoming(inv.id, live, s));
    live.server.maxConnections = 4;
    await new Promise((res, rej) => { live.server.once('error', rej); live.server.listen(0, '127.0.0.1', res); });
    live.port = live.server.address().port;
    const k = onionFor(parseCode(inv.code));
    try { await this.peer.tor.publishExtra(k.key, live.port, VPORT, k.onion); }
    catch (e) { live.server.close(); throw e; }
    this.live.set(inv.id, live);
  }
  _closeSoon(id) { const t = setTimeout(() => this._close(id), 3000); if (t.unref) t.unref(); }
  async _close(id) {
    const live = this.live.get(id);
    if (!live) return;
    this.live.delete(id);
    for (const s of live.socks) s.destroy();
    try { live.server.close(); } catch { /* ignore */ }
    try { await this.peer.tor.unpublishExtra(live.onion); } catch { /* ignore */ }
  }

  /** Someone connected to an invite's address. One at a time per invite. */
  _incoming(id, live, sock) {
    const fsk = new FrameSocket(sock);
    live.socks.add(fsk);
    sock.on('close', () => live.socks.delete(fsk));
    fsk.setIdle(STEP_TIMEOUT);
    const inv = () => this._all().find(i => i.id === id);
    if (live.busy) { fsk.send({ t: 'no', why: 'busy' }); fsk.end(); return; }
    live.busy = true;
    let ex = null, keys = null, done = false;
    const finish = () => { if (!done) { done = true; live.busy = false; } };
    sock.on('close', finish);
    fsk.on('frame', async f => {
      try {
        const i = inv();
        if (!i || i.expires <= Date.now()) { fsk.send({ t: 'no', why: 'closed' }); return fsk.end(); }
        if (f.t === 'hi' && !ex) {
          if (f.v !== 1) { fsk.send({ t: 'no', why: 'version' }); return fsk.end(); }
          ex = spake('B', i.onion, parseCode(i.code));
          keys = ex.finish(f.x);                                   // bad point → throws → closed
          fsk.send({ t: 'pake', y: ex.msg });
        } else if (f.t === 'me' && keys) {
          if (!same(f.mac, keys.macA)) {                         // a wrong code: one try used
            i.tries = (i.tries || 0) + 1;
            const left = MAX_TRIES - i.tries;
            fsk.send({ t: 'no', why: 'wrong code' }); fsk.end();
            if (left <= 0) { this._remove(i.id); this._closeSoon(i.id); this.peer.emit('invite', { kind: 'closed', label: i.label, code: i.code }); }
            this._save();
            return;
          }
          const them = unseal(keys.keyA, f.box);
          const r = this._accept(i, them);
          if (!r.ok) { fsk.send({ t: 'no', why: r.why }); return fsk.end(); }
          const myName = this.store.settings.displayName || this.peer.id.name || '';
          fsk.send({ t: 'ok', mac: keys.macB, box: seal(keys.keyB, { id: this.peer.myId(), name: String(myName).slice(0, 80), multi: !!i.multi }) });
          fsk.end();
          if (r.closeAfter) this._closeSoon(i.id);
        } else { fsk.destroy(); }
      } catch { fsk.destroy(); }
    });
  }

  /** The code was right: add the person (single use) or expect their request (several uses). */
  _accept(i, them) {
    const { parseId } = require('./peer');
    let id;
    try { id = parseId(them && them.id); } catch { return { ok: false, why: 'bad id' }; }
    if (id.fp === this.peer.id.fp) return { ok: false, why: 'own code' };
    const name = String((them && them.name) || '').replace(/[\x00-\x1f]/g, '').slice(0, 80);
    const v = this.store.vault;
    v.inviteJoins = (v.inviteJoins || []).filter(j => j.at > Date.now() - 30 * 24 * 3600e3 && j.fp !== id.fp).slice(-200);
    v.inviteJoins.push({ fp: id.fp, label: i.label || '', at: Date.now(), multi: !!i.multi });
    i.uses = (i.uses || 0) + 1;
    if (!i.multi) {
      const c = this.store.contact(id.fp);
      if (!c || c.status !== 'accepted') {
        try { this.peer.addContact(`sealchat:${id.onion}:${id.fp}`, { nick: c && c.nick ? c.nick : '' }); } catch (e) { this.peer.log('invite add: ' + e.message); }
      }
    }
    const closeAfter = !i.multi || i.uses >= MAX_USES;   // single use: done (taken offline once the answer is sent)
    if (closeAfter) this._remove(i.id);
    this._save();
    this.peer.emit('invite', { kind: 'used', label: i.label, name, multi: !!i.multi, fp: id.fp });
    return { ok: true, closeAfter };
  }

  /** For _onRequest: did this person just use one of your invites? */
  joinFor(fp) { return (this.store.vault.inviteJoins || []).find(j => j.fp === fp && j.at > Date.now() - 30 * 24 * 3600e3) || null; }

  /* =================================================================
   * 6. USING SOMEONE'S CODE
   * → { id, name, multi } of the person who made it. The caller adds them.
   * ================================================================= */
  async join(text) {
    const c = parseCode(text);
    if (!c) throw new Error('That is not an invite code. It looks like 482-crystal-orange-river');
    if (!this.peer.running || !this.peer.myId()) throw new Error('Wait until Seal Chat is connected to Tor');
    const { onion } = onionFor(c);
    if (this._all().some(i => i.onion === onion)) throw new Error('That is your own invite code');
    let fsk;
    try { fsk = await socksConnect(this.peer.tor.socksPort, onion + '.onion', VPORT, this.peer.o.inviteTimeout || 120e3); }
    catch { throw new Error('Couldn\'t reach that invite. Check the code — and the person who made it must have Seal Chat open and online, and the code must not have run out.'); }
    try {
      const ex = spake('A', onion, c);
      const isNo = f => f.t === 'no';
      const why = f => ({ 'wrong code': 'That code isn\'t right — check every word (each wrong try counts; after 3 the invite closes).', busy: 'Someone else is using that invite right now — try again in a minute.', closed: 'That invite has run out or was cancelled.', 'own code': 'That is your own invite code.' }[f.why] || 'The invite was refused (' + f.why + ').');
      const p = await fsk.request({ t: 'hi', v: 1, x: ex.msg }, f => f.t === 'pake' || isNo(f), STEP_TIMEOUT);
      if (isNo(p)) throw new Error(why(p));
      const keys = ex.finish(p.y);
      const myName = this.store.settings.displayName || this.peer.id.name || '';
      const r = await fsk.request({ t: 'me', mac: keys.macA, box: seal(keys.keyA, { id: this.peer.myId(), name: String(myName).slice(0, 80) }) }, f => f.t === 'ok' || isNo(f), STEP_TIMEOUT);
      if (isNo(r)) throw new Error(why(r));
      if (!same(r.mac, keys.macB)) throw new Error('That invite did not prove it knows the code — not added.');
      const them = unseal(keys.keyB, r.box);
      const { parseId } = require('./peer');
      const id = parseId(them.id);
      return { id: `sealchat:${id.onion}:${id.fp}`, fp: id.fp, name: String(them.name || '').replace(/[\x00-\x1f]/g, '').slice(0, 80), multi: !!them.multi };
    } finally { fsk.destroy(); }
  }
}

module.exports = { Invites, makeCode, parseCode, looksLikeCode, onionFor, onionFromSeed, spake, same, seal, LIFETIMES, MAX_TRIES, MAX_OPEN };
