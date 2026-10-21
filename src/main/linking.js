/* =====================================================================
 * Seal Chat — linking.js   (link another device to your ID, 1.9.0)
 * ---------------------------------------------------------------------
 * One Seal Chat ID on several devices: the same PGP key (so the same
 * fingerprint and the same contacts), but each device has its OWN .onion
 * address. Contacts can reach you at any of them; your devices pass
 * everything on to each other (peer.js 6e).
 *
 * Linking a new device works like an invite code (invites.js), with its
 * own kind of code so the two can't be mixed up:
 *
 *       link-482-crystal-orange-river-lemon        (10 minutes, one use)
 *
 *   - On the device you already use: Settings → Your devices → "Link a new
 *     device…" shows the code. "link-482-crystal" picks a temporary .onion
 *     address; the other words are a password that never travels (SPAKE2).
 *   - On the new device: the welcome screen → "Link to my Seal Chat on
 *     another device": the code, your key passphrase and a name for it.
 *   - The new device makes its own device key and .onion address and sends
 *     them; the old one answers with your PGP key (still locked with your
 *     passphrase), your name and picture, mailbox settings and the signed
 *     list of your devices. Contacts and chats follow over the normal
 *     device-to-device sync once the new device is online.
 *   - The new device opens your key with the passphrase you typed BEFORE
 *     it says "done"; only then is it added to your devices.
 *   - 3 wrong codes close it. Everything stays inside Tor.
 *
 * Sections:
 *   1. Link codes
 *   2. Sealing (AES-256-GCM, larger than invite boxes)
 *   3. On the device you already use (Linker: start / cancel / listener)
 *   4. On the new device (join)
 * ===================================================================== */

const net = require('net');
const zlib = require('zlib');
const crypto = require('crypto');
const { FrameSocket, socksConnect } = require('./wire');
const inv = require('./invites');
const devices = require('./devices');

const LINK_MS = 10 * 60e3;          // a link code works for 10 minutes
const MAX_TRIES = 3;
const VPORT = 80;
const STEP_TIMEOUT = 90e3;
const ONION = /^[a-z2-7]{55}d$/;

/* =================================================================
 * 1. LINK CODES — "link-" + number + 4 words
 * ================================================================= */
function makeCode() {
  const c = inv.parseCode(inv.makeCode(inv.LIFETIMES['30d']));      // number + 4 words
  return 'link-' + c.code;
}
/** "link-482-crys-oran-rive-lemo", any case / separators → { code, num, words } (num carries "link") or null. */
function parseCode(text) {
  const t = String(text || '').trim().toLowerCase();
  const m = /^link[^a-z0-9]*(.*)$/.exec(t);
  if (!m) return null;
  const c = inv.parseCode(m[1]);
  if (!c || c.words.length !== 4) return null;
  return { code: 'link-' + c.code, num: 'link-' + c.num, words: c.words };
}
const looksLikeLink = t => /^\s*link\b/i.test(String(t || ''));

/* =================================================================
 * 2. SEALING
 * ================================================================= */
function seal(key, obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(zlib.gzipSync(Buffer.from(JSON.stringify(obj), 'utf8'))), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function unseal(key, b64) {
  const b = Buffer.from(String(b64 || ''), 'base64');
  if (b.length < 29 || b.length > 400 * 1024) throw new Error('bad box');
  const d = crypto.createDecipheriv('aes-256-gcm', key, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return JSON.parse(zlib.gunzipSync(Buffer.concat([d.update(b.subarray(28)), d.final()]), { maxOutputLength: 4 * 1024 * 1024 }).toString('utf8'));
}

/* =================================================================
 * 3. ON THE DEVICE YOU ALREADY USE
 * peer.linker.start() → { code, expires }; events on the peer:
 *   'link' { kind: 'waiting' | 'linked' | 'wrong' | 'closed' | 'failed', name?, why? }
 * ================================================================= */
class Linker {
  constructor(peer) { this.peer = peer; this.cur = null; }

  status() { const c = this.cur; return c ? { code: c.code, expires: c.expires, tries: c.tries, state: c.state, name: c.name || '' } : null; }

  async start() {
    const p = this.peer;
    if (!p.running || !p.id.unlocked) throw new Error('Wait until Seal Chat is connected to Tor');
    if (p.myDevices().length >= devices.MAX_DEVICES) throw new Error(`An ID can be on at most ${devices.MAX_DEVICES} devices — remove one first`);
    await this.cancel();
    const code = makeCode();
    const k = inv.onionFor(parseCode(code));
    const cur = { code, onion: k.onion, expires: Date.now() + LINK_MS, tries: 0, state: 'waiting', busy: false, socks: new Set() };
    cur.server = net.createServer(s => this._incoming(cur, s));
    cur.server.maxConnections = 2;
    await new Promise((res, rej) => { cur.server.once('error', rej); cur.server.listen(0, '127.0.0.1', res); });
    try { await p.tor.publishExtra(k.key, cur.server.address().port, VPORT, k.onion); }
    catch (e) { cur.server.close(); throw e; }
    this.cur = cur;
    cur.timer = setTimeout(() => { if (this.cur === cur) { this.cancel(); p.emit('link', { kind: 'closed', why: 'The link code ran out (10 minutes). Make a new one.' }); } }, LINK_MS);
    if (cur.timer.unref) cur.timer.unref();
    p.emit('link', { kind: 'waiting', code, expires: cur.expires });
    return this.status();
  }

  async cancel() {
    const cur = this.cur;
    if (!cur) return;
    this.cur = null;
    clearTimeout(cur.timer);
    for (const s of cur.socks) s.destroy();
    try { cur.server.close(); } catch { /* ignore */ }
    try { await this.peer.tor.unpublishExtra(cur.onion); } catch { /* ignore */ }
  }

  /** The new device connected. */
  _incoming(cur, sock) {
    const p = this.peer;
    const fsk = new FrameSocket(sock);
    cur.socks.add(fsk);
    sock.on('close', () => { cur.socks.delete(fsk); });
    fsk.setIdle(STEP_TIMEOUT);
    if (cur.busy) { fsk.send({ t: 'no', why: 'busy' }); fsk.end(); return; }
    cur.busy = true;
    sock.on('close', () => { cur.busy = false; });
    let ex = null, keys = null, them = null;
    fsk.on('frame', async f => {
      try {
        if (this.cur !== cur || Date.now() > cur.expires) { fsk.send({ t: 'no', why: 'closed' }); return fsk.end(); }
        if (f.t === 'hi' && !ex) {
          if (f.v !== 1) { fsk.send({ t: 'no', why: 'version' }); return fsk.end(); }
          ex = inv.spake('B', cur.onion, parseCode(cur.code));
          keys = ex.finish(f.x);
          fsk.send({ t: 'pake', y: ex.msg });
        } else if (f.t === 'me' && keys && !them) {
          if (!inv.same(f.mac, keys.macA)) {
            cur.tries++;
            fsk.send({ t: 'no', why: 'wrong code' }); fsk.end();
            p.emit('link', { kind: 'wrong', left: MAX_TRIES - cur.tries });
            if (cur.tries >= MAX_TRIES) { this.cancel(); p.emit('link', { kind: 'closed', why: 'Closed after 3 wrong codes. Make a new one.' }); }
            return;
          }
          const d = unseal(keys.keyA, f.box);
          const dev = d && d.device;
          if (!dev || Buffer.from(String(dev.pub || ''), 'base64').length !== 32 || dev.id !== devices.deviceIdOf(String(dev.pub)) || !ONION.test(String(dev.onion || ''))) { fsk.send({ t: 'no', why: 'bad device' }); return fsk.end(); }
          if (p.myDevices().some(x => x.id === dev.id || x.onion === dev.onion)) { fsk.send({ t: 'no', why: 'already linked' }); return fsk.end(); }
          them = { id: dev.id, pub: String(dev.pub), name: devices.cleanName(dev.name), onion: String(dev.onion), added: Date.now() };
          cur.state = 'linking'; cur.name = them.name;
          const bundle = await p.linkBundle(them);
          fsk.send({ t: 'ok', mac: keys.macB, box: seal(keys.keyB, bundle) });
        } else if (f.t === 'done' && them) {
          // the new device opened the key with your passphrase: it's one of yours now
          await p.addDevice(them);
          fsk.send({ t: 'welcome-device' }); fsk.end();
          await this.cancel();
          p.emit('link', { kind: 'linked', name: them.name, id: them.id });
        } else if (f.t === 'fail' && them) {
          cur.state = 'waiting'; cur.name = '';
          fsk.end();
          p.emit('link', { kind: 'failed', why: String(f.why || 'The new device could not open your key').slice(0, 200) });
        } else fsk.destroy();
      } catch (e) { p.log('link: ' + e.message); fsk.destroy(); }
    });
  }
}

/* =================================================================
 * 4. ON THE NEW DEVICE
 * join({ code, socksPort, name, unlock }) — unlock(bundle) must open the
 * key (throws on a wrong passphrase). Returns { bundle, device, onionKey }.
 * ================================================================= */
async function join({ code, socksPort, name, unlock, timeoutMs }) {
  const c = parseCode(code);
  if (!c) throw new Error('That is not a link code. It looks like link-482-crystal-orange-river-lemon (Settings → Your devices → Link a new device… on your other device)');
  if (!socksPort) throw new Error('Wait until Seal Chat is connected to Tor (bottom of this window), then try again');
  const { onion } = inv.onionFor(c);
  const device = devices.makeDevice(name);
  const own = inv.onionFromSeed(crypto.randomBytes(32));            // this device's own address
  let fsk;
  try { fsk = await socksConnect(socksPort, onion + '.onion', VPORT, timeoutMs || 120e3); }
  catch { throw new Error('Couldn\'t reach your other device. Check the code — and Seal Chat must be open and online there, with the code still showing.'); }
  try {
    const ex = inv.spake('A', onion, c);
    const isNo = f => f.t === 'no';
    const why = f => ({ 'wrong code': 'That code isn\'t right — check every word (after 3 wrong tries the code closes).', busy: 'Your other device is busy linking — try again in a minute.', closed: 'That link code has run out. Make a new one on your other device.', 'already linked': 'This device is already linked.' }[f.why] || 'Linking was refused (' + f.why + ').');
    const p = await fsk.request({ t: 'hi', v: 1, x: ex.msg }, f => f.t === 'pake' || isNo(f), STEP_TIMEOUT);
    if (isNo(p)) throw new Error(why(p));
    const keys = ex.finish(p.y);
    const r = await fsk.request({ t: 'me', mac: keys.macA, box: seal(keys.keyA, { v: 1, device: { id: device.id, pub: device.pub, name: device.name, onion: own.onion } }) }, f => f.t === 'ok' || isNo(f), STEP_TIMEOUT);
    if (isNo(r)) throw new Error(why(r));
    if (!inv.same(r.mac, keys.macB)) throw new Error('The other side did not prove it knows the code — not linked.');
    const bundle = unseal(keys.keyB, r.box);
    try { await unlock(bundle); }
    catch (e) { fsk.send({ t: 'fail', why: 'wrong passphrase' }); throw new Error(/passphrase|decrypt|incorrect/i.test(e.message) ? 'Wrong key passphrase — type the passphrase of your Seal Chat key (the same as on your other device) and try again. The code still works.' : e.message); }
    await fsk.request({ t: 'done' }, f => f.t === 'welcome-device' || isNo(f), STEP_TIMEOUT);
    return { bundle, device, onionKey: own.key, onion: own.onion };
  } finally { fsk.destroy(); }
}

/**
 * After join(): sets up the new device's encrypted vault from what the other
 * device sent (its own address + device key, your device list, settings,
 * mailbox). The caller then opens the key (main.js adopt) and starts Seal Chat;
 * contacts and chats arrive over the sync.
 */
function adoptLink(store, r) {
  const b = r.bundle || {}, v = store.vault;
  v.onionKey = r.onionKey;
  v.device = r.device;
  const list = (Array.isArray(b.devices) ? b.devices : []).filter(d => d && Buffer.from(String(d.pub || ''), 'base64').length === 32 && d.id === devices.deviceIdOf(String(d.pub)) && ONION.test(String(d.onion || '')))
    .map(d => ({ id: d.id, pub: String(d.pub), name: devices.cleanName(d.name), added: Number(d.added) || Date.now(), onion: String(d.onion) }))
    .filter(d => d.id !== r.device.id).slice(0, devices.MAX_DEVICES - 1);
  v.myDevices = [{ id: r.device.id, pub: r.device.pub, name: r.device.name, added: r.device.created, onion: r.onion }, ...list];
  v.myDevicesTs = 0;                                   // the other device's signed list (sent next) is always newer
  delete v.unlinked;
  v.contacts = {}; v.ctl = []; v.syncq = {}; v.syncDigest = {};
  const mb = b.mailbox || {};
  if (typeof mb.drop === 'string' && /^[A-Za-z0-9_-]{20,100}$/.test(mb.drop)) v.mailboxDrop = mb.drop;
  if (mb.workerBox && typeof mb.workerBox.url === 'string' && /^https?:\/\//.test(mb.workerBox.url)) v.workerBox = { url: mb.workerBox.url, owner: String(mb.workerBox.owner || ''), box: String(mb.workerBox.box || '') };
  if (mb.given && typeof mb.given.url === 'string') v.sibMailbox = { url: String(mb.given.url), box: String(mb.given.box || ''), drop: String(mb.given.drop || '') };
  const s = b.settings || {};
  const patch = {};
  if (typeof s.displayName === 'string') patch.displayName = s.displayName.slice(0, 80);
  for (const k of ['readReceipts', 'allowRequests', 'contactMailbox']) if (typeof s[k] === 'boolean') patch[k] = s[k];
  store.setSettings(patch);
  if (s.me && typeof s.me === 'object') v.me = { shareAvatar: s.me.shareAvatar !== false, avatar: typeof s.me.avatar === 'string' && s.me.avatar.length < 600 * 1024 ? s.me.avatar : null, avatarAt: Number(s.me.avatarAt) || 0 };
  store.saveVault();
}

module.exports = { Linker, join, adoptLink, makeCode, parseCode, looksLikeLink, LINK_MS };
