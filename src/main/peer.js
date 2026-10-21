/* =====================================================================
 * Seal Chat — peer.js   (the chat engine, 1.0.0 · 1.8.0)
 * ---------------------------------------------------------------------
 * Everything between "you pressed Send" and "it appeared on their PC":
 *
 *   YOUR SEAL CHAT ID   sealchat:<56-letter onion address>:<40-digit key fingerprint>
 *                       Share it with people you want to chat with. The
 *                       fingerprint inside it means nobody can pretend to
 *                       be you, even if they could somehow take over the address.
 *
 *   ADDING A CONTACT    Paste their ID → Seal Chat connects to their .onion,
 *                       fetches their public key, checks it matches the
 *                       fingerprint in the ID, then sends a signed + encrypted
 *                       contact request. When they accept, both of you can chat.
 *
 *   SENDING             Messages are signed and encrypted (PGP), then handed
 *                       straight to the contact's PC over Tor. Their PC
 *                       confirms it stored the message → "Delivered" ✓.
 *                       When they read it (if read receipts are on) → ✓✓.
 *
 *   OFFLINE CONTACTS    Messages wait in your Outbox. Seal Chat retries on a
 *                       schedule (20 s, 1, 2, 5, 10, then every 15 minutes)
 *                       and immediately whenever that contact's Seal Chat
 *                       starts up or contacts you. Nothing is stored on any
 *                       server — a message only travels when both PCs are on.
 *
 * Frames on the wire (see wire.js) — "box" is always a PGP-sealed block:
 *   hello   {onion, fp}            first frame on every connection
 *   welcome {onion, fp}            reply to hello
 *   getkey  → key {armored}        fetch the other side's public key
 *   req     {key, box}  → ok|no    contact request
 *   msg     {id, box}   → ack|nack chat message / receipt / accept
 *
 * FILES (1.1.0)       A file is sent as an "offer" (name, size, type, its own
 *                       random key, a small preview for photos) inside a normal
 *                       signed + encrypted message. The receiver's PC then
 *                       PULLS the encrypted pieces (see files.js) over the same
 *                       proven connection, a window at a time, and can resume
 *                       from the last good piece after any interruption.
 *                       Small files download by themselves; bigger ones ask.
 *     get   {id, g, i, n}  → n binary "piece" frames tagged "<id>/<g>", or gone {id}
 *     stop  {id, g}        → the sender drops what's left of that request
 *     (g = a new number for every attempt, so leftovers of an earlier,
 *      paused or broken attempt are recognised and ignored)
 *
 * PROFILE (1.2.0)     Your name and — if you choose to share it — your picture
 *                       go to each contact as a signed + encrypted "profile"
 *                       message, again whenever you change them. Contacts can
 *                       show it or pick their own picture for you.
 *
 * REPLIES + REACTIONS (1.8.0)
 *                       A reply is a normal text/file message with
 *                       re: {id, snip} — the id of the message it answers
 *                       and a short excerpt. Older Seal Chats ignore "re" and
 *                       simply show the text. A reaction is its own small
 *                       message {k:'react', mid, e} — one emoji per person per
 *                       message ("" removes it). A contact whose Seal Chat is
 *                       too old to show it answers "unsupported"; the reaction
 *                       is then dropped quietly (it stays on this PC).
 *
 * MAILBOX (1.8.0)     When a contact can't be reached, their messages used to
 *                       wait on YOUR PC until both were online. Now a contact
 *                       can have a mailbox on their own website (Seal Chat
 *                       Web's relay.php). They give it to their contacts as a
 *                       signed + encrypted {k:'mbox', mb:{url, box, drop}}.
 *                       If they're offline for a minute, queued messages,
 *                       file offers, reactions and read receipts are left
 *                       there — each one the same PGP box as always (signed by
 *                       you, readable only by them; who it's from is inside
 *                       the encryption). They show 📬 until delivered. When
 *                       the contact's Seal Chat starts it picks them up
 *                       (fromMailbox); a later direct connection confirms ✓
 *                       as usual (duplicates are recognised by their id).
 *                       Through Tor; directly only if you allow that for
 *                       mailbox websites that block Tor (Settings → Privacy).
 *
 * CONTACT MAILBOX     (1.8.5) For contacts with no mailbox of their own (or
 *                       whose mailbox can't be reached): if Ann is offline,
 *                       Bob can leave a message with Cat — a contact Bob and
 *                       Ann BOTH have — while Cat is online. Bob seals it for
 *                       Ann exactly like a mailbox message (Cat can't read it
 *                       or see what's inside), and sends Cat
 *                       {k:'hold', for: <tag of Ann's ID>, d}. Cat keeps it
 *                       only if Ann is one of Cat's contacts (the tag is a
 *                       hash, so a contact who doesn't know Ann learns
 *                       nothing), and passes it to Ann as {k:'held', d} the
 *                       next time they're both online. Ann checks it like
 *                       any mailbox message (signed by Bob, sealed for her).
 *                       Up to 3 helpers, those seen online recently. Bob's
 *                       message shows 📬 until it's confirmed directly.
 *                       Settings → Mailbox → "Contact mailbox" (on by default)
 *                       covers both: asking others and holding for others.
 *
 * LINKED DEVICES      (1.9.0) One ID on several devices (linking.js): the same
 *                       PGP key, each device with its own .onion address,
 *                       all listed in the signed device list contacts get.
 *                       Contacts deliver to the address they know and, if it
 *                       doesn't answer, to your other devices (6, _connection).
 *                       Your devices keep each other up to date (6e): what
 *                       contacts send you, what you send, reads, reactions,
 *                       contacts, your name/picture, the mailbox address,
 *                       and (1.9.3) web access to Seal Chat Web ("web").
 *                       Each message you write is sent by the device you
 *                       wrote it on (m.dev); the others show it too.
 *
 * DEVICES (1.8.0)     Groundwork for one ID on several devices (devices.js):
 *                       this installation has its own device key; your PGP key
 *                       signs the list of your devices, which goes to each
 *                       contact like your profile ({k:'devices', doc, sig});
 *                       contacts check and keep it; every message names the
 *                       sending device (from.dev). Delivery is unchanged.
 *
 * Sections:
 *   1. IDs (parse / format)
 *   2. Peer class setup + listener (incoming connections)
 *   3. Handling incoming frames
 *   4. Contacts: add, accept, decline, block, remove
 *   5. Messages: send, read receipts, history
 *   6. Delivery engine (outbox, retries, connections)
 *   7. Helpers
 * ===================================================================== */

const net = require('net');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { FrameSocket, socksConnect } = require('./wire');
const { describePublic } = require('./identity');
const { piecesFor, openPiece, SLOT, safeName, isRisky } = require('./files');
const devices = require('./devices');                       // 1.8.0: device keys (groundwork for several devices per ID)
const { Invites } = require('./invites');                   // 1.8.0: invite codes
const { Linker } = require('./linking');                    // 1.9.0: link another device to this ID
const { EMOJI_ONLY, EMOJI_PICT } = require('./noicu');     // 1.9.1: emoji checks that work without ICU (Android)

const PROTO = 1;
const VPORT = 80;                                           // port on the .onion side
const RETRY = [20e3, 60e3, 120e3, 300e3, 600e3, 900e3];     // outbox retry schedule
const MAX_TEXT = 10000;                                     // characters per message
const MAX_PENDING_REQUESTS = 50;
const IDLE_OUT = 2 * 60e3, IDLE_IN = 3 * 60e3;
const MAX_FILE = 4 * 1024 ** 3;                             // hard ceiling for any offer (4 GB)
const WINDOW = 16;                                          // pieces in flight per download (4 MB)
const DL_RETRY = [15e3, 45e3, 120e3, 300e3, 600e3, 900e3];  // download retry schedule
const fileKey = (contactId, msgId) => contactId + '|' + msgId;
const SNIP = 140;                                           // characters of a replied-to message kept as its excerpt (1.8.0)
// control messages that a contact's older Seal Chat may not know: dropped quietly, never shown as an error (1.8.0)
const OPTIONAL_CTL = new Set(['react', 'devices', 'mbox']);
const MB_AFTER = 60e3;                                      // 1.8.0: offline this long → use their mailbox
const MB_CTL = new Set(['react', 'read']);                  //        control messages that may go to a mailbox
// 1.8.5: contact mailbox
const HOLD_HELPERS = 3;                                     // ask up to this many contacts at once
const HOLD_SEEN = 6 * 3600e3;                               // ...who were online in the last 6 hours
const HOLD_SEND_TTL = 2 * 86400e3;                          // a "please hold" not delivered to the helper in 2 days is dropped
const HOLD_RETRY = 3600e3;                                  // try other helpers for the same message after an hour
const HOLD_NO = 7 * 86400e3;                                // "I don't know them" remembered for a week
const HELD_KEEP = 14 * 86400e3;                             // a helper keeps a held message up to 14 days
const HELD_MAX_ITEM = 300 * 1024;                           // one held message (sealed)
const HELD_MAX_PER_TARGET = 200, HELD_MAX_PER_SENDER = 100, HELD_MAX_BYTES = 20 * 1024 * 1024;
// 1.9.0: linked devices
const SYNC_SKIP = new Set(['hold', 'held', 'ping']);        // contacts' messages NOT passed on to your other devices
const SYNC_MAX_QUEUE = 5000;                                // events waiting for one device (more: a full copy instead)
const SYNC_BATCH = 200 * 1024;                              // bytes of events per sync frame
// contact fields that belong to THIS device only (never copied between your devices)
const LOCAL_FIELDS = new Set(['lastError', 'mailboxError', 'lastSeen', 'lastReached', 'lastMailbox', 'mailboxVia', 'profileSent', 'devicesSent', 'mboxSent',
  'olderVersion', 'holdOk', 'holdNo', 'noHold', 'lastDevice', 'unread', 'lastText', 'lastAt', 'lastDir', 'addressChecked']);
const holdTag = fp => crypto.createHash('sha256').update('sealchat-hold-v1|' + String(fp).toUpperCase()).digest('hex').slice(0, 32);

/* =================================================================
 * 1. IDS
 * ================================================================= */
function formatId(onion, fp) { return `sealchat:${onion}:${String(fp).toUpperCase()}`; }

/** Accepts the ID with or without spaces/line breaks, or "<onion>.onion <FP>". */
function parseId(text) {
  const t = String(text || '').replace(/\s+/g, '').replace(/\.onion/gi, '').toLowerCase();
  const m = /^(?:sealchat:)?([a-z2-7]{56})[:/#]?([0-9a-f]{40}|[0-9a-f]{64})$/.exec(t);
  if (!m) throw new Error('That is not a Seal Chat ID. It looks like: sealchat:<56 letters/digits>:<40-digit fingerprint>');
  if (!/d$/.test(m[1])) throw new Error('That .onion address is not valid (check for a typo)');
  return { onion: m[1], fp: m[2].toUpperCase() };
}

const newId = () => crypto.randomBytes(12).toString('hex');
/** What a caller signs to prove who it is (one-time nonce + both addresses). */
const authText = (nonce, serverOnion, clientOnion, clientFp) => `sealchat-auth-v1|${nonce}|${serverOnion}|${clientOnion}|${String(clientFp).toUpperCase()}`;

/* =================================================================
 * 2. PEER
 * ================================================================= */
class Peer extends EventEmitter {
  /**
   * @param {object} o { store, identity, tor, log }
   */
  constructor(o) {
    super();
    this.o = o;                    // 1.8.0: options (http + allowHttpMailbox: tests)
    this.store = o.store;
    this.id = o.identity;
    this.tor = o.tor;
    this.log = o.log || (() => {});
    this.server = null;
    this.port = 0;
    this.onion = null;
    this.out = new Map();          // contactId -> { busy, connecting, kick } (delivery in progress)
    this.links = new Map();        // contactId -> FrameSocket proven to be that contact (either direction)
    this.sched = new Map();        // contactId -> { next, tries }
    this.inbound = new Set();
    this.tick = null;
    this.running = false;
    this.files = o.files;          // FileVault (1.1.0)
    this.dl = new Map();           // "contact|msg" -> { running, next, tries, stop }
    this.lastEmit = new Map();     // progress-event throttling
    this.invites = new Invites(this);   // 1.8.0: invite codes (they live on while Seal Chat runs)
    this.linker = new Linker(this);     // 1.9.0: linking another device
    this.syncSched = new Map();         // 1.9.0: deviceId -> { next, tries, busy }
    this.selfLinks = new Map();         //        deviceId -> FrameSocket to that device of yours
    this.on('contacts', () => this._digestSoon());
  }

  get me() { return { onion: this.onion, fp: this.id.fp, dev: this.device && !this.o.oldKinds ? this.device.id : undefined }; }   // (oldKinds: tests acting like 1.7)   // 1.8.0: dev

  /* ---------- 1.8.0: this installation's device key ---------- */
  _ensureDevice() {
    const v = this.store.vault;
    if (!v.device || !v.device.id || !v.device.priv) { v.device = devices.makeDevice(); this.store.saveVault(); }
    this.device = v.device;
    return this.device;
  }
  /** The devices of this ID: this one first, then your linked ones (1.9.0), each with its .onion address. */
  myDevices() {
    const v = this.store.vault, me = this._ensureDevice();
    const list = (Array.isArray(v.myDevices) ? v.myDevices : []).filter(d => d.id !== me.id);
    const known = (Array.isArray(v.myDevices) ? v.myDevices : []).find(d => d.id === me.id);
    const self = { id: me.id, pub: me.pub, name: me.name, added: me.created, onion: this.onion || (known && known.onion) || undefined };
    return v.unlinked ? [self] : [self, ...list];
  }
  /** 1.9.0: your other devices (that this one passes everything on to). */
  siblings() { return this.store.vault.unlinked ? [] : this.myDevices().slice(1).filter(d => d.onion); }
  renameDevice(name) {
    const d = this._ensureDevice();
    d.name = devices.cleanName(name);
    this.store.saveVault();
    this._devicesChanged().catch(e => this.log('devices: ' + e.message));   // contacts and your other devices get the new list
    return d;
  }
  /** Queues the signed device list for a contact who doesn't have this version yet. */
  async _maybeShareDevices(c) {
    if (!c || c.status !== 'accepted' || !this.id.unlocked) return;
    const list = this.myDevices();
    const ver = devices.listVersion(list);
    if (c.devicesSent === ver || (this.store.vault.ctl || []).some(x => x.to === c.id && x.k === 'devices' && x.ver === ver)) return;
    const { doc, sig } = await devices.signedList(this.id, list);
    const v = this.store.vault;
    v.ctl = (v.ctl || []).filter(x => !(x.to === c.id && x.k === 'devices'));       // only the newest
    this.store.saveVault();
    this._queueCtl(c.id, { k: 'devices', doc, sig, ver });
  }
  myId() { return this.onion && this.id.fp ? formatId(this.onion, this.id.fp) : null; }

  /** Starts listening and publishes the .onion address. Tor must be connected. */
  async start() {
    if (this.running) return;
    this.server = net.createServer(s => this._incoming(s));
    this.server.maxConnections = 40;
    await new Promise((res, rej) => { this.server.once('error', rej); this.server.listen(0, '127.0.0.1', res); });
    this.port = this.server.address().port;
    const v = this.store.vault;
    const r = await this.tor.publish(v.onionKey || null, this.port, VPORT);
    if (!v.onionKey) { v.onionKey = r.key; this.store.saveVault(); }
    this.onion = r.onion;
    this.running = true;
    this._ensureDevice();                // 1.8.0
    this._startDevices();                // 1.9.0: this device's address in your device list; say hello to your other devices
    // 1.8.1: 1.8.0 could mark the mailbox address / device list as "sent" to a
    // contact whose older Seal Chat couldn't take it — send both to everyone once more
    if (!v.resent181) {
      for (const c of this.store.contacts()) if (c.mboxSent || c.devicesSent) { delete c.mboxSent; delete c.devicesSent; this.store.putContact(c); this._maybeShareMailbox(c); }   // queued: goes out the next time they're reached
      v.resent181 = true; this.store.saveVault();
    }
    this._recoverFiles();
    this.tick = setInterval(() => this._tick(), 5000);
    this.invites.resume().catch(e => this.log('invites: ' + e.message));   // 1.8.0
    // say hello to everyone: anyone holding messages for us sends them now
    for (const c of this.store.contacts()) {
      if (c.status === 'blocked') continue;
      this.sched.set(c.id, { next: Date.now() + 500 + Math.random() * 3000, tries: 0, hello: true });
    }
    this.emit('status');
  }

  async stop() {
    this.running = false;
    clearInterval(this.tick); this.tick = null;
    for (const l of this.links.values()) l.destroy();
    this.links.clear();
    for (const l of this.selfLinks.values()) l.destroy();          // 1.9.0
    this.selfLinks.clear(); this.syncSched.clear();
    try { await this.linker.cancel(); } catch { /* ignore */ }
    this.out.clear();
    for (const s of this.inbound) s.destroy();
    this.inbound.clear();
    if (this.server) await new Promise(r => this.server.close(() => r()));
    this.server = null;
    try { await this.invites.pause(); } catch { /* ignore */ }        // 1.8.0
    try { await this.tor.unpublish(); } catch { /* ignore */ }
    this.store.flush();
  }

  _incoming(sock) {
    const fsk = new FrameSocket(sock);
    this.inbound.add(fsk);
    fsk.setIdle(IDLE_IN);
    fsk.on('close', () => this.inbound.delete(fsk));
    this._attach(fsk, { hello: null, authed: null, outbound: false });
  }

  /**
   * Frame handling for any connection. Connections work both ways: once a
   * contact has proven who they are, either side can send messages over it.
   */
  _attach(fsk, st) {
    st.frames = 0; st.since = Date.now();
    fsk.on('error', () => {});
    fsk.on('close', () => { if (st.authed && this.links.get(st.authed) === fsk) this.links.delete(st.authed); });
    fsk.on('frame', f => {
      // simple flood protection: 600 frames per minute per connection
      if (f.t !== 'piece' && ++st.frames > 600) { if (Date.now() - st.since < 60e3) return fsk.destroy(); st.frames = 0; st.since = Date.now(); }
      this._frame(fsk, st, f).catch(e => { this.log('frame error: ' + e.message); try { fsk.send({ t: 'nack', id: f.id, why: 'bad' }); } catch { /* closed */ } });
    });
  }

  /* =================================================================
   * 3. INCOMING FRAMES
   * ================================================================= */
  async _frame(fsk, st, f) {
    switch (f.t) {
      case 'hello': {
        if (st.outbound || st.hello) return;
        if (!/^[a-z2-7]{56}$/.test(f.onion || '') || !/^[0-9A-F]{40,64}$/.test(f.fp || '')) return fsk.destroy();
        st.hello = { onion: f.onion, fp: f.fp };
        st.nonce = crypto.randomBytes(24).toString('hex');
        fsk.send({ t: 'welcome', v: PROTO, onion: this.onion, fp: this.id.fp, nonce: st.nonce });
        return;
      }
      case 'auth': {
        // the caller proves it holds the private key of a contact (signature over our
        // one-time nonce + both addresses) — then this connection counts as theirs
        if (st.outbound || !st.hello || st.authed || st.self) return;
        if (st.hello.fp === this.id.fp) return this._onSelfAuth(fsk, st, f);   // 1.9.0: one of your other devices
        const c = this.store.contact(st.hello.fp);
        let good = false;
        if (c && c.publicKey && c.status !== 'blocked' && c.status !== 'pending-in') {
          good = await this.id.verifyText(authText(st.nonce, this.onion, st.hello.onion, st.hello.fp), f.sig, c.publicKey);
        }
        fsk.send({ t: good ? 'authok' : 'authno' });
        if (!good) return;
        st.authed = c.id;
        if (c.onion !== st.hello.onion) c.onion = st.hello.onion;      // proven by their signature
        c.lastSeen = Date.now(); this.store.putContact(c);
        this.links.set(c.id, fsk);
        // they're online: if we were still dialling their old circuit, use this one instead
        const slot = this.out.get(c.id);
        if (slot && slot.connecting) { slot.kick = true; slot.connecting.destroy(); }
        this._soon(c.id, 100);
        this._dlKick(c.id);
        this.emit('contacts');
        return;
      }
      case 'getkey':
        return fsk.send({ t: 'key', armored: this.id.pubArmored });
      case 'sync':                                                      // 1.9.0: from one of your other devices
        return this._onSync(fsk, st, f);
      case 'req':
        return this._onRequest(fsk, st, f);
      case 'msg':
        return this._onMsg(fsk, st, f);
      case 'get':
        return this._onGet(fsk, st, f);
      case 'stop':
        (st.stopped = st.stopped || new Set()).add(String(f.id) + '/' + String(f.g));
        return;
      case 'piece': case 'gone':
        return;   // answers to our own downloads — read by _download()
      case 'bye':
        return fsk.end();
      default:
        return; // unknown frame types are ignored (newer versions)
    }
  }

  /* ---------- contact request arriving ---------- */
  async _onRequest(fsk, st, f) {
    const reply = (ok, why) => fsk.send(ok ? { t: 'ok', id: f.id } : { t: 'no', id: f.id, why });
    if (!st.hello) return reply(false, 'hello first');
    if (!this.id.unlocked) return reply(false, 'locked');
    if (this.store.settings.allowRequests === false) return reply(false, 'not accepting requests');
    let info;
    try { info = await describePublic(String(f.key || '')); } catch { return reply(false, 'bad key'); }
    if (info.fp !== st.hello.fp) return reply(false, 'key mismatch');
    if (!info.canEncrypt) return reply(false, 'key cannot encrypt');
    const r = await this.id.open(f.box, info.armored);
    const o = r.obj || {};
    if (!r.valid || o.k !== 'req' || o.to !== this.id.fp || !o.from || o.from.fp !== info.fp || o.from.onion !== st.hello.onion) return reply(false, 'bad request');

    let c = this.store.contact(info.fp);
    if (c && c.status === 'blocked') return reply(false, 'blocked');
    if (c && (c.status === 'accepted' || c.status === 'pending-out')) {
      // we know them already (or we asked them too): accept automatically — after
      // checking their address really belongs to that key
      c.publicKey = info.armored; c.keyName = info.name;
      if (o.avatar !== undefined) c.sharedAvatar = cleanAvatar(o.avatar);
      c.onion = st.hello.onion;          // signed by their key: a new address (new PC) is fine
      if (c.status === 'pending-out') { c.status = 'accepted'; c.acceptedAt = Date.now(); }
      this._queueCtl(c.id, { k: 'accept' });
      this._maybeShareProfile(c);
      this.store.putContact(c);
      reply(true);
      this.emit('contacts');
      this._soon(c.id, 200);
      return;
    }
    if (!c) {
      const pending = this.store.contacts().filter(x => x.status === 'pending-in').length;
      if (pending >= MAX_PENDING_REQUESTS) return reply(false, 'too many requests');
    }
    c = {
      ...(c || {}),
      id: info.fp, fp: info.fp, onion: st.hello.onion, publicKey: info.armored,
      keyName: info.name, name: String(o.from.name || info.name || '').slice(0, 80),
      note: String(o.note || '').slice(0, 500), status: 'pending-in', sharedAvatar: cleanAvatar(o.avatar),
      invite: (() => { const j = this.invites.joinFor(info.fp); return j ? { label: j.label, at: j.at } : undefined; })(),   // 1.8.0: came with your invite code
      addedAt: (c && c.addedAt) || Date.now(), lastSeen: Date.now(), verified: false
    };
    this.store.putContact(c);
    reply(true);
    this.emit('contacts');
    this.emit('request', c);
  }

  /* ---------- chat message / receipt / accept arriving ---------- */
  async _onMsg(fsk, st, f) {
    const nack = why => fsk.send({ t: 'nack', id: f.id, why });
    if (!st.hello) return nack('hello first');
    const c = this.store.contact(st.hello.fp);
    if (!c || !c.publicKey) return nack('unknown');
    if (c.status === 'blocked') return nack('blocked');
    if (c.status === 'pending-in') return nack('pending');
    if (!this.id.unlocked) return nack('locked');
    const r = await this.id.open(f.box, c.publicKey);
    const o = r.obj || {};
    if (!r.valid || o.to !== this.id.fp || !o.from || o.from.fp !== c.fp) return nack('bad');
    const why = await this._apply(c, o);
    if (why) return nack(why);
    fsk.send({ t: 'ack', id: f.id });
    this._syncIn(c, o);                                                // 1.9.0: your other devices get it too
    this._afterApply(c);
  }

  /**
   * What a verified message from contact c does (shared by direct delivery
   * and the mailbox, 1.8.0). Returns a "nack" reason, or null when handled.
   */
  async _apply(c, o, via = 'direct') {
    if (o.from.onion && o.from.onion !== c.onion) {
      // contact moved to a new address (e.g. new PC, same key) — the signature proves it's them
      c.onion = o.from.onion;
    }
    if (via === 'direct') c.lastSeen = Date.now();                     // (a mailbox message doesn't mean they're online)
    if (/^[0-9a-f]{16}$/.test(String(o.from.dev || ''))) {
      c.lastDevice = o.from.dev;                                       // 1.8.0: which of their devices sent it
      // 1.8.1: they were on an older Seal Chat when we sent our mailbox address /
      // device list — now they're on 1.8+, so send those again
      if (c.olderVersion) { delete c.olderVersion; delete c.mboxSent; delete c.devicesSent; this._maybeShareMailbox(c); this._maybeShareDevices(c).catch(() => {}); this._soon(c.id, 2000); }
    }
    if (this.o.oldKinds && this.o.oldKinds.includes(o.k)) return 'unsupported';   // (tests: act like an older Seal Chat)

    switch (o.k) {
      case 'accept':
        if (c.status === 'pending-out') { c.status = 'accepted'; c.acceptedAt = Date.now(); this.emit('accepted', c); }
        break;
      case 'text': {
        if (c.status === 'pending-out') { c.status = 'accepted'; c.acceptedAt = Date.now(); } // their message implies they accepted
        const chat = this.store.chat(c.id);
        if (!chat.messages.some(m => m.id === o.id && m.dir === 'in')) {
          const msg = { id: String(o.id).slice(0, 40), dir: 'in', text: String(o.text || '').slice(0, MAX_TEXT), ts: Number(o.ts) || Date.now(), at: Date.now(), read: false };
          const re = cleanRe(o.re, chat); if (re) msg.re = re;          // 1.8.0: a reply
          chat.messages.push(msg);
          c.unread = (c.unread || 0) + 1;
          c.lastAt = msg.at; c.lastText = msg.text.slice(0, 120); c.lastDir = 'in';
          this.store.saveChat(c.id);
          this.emit('message', { contactId: c.id, msg, via });          // 1.9.3: via (no phone notification for 'sync' — the device that got it sends one)
        }
        break;
      }
      case 'read': {
        const chat = this.store.chat(c.id);
        const ids = new Set((Array.isArray(o.ids) ? o.ids : []).slice(0, 500));
        let n = 0;
        for (const m of chat.messages) if (m.dir === 'out' && ids.has(m.id) && m.state !== 'read') { m.state = 'read'; m.readAt = Date.now(); n++; }
        if (n) { this.store.saveChat(c.id); this.emit('receipts', { contactId: c.id }); }
        break;
      }
      case 'file': {
        if (c.status === 'pending-out') { c.status = 'accepted'; c.acceptedAt = Date.now(); }
        const chat = this.store.chat(c.id);
        if (chat.messages.some(m => m.id === o.id && m.dir === 'in')) break;
        const f = checkOffer(o);
        if (!f) return 'bad';
        // program files never download by themselves, whatever their size
        const auto = !isRisky(f.name) && f.size <= (Number(this.store.settings.autoDownloadMB ?? 25) * 1024 * 1024);
        const msg = { id: String(o.id).slice(0, 40), dir: 'in', kind: 'file', text: String(o.text || '').slice(0, MAX_TEXT), file: f,
          ts: Number(o.ts) || Date.now(), at: Date.now(), read: false, transfer: { state: auto ? 'queued' : 'offered', got: 0 } };
        const re = cleanRe(o.re, chat); if (re) msg.re = re;            // 1.8.0
        chat.messages.push(msg);
        c.unread = (c.unread || 0) + 1;
        c.lastAt = msg.at; c.lastText = '📎 ' + f.name; c.lastDir = 'in';
        this.store.saveChat(c.id);
        this.emit('message', { contactId: c.id, msg, via });            // 1.9.3: via
        if (auto) this._dlSoon(c.id, msg.id, 500);
        break;
      }
      case 'filedone': {
        const m = this.store.chat(c.id).messages.find(x => x.id === o.fid && x.dir === 'out' && x.kind === 'file');
        if (m) {
          m.transfer = { ...(m.transfer || {}), state: o.status === 'done' ? 'done' : 'declined', at: Date.now() };
          this.store.saveChat(c.id);
          this.emit('transfer', { contactId: c.id, id: m.id, transfer: m.transfer });
        }
        break;
      }
      case 'profile':
        if (o.name) c.name = String(o.name).slice(0, 80);
        if ('avatar' in o) { c.sharedAvatar = cleanAvatar(o.avatar); c.sharedAvatarAt = Date.now(); }
        break;
      case 'react': {                                                   // 1.8.0
        const chat = this.store.chat(c.id);
        const m = chat.messages.find(x => x.id === String(o.mid || ''));
        if (m) {
          const e = cleanEmoji(o.e);
          m.reactions = { ...(m.reactions || {}) };
          if (e) m.reactions.them = e; else delete m.reactions.them;
          this.store.saveChat(c.id);
          this.emit('msgupdate', { contactId: c.id, msg: m });
          if (e && m.dir === 'out') this.emit('reacted', { contactId: c.id, msg: m, e });
        }
        break;
      }
      case 'devices': {                                                 // 1.8.0
        const { keep, why } = await devices.checkList(this.id, c, o.doc, o.sig);
        if (keep) c.devices = keep;
        else if (why !== 'not newer') this.log('device list from ' + c.fp.slice(0, 8) + ' ignored: ' + why);
        break;
      }
      case 'ping':
        break;
      case 'mbox':                                                      // 1.8.0: where to leave messages for them
        c.mailbox = cleanMbox(o.mb, this.o.allowHttpMailbox);
        break;
      case 'hold': {                                                    // 1.8.5: please pass this on to a contact we both have
        const why = this._hold(c, o, via);
        if (why) return why;
        break;
      }
      case 'held': {                                                    // 1.8.5: a contact passes on a message someone left with them for us
        if (via !== 'direct') return 'bad';
        const r = await this.fromMailbox(String(o.d || ''));
        if (!r.ok && r.why === 'locked') return 'locked';
        if (!r.ok) this.log('held message from ' + c.fp.slice(0, 8) + ' ignored: ' + r.why);
        else this.log('got a message passed on by ' + c.fp.slice(0, 8));
        break;
      }
      default:
        // something from a newer Seal Chat that this version can't show: say so
        // (instead of "delivered"), so the sender knows to tell us to update
        return 'unsupported';
    }
    this._maybeShareProfile(c);
    this.store.putContact(c);
    this.store.flush();                 // safely on disk BEFORE we tell them it arrived
    return null;
  }
  _afterApply(c) {
    this.emit('contacts');
    this._soon(c.id, 300); // they're online: deliver anything waiting for them
    this._dlKick(c.id);    // …and fetch any files we were waiting for
  }

  /* =================================================================
   * 4. CONTACTS
   * ================================================================= */
  /** Add someone by their Seal Chat ID. The request is sent in the background. */
  addContact(idText, { nick, note } = {}) {
    const { onion, fp } = parseId(idText);
    if (fp === this.id.fp) throw new Error('That is your own Seal Chat ID');
    let c = this.store.contact(fp);
    if (c && c.status === 'accepted') throw new Error('That person is already in your contacts');
    if (c && c.status === 'pending-in') { c.onion = onion; this.store.putContact(c); return this.accept(fp); }
    c = { ...(c || {}), id: fp, fp, onion, nick: nick ? String(nick).slice(0, 80) : (c && c.nick) || '', note: String(note || '').slice(0, 500),
      status: 'pending-out', requested: false, addedAt: Date.now(), verified: false, publicKey: (c && c.publicKey) || null };
    this.store.putContact(c);
    this.emit('contacts');
    this._soon(fp, 0);
    return c;
  }

  accept(id) {
    const c = this.store.contact(id);
    if (!c || c.status !== 'pending-in') throw new Error('No request from that contact');
    // Their address is double-checked before anything is sent: we fetch the key
    // from that .onion and it must be the same key that signed the request.
    c.status = 'accepted'; c.acceptedAt = Date.now(); c.addressChecked = false;
    this._queueCtl(id, { k: 'accept' });
    this._maybeShareProfile(c);
    this.store.putContact(c);
    this.emit('contacts');
    this._soon(id, 0);
    return c;
  }

  decline(id) {
    const c = this.store.contact(id);
    if (c && c.status === 'pending-in') this.store.removeContact(id);
    this.emit('contacts');
  }

  block(id) {
    const c = this.store.contact(id);
    if (!c) return;
    c.status = 'blocked'; c.blockedAt = Date.now();
    this.store.putContact(c);
    this._dropCtl(id);
    this.emit('contacts');
  }

  unblock(id) {
    const c = this.store.contact(id);
    if (!c || c.status !== 'blocked') return;
    c.status = c.publicKey ? 'accepted' : 'pending-out';
    this.store.putContact(c);
    this.emit('contacts');
    this._soon(id, 0);
  }

  remove(id) {
    this._dropCtl(id);
    for (const m of this.store.chat(id).messages) if (m.kind === 'file') this._dropFile(id, m);
    const o = this.out.get(id); if (o && o.sock) o.sock.destroy();
    this.out.delete(id); this.sched.delete(id);
    this.store.removeContact(id);
    this.emit('contacts');
  }

  rename(id, nick) { const c = this.store.contact(id); if (c) { c.nick = String(nick || '').slice(0, 80); this.store.putContact(c); this.emit('contacts'); } }
  setVerified(id, v) { const c = this.store.contact(id); if (c) { c.verified = !!v; this.store.putContact(c); this.emit('contacts'); } }

  /* =================================================================
   * 5. MESSAGES
   * ================================================================= */
  /** @param opts { re: id of the message this answers (1.8.0) } */
  send(id, text, opts = {}) {
    const c = this.store.contact(id);
    if (!c) throw new Error('Unknown contact');
    if (c.status === 'blocked') throw new Error('You blocked this contact');
    if (c.status === 'pending-in') throw new Error('Accept their request first');
    text = String(text || '').replace(/\r\n/g, '\n');
    if (!text.trim()) throw new Error('Nothing to send');
    if (text.length > MAX_TEXT) throw new Error(`Messages can be up to ${MAX_TEXT.toLocaleString()} characters`);
    const msg = { id: newId(), dir: 'out', text, ts: Date.now(), at: Date.now(), state: 'queued', dev: this._ensureDevice().id };   // 1.9.0: dev = sent by this device
    const chat = this.store.chat(id);
    const re = this._reFor(chat, opts.re); if (re) msg.re = re;
    chat.messages.push(msg);
    c.lastAt = msg.at; c.lastText = text.slice(0, 120); c.lastDir = 'out';
    this.store.saveChat(id);
    this.store.putContact(c);
    this._syncMsg(id, msg);                                            // 1.9.0
    this._soon(id, 0);
    return msg;
  }

  /** Marks a chat as read; queues a read receipt if those are on. */
  markRead(id) {
    const c = this.store.contact(id);
    if (!c) return;
    const chat = this.store.chat(id);
    const ids = [];
    for (const m of chat.messages) if (m.dir === 'in' && !m.read) { m.read = true; ids.push(m.id); }
    if (ids.length) { this.store.saveChat(id); this._syncOut({ e: 'read', cid: id, ids }); }   // 1.9.0: read on your other devices too
    if (c.unread) { c.unread = 0; this.store.putContact(c); }
    if (ids.length && this.store.settings.readReceipts !== false && c.status === 'accepted') {
      this._queueCtl(id, { k: 'read', ids });
      this._soon(id, 500);
    }
  }

  history(id) { return this.store.chat(id).messages; }

  /* ---------- 1.8.0 replies + reactions ---------- */
  /** The reply reference stored with a new message: { id, snip, dir } of the message it answers. */
  _reFor(chat, reId) {
    if (!reId) return null;
    const m = chat.messages.find(x => x.id === String(reId));
    if (!m) throw new Error('The message you are replying to is no longer here');
    return { id: m.id, dir: m.dir, snip: snipOf(m) };
  }

  /** Your reaction to a message ("" removes it). Sent to the contact as a small control message. */
  react(id, msgId, emoji) {
    const c = this.store.contact(id);
    if (!c) throw new Error('Unknown contact');
    if (c.status !== 'accepted') throw new Error('You can react once they have accepted your request');
    const chat = this.store.chat(id);
    const m = chat.messages.find(x => x.id === String(msgId));
    if (!m) throw new Error('That message is no longer here');
    const e = cleanEmoji(emoji);
    if (emoji && !e) throw new Error('A reaction is one emoji');
    m.reactions = { ...(m.reactions || {}) };
    if (e) m.reactions.me = e; else delete m.reactions.me;
    this.store.saveChat(id);
    const v = this.store.vault;
    v.ctl = (v.ctl || []).filter(x => !(x.to === id && x.k === 'react' && x.mid === m.id));   // only the newest per message
    this.store.saveVault();
    this._queueCtl(id, { k: 'react', mid: m.id, e: e || '' });
    this._syncOut({ e: 'react', cid: id, mid: m.id, emoji: e || '' });   // 1.9.0
    this._soon(id, 200);
    this.emit('msgupdate', { contactId: id, msg: m });
    return m;
  }

  deleteMessage(id, msgId, fromSync) {
    const chat = this.store.chat(id);
    const i = chat.messages.findIndex(m => m.id === msgId);
    if (i >= 0) { const [m] = chat.messages.splice(i, 1); if (m.kind === 'file') this._dropFile(id, m); this.store.saveChat(id); }
    if (!fromSync) this._syncOut({ e: 'del', cid: id, mid: msgId });   // 1.9.0
  }

  clearChat(id, fromSync) {
    if (!fromSync) this._syncOut({ e: 'clear', cid: id });             // 1.9.0
    const chat = this.store.chat(id);
    // keep messages still waiting to be sent
    const keep = m => m.dir === 'out' && (m.state === 'queued' || m.state === 'preparing');
    for (const m of chat.messages) if (!keep(m) && m.kind === 'file') this._dropFile(id, m);
    chat.messages = chat.messages.filter(keep);
    const c = this.store.contact(id); if (c) { c.lastText = ''; c.unread = 0; this.store.putContact(c); }
    this.store.saveChat(id);
  }

  retryNow(id) { const s = this.sched.get(id); if (s) s.tries = 0; this._soon(id, 0); }

  /** Counts for the window title / tray. */
  counts() {
    let unread = 0, queued = 0, requests = 0;
    for (const c of this.store.contacts()) {
      unread += c.unread || 0;
      if (c.status === 'pending-in') requests++;
    }
    for (const c of this.store.contacts()) queued += this.store.chat(c.id).messages.filter(m => m.state === 'queued').length;
    return { unread, queued, requests };
  }

  /* =================================================================
   * 6. DELIVERY ENGINE
   * ================================================================= */
  _queueCtl(id, item) {
    const v = this.store.vault;
    v.ctl = v.ctl || [];
    if (item.k === 'read') {
      const prev = v.ctl.find(x => x.to === id && x.k === 'read');
      if (prev) { prev.ids = [...new Set([...prev.ids, ...item.ids])].slice(-500); this.store.saveVault(); return; }
    }
    if (item.k === 'accept' && v.ctl.some(x => x.to === id && x.k === 'accept')) return;
    if (item.k === 'profile') v.ctl = v.ctl.filter(x => !(x.to === id && x.k === 'profile'));   // only the newest
    v.ctl.push({ ...item, id: newId(), to: id, ts: Date.now() });
    this.store.saveVault();
  }
  _dropCtl(id) { const v = this.store.vault; if (v.ctl) { v.ctl = v.ctl.filter(x => x.to !== id); this.store.saveVault(); } }

  _soon(id, ms) {
    const s = this.sched.get(id) || { tries: 0 };
    s.next = Math.min(s.next || Infinity, Date.now() + ms);
    this.sched.set(id, s);
    if (ms <= 0) setImmediate(() => this._tick());
  }

  _hasWork(c) {
    if (c.status === 'blocked' || c.status === 'pending-in') return false;
    if (c.status === 'pending-out' && !c.requested) return true;
    if ((this.store.vault.ctl || []).some(x => x.to === c.id)) return true;
    if (c.status === 'accepted' && (this.store.vault.held || []).some(x => x.to === c.id)) return true;   // 1.8.5: held for them
    return this.store.chat(c.id).messages.some(m => m.dir === 'out' && (m.state === 'queued' || m.state === 'mailbox') && this._mine(m));   // 1.8.0: mailbox ones still get confirmed directly (1.9.0: only the device that wrote it sends it)
  }

  _tick() {
    if (!this.running || !this.tor.ready) return;
    const now = Date.now();
    this._dlTick(now);
    if (!this._lastPurge || now - this._lastPurge > 60e3) { this._lastPurge = now; this._purgeHolds(); }   // 1.8.5
    this._syncTick(now);                                               // 1.9.0
    for (const [id, s] of this.sched) {
      if (!s.next || s.next > now) continue;
      const c = this.store.contact(id);
      if (!c) { this.sched.delete(id); continue; }
      const o = this.out.get(id);
      if (o && o.busy) continue;
      if (!this._hasWork(c) && !s.hello) { this.sched.delete(id); continue; }
      s.next = 0;
      this._deliver(c, s).catch(e => this.log('deliver: ' + e.message));
    }
  }

  async _connection(c) {
    const have = this.links.get(c.id);
    if (have && !have.closed) return have;
    const slot = this.out.get(c.id);
    let sock;
    try { sock = await socksConnect(this.tor.socksPort, c.onion + '.onion', VPORT, undefined, raw => { if (slot) slot.connecting = raw; }); }
    catch (e) {
      // 1.9.0: their other devices (from their signed device list) — any of them will do
      const others = ((c.devices && c.devices.devices) || []).map(d => d.onion).filter(o => o && o !== c.onion);
      if (!others.length) throw e;
      const tries = others.map(o => socksConnect(this.tor.socksPort, o + '.onion', VPORT).then(s => ({ s, o })));
      let won;
      try { won = await Promise.any(tries); } catch { throw e; }
      for (const t of tries) t.then(x => { if (x !== won) x.s.destroy(); }, () => {});
      sock = won.s;
      this.log(`deliver ${c.fp.slice(0, 8)}: reached their other device`);
      c.onion = won.o;                                                 // talk to the device that answered (it's the same key — checked below)
    }
    if (slot) slot.connecting = null;
    sock.on('error', () => {});
    sock.setIdle(IDLE_OUT);
    const w = await sock.request({ t: 'hello', v: PROTO, onion: this.onion, fp: this.id.fp }, f => f.t === 'welcome', 60e3);
    if (String(w.fp).toUpperCase() !== c.fp) {
      sock.destroy();
      throw Object.assign(new Error('The key at that address does not match the fingerprint in their ID — check the ID with them'), { fatal: true });
    }
    // We dialled their .onion, so Tor guarantees who answered. Prove who WE are,
    // so they can send their messages back over this same connection.
    if (w.nonce && /^[0-9a-f]{48}$/.test(w.nonce)) {
      try {
        const sig = await this.id.signText(authText(w.nonce, c.onion, this.onion, this.id.fp));
        await sock.request({ t: 'auth', sig }, f => f.t === 'authok' || f.t === 'authno', 30e3);
      } catch { /* older/unknown: still fine for sending */ }
    }
    const st = { hello: { onion: c.onion, fp: c.fp }, authed: c.id, outbound: true };
    this._attach(sock, st);
    this.links.set(c.id, sock);
    return sock;
  }

  async _deliver(c, s) {
    const slot = this.out.get(c.id) || { sock: null, busy: false };
    slot.busy = true; this.out.set(c.id, slot);
    let ok = false, why = null, connected = false;
    try {
      const sock = await this._connection(c);
      connected = true;
      c.lastReached = Date.now(); c.lastError = null;
      s.hello = false;
      this._maybeShareProfile(c);

      // a) make sure we have their key, straight from their .onion
      if (!c.publicKey || c.status === 'pending-out' && !c.requested || c.addressChecked === false) {
        const k = await sock.request({ t: 'getkey' }, f => f.t === 'key', 60e3);
        const info = await describePublic(String(k.armored || ''));
        if (info.fp !== c.fp) throw Object.assign(new Error('Their key does not match the fingerprint in their ID — not added'), { fatal: true });
        c.publicKey = info.armored; c.keyName = info.name; c.addressChecked = true;
        if (!c.name) c.name = info.name;
      }

      // b) contact request
      if (c.status === 'pending-out' && !c.requested) {
        const id = newId();
        const prof = this.profile();
        const box = await this.id.sealFor(c.publicKey, { k: 'req', id, to: c.fp, from: { ...this.me, name: prof.name }, avatar: prof.avatar, note: c.note || '', ts: Date.now() });
        const r = await sock.request({ t: 'req', id, key: this.id.pubArmored, box }, f => (f.t === 'ok' || f.t === 'no') && f.id === id, 90e3);
        if (r.t === 'no') throw Object.assign(new Error('Request not accepted: ' + r.why), { why: r.why });
        c.requested = true; c.requestedAt = Date.now();
      }

      // c) control items (accept, read receipts) then queued messages, oldest first
      await this._maybeShareDevices(c);                                 // 1.8.0
      this._maybeShareMailbox(c);
      const v = this.store.vault;
      for (const item of (v.ctl || []).filter(x => x.to === c.id)) {
        if (item.k === 'accept' && c.status !== 'accepted') continue;
        if (item.k === 'hold') { await this._sendHold(sock, c, item); continue; }   // 1.8.5: contact mailbox
        const { to: _to, ver: _ver, ...payload } = item;
        let tooOld = false;
        try { await this._sendBox(sock, c, payload); }
        catch (e) {
          // 1.8.0: an older Seal Chat that doesn't know this kind of control message: drop it quietly
          if (!(OPTIONAL_CTL.has(item.k) && (e.why === 'unsupported' || e.why === 'bad'))) throw e;
          tooOld = true;
          c.olderVersion = true;     // 1.8.1: send it again once they update (see _apply)
        }
        if (item.k === 'profile') c.profileSent = item.ver;
        if (item.k === 'devices' && !tooOld) c.devicesSent = item.ver;   // 1.8.0 (1.8.1: not "sent" if they couldn't take it)
        if (item.k === 'mbox' && !tooOld) c.mboxSent = item.ver;
        v.ctl = v.ctl.filter(x => x !== item);
        this.store.saveVault();
      }
      if (c.status === 'accepted' || c.status === 'pending-out') {
        const chat = this.store.chat(c.id);
        for (const m of chat.messages.filter(x => x.dir === 'out' && (x.state === 'queued' || x.state === 'mailbox') && this._mine(x)).slice(0, 100)) {   // 1.8.0: also confirm mailbox ones (1.9.0: written on this device)
          if (m.kind === 'file') {
            if (!this.files || !this.files.isComplete(fileKey(c.id, m.id), m.file)) { m.state = 'failed'; m.transfer = { state: 'failed', err: 'The file is no longer on this PC' }; this.store.saveChat(c.id); continue; }
            const { name, size, mime, pieces, key, nonce, thumb } = m.file;
            try { await this._sendBox(sock, c, { k: 'file', id: m.id, text: m.text || '', ts: m.ts, re: wireRe(m.re), file: { name, size, mime, pieces, key, nonce, thumb } }); }
            catch (e) {
              if (e.why !== 'unsupported' && e.why !== 'bad') throw e;
              m.state = 'failed'; m.transfer = { state: 'failed', err: `${c.nick || c.name || 'Your contact'} needs Seal Chat 1.1 or newer to receive files` };
              this.store.saveChat(c.id); this.emit('receipts', { contactId: c.id }); continue;
            }
            m.transfer = { ...(m.transfer || {}), state: 'waiting' };
          } else {
            await this._sendBox(sock, c, { k: 'text', id: m.id, text: m.text, ts: m.ts, re: wireRe(m.re) });
          }
          m.state = 'sent'; m.deliveredAt = Date.now();
          this.store.saveChat(c.id);
          this._syncMsg(c.id, m);                                      // 1.9.0: ✓ on your other devices too
          this.emit('receipts', { contactId: c.id });
        }
      }
      if (c.status === 'accepted') await this._passHeld(sock, c);      // 1.8.5: messages others left with us for them
      ok = true;
    } catch (e) {
      why = e.why || e.message;
      c.lastError = e.message;
      if (e.fatal) { c.status = 'failed'; c.failReason = e.message; }
      if (e.code === 'UNREACHABLE') c.lastError = 'Offline — will keep trying';
      this.log(`deliver ${c.fp.slice(0, 8)}: ${e.message}`);
      // 1.8.0: couldn't reach them at all → leave what's waiting in their mailbox (if they have one)
      let mbOk = false;
      if (!connected && c.mailbox && c.status === 'accepted') {
        try { const n = await this._toMailbox(c); mbOk = true; if (n) c.lastError = `Offline — ${n} left in their mailbox`; }
        catch (me) { c.mailboxError = me.message; c.lastError = 'Offline — couldn\'t leave it in their mailbox: ' + me.message; this.log('mailbox ' + c.fp.slice(0, 8) + ': ' + me.message); }   // 1.8.1: say why
      }
      // 1.8.5: no mailbox (or it didn't work) → ask contacts we both have to pass it on
      if (!connected && !mbOk && c.status === 'accepted') {
        try { const n = await this._toHelpers(c); if (n && !c.mailbox) c.lastError = `Offline — asked ${n} contact${n === 1 ? '' : 's'} you both have to pass it on`; }
        catch (he) { this.log('contact mailbox ' + c.fp.slice(0, 8) + ': ' + he.message); }
      }
    } finally {
      slot.busy = false; slot.connecting = null;
      this.store.putContact(c);
      this.emit('contacts');
    }
    // schedule the next attempt
    if (ok && !this._hasWork(c)) { this.sched.delete(c.id); return; }
    if (ok) { s.tries = 0; s.next = Date.now() + 200; return; }
    if (slot.kick) { slot.kick = false; s.tries = 0; s.next = Date.now() + 500; return; }   // they just said hello: try again at once
    if (c.status === 'failed') { this.sched.delete(c.id); return; }
    const wait = why === 'pending' ? 120e3 : RETRY[Math.min(s.tries, RETRY.length - 1)];
    s.tries++;
    s.next = Date.now() + wait * (0.85 + Math.random() * 0.3);
  }

  async _sendBox(sock, c, payload) {
    const id = payload.id || newId();
    const box = await this.id.sealFor(c.publicKey, { ...payload, id, to: c.fp, from: this.me, ts: payload.ts || Date.now() });
    const r = await sock.request({ t: 'msg', id, box }, f => (f.t === 'ack' || f.t === 'nack') && f.id === id, 90e3);
    if (r.t === 'nack') {
      const msgs = { pending: 'Waiting for them to accept your request', unknown: 'They don\'t have you as a contact', blocked: 'Not delivered', locked: 'Their Seal Chat is locked', bad: 'They could not read the message', unsupported: 'Their Seal Chat needs updating to receive this' };
      throw Object.assign(new Error(msgs[r.why] || 'Not delivered (' + r.why + ')'), { why: r.why });
    }
  }

  /* =================================================================
   * 6c. MAILBOX (1.8.0)
   * ================================================================= */
  /** Your own mailbox (from Settings → Web access), given to your contacts — or null. */
  setMailbox(mb) {
    const v = this.store.vault;
    const own = mb ? { url: String(mb.url), box: String(mb.box), drop: String(mb.drop) } : null;
    if (JSON.stringify(v.ownMailbox === undefined ? (v.mailbox || null) : v.ownMailbox) !== JSON.stringify(own) || v.ownMailbox === undefined) {
      v.ownMailbox = own; this.store.saveVault();
      this._syncOut({ e: 'mbox', mb: own });                            // 1.9.0: your other devices can give it out too
    }
    this._applyMailbox();
  }
  /** 1.9.0: the address contacts get: this device's mailbox, or your other device's. */
  _applyMailbox() {
    const v = this.store.vault;
    const next = v.ownMailbox || v.sibMailbox || null;
    if (JSON.stringify(v.mailbox || null) === JSON.stringify(next)) return;
    v.mailbox = next; this.store.saveVault();
    for (const c of this.store.contacts()) if (c.status === 'accepted') { this._maybeShareMailbox(c); this._soon(c.id, 1000 + Math.random() * 4000); }
  }
  _maybeShareMailbox(c) {
    if (!c || c.status !== 'accepted') return;
    const mb = this.store.vault.mailbox || null;
    const ver = crypto.createHash('sha256').update(JSON.stringify(mb)).digest('hex').slice(0, 16);
    const v = this.store.vault;
    const queued = (v.ctl || []).find(x => x.to === c.id && x.k === 'mbox');
    if (queued ? queued.ver === ver : (c.mboxSent === ver || (!mb && !c.mboxSent))) return;   // nothing new (1.8.1: also when a different one is still waiting)
    v.ctl = (v.ctl || []).filter(x => !(x.to === c.id && x.k === 'mbox'));
    this._queueCtl(c.id, { k: 'mbox', mb, ver });
  }

  /** 1.8.1: how many contacts already have your current mailbox address (for Settings → Web access). */
  mailboxShared() {
    const mb = this.store.vault.mailbox || null;
    if (!mb) return null;
    const ver = crypto.createHash('sha256').update(JSON.stringify(mb)).digest('hex').slice(0, 16);
    const acc = this.store.contacts().filter(c => c.status === 'accepted');
    return { have: acc.filter(c => c.mboxSent === ver).length, of: acc.length, older: acc.filter(c => c.olderVersion).length };
  }

  /** Leaves what's waiting for contact c in their mailbox. Returns how many were left. */
  async _toMailbox(c) {
    if (!c.mailbox || !c.publicKey || !this.id.unlocked) return 0;
    const now = Date.now(), chat = this.store.chat(c.id), v = this.store.vault;
    const after = this.o.mbAfter ?? MB_AFTER;      // (tests: shorter)
    const waiting = chat.messages.filter(m => m.dir === 'out' && m.state === 'queued' && now - m.at >= after && this._mine(m)).slice(0, 50);
    const ctl = (v.ctl || []).filter(x => x.to === c.id && MB_CTL.has(x.k) && now - x.ts >= after);
    let n = 0;
    for (const m of waiting) {
      let payload;
      if (m.kind === 'file') {
        if (!this.files || !this.files.isComplete(fileKey(c.id, m.id), m.file)) continue;
        const { name, size, mime, pieces, key, nonce, thumb } = m.file;
        payload = { k: 'file', id: m.id, text: m.text || '', ts: m.ts, re: wireRe(m.re), file: { name, size, mime, pieces, key, nonce, thumb } };
      } else payload = { k: 'text', id: m.id, text: m.text, ts: m.ts, re: wireRe(m.re) };
      await this._drop(c, payload);
      m.state = 'mailbox'; m.mailboxAt = Date.now(); n++;
      this.store.saveChat(c.id);
      this._syncMsg(c.id, m);                                          // 1.9.0
      this.emit('receipts', { contactId: c.id });
    }
    for (const item of ctl) {
      const { to: _to, ver: _ver, ...payload } = item;
      await this._drop(c, payload);
      v.ctl = v.ctl.filter(x => x !== item); this.store.saveVault(); n++;
    }
    if (n) { c.mailboxError = null; c.lastMailbox = Date.now(); }
    return n;
  }

  /** One sealed message into contact c's mailbox (through Tor; directly only if allowed and Tor is blocked). */
  async _drop(c, payload) {
    const id = payload.id || newId();
    const box = await this.id.sealFor(c.publicKey, { ...payload, id, to: c.fp, from: this.me, ts: payload.ts || Date.now(), via: 'mbox' });
    const url = c.mailbox.url + 'relay.php?a=mbox_drop';
    const body = JSON.stringify({ d: box });
    const headers = { 'Content-Type': 'application/json', 'X-SC-Box': c.mailbox.box, 'X-SC-Drop': c.mailbox.drop };
    // Tor first; if their website blocks Tor, directly — only if you allowed that (Settings → Privacy)
    const { viaFallbacks, looksBlocked, pageHint } = require('./webhttp');
    let host = ''; try { host = new URL(url).hostname; } catch { /* keep empty */ }
    let r;
    try {
      r = await viaFallbacks(url, { method: 'POST', body, headers, socksPort: this.tor.socksPort, direct: this.store.settings.directIfTorBlocked === true,
        http: this.o.http, allowHttp: !!this.o.allowHttpMailbox, timeoutMs: 90e3, maxBytes: 65536 });
    } catch (e) {
      if (e.code !== 'TOR_BLOCKED') throw e;
      throw new Error(`their website${host ? ' (' + host + ')' : ''} blocks visitors that come through Tor. Settings → Privacy can allow contacting it directly.`);
    }
    if (r.via === 'direct') c.mailboxVia = r.via;
    let j = null; try { j = JSON.parse(r.body.toString('utf8')); } catch { /* not JSON */ }
    // 1.8.4: a web page instead of Seal Chat's answer — say what it was (a security check for Tor visitors, a wrong address…)
    if (!j) throw new Error(`their website${host ? ' (' + host + ')' : ''} answered ${r.status} with a web page instead of Seal Chat Web's answer: ${pageHint(r)}` + (looksBlocked(r) || r.via === 'blocked' ? ' — it seems to block visitors that come through Tor' : ' — this is often a security check for Tor visitors, or Seal Chat Web is not at that address'));
    if (!j.ok) {
      if (j.code === 'nombox') { c.mailbox = null; this.store.putContact(c); }      // they turned it off
      throw new Error('Their mailbox: ' + (j.error || j.code));
    }
    return j.id;
  }

  /**
   * A sealed message picked up from YOUR mailbox (main.js fetches them).
   * Checked exactly like a direct one: it must decrypt with your key and be
   * signed by the contact it claims to be from. Returns { ok, why }.
   */
  async fromMailbox(b64) {
    if (!this.id.unlocked) return { ok: false, why: 'locked' };
    let first;
    try { first = await this.id.open(b64); } catch { return { ok: false, why: 'unreadable' }; }   // who is it from? (inside the encryption)
    const fp = first.obj && first.obj.from && String(first.obj.from.fp || '').toUpperCase();
    const c = fp && this.store.contact(fp);
    if (!c || !c.publicKey) return { ok: false, why: 'not from a contact' };
    if (c.status === 'blocked' || c.status === 'pending-in') return { ok: false, why: c.status };
    const r = await this.id.open(b64, c.publicKey);
    const o = r.obj || {};
    if (!r.valid || o.to !== this.id.fp || !o.from || o.from.fp !== c.fp) return { ok: false, why: 'bad signature' };
    if (!['text', 'file', 'react', 'read'].includes(o.k)) return { ok: false, why: 'not allowed by mailbox' };
    const why = await this._apply(c, o, 'mailbox');
    if (why) return { ok: false, why };
    this._syncIn(c, o);                                                // 1.9.0
    this._afterApply(c);
    return { ok: true, from: c.id, k: o.k };
  }

  /* =================================================================
   * 6d. CONTACT MAILBOX (1.8.5)
   * Bob → Cat → Ann, when Ann is offline. See the header for the idea.
   * ================================================================= */
  _holdOn() { return this.store.settings.contactMailbox !== false; }

  /** Bob's side: asks up to 3 recently-online contacts to hold what's waiting for c. Returns how many were asked. */
  async _toHelpers(c) {
    if (!this._holdOn() || !c.publicKey || !this.id.unlocked) return 0;
    const now = Date.now(), chat = this.store.chat(c.id), v = this.store.vault;
    const after = this.o.mbAfter ?? MB_AFTER;
    const waiting = chat.messages.filter(m => m.dir === 'out' && m.state === 'queued' && now - m.at >= after && this._mine(m) && (!m.holdAt || now - m.holdAt >= HOLD_RETRY)).slice(0, 30);
    if (!waiting.length) return 0;
    const no = c.holdNo || {};
    const helpers = this.store.contacts()
      .filter(h => h.id !== c.id && h.status === 'accepted' && h.publicKey && !h.noHold && !(no[h.id] && now - no[h.id] < HOLD_NO)
        && ((c.holdOk && c.holdOk[h.id]) || (h.lastSeen && now - h.lastSeen < HOLD_SEEN) || (this.links.get(h.id) && !this.links.get(h.id).closed)))
      .sort((a, b) => ((c.holdOk && c.holdOk[b.id]) ? 1 : 0) - ((c.holdOk && c.holdOk[a.id]) ? 1 : 0) || (b.lastSeen || 0) - (a.lastSeen || 0))
      .slice(0, HOLD_HELPERS);
    if (!helpers.length) return 0;
    const tag = holdTag(c.fp);
    for (const m of waiting) {
      let payload;
      if (m.kind === 'file') {
        if (!this.files || !this.files.isComplete(fileKey(c.id, m.id), m.file)) continue;
        const { name, size, mime, pieces, key, nonce, thumb } = m.file;
        payload = { k: 'file', id: m.id, text: m.text || '', ts: m.ts, re: wireRe(m.re), file: { name, size, mime, pieces, key, nonce, thumb } };
      } else payload = { k: 'text', id: m.id, text: m.text, ts: m.ts, re: wireRe(m.re) };
      const d = await this.id.sealFor(c.publicKey, { ...payload, to: c.fp, from: this.me, ts: payload.ts || Date.now(), via: 'mbox' });
      if (d.length > HELD_MAX_ITEM) continue;
      for (const h of helpers) {
        v.ctl = (v.ctl || []).filter(x => !(x.to === h.id && x.k === 'hold' && x.mid === m.id));   // only the newest per helper
        this._queueCtl(h.id, { k: 'hold', for: tag, d, mid: m.id, ann: c.id });
      }
      m.holdAt = now;
    }
    this.store.saveChat(c.id); this.store.saveVault();
    for (const h of helpers) this._soon(h.id, 300 + Math.random() * 1500);
    return helpers.length;
  }

  /** Bob's side, connected to helper h: hands over one "please hold". Never stops the rest of the delivery. */
  async _sendHold(sock, h, item) {
    const v = this.store.vault;
    const done = () => { v.ctl = (v.ctl || []).filter(x => x !== item); this.store.saveVault(); };
    const target = this.store.contact(item.ann);
    const m = target && this.store.chat(target.id).messages.find(x => x.id === item.mid && x.dir === 'out');
    if (!target || !m || !(m.state === 'queued' || m.state === 'mailbox') || Date.now() - item.ts > HOLD_SEND_TTL || !this._holdOn()) return done();   // already delivered / gone / too old
    try {
      await this._sendBox(sock, h, { k: 'hold', id: item.id, for: item.for, d: item.d });
    } catch (e) {
      if (!e.why) throw e;                                             // connection trouble: try again later
      if (e.why === 'unsupported' || e.why === 'bad') h.noHold = true; // their Seal Chat is older than 1.8.5
      else { target.holdNo = { ...(target.holdNo || {}), [h.id]: Date.now() }; this.store.putContact(target); }   // they don't know them (or are full / turned it off)
      return done();
    }
    done();
    target.holdOk = { ...(target.holdOk || {}), [h.id]: Date.now() };
    if (m.state === 'queued') { m.state = 'mailbox'; m.mailboxAt = Date.now(); }
    m.heldBy = [...new Set([...(m.heldBy || []), h.nick || h.name || 'a contact'])].slice(0, HOLD_HELPERS);
    if (!target.mailbox) target.lastError = `Offline — left with ${m.heldBy.join(', ')} to pass on`;
    this.store.putContact(target);
    this.store.saveChat(target.id);
    this._syncMsg(target.id, m);                                       // 1.9.0
    this.emit('receipts', { contactId: target.id });
    this.emit('contacts');
  }

  /** Cat's side: contact c (Bob) asks us to hold a sealed message for one of our contacts. Returns a nack reason or null. */
  _hold(c, o, via) {
    if (via !== 'direct' || c.status !== 'accepted') return 'bad';
    if (!this._holdOn()) return 'nohold';
    const target = this.store.contacts().find(x => x.status === 'accepted' && x.id !== c.id && holdTag(x.fp) === String(o.for || ''));
    if (!target) return 'nohold';                                     // not one of our contacts (we can't tell who it was)
    const d = String(o.d || '');
    if (!d || d.length > HELD_MAX_ITEM || !/^[A-Za-z0-9+/=\s-]+$/.test(d.slice(0, 200))) return 'nohold';
    const v = this.store.vault;
    this._purgeHolds();
    v.held = v.held || [];
    const sum = crypto.createHash('sha256').update(d).digest('hex').slice(0, 24);
    if (v.held.some(x => x.sum === sum)) return null;                 // already have it
    if (v.held.filter(x => x.to === target.id).length >= HELD_MAX_PER_TARGET || v.held.filter(x => x.from === c.id).length >= HELD_MAX_PER_SENDER
      || v.held.reduce((n, x) => n + x.d.length, 0) + d.length > HELD_MAX_BYTES) return 'full';
    v.held.push({ to: target.id, from: c.id, d, sum, ts: Date.now() });
    this.store.saveVault();
    this.log('holding a message for ' + target.fp.slice(0, 8) + ' from ' + c.fp.slice(0, 8));
    this._soon(target.id, 1000 + Math.random() * 3000);
    return null;
  }

  /** Cat's side, connected to Ann: passes on what others left with us for her. */
  async _passHeld(sock, c) {
    const v = this.store.vault;
    for (const it of (v.held || []).filter(x => x.to === c.id)) {
      try { await this._sendBox(sock, c, { k: 'held', d: it.d }); }
      catch (e) { if (!(e.why === 'unsupported' || e.why === 'bad')) throw e; }   // her Seal Chat is too old: the sender confirms it directly later anyway
      v.held = (v.held || []).filter(x => x !== it);
      this.store.saveVault();
    }
  }

  /** Drops expired "please hold" requests and held messages (and ones for people who are no longer contacts). */
  _purgeHolds() {
    const v = this.store.vault, now = Date.now();
    let changed = false;
    if (v.ctl && v.ctl.some(x => x.k === 'hold')) {
      const keep = v.ctl.filter(x => {
        if (x.k !== 'hold') return true;
        if (now - x.ts > HOLD_SEND_TTL) return false;
        const t = this.store.contact(x.ann);
        const m = t && this.store.chat(t.id).messages.find(y => y.id === x.mid && y.dir === 'out');
        return !!m && (m.state === 'queued' || m.state === 'mailbox');
      });
      if (keep.length !== v.ctl.length) { v.ctl = keep; changed = true; }
    }
    if (v.held && v.held.length) {
      const keep = v.held.filter(x => now - x.ts < HELD_KEEP && this.store.contact(x.to) && this.store.contact(x.to).status === 'accepted');
      if (keep.length !== v.held.length) { v.held = keep; changed = true; }
    }
    if (changed) this.store.saveVault();
  }
  /** How many messages we're holding for others right now (Settings → Mailbox). */
  holdingCount() { return (this.store.vault.held || []).length; }

  /* =================================================================
   * 6e. YOUR OTHER DEVICES (1.9.0)
   * Every device of your ID keeps a queue of "events" for each of your other
   * devices (vault.syncq) and delivers it over Tor, signed and encrypted with
   * your own key (only your devices can read it). Events:
   *   in       a verified message a contact sent you (replayed with _apply)
   *   out      a message you wrote, or its new state (✓, 📬)
   *   read / react / del / clear     your reading, reactions and deleting
   *   contact / contactdel           a contact's record (local fields kept)
   *   chat     a chat's history (when a device is first linked)
   *   devices  the signed list of your devices
   *   settings your name, picture and a few settings
   *   mbox     the mailbox address to give contacts
   *   full     "send everything" (a new device, or a queue that overflowed)
   *   hi       nothing — "I'm online" (so the other device sends what waits)
   * ================================================================= */
  _mine(m) { return !m.dev || !this.device || m.dev === this.device.id; }

  /** A message as it travels to your other devices (no download progress; who wrote it). */
  _msgForSync(m) {
    const { transfer: _t, holdAt: _h, ...rest } = m;
    if (rest.dir === 'out' && !rest.dev && this.device) rest.dev = this.device.id;
    return rest;
  }
  _syncMsg(cid, m) { this._syncOut({ e: 'out', cid, m: this._msgForSync(m) }); }

  /** Queues one event for your other devices (or one of them). */
  _syncOut(ev, only) {
    const sibs = this.siblings().filter(d => !only || d.id === only);
    if (!sibs.length) return;
    let size = 0; try { size = JSON.stringify(ev).length; } catch { return; }
    if (size > SYNC_BATCH) {                                           // too big for one frame: leave out pictures
      if (ev.e === 'contact') ev = { ...ev, c: { ...ev.c, customAvatar: undefined, sharedAvatar: undefined } };
      else if (ev.e === 'settings') ev = { ...ev, s: { ...ev.s, me: { ...(ev.s.me || {}), avatar: undefined } } };
      else if (ev.e === 'out' || ev.e === 'in') { this.log('sync: an event too large to pass on was skipped'); return; }
    }
    const v = this.store.vault;
    v.syncq = v.syncq || {};
    for (const d of sibs) {
      let q = v.syncq[d.id] || [];
      if (q.length >= SYNC_MAX_QUEUE) q = [{ sid: newId(), ev: { e: 'full' }, ts: Date.now() }];   // too far behind: a full copy instead
      q.push({ sid: newId(), ev, ts: Date.now() });
      v.syncq[d.id] = q;
      this._syncSoon(d.id, 300);
    }
    this.store.saveVault();
  }
  /** A verified message from a contact → your other devices. */
  _syncIn(c, o) { if (!SYNC_SKIP.has(o.k)) this._syncOut({ e: 'in', cid: c.id, o }); }

  /** Your name, picture and a few settings → your other devices. */
  _syncSettings() {
    const s = this.store.settings, me = this.store.vault.me || {};
    return { displayName: s.displayName, readReceipts: s.readReceipts, allowRequests: s.allowRequests, contactMailbox: s.contactMailbox,
      me: { avatar: me.avatar || null, shareAvatar: me.shareAvatar !== false, avatarAt: me.avatarAt || 0 } };
  }
  syncSettings() { this._syncOut({ e: 'settings', s: this._syncSettings() }); }
  /** 1.9.3: web access (Seal Chat Web) → your other devices; they all answer the same phones. */
  syncWeb(w) { if (w) this._syncOut({ e: 'web', w }); }

  /** At start: this device's address into your device list; tell your other devices you're online. */
  _startDevices() {
    const v = this.store.vault, me = this.device;
    const known = (v.myDevices || []).find(d => d.id === me.id);
    if (!v.unlinked && (v.myDevices || []).length && (!known || known.onion !== this.onion)) this._devicesChanged().catch(e => this.log('devices: ' + e.message));
    for (const d of this.siblings()) this._syncOut({ e: 'hi' }, d.id);
  }

  /** Your device list changed: save it, and give it to contacts and your other devices. */
  async _devicesChanged() {
    const v = this.store.vault;
    const list = this.myDevices().map(d => ({ id: d.id, pub: d.pub, name: devices.cleanName(d.name), added: d.added || d.created || Date.now(), onion: d.onion }));
    const { doc, sig } = await devices.signedList(this.id, list);
    v.myDevices = list; v.myDevicesTs = doc.ts;
    this.store.saveVault();
    for (const c of this.store.contacts()) if (c.status === 'accepted') { this._maybeShareDevices(c).catch(() => {}); this._soon(c.id, 1000 + Math.random() * 4000); }
    this._syncOut({ e: 'devices', doc, sig });
    this.emit('devices');
  }

  /** Linking (linking.js): what the new device gets — your key (still locked with your passphrase) and the basics. */
  async linkBundle(them) {
    const v = this.store.vault;
    if (!v.identity || !v.identity.armored) throw new Error('No key to share');
    return {
      v: 1, armored: v.identity.armored,
      devices: [...this.myDevices().map(d => ({ id: d.id, pub: d.pub, name: d.name, added: d.added || d.created, onion: d.onion })), them],
      settings: this._syncSettings(),
      mailbox: { drop: v.mailboxDrop || null, workerBox: v.workerBox || null, given: v.mailbox || null }
    };
  }
  /** Linking finished: the new device is one of yours. It gets everything over the sync. */
  async addDevice(d) {
    const v = this.store.vault;
    if (v.unlinked) { delete v.unlinked; v.myDevices = []; }
    v.myDevices = [...this.myDevices().filter(x => x.id !== d.id), d];
    await this._devicesChanged();
    v.syncq = v.syncq || {};
    v.syncq[d.id] = [{ sid: newId(), ev: { e: 'full' }, ts: Date.now() }];
    this.store.saveVault();
    this._syncSoon(d.id, 2000);
  }
  /** Takes a device off your ID. Messages it was still sending are sent by this one. */
  async removeDevice(id) {
    const v = this.store.vault;
    if (id === this.device.id) throw new Error('This is the device you are using');
    if (!this.myDevices().some(d => d.id === id)) throw new Error('That device is not on your ID');
    v.myDevices = this.myDevices().filter(d => d.id !== id);
    if (v.syncq) delete v.syncq[id];
    const l = this.selfLinks.get(id); if (l) l.destroy();
    for (const c of this.store.contacts()) {
      const chat = this.store.chat(c.id); let ch = false;
      for (const m of chat.messages) if (m.dir === 'out' && m.dev === id && (m.state === 'queued' || m.state === 'mailbox')) { m.dev = this.device.id; ch = true; }
      if (ch) { this.store.saveChat(c.id); this._soon(c.id, 1000); }
    }
    await this._devicesChanged();
  }
  /** For Settings → Your devices. */
  devicesStatus() {
    const v = this.store.vault, seen = v.devSeen || {};
    return {
      unlinked: !!v.unlinked,
      devices: this.myDevices().map((d, i) => ({ id: d.id, name: d.name, onion: d.onion || null, added: d.added || d.created || 0, self: i === 0,
        lastSync: seen[d.id] || 0, waiting: i === 0 ? 0 : ((v.syncq || {})[d.id] || []).filter(x => x.ev.e !== 'hi').length })),
      link: this.linker.status()
    };
  }

  /* ---------- contacts: what changed since we last told your other devices ---------- */
  _digestSoon() { if (this._dgT || !this.running) return; this._dgT = setTimeout(() => { this._dgT = null; try { this._digest(); } catch (e) { this.log('sync digest: ' + e.message); } }, 800); if (this._dgT.unref) this._dgT.unref(); }
  _digest() {
    if (!this.siblings().length) return;
    const v = this.store.vault, dg = v.syncDigest || (v.syncDigest = {});
    const seen = new Set(); let changed = false;
    for (const c of this.store.contacts()) {
      seen.add(c.id);
      const sc = syncedContact(c), h = hashOf(sc);
      if (dg[c.id] !== h) { dg[c.id] = h; this._syncOut({ e: 'contact', c: sc }); changed = true; }
    }
    for (const id of Object.keys(dg)) if (!seen.has(id)) { delete dg[id]; this._syncOut({ e: 'contactdel', id }); changed = true; }
    if (changed) this.store.saveVault();
  }

  /* ---------- sending to your other devices ---------- */
  _syncSoon(devId, ms) {
    const s = this.syncSched.get(devId) || { tries: 0, next: 0 };
    s.next = Math.min(s.next || Infinity, Date.now() + ms);
    this.syncSched.set(devId, s);
    const t = setTimeout(() => this._syncTick(Date.now()), ms + 20); if (t.unref) t.unref();
  }
  _syncTick(now) {
    if (!this.running || !this.tor.ready || !this.id.unlocked) return;
    const q = this.store.vault.syncq || {};
    for (const d of this.siblings()) {
      if (!(q[d.id] || []).length) continue;
      const s = this.syncSched.get(d.id) || { tries: 0, next: 0 };
      this.syncSched.set(d.id, s);
      if (s.busy || (s.next && s.next > now)) continue;
      s.busy = true;
      this._syncDeliver(d, s).finally(() => { s.busy = false; });
    }
  }
  async _syncDeliver(d, s) {
    const v = this.store.vault;
    try {
      const sock = await this._selfConnection(d);
      for (let round = 0; round < 1000; round++) {
        const q = (v.syncq || {})[d.id] || [];
        if (!q.length) break;
        let batch = [], size = 0;
        if (q[0].ev.e === 'full') batch = [q[0]];
        else for (const it of q) {
          if (it.ev.e === 'full') break;
          const n = JSON.stringify(it.ev).length;
          if (batch.length && size + n > SYNC_BATCH) break;
          batch.push(it); size += n;
        }
        if (batch[0].ev.e === 'full') await this._sendFull(sock, d);
        else await this._sendSync(sock, d, batch.map(x => x.ev));
        const done = new Set(batch.map(x => x.sid));
        v.syncq[d.id] = ((v.syncq || {})[d.id] || []).filter(x => !done.has(x.sid));
        this.store.saveVault();
      }
      s.tries = 0; s.next = 0;
      v.devSeen = { ...(v.devSeen || {}), [d.id]: Date.now() }; this.store.saveVault();
      this.emit('devices');
    } catch (e) {
      s.next = Date.now() + RETRY[Math.min(s.tries, RETRY.length - 1)] * (0.85 + Math.random() * 0.3);
      s.tries++;
      this.log(`sync to ${d.name}: ${e.message}`);
    }
  }
  async _selfConnection(d) {
    const have = this.selfLinks.get(d.id);
    if (have && !have.closed) return have;
    const sock = await socksConnect(this.tor.socksPort, d.onion + '.onion', VPORT);
    sock.on('error', () => {});
    sock.setIdle(IDLE_OUT);
    try {
      const w = await sock.request({ t: 'hello', v: PROTO, onion: this.onion, fp: this.id.fp }, f => f.t === 'welcome', 60e3);
      if (String(w.fp).toUpperCase() !== this.id.fp) throw new Error('That address is not one of your devices any more');
      const sig = await this.id.signText(authText(w.nonce, d.onion, this.onion, this.id.fp));
      const a = await sock.request({ t: 'auth', sig }, f => f.t === 'authok' || f.t === 'authno', 30e3);
      if (a.t !== 'authok') throw new Error('Your other device did not accept this one (was it removed there?)');
    } catch (e) { sock.destroy(); throw e; }
    this.selfLinks.set(d.id, sock);
    sock.on('close', () => { if (this.selfLinks.get(d.id) === sock) this.selfLinks.delete(d.id); });
    return sock;
  }
  async _sendSync(sock, d, evs) {
    const id = newId();
    const box = await this.id.sealFor(this.id.pubArmored, { k: 'sync', id, to: d.id, fromDev: this.device.id, evs, ts: Date.now() });
    const r = await sock.request({ t: 'sync', id, box }, f => (f.t === 'ack' || f.t === 'nack') && f.id === id, 120e3);
    if (r.t === 'nack') throw new Error('refused: ' + r.why);
  }
  /** Everything, for a newly linked device: devices, settings, mailbox, then each contact with its chat. */
  async _sendFull(sock, d) {
    const v = this.store.vault;
    let batch = [], size = 0;
    const add = async ev => {
      const n = JSON.stringify(ev).length;
      if (batch.length && size + n > SYNC_BATCH) { await this._sendSync(sock, d, batch); batch = []; size = 0; }
      batch.push(ev); size += n;
    };
    const { doc, sig } = await devices.signedList(this.id, this.myDevices());
    await add({ e: 'devices', doc, sig });
    await add({ e: 'settings', s: this._syncSettings() });
    await add({ e: 'mbox', mb: v.ownMailbox !== undefined ? v.ownMailbox : (v.mailbox || null) });
    if (this.o.webShare) { const w = this.o.webShare(); if (w) await add({ e: 'web', w }); }   // 1.9.3: web access (Seal Chat Web), shared
    const dg = v.syncDigest || (v.syncDigest = {});
    for (const c of this.store.contacts()) {
      const sc = syncedContact(c);
      let ev = { e: 'contact', c: sc };
      if (JSON.stringify(ev).length > SYNC_BATCH) ev = { e: 'contact', c: { ...sc, customAvatar: undefined, sharedAvatar: undefined } };
      await add(ev);
      dg[c.id] = hashOf(sc);
      let chunk = [], csize = 0;
      for (const m of this.store.chat(c.id).messages) {
        const sm = this._msgForSync(m), n = JSON.stringify(sm).length;
        if (n > SYNC_BATCH - 1024) continue;
        if (chunk.length && csize + n > SYNC_BATCH - 1024) { await add({ e: 'chat', cid: c.id, msgs: chunk }); chunk = []; csize = 0; }
        chunk.push(sm); csize += n;
      }
      if (chunk.length) await add({ e: 'chat', cid: c.id, msgs: chunk });
    }
    if (batch.length) await this._sendSync(sock, d, batch);
    this.store.saveVault();
  }

  /* ---------- receiving from your other devices ---------- */
  async _onSelfAuth(fsk, st, f) {
    const sib = this.siblings().find(d => d.onion === st.hello.onion);
    let good = false;
    if (sib && this.id.unlocked) good = await this.id.verifyText(authText(st.nonce, this.onion, st.hello.onion, st.hello.fp), f.sig, this.id.pubArmored);
    fsk.send({ t: good ? 'authok' : 'authno' });
    if (!good) return;
    st.self = sib.id;
    const v = this.store.vault; v.devSeen = { ...(v.devSeen || {}), [sib.id]: Date.now() }; this.store.saveVault();
    const s = this.syncSched.get(sib.id); if (s) { s.tries = 0; s.next = 0; }
    this._syncSoon(sib.id, 300);                                       // it's online: send it what waits
    this.emit('devices');
  }
  async _onSync(fsk, st, f) {
    const nack = why => fsk.send({ t: 'nack', id: f.id, why });
    if (!st.self || !this.siblings().some(d => d.id === st.self)) return nack('unknown');   // (a device removed from your ID: nothing more from it)
    if (!this.id.unlocked) return nack('locked');
    const r = await this.id.open(f.box, this.id.pubArmored);
    const o = r.obj || {};
    if (!r.valid || o.k !== 'sync' || o.to !== this.device.id || o.fromDev !== st.self || !Array.isArray(o.evs)) return nack('bad');
    const touched = new Set();
    for (const ev of o.evs.slice(0, 5000)) {
      try { const cid = await this._syncApply(ev); if (cid) touched.add(cid); }
      catch (e) { this.log('sync event ' + (ev && ev.e) + ': ' + e.message); }
    }
    fsk.send({ t: 'ack', id: f.id });
    for (const cid of touched) this.emit('receipts', { contactId: cid });
    this.emit('contacts');
  }
  /** One event from your other device. Returns the contact id whose chat changed (to redraw it). */
  async _syncApply(ev) {
    if (!ev || typeof ev !== 'object') return null;
    const v = this.store.vault;
    const cid = String(ev.cid || '');
    const c = cid ? this.store.contact(cid) : null;
    switch (ev.e) {
      case 'hi': case 'full': return null;
      case 'in': {
        const o = ev.o;
        if (!c || !c.publicKey || !o || typeof o !== 'object' || !o.from || String(o.from.fp).toUpperCase() !== c.fp || o.to !== this.id.fp || SYNC_SKIP.has(o.k)) return null;
        await this._apply(c, o, 'sync');
        this._dlKick(c.id);
        return c.id;
      }
      case 'out': {
        const m = ev.m;
        if (!c || !m || typeof m !== 'object' || m.dir !== 'out' || !m.id) return null;
        const chat = this.store.chat(c.id);
        const have = chat.messages.find(x => x.id === m.id && x.dir === 'out');
        if (have) {
          const order = { preparing: 0, queued: 1, mailbox: 2, failed: 2, sent: 3 };
          if ((order[m.state] ?? 0) >= (order[have.state] ?? 0)) Object.assign(have, { state: m.state, deliveredAt: m.deliveredAt, mailboxAt: m.mailboxAt, heldBy: m.heldBy });
          if (m.readAt) have.readAt = m.readAt;
        } else {
          const nm = { ...m }; delete nm.transfer;
          if (nm.kind === 'file') nm.transfer = { state: 'elsewhere' };  // the file itself stays on the device that sent it
          chat.messages.push(nm);
          chat.messages.sort((a, b) => (a.at || 0) - (b.at || 0));
          if ((nm.at || 0) >= (c.lastAt || 0)) { c.lastAt = nm.at; c.lastText = nm.kind === 'file' ? '📎 ' + ((nm.file && nm.file.name) || '') : String(nm.text || '').slice(0, 120); c.lastDir = 'out'; this.store.putContact(c); }
        }
        this.store.saveChat(c.id);
        return c.id;
      }
      case 'read': {
        if (!c || !Array.isArray(ev.ids)) return null;
        const ids = new Set(ev.ids.map(String)), chat = this.store.chat(c.id);
        let n = 0; for (const m of chat.messages) if (m.dir === 'in' && !m.read && ids.has(m.id)) { m.read = true; n++; }
        if (n) { this.store.saveChat(c.id); c.unread = chat.messages.filter(m => m.dir === 'in' && !m.read).length; this.store.putContact(c); }
        return c.id;
      }
      case 'react': {
        if (!c) return null;
        const m = this.store.chat(c.id).messages.find(x => x.id === String(ev.mid || ''));
        if (!m) return null;
        const e = cleanEmoji(ev.emoji);
        m.reactions = { ...(m.reactions || {}) };
        if (e) m.reactions.me = e; else delete m.reactions.me;
        this.store.saveChat(c.id);
        this.emit('msgupdate', { contactId: c.id, msg: m });
        return null;
      }
      case 'del': if (c) this.deleteMessage(c.id, String(ev.mid || ''), true); return c ? c.id : null;
      case 'clear': if (c) this.clearChat(c.id, true); return c ? c.id : null;
      case 'contact': {
        const x = ev.c;
        if (!x || typeof x !== 'object' || !/^[0-9A-F]{40,64}$/.test(String(x.id || '')) || x.id !== x.fp || x.id === this.id.fp) return null;
        const cur = this.store.contact(x.id) || {};
        const merged = { ...cur };
        for (const [k, val] of Object.entries(x)) if (!LOCAL_FIELDS.has(k)) merged[k] = val;   // (pictures left out of a too-large record keep the ones here)
        if (!cur.id) { merged.unread = 0; }
        this.store.putContact(merged);
        (v.syncDigest || (v.syncDigest = {}))[x.id] = hashOf(syncedContact(merged));
        if (merged.status === 'accepted' || merged.status === 'pending-out') this._soon(merged.id, 2000 + Math.random() * 3000);
        return null;
      }
      case 'contactdel': {
        const id = String(ev.id || '');
        if (!this.store.contact(id)) return null;
        if (v.syncDigest) delete v.syncDigest[id];
        this.remove(id);
        return null;
      }
      case 'chat': {
        if (!c || !Array.isArray(ev.msgs)) return null;
        const chat = this.store.chat(c.id);
        const have = new Set(chat.messages.map(m => m.dir + '|' + m.id));
        for (const m of ev.msgs) {
          if (!m || typeof m !== 'object' || !m.id || (m.dir !== 'in' && m.dir !== 'out') || have.has(m.dir + '|' + m.id)) continue;
          const nm = { ...m }; delete nm.transfer;
          if (nm.kind === 'file') nm.transfer = nm.dir === 'out' ? { state: 'elsewhere' } : { state: 'offered' };
          chat.messages.push(nm);
        }
        chat.messages.sort((a, b) => (a.at || 0) - (b.at || 0));
        const last = chat.messages[chat.messages.length - 1];
        if (last) { c.lastAt = last.at; c.lastDir = last.dir; c.lastText = last.kind === 'file' ? '📎 ' + ((last.file && last.file.name) || '') : String(last.text || '').slice(0, 120); }
        c.unread = chat.messages.filter(m => m.dir === 'in' && !m.read).length;
        this.store.putContact(c); this.store.saveChat(c.id);
        return c.id;
      }
      case 'devices': {
        const { keep, why } = await devices.checkList(this.id, { fp: this.id.fp, publicKey: this.id.pubArmored, devices: { ts: v.myDevicesTs || 0 } }, ev.doc, ev.sig);
        if (!keep) { if (why !== 'not newer') this.log('device list ignored: ' + why); return null; }
        v.myDevices = keep.devices; v.myDevicesTs = keep.ts;
        if (!keep.devices.some(d => d.id === this.device.id)) v.unlinked = Date.now(); else delete v.unlinked;
        this.store.saveVault();
        this.emit('devices');
        return null;
      }
      case 'settings': {
        const x = ev.s || {};
        const patch = {};
        if (typeof x.displayName === 'string') patch.displayName = x.displayName.slice(0, 80);
        for (const k of ['readReceipts', 'allowRequests', 'contactMailbox']) if (typeof x[k] === 'boolean') patch[k] = x[k];
        this.store.setSettings(patch);
        if (x.me && typeof x.me === 'object' && (x.me.avatarAt || 0) >= ((v.me || {}).avatarAt || 0)) {
          v.me = { ...(v.me || {}), shareAvatar: x.me.shareAvatar !== false, avatarAt: x.me.avatarAt || 0, ...(x.me.avatar !== undefined ? { avatar: cleanAvatar(x.me.avatar) } : {}) };
          this.store.saveVault();
        }
        this.emit('settings');
        return null;
      }
      case 'mbox': {
        v.sibMailbox = cleanMbox(ev.mb, this.o.allowHttpMailbox);
        this.store.saveVault();
        this._applyMailbox();
        return null;
      }
      case 'web': {                                                      // 1.9.3: web access shared by your devices (main.js → webaccess.js)
        if (ev.w && typeof ev.w === 'object') this.emit('syncweb', ev.w);
        return null;
      }
      default: return null;
    }
  }

  /* =================================================================
   * 6b. PROFILE (1.2.0)
   * ================================================================= */
  /** What contacts get: your name, and your picture only if you share it. */
  profile() {
    const me = this.store.vault.me || {};
    return { name: this.store.settings.displayName || this.id.name || '', avatar: me.shareAvatar !== false && me.avatar ? me.avatar : null };
  }
  _profileVersion() { const p = this.profile(); return crypto.createHash('sha256').update(p.name + '|' + (p.avatar || '')).digest('hex').slice(0, 16); }

  /** Queues your current profile for a contact if they don't have it yet. */
  _maybeShareProfile(c) {
    if (!c || c.status !== 'accepted') return;
    const ver = this._profileVersion();
    if (c.profileSent === ver || (this.store.vault.ctl || []).some(x => x.to === c.id && x.k === 'profile' && x.ver === ver)) return;
    const p = this.profile();
    this._queueCtl(c.id, { k: 'profile', name: p.name, avatar: p.avatar, ver });
  }

  /** After you change your name or picture: send it to everyone. */
  shareProfileAll() {
    this.syncSettings();                                               // 1.9.0: your other devices too
    for (const c of this.store.contacts()) if (c.status === 'accepted') { this._maybeShareProfile(c); this._soon(c.id, 1000 + Math.random() * 4000); }
  }

  /* =================================================================
   * 7. FILES (1.1.0)
   * ================================================================= */
  /**
   * Sends a file. source: { path } or { buffer }; info: { name, mime, thumb, text }.
   * The message appears at once ("Preparing…") while the file is encrypted
   * into Seal Chat's storage; then its offer goes out like any message.
   */
  async sendFile(id, source, info, onAdded) {
    const c = this.store.contact(id);
    if (!c) throw new Error('Unknown contact');
    if (c.status === 'blocked') throw new Error('You blocked this contact');
    if (c.status === 'pending-in') throw new Error('Accept their request first');
    if (!this.files) throw new Error('File sending is not available');
    const size = source.buffer ? source.buffer.length : require('fs').statSync(source.path).size;
    const maxMB = Number(this.store.settings.maxFileMB ?? 2048);
    if (size > maxMB * 1024 * 1024) throw new Error(`"${info.name}" is ${fmtSize(size)}. The largest file you can send is ${fmtSize(maxMB * 1024 * 1024)} (Settings → Files).`);
    if (size > MAX_FILE) throw new Error('Files can be up to 4 GB');
    const msg = { id: newId(), dir: 'out', kind: 'file', dev: this._ensureDevice().id, text: String(info.text || '').slice(0, MAX_TEXT), ts: Date.now(), at: Date.now(), state: 'preparing',
      file: { name: safeName(info.name), size, mime: cleanMime(info.mime), pieces: piecesFor(size), thumb: cleanThumb(info.thumb) }, transfer: { state: 'preparing', done: 0 } };
    const chat = this.store.chat(id);
    const re = this._reFor(chat, info.re); if (re) msg.re = re;        // 1.8.0
    chat.messages.push(msg);
    c.lastAt = msg.at; c.lastText = '📎 ' + msg.file.name; c.lastDir = 'out';
    this.store.saveChat(id); this.store.putContact(c);
    if (onAdded) onAdded(msg);
    try {
      const meta = await this.files.importFile(fileKey(id, msg.id), msg.id, source, (done, total) => this._progress(id, msg, { state: 'preparing', done, total }));
      Object.assign(msg.file, { key: meta.key, nonce: meta.nonce, pieces: meta.pieces, size: meta.size });
      msg.state = 'queued'; msg.transfer = { state: 'offered' };
    } catch (e) {
      msg.state = 'failed'; msg.transfer = { state: 'failed', err: 'Could not read the file: ' + e.message };
      this.files.remove(fileKey(id, msg.id));
    }
    this.store.saveChat(id);
    this.emit('transfer', { contactId: id, id: msg.id, transfer: msg.transfer, state: msg.state });
    if (msg.state === 'queued') { this._syncMsg(id, msg); this._soon(id, 0); }   // 1.9.0: shown on your other devices (the file stays on this one)
    return msg;
  }

  /** Receiver: start (or resume / retry) downloading a file. */
  download(id, msgId) {
    const m = this.store.chat(id).messages.find(x => x.id === msgId && x.dir === 'in' && x.kind === 'file');
    if (!m) throw new Error('File not found');
    if (m.transfer.state === 'done') return m;
    m.transfer = { ...m.transfer, state: 'queued', err: null };
    this.store.saveChat(id);
    const d = this.dl.get(fileKey(id, msgId)); if (d) d.tries = 0;
    this._dlSoon(id, msgId, 0);
    this.emit('transfer', { contactId: id, id: msgId, transfer: m.transfer });
    return m;
  }

  /** Receiver: pause a download (keeps what has arrived). */
  pauseDownload(id, msgId) {
    const m = this.store.chat(id).messages.find(x => x.id === msgId && x.dir === 'in' && x.kind === 'file');
    if (!m || m.transfer.state === 'done') return;
    m.transfer = { ...m.transfer, state: 'paused' };
    const d = this.dl.get(fileKey(id, msgId)); if (d) { d.stop = true; if (d.cancel) d.cancel(); }
    this.store.saveChat(id);
    this.emit('transfer', { contactId: id, id: msgId, transfer: m.transfer });
  }

  /** Receiver: say no to a file (the sender sees "Declined"). */
  declineFile(id, msgId) {
    const m = this.store.chat(id).messages.find(x => x.id === msgId && x.dir === 'in' && x.kind === 'file');
    if (!m) return;
    const d = this.dl.get(fileKey(id, msgId)); if (d) { d.stop = true; if (d.cancel) d.cancel(); }
    this.files.remove(fileKey(id, msgId));
    m.transfer = { state: 'declined', got: 0 };
    this.store.saveChat(id);
    this._queueCtl(id, { k: 'filedone', fid: msgId, status: 'declined' });
    this._soon(id, 500);
    this.emit('transfer', { contactId: id, id: msgId, transfer: m.transfer });
  }

  /** Where a finished file is, for showing / saving. */
  fileRef(id, msgId) {
    const m = this.store.chat(id).messages.find(x => x.id === msgId && x.kind === 'file');
    if (!m) throw new Error('File not found');
    const where = fileKey(id, msgId);
    if (!this.files.isComplete(where, m.file)) throw new Error(m.dir === 'in' ? 'The file has not finished downloading' : 'The file is no longer on this PC');
    return { where, msg: m, meta: m.file };
  }

  /** Removes the stored data of files older than `days` (0 = all); the messages stay. */
  freeFileSpace(days = 0) {
    const cutoff = Date.now() - days * 864e5;
    let n = 0;
    for (const c of this.store.contacts()) {
      const chat = this.store.chat(c.id); let changed = false;
      for (const m of chat.messages) {
        if (m.kind !== 'file' || m.at > cutoff || m.removed) continue;
        if (m.dir === 'out' && (m.state === 'queued' || m.state === 'preparing')) continue;
        const d = this.dl.get(fileKey(c.id, m.id)); if (d) d.stop = true;
        this.files.remove(fileKey(c.id, m.id));
        m.removed = true; m.transfer = { ...(m.transfer || {}), state: m.dir === 'in' && m.transfer && m.transfer.state !== 'done' ? 'paused' : (m.transfer || {}).state, got: 0 };
        changed = true; n++;
      }
      if (changed) this.store.saveChat(c.id);
    }
    return n;
  }

  _dropFile(id, m) {
    const d = this.dl.get(fileKey(id, m.id)); if (d) { d.stop = true; if (d.cancel) d.cancel(); }
    this.dl.delete(fileKey(id, m.id));
    if (this.files) this.files.remove(fileKey(id, m.id));
  }

  /** After a restart: "preparing" can't continue; running downloads resume. */
  _recoverFiles() {
    if (!this.files) return;
    for (const c of this.store.contacts()) {
      const chat = this.store.chat(c.id); let changed = false;
      for (const m of chat.messages) {
        if (m.kind !== 'file') continue;
        if (m.dir === 'out' && m.state === 'preparing') { m.state = 'failed'; m.transfer = { state: 'failed', err: 'Seal Chat closed before the file was ready — send it again' }; this.files.remove(fileKey(c.id, m.id)); changed = true; }
        if (m.dir === 'in' && (m.transfer.state === 'queued' || m.transfer.state === 'downloading')) { m.transfer.state = 'queued'; this._dlSoon(c.id, m.id, 3000 + Math.random() * 3000); changed = true; }
      }
      if (changed) this.store.saveChat(c.id);
    }
  }

  _progress(contactId, m, transfer) {
    m.transfer = { ...(m.transfer || {}), ...transfer };
    const k = fileKey(contactId, m.id), now = Date.now();
    if (now - (this.lastEmit.get(k) || 0) < 250 && transfer.state === (m.lastSentState || transfer.state)) return;
    this.lastEmit.set(k, now); m.lastSentState = transfer.state;
    this.emit('transfer', { contactId, id: m.id, transfer: m.transfer });
  }

  /* ---------- sender side: answering "get" ---------- */
  async _onGet(fsk, st, f) {
    const id = String(f.id || '');
    // only over a connection proven to be the contact the file was sent to
    const c = st.authed && this.store.contact(st.authed);
    const m = c && this.store.chat(c.id).messages.find(x => x.id === id && x.dir === 'out' && x.kind === 'file' && x.state !== 'preparing' && x.state !== 'failed');
    if (!m || !this.files || !this.files.isComplete(fileKey(c.id, id), m.file)) return fsk.send({ t: 'gone', id });
    const i = Number(f.i), n = Math.min(Number(f.n) || 1, WINDOW);
    const tag = id + '/' + String(f.g || 0).slice(0, 12);
    if (!Number.isInteger(i) || i < 0 || i >= m.file.pieces || n < 1) return fsk.send({ t: 'gone', id });
    // one connection serves its requests strictly in order
    st.serving = (st.serving || Promise.resolve()).then(async () => {
      for (let k = i; k < Math.min(i + n, m.file.pieces); k++) {
        if (fsk.closed || (st.stopped && st.stopped.has(tag))) return;
        const data = await this.files.readSealed(fileKey(c.id, id), m.file, k);
        await fsk.sendPiece(tag, k, data);
        if (!m.transfer || m.transfer.state !== 'done') this._progress(c.id, m, { state: 'uploading', done: Math.min((k + 1) * (SLOT - 16), m.file.size), total: m.file.size });
      }
    }).catch(e => this.log('serve: ' + e.message));
  }

  /* ---------- receiver side: the download loop ---------- */
  _dlSoon(contactId, msgId, ms) {
    const k = fileKey(contactId, msgId);
    const d = this.dl.get(k) || { contactId, msgId, tries: 0, running: false };
    d.next = Math.min(d.next || Infinity, Date.now() + ms);
    this.dl.set(k, d);
    if (ms <= 0) setImmediate(() => this._tick());
  }

  _dlKick(contactId) { for (const d of this.dl.values()) if (d.contactId === contactId && !d.running) { d.tries = 0; d.next = Date.now(); } }

  _dlTick(now) {
    const busy = new Set([...this.dl.values()].filter(d => d.running).map(d => d.contactId));
    for (const [k, d] of this.dl) {
      if (d.running || !d.next || d.next > now || busy.has(d.contactId)) continue;   // one download per contact at a time
      const c = this.store.contact(d.contactId);
      const m = c && this.store.chat(c.id).messages.find(x => x.id === d.msgId && x.dir === 'in' && x.kind === 'file');
      if (!m || m.transfer.state !== 'queued' || c.status === 'blocked') { this.dl.delete(k); continue; }
      busy.add(d.contactId);
      d.next = 0;
      this._download(c, m, d).catch(e => this.log('download: ' + e.message));
    }
  }

  async _download(c, m, d) {
    d.running = true; d.stop = false; d.cancel = null;
    const where = fileKey(c.id, m.id);
    const meta = m.file;
    let fh = null, failed = null, finished = false;
    try {
      const got0 = this.files.completePieces(where, meta);
      const need = (meta.size + meta.pieces * 16) - got0 * SLOT;
      if (this.files.freeSpace() < need + 200 * 1024 * 1024) throw Object.assign(new Error('Not enough free disk space for this file'), { stop: true });
      this._progress(c.id, m, { state: 'downloading', got: got0, done: Math.min(got0 * (SLOT - 16), meta.size), total: meta.size, err: null });
      const sock = await this._connection(c);
      fh = await this.files.openForDownload(where, got0);
      let got = got0, asked = got0;
      const gen = String(Date.now() % 1e9), tag = m.id + '/' + gen;   // this attempt's tag
      if (meta.pieces > 0) await new Promise((resolve, reject) => {
        let timer = null;
        const arm = () => { clearTimeout(timer); timer = setTimeout(() => done(Object.assign(new Error('The transfer stalled'), { code: 'UNREACHABLE' })), 90e3); };
        const ask = () => {
          while (asked - got < WINDOW && asked < meta.pieces) {
            const n = Math.min(8, meta.pieces - asked, WINDOW - (asked - got));
            sock.send({ t: 'get', id: m.id, g: gen, i: asked, n }); asked += n;
          }
        };
        let chain = Promise.resolve();
        const onFrame = f => {
          if (f.t === 'gone' && f.id === m.id) return done(Object.assign(new Error('The sender no longer has this file'), { stop: true }));
          if (f.t !== 'piece' || f.id !== tag) return;          // not for this attempt
          // pieces are checked and written strictly in order
          chain = chain.then(async () => {
            if (d.stop) return done(null, 'stopped');
            if (f.i < got) return;                         // a repeat (left over from before a pause): skip
            if (f.i !== got) throw new Error('pieces arrived out of order');
            openPiece(meta, m.id, f.i, f.data);              // throws if changed or damaged
            await fh.write(f.data, 0, f.data.length, f.i * SLOT);
            got++; arm();
            if (got % 16 === 0) { m.transfer.got = got; this.store.saveChat(c.id); }
            this._progress(c.id, m, { state: 'downloading', got, done: Math.min(got * (SLOT - 16), meta.size), total: meta.size });
            if (got >= meta.pieces) return done(null, 'ok');
            ask();
          }).catch(e => done(e));
        };
        const onClose = () => done(Object.assign(new Error('Connection closed'), { code: 'UNREACHABLE' }));
        let settled = false;
        const done = (err, v) => {
          if (settled) return; settled = true;
          clearTimeout(timer); sock.off('frame', onFrame); sock.off('close', onClose);
          if (got < meta.pieces && !sock.closed) { try { sock.send({ t: 'stop', id: m.id, g: gen }); } catch { /* closed */ } }
          if (err) reject(err); else resolve(v);
        };
        sock.on('frame', onFrame); sock.once('close', onClose);
        d.cancel = () => done(null, 'stopped');           // Pause / Decline stop at once
        if (d.stop) return done(null, 'stopped');
        arm(); ask();
      });
      finished = !d.stop && this.files.completePieces(where, meta) >= meta.pieces;
    } catch (e) {
      failed = e;
    } finally {
      if (fh) await fh.close().catch(() => {});
      d.running = false;
    }
    if (finished) {
      if (!this.files.isComplete(where, meta)) { failed = new Error('file size check failed'); finished = false; }
    }
    if (finished) {
      m.transfer = { state: 'done', got: meta.pieces, at: Date.now() };
      this.dl.delete(where);
      this._queueCtl(c.id, { k: 'filedone', fid: m.id, status: 'done' });
      this._soon(c.id, 300);
      this.store.saveChat(c.id); this.store.flush();
      this.emit('transfer', { contactId: c.id, id: m.id, transfer: m.transfer });
      this.emit('fileReady', { contactId: c.id, msg: m });
      return;
    }
    if (d.stop && !failed) { this.store.saveChat(c.id); return; }   // paused / declined by you
    const e = failed || new Error('Download interrupted');
    m.transfer.got = this.files.completePieces(where, meta);
    if (e.stop) { m.transfer = { ...m.transfer, state: 'failed', err: e.message }; this.dl.delete(where); }
    else {
      m.transfer = { ...m.transfer, state: 'queued', err: e.code === 'UNREACHABLE' ? 'Waiting for ' + (c.nick || c.name || 'contact') + ' to be online' : e.message };
      d.next = Date.now() + DL_RETRY[Math.min(d.tries++, DL_RETRY.length - 1)] * (0.85 + Math.random() * 0.3);
    }
    this.log(`download ${m.id.slice(0, 6)}: ${e.message}`);
    this.store.saveChat(c.id);
    this.emit('transfer', { contactId: c.id, id: m.id, transfer: m.transfer });
  }

  /** When a contact is due next (for "will retry in …"). */
  nextAttempt(id) { const s = this.sched.get(id); return s && s.next ? s.next : null; }
}

/* =================================================================
 * HELPERS (files)
 * ================================================================= */
function fmtSize(n) {
  if (n < 1024) return n + ' bytes';
  const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return (n >= 100 ? Math.round(n) : n.toFixed(1)) + ' ' + u[i];
}
function cleanMime(m) { m = String(m || '').toLowerCase().slice(0, 100); return /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(m) ? m : 'application/octet-stream'; }
/** A shared profile picture: a small JPEG/PNG as a data URL, or null. */
function cleanAvatar(a) { return typeof a === 'string' && a.length < 120000 && /^data:image\/(jpeg|png);base64,[A-Za-z0-9+/=]+$/.test(a) ? a : null; }
function cleanThumb(t) { return typeof t === 'string' && t.length < 90000 && /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(t) ? t : null; }

/** Checks a received file offer; returns the cleaned file info or null. */
function checkOffer(o) {
  const f = o && o.file;
  if (!f || typeof f !== 'object') return null;
  const size = Number(f.size), pieces = Number(f.pieces);
  if (!Number.isInteger(size) || size < 0 || size > MAX_FILE) return null;
  if (pieces !== piecesFor(size)) return null;
  let key, nonce;
  try { key = Buffer.from(String(f.key), 'base64'); nonce = Buffer.from(String(f.nonce), 'base64'); } catch { return null; }
  if (key.length !== 32 || nonce.length !== 8) return null;
  if (!/^[0-9a-f]{24}$/.test(String(o.id))) return null;
  return { name: safeName(f.name), size, pieces, mime: cleanMime(f.mime), key: key.toString('base64'), nonce: nonce.toString('base64'), thumb: cleanThumb(f.thumb) };
}

/* ---------- 1.8.0: replies + reactions ---------- */
/** A short excerpt of a message, for the reply quote. */
function snipOf(m) {
  if (m.kind === 'file' && m.file) return ('📎 ' + m.file.name + (m.text ? ' — ' + m.text : '')).slice(0, SNIP);
  return String(m.text || '').replace(/\s+/g, ' ').trim().slice(0, SNIP);
}
/** What goes over the wire for a reply (or nothing). */
function wireRe(re) { return re && re.id ? { id: String(re.id).slice(0, 40), snip: String(re.snip || '').slice(0, SNIP) } : undefined; }
/** A received reply reference, checked; "dir" tells whose message it answers (as seen on THIS PC). */
function cleanRe(re, chat) {
  if (!re || typeof re !== 'object' || !re.id) return null;
  const id = String(re.id).slice(0, 40);
  const orig = chat && chat.messages.find(x => x.id === id);
  return { id, dir: orig ? orig.dir : '', snip: orig ? snipOf(orig) : String(re.snip || '').slice(0, SNIP) };
}
/** 1.9.0: a contact record as your other devices get it (this device's own bits left out). */
function syncedContact(c) { const o = {}; for (const [k, v] of Object.entries(c)) if (!LOCAL_FIELDS.has(k) && v !== undefined) o[k] = v; return o; }
function hashOf(o) { return crypto.createHash('sha256').update(JSON.stringify(o)).digest('hex').slice(0, 24); }
/** A contact's mailbox address as they sent it, checked (https only; http only in tests). */
function cleanMbox(mb, allowHttp) {
  if (!mb || typeof mb !== 'object') return null;
  const url = String(mb.url || '');
  if (!(/^https:\/\/[^\s"<>]+\/$/i.test(url) || (allowHttp && /^http:\/\/[^\s"<>]+\/$/i.test(url))) || url.length > 300) return null;
  if (!/^[a-f0-9]{32}$/.test(String(mb.box || '')) || !/^[A-Za-z0-9_-]{30,100}$/.test(String(mb.drop || ''))) return null;
  return { url, box: String(mb.box), drop: String(mb.drop) };
}
/** One emoji (with skin tone / joiners), or '' — no letters, no long text. */
function cleanEmoji(e) {
  const t = String(e || '').trim();
  if (!t || t.length > 16) return '';
  return EMOJI_ONLY.test(t) && EMOJI_PICT.test(t) ? t : '';   // 1.9.1: noicu.js (Android's Node.js can't compile \\p{…} literals)
}

module.exports = { Peer, parseId, formatId, fmtSize, cleanAvatar, cleanEmoji, snipOf };
