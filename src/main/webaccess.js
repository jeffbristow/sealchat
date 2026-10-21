/* =====================================================================
 * Seal Chat — webaccess.js   (use Seal Chat from a phone browser, 1.4.0 · 1.6.0 · 1.7.0)
 * ---------------------------------------------------------------------
 * The web interface (Seal Chat Web, on YOUR website, e.g. https://example.com/chat/)
 * is a remote screen for this app. Your PGP key never leaves this
 * computer: Seal Chat reads/sends your messages as usual and passes
 * them to the paired browser, sealed with a key only the two share.
 * The website's relay.php only carries sealed blobs.
 *
 * OFF BY DEFAULT. When on, it works in two speeds:
 *   IDLE    every N seconds (Settings, default 30) one tiny request for
 *           the website's static "wake" file, asking "changed since…?".
 *           The web server answers "304 Not Modified" without running
 *           PHP. Nothing else is sent.
 *   ACTIVE  when the wake file HAS changed (someone opened the web
 *           interface) or while pairing: Seal Chat calls relay.php and
 *           waits there for messages (~1-2 s delivery), until the web
 *           interface has been quiet for 5 minutes.
 * It can also switch itself off after a set time (1 h / 8 h / 24 h).
 *
 * Saved (encrypted, in vault.dat → vault.web): the website address, the
 * relay code + mailbox token, and each paired device: its name, its key,
 * a hash of its PIN, and (1.6.0) its notification subscription. Settings
 * (plain): webEnabled, webUntil, webIdleSec, webViaTor.
 *
 * 1.6.0 NOTIFICATIONS (see webpush.js): a paired device can ask for
 * notifications. Seal Chat then sends "New message" (or, if allowed,
 * "New message from <name>") through the phone maker's push service
 * while that device isn't looking at Seal Chat. Turned on/off per device,
 * on the device or in Settings → Web access. Only while web access is on.
 *
 * 1.8.0 MAILBOX: your website's relay.php can also hold sealed messages your
 * contacts leave while this computer is off (mbox_set / mbox_get here;
 * peer.js leaves them in contacts' mailboxes).
 *
 * 1.7.0 FILES (see webfiles.js): the device can send files (up to 100 MB)
 * and open / save the files in its chats, in sealed 512 KB pieces.
 *
 * 1.9.3 SHARED BY YOUR LINKED DEVICES (section 9): your devices (Settings →
 * Your devices) share ONE connection to your website — the same mailbox,
 * the same paired phones, the same notification key — passed between them
 * over the encrypted device sync. So the phone works with whichever of
 * them is running. With Seal Chat Web 1.3.2 the website gives one of them
 * the "lease" to answer; the others wait on standby and take over if it
 * goes quiet (about a minute). With an older Seal Chat Web only the device
 * that connected it answers (as before). Removing a device gives the
 * website a new computer token, so the removed one can't use it any more.
 *
 * Sections:
 *   1. Crypto (must match crypto.js in Seal Chat Web)
 *   2. WebAccess: state, status, on/off
 *   3. Connecting to the website (connection link → mailbox)
 *   4. The loop: idle wake-file checks ↔ active listening
 *   5. Pairing a device (QR code, approve / decline)
 *   6. Requests from a paired device (PIN, contacts, chats, sending)
 *   7. Sending to devices + live updates
 *   8. Notifications (1.6.0): per-device on/off, sending
 *   9. Shared by your linked devices (1.9.3): sync in/out, lease, new token
 * ===================================================================== */

const crypto = require('crypto');
const { EventEmitter } = require('events');
const { request } = require('./webhttp');
const webpush = require('./webpush');

const ACTIVE_MS = 5 * 60e3;        // stay listening this long after the last device message
const PAIR_MS = 10 * 60e3;         // a pairing QR code works this long
const SESSION_MS = 12 * 3600e3;    // a PIN unlock lasts this long (while the page is open)
const PIN_TRIES = 10;              // wrong PINs before the device is removed
const PIN_ITER = 150000;
const WAIT_S = 20;                 // how long relay.php holds a "recv" open
const VIEWING_MS = 75e3;           // a device that pinged this recently has Seal Chat on screen (it pings every 60 s while visible)
const PUSH_GAP_MS = 10e3;          // at most one notification per device per 10 s (a newer one replaces a waiting one anyway)
const STANDBY_MS = 15e3;           // 1.9.3: while another of your devices answers the phone, ask again this often
const SEQ_JUMP = 30e6;             // 1.9.3: taking over, number messages a bit (30 s worth) past the previous device's
const GONE_KEEP = 90 * 86400e3;    // 1.9.3: "this phone was removed" is remembered this long (so a sync can't bring it back)
const FEAT_RECHECK_MS = 10 * 60e3; // 1.9.6: shared but no lease: ask the website again this often (it may have been updated)

/* =================================================================
 * 1. CRYPTO  (same as Seal Chat Web's crypto.js)
 * ================================================================= */
const b64u = b => Buffer.from(b).toString('base64url');
const unb64u = s => Buffer.from(String(s || ''), 'base64url');
const sha256hex = s => crypto.createHash('sha256').update(s).digest('hex');
const hkdf = (ikm, salt, info, len) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt || Buffer.alloc(0), Buffer.from(info), len));
const AAD = {
  pair: (dir, tid) => `sealchat-web-pair-v1|${dir}|${tid}`,
  msg: (dir, devId) => `sealchat-web-v1|${dir}|${devId}`
};
function pairSecrets(P) {
  return { pairKey: hkdf(P, null, 'sealchat-web-pair-v1', 32), ticket: b64u(hkdf(P, null, 'sealchat-web-ticket-v1', 24)) };
}
function deviceSecrets(shared, P, devId) {
  const c = hkdf(shared, P, 'sealchat-web-code-v1', 4);
  const six = String(c.readUInt32BE(0) % 1000000).padStart(6, '0');
  return { key: hkdf(shared, P, 'sealchat-web-key-v1|' + devId, 32), code: six.slice(0, 3) + ' ' + six.slice(3) };
}
function seal(key, aad, obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final(), c.getAuthTag()]);
  return JSON.stringify({ n: b64u(iv), c: b64u(ct) });
}
function open(key, aad, text) {
  const o = JSON.parse(text);
  const all = unb64u(o.c);
  if (all.length < 16) throw new Error('short');
  const d = crypto.createDecipheriv('aes-256-gcm', key, unb64u(o.n));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(all.subarray(all.length - 16));
  return JSON.parse(Buffer.concat([d.update(all.subarray(0, all.length - 16)), d.final()]).toString('utf8'));
}
const pbkdf2 = (pin, salt) => new Promise((res, rej) => crypto.pbkdf2(String(pin), salt, PIN_ITER, 32, 'sha256', (e, k) => e ? rej(e) : res(k)));

/** "https://site/sealchat/web/#relay=CODE" → { base, code } */
function parseLink(text, allowHttp) {
  const s = String(text || '').trim();
  let u;
  try { u = new URL(s); } catch { throw new Error('Paste the connection link from your Seal Chat Web setup page (admin.php)'); }
  if (u.protocol !== 'https:' && !(allowHttp && u.protocol === 'http:')) throw new Error('The link must start with https://');
  const m = /(?:^|[#&?])relay=([A-Za-z0-9-]{8,40})/.exec(u.hash + '&' + u.search);
  if (!m) throw new Error('That link has no relay code in it. Copy the whole "connection link" from your Seal Chat Web setup page (admin.php).');
  let p = u.pathname.replace(/index\.(php|html)$/i, '');
  if (!p.endsWith('/')) p += '/';
  return { base: `${u.protocol}//${u.host}${p}`, code: m[1].toUpperCase() };
}

/* =================================================================
 * 2. WEBACCESS
 * ================================================================= */
class WebAccess extends EventEmitter {
  /**
   * @param {object} o
   *   state()        → the saved object (vault.web), changed in place
   *   save()         → saves it (encrypted)
   *   settings()     → plain settings; setSettings(patch)
   *   socksPort()    → Tor's SOCKS port or null
   *   handler        { me(), contacts(), history(cid, before), send(cid, text), read(cid),
   *                    1.6.0 contacts: myId(), checkId(text), addContact(id, nick), contactDetails(cid), contactAct(cid, act, value) }
   *   ca, allowHttp  (tests only; allowHttp also allows any push address)
   *   1.9.3 (all optional): node() → this device's id · siblings() → how many linked devices ·
   *                    syncOut(shared) → send the shared state to them · nodeName(id) → a device's name
   */
  constructor(o) {
    super();
    this.o = o;
    this.mode = 'off';           // off | idle | active | waiting-tor | error
    this.error = null;
    this.lastCheck = 0;
    this.activeUntil = 0;
    this.ack = 0;
    this.pairing = null;
    this.sessions = new Map();   // devId -> { sid, at }
    this.sendChains = new Map(); // devId/tid -> Promise (keeps messages in order)
    this.outSeq = 0;
    this.running = false;
    this._kick = null;
    this.stats = { checks: 0, polls: 0 };
    this.standby = null;         // 1.9.3: { by, until, view:Set, at } while another of your devices answers the phone
    this.holding = false;        // 1.9.3: this device holds the lease right now
    this.claim = false;          // 1.9.3: woken / asked to do something: may take a released lease
    this._shareTimer = null;
  }

  st() { const s = this.o.state(); if (!s.devices) s.devices = {}; return s; }
  S() { return this.o.settings(); }
  enabled() {
    const s = this.S();
    if (!s.webEnabled) return false;
    if (s.webUntil && Date.now() > s.webUntil) { this.o.setSettings({ webEnabled: false, webUntil: undefined }); this._changed(); return false; }
    return true;
  }
  idleMs() { return this.o.idleMs || Math.max(10, Math.min(900, Number(this.S().webIdleSec) || 30)) * 1000; }
  activeMs() { return this.o.activeMs || ACTIVE_MS; }
  viaTor() { return this.S().webViaTor !== false; }
  _net() {
    const socksPort = this.viaTor() ? this.o.socksPort() : null;
    return { socksPort, ca: this.o.ca, allowHttp: !!this.o.allowHttp };
  }

  /** Everything the Settings screen shows. */
  status() {
    const s = this.st(), S = this.S();
    return {
      enabled: !!S.webEnabled, until: S.webUntil || null, idleSec: this.idleMs() / 1000, viaTor: this.viaTor(),
      linked: !!s.box, base: s.base || '', mode: this.mode, error: this.error, errorCode: this.mode === 'error' ? this.errorCode || null : null, lastCheck: this.lastCheck,
      devices: Object.entries(s.devices).map(([id, d]) => ({ id, name: d.name, added: d.added, lastUsed: d.lastUsed || 0, connected: this._sessionAlive(id) && this.mode === 'active',
        push: d.push ? { on: !!d.push.on, names: !!d.push.names, lastOk: d.push.lastOk || 0, lastErr: d.push.lastErr || null, svc: d.push.svc || '' } : null })),
      pairing: this.pairing ? { tid: this.pairing.tid, stage: this.pairing.stage, name: this.pairing.cand && this.pairing.cand.name, code: this.pairing.cand && this.pairing.cand.code, exp: this.pairing.exp } : null,
      stats: this.stats,
      // 1.9.3: shared with your linked devices
      shared: this._shared() ? { serving: this._serves(), holding: this.holding, standbyBy: this.standby ? this._name(this.standby.by) : null, owner: s.owner ? this._name(s.owner) : null, lease: this._leaseOk() } : null
    };
  }
  _changed() { this.emit('status', this.status()); }

  /** Turns web access on (optionally for some hours) or off. */
  setEnabled(on, hours) {
    if (on && !this.st().box) throw new Error('First paste the connection link from your website');
    this.o.setSettings({ webEnabled: !!on, webUntil: on && Number(hours) > 0 ? Date.now() + Number(hours) * 3600e3 : undefined });
    if (!on) { this.sessions.clear(); this.pairing = null; this.activeUntil = 0; this._release(); }
    this.st().onAt = Date.now(); this.o.save();
    this._shareOut();                                  // 1.9.3: on / off for all your devices
    this.kick();
    this._changed();
    return this.status();
  }

  start() { if (this.running) return; this.running = true; this._loop(); }
  stop() { this.running = false; this.kick(); }
  /** Wakes the loop now (settings changed, pairing started, Tor ready …). */
  kick() { if (this._kick) { const k = this._kick; this._kick = null; k(); } }
  _sleep(ms) { return new Promise(r => { const t = setTimeout(() => { this._kick = null; r(); }, ms); this._kick = () => { clearTimeout(t); r(); }; }); }

  /* =================================================================
   * 3. CONNECTING TO THE WEBSITE
   * ================================================================= */
  async _call(action, body, timeoutMs) {
    const s = this.st();
    const r = await request(s.base + 'relay.php?a=' + action, {
      ...this._net(), method: 'POST', body: JSON.stringify(body || {}), timeoutMs: timeoutMs || 60000,
      headers: { 'X-SC-Box': s.box, 'Authorization': 'Bearer ' + s.token, 'X-SC-Auth': s.token }
    });
    let j = null;
    try { j = JSON.parse(r.body.toString('utf8')); } catch { /* not JSON */ }
    if (!j) {
      // a page instead of the relay's answer: through Tor, usually the host's "blocked visitor" page
      if (this.viaTor() && [403, 429, 503].includes(r.status)) {
        const e = new Error(`The website answered ${r.status} (blocked) to a visit through Tor. Your website doesn't need to be on Tor — but its host seems to block visitors that arrive through Tor.`);
        e.code = 'TOR_BLOCKED'; throw e;
      }
      const e = new Error(r.status === 404 ? 'relay.php was not found at ' + s.base + ' — is the web interface uploaded there?' : `The website answered ${r.status} instead of the relay's reply`);
      e.code = 'HTTP' + r.status; throw e;
    }
    if (!j.ok) { const e = new Error(j.error || 'The relay refused'); e.code = j.code; e.status = r.status; throw e; }
    return j;
  }

  /** Paste of the connection link from admin.php → sets up this computer's mailbox. */
  async connect(linkText) {
    const { base, code } = parseLink(linkText, this.o.allowHttp);
    const s = this.st();
    if (s.box && s.base === base) {           // same site: keep the mailbox + paired devices
      s.code = code; this.o.save();
      await this._register();
      return this.status();
    }
    if (s.box) await this.disconnect().catch(() => {});
    // 1.9.3: owner / since / chosen: which device connected it, and when (see section 9)
    Object.assign(s, { base, code, box: crypto.randomBytes(16).toString('hex'), token: b64u(crypto.randomBytes(32)), wake: null, devices: {}, lastWakeTag: null,
      owner: this._node() || undefined, since: Date.now(), chosen: Date.now(), gone: {} });
    try { await this._register(); }
    catch (e) { for (const k of ['base', 'code', 'box', 'token', 'wake']) delete s[k]; this.o.save(); throw e; }
    this._vapid();                                    // made now, so all your devices use the same one
    this.o.save();
    this._shareOut();
    this.kick(); this._changed();
    return this.status();
  }

  async _register() {
    const s = this.st();
    const j = await this._call('register', { code: s.code, token: s.token });
    s.wake = String(j.wake || '');
    const feat = Array.isArray(j.feat) ? j.feat.filter(x => typeof x === 'string').slice(0, 20) : [];   // 1.9.3: Seal Chat Web 1.3.2+
    const featChanged = JSON.stringify(feat) !== JSON.stringify(s.feat || []);
    s.feat = feat;
    this.o.save();
    if (featChanged) this._shareOut();
    await this._syncAllow();
  }

  /** Removes this computer's mailbox from the website and forgets the paired devices. */
  async disconnect() {
    const s = this.st();
    if (s.box) { try { await this._call('unregister', {}); } catch { /* website gone: forget anyway */ } }
    const box = s.box;
    for (const k of Object.keys(s)) delete s[k];
    s.devices = {};
    if (box && this.o.syncOut && this._siblings()) this.o.syncOut({ off: true, box, ver: Date.now() });   // 1.9.3: off on your other devices too
    this.sessions.clear(); this.pairing = null;
    this.o.setSettings({ webEnabled: false, webUntil: undefined });
    this.o.save();
    this.kick(); this._changed();
    return this.status();
  }

  /** Tells the relay which devices (and which pairing ticket) may use the mailbox. */
  async _syncAllow(remove = [], untickets = []) {
    const s = this.st();
    const devices = {};
    for (const [id, d] of Object.entries(s.devices)) devices[id] = d.th;
    const tickets = {};
    if (this.pairing && Date.now() < this.pairing.exp) tickets[this.pairing.tid] = { h: sha256hex(this.pairing.ticket), exp: Math.floor(this.pairing.exp / 1000) };
    // 1.9.3 (v 2, Seal Chat Web 1.3.2): add / remove instead of replacing, so your linked devices can't undo each other's changes
    const v2 = (s.feat || []).includes('allow2');
    for (const id of Object.keys(s.gone || {})) if (!devices[id]) remove.push(id);
    await this._call('allow', v2 ? { v: 2, devices, tickets, remove: [...new Set(remove)].slice(0, 50), untickets } : { devices, tickets });
  }

  /** The mailbox was removed on the website (or the code changed): connect again. */
  async _recover(e) {
    if (!['nobox', 'auth'].includes(e.code)) return false;
    const s = this.st();
    if (e.code === 'auth' && this._shared()) {
      // 1.9.3: another of your devices gave the website a new token (you removed a device) — it comes with the device sync
      e.message = 'Waiting for the new web access key from your other device (it arrives when both are online)';
      return false;
    }
    if (e.code === 'auth') s.box = crypto.randomBytes(16).toString('hex');   // someone else's now
    try { await this._register(); this.error = null; return true; } catch (e2) { this.error = e2.message; return false; }
  }

  /* =================================================================
   * 4. THE LOOP
   * ================================================================= */
  async _loop() {
    let backoff = 0;
    while (this.running) {
      const s = this.st();
      if (!this.enabled() || !s.box) {
        if (this.mode !== 'off') { this.mode = 'off'; this._changed(); }
        await this._sleep(60e3); continue;
      }
      if (this.viaTor() && !this.o.socksPort()) {
        if (this.mode !== 'waiting-tor') { this.mode = 'waiting-tor'; this._changed(); }
        await this._sleep(5000); continue;
      }
      if (this._shared() && !this._leaseOk() && Date.now() - (this._featAt || 0) > FEAT_RECHECK_MS) {
        // 1.9.6: the website's features are only learned at "register" — if it was connected before
        // Seal Chat Web 1.3.2 and updated since, ask again (otherwise only the device that connected it ever answers)
        this._featAt = Date.now();
        try { await this._register(); } catch (e) { this.emit('log', 'web access: feature check: ' + e.message); }
      }
      if (!this._serves()) {
        // 1.9.3: shared, but the website is older than Seal Chat Web 1.3.2: only the device that connected it answers
        if (this.mode !== 'other') { this.mode = 'other'; this.sessions.clear(); this.error = null; this._changed(); }
        await this._sleep(60e3); continue;
      }
      try {
        if (Date.now() < this.activeUntil || (this.pairing && Date.now() < this.pairing.exp)) {
          const mode = this.standby ? 'standby' : 'active';
          if (this.mode !== mode) { this.mode = mode; this.error = null; this._changed(); }
          await this._poll();
          if (this.standby && this.running) await this._sleep(STANDBY_MS);
        } else {
          if (this.holding) await this._release();
          this.standby = null; this.claim = false;
          if (this.mode !== 'idle') { this.mode = 'idle'; this.sessions.clear(); this._changed(); this._shareSoon(); }
          if (this.pairing && Date.now() >= this.pairing.exp) { this.pairing = null; this._changed(); }
          if (this.st().rekeyDue) await this.rekey();      // 1.9.3: still to do after removing a device
          const woke = await this._checkWake();
          if (this.error) { this.error = null; this._changed(); }
          if (!woke) await this._sleep(this.idleMs());
        }
        backoff = 0;
      } catch (e) {
        if (await this._recover(e)) continue;
        this.error = e.message; this.errorCode = e.code || null;
        this.mode = 'error';
        this._changed();
        backoff = Math.min(backoff ? backoff * 2 : 15000, 300000);
        await this._sleep(backoff);
      }
    }
    this.mode = 'off';
  }

  /** IDLE: has the wake file changed? (304 = no; costs no PHP on the website). */
  async _checkWake() {
    const s = this.st();
    if (!s.wake) { await this._register(); }
    const tag = s.lastWakeTag || {};
    const headers = {};
    if (tag.etag) headers['If-None-Match'] = tag.etag;
    if (tag.lm) headers['If-Modified-Since'] = tag.lm;
    const r = await request(s.base + s.wake, { ...this._net(), headers, timeoutMs: 60000, maxBytes: 4096 });
    this.lastCheck = Date.now(); this.stats.checks++;
    if (r.status === 304) return false;
    if (r.status === 404) { const e = new Error('nobox'); e.code = 'nobox'; throw e; }
    if (r.status !== 200) {
      const e = new Error(`The website answered ${r.status} for the wake file`);
      if (this.viaTor() && [403, 429, 503].includes(r.status)) { e.message = `The website answered ${r.status} (blocked) to a visit through Tor — its host seems to block visitors that arrive through Tor.`; e.code = 'TOR_BLOCKED'; }
      throw e;
    }
    const body = sha256hex(r.body);
    const changed = tag.body !== body;
    s.lastWakeTag = { etag: r.headers.etag || null, lm: r.headers['last-modified'] || null, body };
    this.o.save();
    if (changed) { this.activeUntil = Date.now() + Math.min(2 * 60e3, this.activeMs()); this.claim = true; this.emit('log', 'web access: woken'); this.emit('woken'); return true; }   // 1.8.0: 'woken' → check the mailbox too · 1.9.3: claim
    return false;
  }

  /** ACTIVE: wait at relay.php for messages from devices. */
  async _poll() {
    const wait = this.o.waitS || WAIT_S;
    const body = { ack: this.ack, wait, until: Math.floor(this.activeUntil / 1000) };
    const lease = this._leaseOk();
    if (lease) {
      // 1.9.3: which of your devices answers the phone (relay.php section 6)
      const pairingHere = !!(this.pairing && Date.now() < this.pairing.exp);
      Object.assign(body, { node: this._node(), seq: this.outSeq, claim: this.claim || pairingHere || this.holding, force: pairingHere,
        view: [...this.sessions.keys()].filter(id => this._viewingHere(id)) });
    }
    const j = await this._call('recv', body, (wait + 40) * 1000);
    this.stats.polls++;
    this.lastCheck = Date.now();
    if (lease && j.standby) {
      // another of your devices answers: stand by (and know which phones are looking, so no notifications for them)
      const first = !this.standby;
      this.standby = { by: String(j.standby.by || ''), until: Number(j.standby.until || 0) * 1000, view: new Set((j.standby.view || []).map(String)), at: Date.now() };
      this.holding = false;
      this.sessions.clear();
      this.activeUntil = Math.max(this.activeUntil, Date.now() + 60e3);
      if (first) { this.mode = 'standby'; this._changed(); }
      return;
    }
    if (lease && j.released) { this.standby = null; this.holding = false; this.activeUntil = 0; this.claim = false; return; }   // the phone went quiet
    if (lease) {
      if (this.standby) { this.standby = null; this.mode = 'active'; this._changed(); }
      this.holding = true; this.claim = false;
      if (j.took) {                                     // took over from another of your devices
        this.ack = Math.max(this.ack, Number(j.took.ack) || 0);
        this.outSeq = Math.max(this.outSeq, (Number(j.took.seq) || 0) + SEQ_JUMP);
        this.emit('log', 'web access: answering the phone on this device now');
      }
    }
    for (const it of j.items || []) {
      this.ack = Math.max(this.ack, Number(it.id) || 0);
      try {
        if (/^d:/.test(it.f)) await this._fromDevice(it.f.slice(2), it.d);
        else if (/^t:/.test(it.f)) await this._fromPairing(it.f.slice(2), it.d);
      } catch (e) { this.emit('log', 'web access: ' + e.message); }
    }
  }

  /* =================================================================
   * 5. PAIRING
   * ================================================================= */
  /** Starts pairing: returns the link to show as a QR code (valid 10 minutes). */
  async startPairing() {
    const s = this.st();
    if (!s.box) throw new Error('First paste the connection link from your website');
    if (!this.enabled()) throw new Error('Turn web access on first');
    if (Object.keys(s.devices).length >= 10) throw new Error('You can pair up to 10 devices — remove one first');
    const P = crypto.randomBytes(32);
    const tid = crypto.randomBytes(8).toString('hex');
    const { pairKey, ticket } = pairSecrets(P);
    this.pairing = { tid, P, pairKey, ticket, exp: Date.now() + PAIR_MS, stage: 'waiting', cand: null };
    await this._syncAllow();
    this.kick(); this._changed();
    return { link: `${s.base}#pair=${s.box}.${tid}.${b64u(P)}`, exp: this.pairing.exp, tid };
  }

  cancelPairing() { this.pairing = null; this._syncAllow().catch(() => {}); this._changed(); }

  async _fromPairing(tid, data) {
    const p = this.pairing;
    if (!p || p.tid !== tid || Date.now() > p.exp) return;
    const m = open(p.pairKey, AAD.pair('d2c', tid), data);
    if (m.t !== 'pair' || p.stage !== 'waiting') return;
    const dev = String(m.dev || ''), pub = unb64u(m.pub), th = String(m.th || '');
    if (!/^[a-f0-9]{16}$/.test(dev) || pub.length !== 65 || !/^[a-f0-9]{64}$/.test(th)) throw new Error('bad pairing request');
    if (!/^\d{4,12}$/.test(String(m.pin || ''))) throw new Error('bad PIN');
    const ec = crypto.createECDH('prime256v1');
    ec.generateKeys();
    const shared = ec.computeSecret(pub);
    const { key, code } = deviceSecrets(shared, p.P, dev);
    const salt = crypto.randomBytes(16);
    p.cand = { dev, th, key, code, name: String(m.name || 'Browser').replace(/[\x00-\x1f]/g, '').slice(0, 40) || 'Browser', pin: { salt: b64u(salt), hash: b64u(await pbkdf2(m.pin, salt)), iter: PIN_ITER } };
    p.stage = 'confirm';
    await this._sendRaw('t:' + tid, [seal(p.pairKey, AAD.pair('c2d', tid), { t: 'pairKey', pub: b64u(ec.getPublicKey()) })]);
    this._changed();
    this.emit('pairRequest', { tid, name: p.cand.name, code });
  }

  /** You clicked Approve (after checking the code matches the one on the device). */
  async approvePairing(tid) {
    const p = this.pairing;
    if (!p || p.tid !== tid || p.stage !== 'confirm') throw new Error('That pairing request has expired');
    const c = p.cand, s = this.st();
    s.devices[c.dev] = { name: c.name, k: b64u(c.key), th: c.th, pin: c.pin, fails: 0, inSeq: 0, added: Date.now(), lastUsed: 0, cfg: Date.now() };   // 1.9.3: cfg
    if (s.gone) delete s.gone[c.dev];
    this.o.save();
    this._shareOut();                                 // 1.9.3: your other devices know this phone now
    p.stage = 'approved';
    await this._syncAllow();                  // the device's own token works from now on
    await this._sendRaw('t:' + tid, [seal(p.pairKey, AAD.pair('c2d', tid), { t: 'pairOk', name: c.name })]);
    this.activeUntil = Date.now() + this.activeMs();
    this._changed();
    return this.status();
  }

  async declinePairing(tid) {
    const p = this.pairing;
    if (!p || p.tid !== tid) return this.status();
    await this._sendRaw('t:' + tid, [seal(p.pairKey, AAD.pair('c2d', tid), { t: 'pairNo' })]).catch(() => {});
    p.stage = 'declined'; p.exp = Math.min(p.exp, Date.now() + 60e3);
    this._changed();
    return this.status();
  }

  async removeDevice(id) {
    const s = this.st();
    const d = s.devices[id];
    if (!d) return this.status();
    try { await this._send(id, { t: 'revoked', why: 'removed' }); } catch { /* offline */ }
    this._forgetDevice(id);
    await this._syncAllow([id]).catch(() => {});
    this._changed();
    return this.status();
  }

  /* =================================================================
   * 6. REQUESTS FROM A PAIRED DEVICE
   * ================================================================= */
  _sessionAlive(id) { const x = this.sessions.get(id); return !!x && Date.now() - x.at < SESSION_MS; }

  async _fromDevice(devId, data) {
    const s = this.st();
    const d = s.devices[devId];
    if (!d) return;
    const key = unb64u(d.k);
    let m;
    try { m = open(key, AAD.msg('d2c', devId), data); } catch { return; }   // not sealed with this device's key: ignore
    if (!(Number(m.s) > (d.inSeq || 0))) return;                            // old or repeated
    d.inSeq = Number(m.s); d.lastUsed = Date.now();
    this.o.save();
    this.activeUntil = Date.now() + this.activeMs();
    if (this.pairing && this.pairing.cand && this.pairing.cand.dev === devId) { this.pairing = null; this._syncAllow().catch(() => {}); }   // pairing finished
    const reply = o => this._send(devId, { ...o, re: m.q });

    if (m.t === 'hello') {
      if (d.fails >= 3) await new Promise(r => setTimeout(r, Math.min(10, d.fails) * 400));
      const ok = crypto.timingSafeEqual(await pbkdf2(String(m.pin || ''), unb64u(d.pin.salt)), unb64u(d.pin.hash));
      if (!ok) {
        d.fails = (d.fails || 0) + 1; d.failsAt = Date.now(); this.o.save();
        this._shareOut();                             // 1.9.3: wrong PINs count on all your devices together
        if (d.fails >= PIN_TRIES) {
          await reply({ t: 'revoked', why: 'pin' });
          this._forgetDevice(devId); await this._syncAllow([devId]).catch(() => {});
          this.emit('log', 'web access: device removed after too many wrong PINs');
        } else await reply({ t: 'badpin', left: PIN_TRIES - d.fails });
        this._changed();
        return;
      }
      if (d.fails) { d.fails = 0; d.failsAt = Date.now(); this._shareOut(); }
      this.o.save();
      const sid = b64u(crypto.randomBytes(18));
      this.sessions.set(devId, { sid, at: Date.now() });
      await reply({ t: 'welcome', sid, me: this.o.handler.me(), contacts: this.o.handler.contacts(), name: d.name, push: this._pushState(d), can: (this.o.handler.fileUp ? ['files'] : []).concat(this.o.handler.react ? ['react'] : []), fileMax: this.o.handler.fileMax || 0 });   // 1.7.0: can
      this._changed();
      return;
    }
    const sess = this.sessions.get(devId);
    if (m.t === 'bye') { if (sess && sess.sid === m.sid) this.sessions.delete(devId); this._quietCheck(); this._changed(); return; }
    if (!sess || sess.sid !== m.sid || !this._sessionAlive(devId)) { await reply({ t: 'relogin' }); return; }
    sess.at = Date.now();
    const h = this.o.handler;
    try {
      switch (m.t) {
        case 'ping': await reply({ t: 'pong' }); break;
        case 'contacts': await reply({ t: 'contacts', list: h.contacts() }); break;
        case 'history': await reply({ t: 'history', cid: m.cid, ...h.history(String(m.cid || ''), m.before || null) }); break;
        case 'send': await reply({ t: 'sent', cid: m.cid, tmp: m.tmp, msg: h.send(String(m.cid || ''), String(m.text || ''), m.re ? String(m.re).slice(0, 40) : undefined) }); break;
        case 'react': await reply({ t: 'reacted', msg: h.react(String(m.cid || ''), String(m.mid || ''), String(m.e || '').slice(0, 16)) }); break;   // 1.8.0
        case 'read': h.read(String(m.cid || '')); await reply({ t: 'ok' }); break;
        // ---- 1.6.0 contacts from the device (the computer does the work, same checks as its own window) ----
        case 'myId': await reply({ t: 'myId', ...(await h.myId()) }); break;
        case 'checkId': await reply({ t: 'checkId', ...(await h.checkId(String(m.text || '').slice(0, 400))) }); break;      // 1.8.0: async (name@domain)
        case 'addContact': await reply({ t: 'added', contact: await h.addContact(String(m.id || '').slice(0, 400), String(m.nick || '').slice(0, 80)) }); break;
        case 'contactDetails': await reply({ t: 'details', ...(await h.contactDetails(String(m.cid || ''))) }); break;
        case 'contactAct': await reply({ t: 'acted', cid: m.cid, act: m.act, contact: h.contactAct(String(m.cid || ''), String(m.act || ''), m.value) }); break;
        // ---- 1.7.0 files (webfiles.js, through the handler) ----
        case 'fileUp': await reply({ t: 'fileUp', ...(await h.fileUp(devId, m)) }); break;
        case 'fileUpPart': await reply({ t: 'fileUpPart', ...(await h.fileUpPart(devId, m)) }); break;
        case 'fileUpEnd': await reply({ t: 'sent', cid: m.cid, tmp: m.tmp, msg: await h.fileUpEnd(devId, m) }); break;
        case 'fileUpStop': await reply({ t: 'ok', ...h.fileUpStop(devId, m) }); break;
        case 'fileGet': await reply({ t: 'fileGet', ...(await h.fileGet(m)) }); break;
        case 'fileThumb': await reply({ t: 'fileThumb', ...h.fileThumb(m) }); break;
        case 'fileFetch': await reply({ t: 'fileFetch', ...h.fileFetch(m) }); break;
        // ---- 1.6.0 notifications (section 8) ----
        case 'pushKey': await reply({ t: 'pushKey', key: this._vapid().pub }); break;
        case 'pushOn': this._pushOn(devId, m.sub, m.names); await reply({ t: 'push', push: this._pushState(d) }); break;
        case 'pushOff': delete d.push; d.cfg = Date.now(); this.o.save(); this._shareOut(); this._changed(); await reply({ t: 'push', push: this._pushState(d) }); break;
        case 'pushNames': if (d.push) { d.push.names = !!m.names; d.cfg = Date.now(); this.o.save(); this._shareOut(); this._changed(); } await reply({ t: 'push', push: this._pushState(d) }); break;
        case 'pushTest': {
          const r = await this._pushTo(devId, { title: 'Seal Chat', body: 'Notifications are working on ' + d.name + '.', tag: 'sealchat-test' }, true);
          await reply({ t: 'pushTest', ok: r.ok, error: r.error || null });
          break;
        }
        case 'unpair':                        // "Unpair this device" on the device itself
          this._forgetDevice(devId);
          await this._syncAllow([devId]).catch(() => {}); this._changed();
          break;
        default: await reply({ t: 'err', error: 'This version of Seal Chat does not know "' + String(m.t).slice(0, 20) + '"' });
      }
    } catch (e) { await reply({ t: 'err', error: e.message, tmp: m.tmp }); }
  }

  /** No device open any more → go back to idle checks straight away. */
  _quietCheck() { if (![...this.sessions.keys()].some(id => this._sessionAlive(id)) && !this.pairing) this.activeUntil = Math.min(this.activeUntil, Date.now() + (this.o.quietMs || 20e3)); }

  /* =================================================================
   * 7. SENDING TO DEVICES
   * ================================================================= */
  _nextSeq() { this.outSeq = Math.max(Date.now() * 1000, this.outSeq + 1); return this.outSeq; }

  /** Seals and sends one message to a paired device (in order). */
  _send(devId, obj) {
    const d = this.st().devices[devId];
    if (!d) return Promise.resolve();
    const sealed = seal(unb64u(d.k), AAD.msg('c2d', devId), { ...obj, s: this._nextSeq() });
    return this._sendRaw('d:' + devId, [sealed]);
  }

  _sendRaw(to, items) {
    const prev = this.sendChains.get(to) || Promise.resolve();
    const next = prev.catch(() => {}).then(() => this._call('send', { to, items }));
    this.sendChains.set(to, next);
    next.finally(() => { if (this.sendChains.get(to) === next) this.sendChains.delete(to); }).catch(() => {});
    return next;
  }

  /* ---------- 1.8.0: the mailbox on your website ---------- */
  /** Where contacts leave messages: { url, box } — or null when this computer isn't connected to a website. */
  mailboxPlace() { const s = this.st(); return s.box && s.base && s.token ? { url: s.base, box: s.box } : null; }
  /** Turns the mailbox on (with the hash of the drop token contacts get) or off (null). */
  async mboxSet(dropToken) {
    if (!this.mailboxPlace()) throw new Error('Connect to your website first (Settings → Web access)');
    return this._call('mbox_set', { drop: dropToken ? sha256hex(dropToken) : null }, 30000);
  }
  /** Picks up waiting messages; ack = the last id already handled (deletes those). */
  async mboxGet(ack) {
    if (!this.mailboxPlace()) return { items: [], more: false };
    return this._call('mbox_get', { ack: Number(ack) || 0 }, 60000);
  }

  /** Live update for every device that has the web interface open right now. */
  push(obj) {
    if (this.mode !== 'active') return;
    for (const id of this.sessions.keys()) if (this._sessionAlive(id)) this._send(id, obj).catch(e => this.emit('log', 'web access push: ' + e.message));
  }
  hasViewers() { return this.mode === 'active' && [...this.sessions.keys()].some(id => this._sessionAlive(id)); }

  /* =================================================================
   * 8. NOTIFICATIONS (1.6.0)
   * ================================================================= */
  /** This computer's push key pair (made once, kept in the vault). */
  _vapid() { const s = this.st(); if (!s.vapid || !s.vapid.pub) { s.vapid = webpush.makeVapid(); s.vapidAt = Date.now(); this.o.save(); this._shareOut(); } return s.vapid; }   // 1.9.3: vapidAt
  _pushState(d) { return d.push ? { on: !!d.push.on, names: !!d.push.names, endpointTail: String(d.push.endpoint || '').slice(-12) } : { on: false, names: false }; }

  /** The device subscribed (or subscribed again with a new address). */
  _pushOn(devId, sub, names) {
    const d = this.st().devices[devId];
    const endpoint = String(sub && sub.endpoint || ''), keys = (sub && sub.keys) || {};
    const u = webpush.checkEndpoint(endpoint, !!this.o.allowHttp);
    if (unb64u(keys.p256dh).length !== 65 || unb64u(keys.auth).length < 16) throw new Error('The browser gave an incomplete notification subscription');
    const old = d.push || {};
    d.push = { endpoint, p256dh: String(keys.p256dh), auth: String(keys.auth), on: true, names: names == null ? !!old.names : !!names, svc: u.hostname, added: old.endpoint === endpoint ? old.added : Date.now(), lastOk: old.lastOk || 0, lastErr: null };
    d.cfg = Date.now();
    this.o.save(); this._shareOut(); this._changed();
  }

  /** Settings → Web access: notifications on/off and "show names" for one device. */
  setDevicePush(devId, patch) {
    const d = this.st().devices[devId];
    if (!d) throw new Error('That device is not paired any more');
    if (!d.push) throw new Error(`Notifications haven't been set up on "${d.name}" yet — turn them on there first (menu ⋯ → Notifications).`);
    if ('on' in patch) d.push.on = !!patch.on;
    if ('names' in patch) d.push.names = !!patch.names;
    d.cfg = Date.now();
    this.o.save(); this._shareOut(); this._changed();
    if (this._sessionAlive(devId)) this._send(devId, { t: 'push', push: this._pushState(d) }).catch(() => {});
    return this.status();
  }

  /** A device is looking at Seal Chat right now (no notification needed). */
  _viewingHere(devId) { const d = this.st().devices[devId]; return !!d && this._sessionAlive(devId) && this.mode === 'active' && Date.now() - (d.lastUsed || 0) < VIEWING_MS; }
  /** 1.9.3: …or through another of your devices (it says so while this one stands by). */
  _viewing(devId) { return this._viewingHere(devId) || !!(this.standby && Date.now() - this.standby.at < 2 * STANDBY_MS + 10e3 && this.standby.view.has(devId)); }

  /**
   * Something happened that's worth a notification.
   * @param ev { kind: 'msg' | 'request', name }  (name only used where a device allowed names)
   */
  notify(ev) {
    if (!this.enabled() || !this.st().box) return;
    for (const [id, d] of Object.entries(this.st().devices)) {
      if (!d.push || !d.push.on || this._viewing(id)) continue;
      if (Date.now() - (d.push.lastTry || 0) < PUSH_GAP_MS) continue;
      const who = d.push.names && ev.name ? String(ev.name).slice(0, 60) : '';
      const body = ev.kind === 'request' ? (who ? `${who} wants to chat with you` : 'New contact request') : (who ? `New message from ${who}` : 'New message');
      this._pushTo(id, { title: 'Seal Chat', body, tag: 'sealchat' }).catch(() => {});
    }
  }

  /** Sends one notification to one device; remembers how it went. */
  async _pushTo(devId, note, test) {
    const d = this.st().devices[devId];
    if (!d || !d.push) return { ok: false, error: 'not set up' };
    if (!test && !d.push.on) return { ok: false, error: 'off' };
    const socksPort = this.viaTor() ? this.o.socksPort() : null;
    if (this.viaTor() && !socksPort) return { ok: false, error: 'Tor is not connected yet' };
    d.push.lastTry = Date.now();
    try {
      const r = await webpush.send(d.push, note, { vapid: this._vapid(), subject: this.st().base || 'mailto:sealchat@localhost', socksPort, ca: this.o.ca, allowAny: !!this.o.allowHttp, topic: note.tag === 'sealchat' ? 'sealchat' : undefined, ttl: test ? 600 : undefined });
      if (r.gone) {                                   // the browser unsubscribed (or the app was deleted from the Home Screen)
        delete d.push; d.cfg = Date.now(); this.o.save(); this._shareOut(); this._changed();
        if (this._sessionAlive(devId)) this._send(devId, { t: 'push', push: this._pushState(d) }).catch(() => {});
        return { ok: false, error: 'The device has turned notifications off — turn them on again there.' };
      }
      if (r.status < 200 || r.status >= 300) throw new Error(`the push service answered ${r.status}${r.text ? ': ' + r.text.slice(0, 120) : ''}`);
      d.push.lastOk = Date.now(); d.push.lastErr = null; this.o.save(); this._changed();
      return { ok: true };
    } catch (e) {
      const msg = e.code === 'TOR_BLOCKED' ? 'The push service blocked the request through Tor — try with "Connect through Tor" off.' : e.message;
      d.push.lastErr = msg; this.o.save(); this._changed();
      this.emit('log', 'web access push to ' + d.name + ': ' + msg);
      return { ok: false, error: msg };
    }
  }

  /* =================================================================
   * 9. SHARED BY YOUR LINKED DEVICES (1.9.3)
   * The connection (website, mailbox id, token), the paired phones (keys,
   * PIN checks, notification subscriptions) and the notification key go to
   * your other devices in the encrypted device sync (peer.js, event "web").
   * Each phone entry has "cfg" (when its settings last changed) so the
   * newer one wins; "gone" remembers removed phones so a late sync can't
   * bring one back. If two of your devices were each connected to a website
   * on their own, ONE connection is kept for all: the one you connected
   * most recently with 1.9.3, else the one with more phones, else the
   * older one. The other device takes it off its website.
   * ================================================================= */
  _node() { return this.o.node ? this.o.node() || null : null; }
  _siblings() { try { return this.o.siblings ? Number(this.o.siblings()) || 0 : 0; } catch { return 0; } }
  _name(id) { try { return (this.o.nodeName && this.o.nodeName(id)) || 'your other device'; } catch { return 'your other device'; } }
  /** Shared with at least one linked device. */
  _shared() { return !!(this._node() && this._siblings() && this.st().box); }
  /** The website can pick ONE of your devices to answer the phone (Seal Chat Web 1.3.2+). */
  _leaseOk() { return this._shared() && (this.st().feat || []).includes('lease'); }
  /** Should this device answer the phone at all? (an older website: only the device that connected it) */
  _serves() {
    if (!this._shared() || this._leaseOk()) return true;
    const s = this.st();
    return !s.owner || s.owner === this._node();
  }
  /** The website's mailbox (contacts' messages) is set up by the device that connected it; the others only pick up. */
  ownsMailbox() { const s = this.st(); return !this._shared() || !s.owner || s.owner === this._node(); }
  async _release() {
    if (!this.holding) return;
    this.holding = false;
    try { await this._call('release', { node: this._node() }, 20000); } catch { /* it runs out by itself */ }
  }
  /** A phone is removed (here, by PIN, or on the phone): remembered as gone, for your other devices too. */
  _forgetDevice(id) {
    const s = this.st();
    delete s.devices[id]; this.sessions.delete(id);
    s.gone = s.gone || {}; s.gone[id] = Date.now();
    this.o.save();
    this._shareOut();
  }

  /** What your other devices get (null = not connected). */
  shareable() {
    const s = this.st(), S = this.S();
    if (!s.box) return null;
    const devices = {};
    for (const [id, d] of Object.entries(s.devices || {})) {
      const c = { ...d };
      if (c.push) { c.push = { ...c.push }; delete c.push.lastTry; }
      devices[id] = c;
    }
    const gone = {};
    for (const [id, t] of Object.entries(s.gone || {})) if (Date.now() - t < GONE_KEEP) gone[id] = t;
    return { v: 1, base: s.base, code: s.code, box: s.box, token: s.token, kver: s.kver || 0, wake: s.wake || null, feat: s.feat || [],
      owner: s.owner || null, since: s.since || 0, chosen: s.chosen || 0, ver: s.ver || 0, gone, devices,
      vapid: s.vapid || null, vapidAt: s.vapidAt || 0, onAt: s.onAt || 0, enabled: !!S.webEnabled, until: S.webUntil || null };
  }
  /** Sends the shared state to your other devices (a moment later, so a burst of changes is one sync). */
  _shareOut() {
    if (!this.o.syncOut || !this._siblings() || !this.st().box) return;
    clearTimeout(this._shareTimer);
    this._shareTimer = setTimeout(() => {
      this._shareTimer = null;
      const w = this.shareable();
      if (!w) return;
      w.ver = this.st().ver = Date.now();
      this.o.save();
      try { this.o.syncOut(w); } catch (e) { this.emit('log', 'web access sync: ' + e.message); }
    }, this.o.shareDelayMs != null ? this.o.shareDelayMs : 1500);
    if (this._shareTimer.unref) this._shareTimer.unref();
  }
  /** After answering the phone a while: the counters (last used, message numbers) to your other devices. */
  _shareSoon() { if (this._shared()) this._shareOut(); }
  /** At start (and when a device was linked): make sure your other devices have it. */
  shareNow() { if (this._shared()) this._shareOut(); }

  /** Checks what another of your devices sent (it's your own, but stay strict about the shape). */
  _cleanShared(w) {
    const hex = (x, n) => typeof x === 'string' && new RegExp('^[a-f0-9]{' + n + '}$').test(x);
    const str = (x, max) => typeof x === 'string' && x.length > 0 && x.length <= max;
    if (!w || typeof w !== 'object' || !hex(w.box, 32) || !str(w.token, 200) || !str(w.code, 60) || !str(w.base, 400)) return null;
    if (!/^https:\/\//i.test(w.base) && !(this.o.allowHttp && /^http:\/\//i.test(w.base))) return null;
    const devices = {};
    for (const [id, d] of Object.entries(w.devices && typeof w.devices === 'object' ? w.devices : {}).slice(0, 20)) {
      if (!hex(id, 16) || !d || typeof d !== 'object' || !str(d.k, 100) || !hex(d.th, 64) || !d.pin || typeof d.pin !== 'object') continue;
      devices[id] = { ...d, name: String(d.name || 'Browser').slice(0, 40) };
    }
    const gone = {};
    for (const [id, t] of Object.entries(w.gone && typeof w.gone === 'object' ? w.gone : {}).slice(0, 200)) if (hex(id, 16) && Number(t) > 0) gone[id] = Number(t);
    const n = x => Number(x) || 0;
    return { base: w.base, code: w.code, box: w.box, token: w.token, kver: n(w.kver), wake: typeof w.wake === 'string' && /^wake\/[a-f0-9]{32}\.txt$/.test(w.wake) ? w.wake : null,
      feat: Array.isArray(w.feat) ? w.feat.filter(x => typeof x === 'string').slice(0, 20) : [], owner: typeof w.owner === 'string' ? w.owner.slice(0, 64) : null,
      since: n(w.since), chosen: n(w.chosen), ver: n(w.ver), gone, devices,
      vapid: w.vapid && typeof w.vapid === 'object' && str(w.vapid.pub, 200) ? w.vapid : null, vapidAt: n(w.vapidAt),
      onAt: n(w.onAt), enabled: !!w.enabled, until: n(w.until) || null };
  }
  /** Which connection to keep when two of your devices had different ones. true = a wins. */
  _wins(a, b) {
    const cnt = x => Object.keys(x.devices || {}).length;
    if ((a.chosen || 0) !== (b.chosen || 0)) return (a.chosen || 0) > (b.chosen || 0);
    if (cnt(a) !== cnt(b)) return cnt(a) > cnt(b);
    if ((a.since || 0) !== (b.since || 0)) return (a.since || Infinity) < (b.since || Infinity);
    return a.box < b.box;
  }
  /** Uses another device's connection instead of (or in place of nothing on) this one. */
  _adopt(inc) {
    const s = this.st();
    for (const k of Object.keys(s)) delete s[k];
    const { enabled, until, ...keep } = inc;
    Object.assign(s, keep, { lastWakeTag: null });
    this.ack = 0; this.sessions.clear(); this.standby = null; this.holding = false; this.pairing = null;
    this.o.setSettings({ webEnabled: !!enabled && !(until && Date.now() > until), webUntil: until || undefined });
    this.o.save();
    this.emit('log', 'web access: using the connection shared by your other device');
    this.kick(); this._changed();
  }

  /** The shared state from another of your devices (peer.js sync event "web"). */
  async applyShared(w) {
    const s = this.st();
    if (w && w.off) {                                 // turned off / disconnected there
      if (s.box && s.box === w.box && (Number(w.ver) || 0) > (s.ver || 0)) this.forgetLocal('disconnected on your other device');
      return this.status();
    }
    const inc = this._cleanShared(w);
    if (!inc) return this.status();
    if (!s.box) { this._adopt(inc); return this.status(); }
    if (s.box !== inc.box) {
      if (this._wins(s, inc)) { this._shareOut(); return this.status(); }      // ours is kept — the other device switches
      try { await this._call('unregister', {}); } catch { /* gone already */ }
      this._adopt(inc);
      return this.status();
    }
    // the same connection: merge
    const newer = inc.ver > (s.ver || 0);
    if (inc.kver > (s.kver || 0)) { s.token = inc.token; s.kver = inc.kver; if (inc.owner) s.owner = inc.owner; if (this.mode === 'error') this.error = null; }
    if (newer) { s.code = inc.code; if (inc.feat.length) s.feat = inc.feat; s.ver = inc.ver; }
    if (!s.wake && inc.wake) s.wake = inc.wake;
    if (!s.owner && inc.owner) s.owner = inc.owner;
    if (inc.chosen > (s.chosen || 0)) s.chosen = inc.chosen;
    if (inc.vapid && (!s.vapid || (s.vapid.pub !== inc.vapid.pub && (inc.vapidAt || Infinity) < (s.vapidAt || Infinity)))) { s.vapid = inc.vapid; s.vapidAt = inc.vapidAt; }
    s.gone = s.gone || {};
    for (const [id, t] of Object.entries(inc.gone)) s.gone[id] = Math.max(s.gone[id] || 0, t);
    const before = JSON.stringify(Object.keys(s.devices).sort());
    for (const [id, b] of Object.entries(inc.devices)) {
      const a = s.devices[id];
      if (!a) { s.devices[id] = { ...b }; continue; }
      if ((b.cfg || b.added || 0) > (a.cfg || a.added || 0)) {
        const lastTry = a.push && a.push.lastTry;
        Object.assign(a, { name: b.name, k: b.k, th: b.th, pin: b.pin, added: b.added, cfg: b.cfg });
        if (b.push) a.push = { ...b.push, ...(lastTry ? { lastTry } : {}) }; else delete a.push;
      }
      a.inSeq = Math.max(a.inSeq || 0, b.inSeq || 0);
      a.lastUsed = Math.max(a.lastUsed || 0, b.lastUsed || 0);
      if ((b.failsAt || 0) > (a.failsAt || 0)) { a.fails = b.fails || 0; a.failsAt = b.failsAt; }
    }
    const removed = [];
    for (const [id, t] of Object.entries(s.gone)) {
      const d = s.devices[id];
      if (d && t >= (d.cfg || d.added || 0)) { delete s.devices[id]; this.sessions.delete(id); removed.push(id); }
      if (Date.now() - t > GONE_KEEP) delete s.gone[id];
    }
    if (inc.onAt > (s.onAt || 0)) {
      s.onAt = inc.onAt;
      this.o.setSettings({ webEnabled: inc.enabled && !(inc.until && Date.now() > inc.until), webUntil: inc.until || undefined });
      if (!inc.enabled) { this.sessions.clear(); this.activeUntil = 0; this._release(); }
    }
    this.o.save();
    if (before !== JSON.stringify(Object.keys(s.devices).sort()) && this.enabled() && this._serves()) this._syncAllow(removed).catch(() => {});
    this.kick(); this._changed();
    return this.status();
  }

  /** A new computer token on the website — after you removed one of your devices (it had the old one). */
  async rekey() {
    const s = this.st();
    if (!s.box) return false;
    if (!(s.feat || []).includes('rekey')) { s.rekeyDue = false; this.o.save(); this.emit('log', 'web access: Seal Chat Web 1.3.2 is needed to change the key after removing a device'); return false; }
    try {
      const tok = b64u(crypto.randomBytes(32));
      await this._call('rekey', { token: tok }, 30000);
      s.token = tok; s.kver = Date.now(); s.owner = this._node() || s.owner; delete s.rekeyDue;
      this.o.save();
      this._shareOut();
      this.emit('log', 'web access: new key on the website');
      return true;
    } catch (e) {
      s.rekeyDue = true; this.o.save();               // tried again on the next idle check
      this.emit('log', 'web access: new key not set yet: ' + e.message);
      return false;
    }
  }

  /** This device was removed from your ID: it stops using the shared connection (without touching the website). */
  forgetLocal(why) {
    const s = this.st();
    if (!s.box) return;
    for (const k of Object.keys(s)) delete s[k];
    s.devices = {};
    this.sessions.clear(); this.pairing = null; this.standby = null; this.holding = false; this.activeUntil = 0;
    this.o.setSettings({ webEnabled: false, webUntil: undefined });
    this.o.save();
    this.emit('log', 'web access: off on this device (' + (why || 'removed') + ')');
    this.kick(); this._changed();
  }
}

module.exports = { WebAccess, parseLink, seal, open, AAD, pairSecrets, deviceSecrets, b64u, unb64u, sha256hex };
