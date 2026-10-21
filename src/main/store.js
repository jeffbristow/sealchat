/* =====================================================================
 * Seal Chat — store.js   (everything saved on this PC, 1.0.0)
 * ---------------------------------------------------------------------
 * Files in %APPDATA%\Seal Chat\ :
 *   settings.json   ordinary preferences (window size, sounds, …) — no secrets
 *   key.bin         the random "data key", locked to your Windows account
 *                   (Windows DPAPI via Electron safeStorage)
 *   vault.dat       your identity (PGP key + passphrase), your .onion key
 *                   and your contacts — encrypted with the data key
 *   chats\*.dat     one file per conversation — encrypted with the data key
 *
 * Encryption: AES-256-GCM, a fresh random IV every save, file name as
 * extra authenticated data (a file can't be swapped for another one).
 * Saves are atomic (write a temp file, then rename) so a crash or power
 * cut can't leave half a file.
 *
 * Sections:
 *   1. Low-level encrypted files
 *   2. Data key (protected by Windows)
 *   3. Store class: settings, vault, chats
 *   4. Delayed (batched) saving
 * ===================================================================== */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* =================================================================
 * 1. ENCRYPTED FILES
 * ================================================================= */
const MAGIC = Buffer.from('SCH1');

function sealBuf(key, plain, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([MAGIC, iv, c.getAuthTag(), ct]);
}

function openBuf(key, data, aad) {
  if (data.length < 32 || !data.subarray(0, 4).equals(MAGIC)) throw new Error('not a Seal Chat file');
  const iv = data.subarray(4, 16), tag = data.subarray(16, 32), ct = data.subarray(32);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(Buffer.from(aad)); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

function writeAtomic(file, data, mode = 0o600) {
  const tmp = file + '.' + process.pid + '.tmp';
  fs.writeFileSync(tmp, data, { mode });
  fs.renameSync(tmp, file);
}

/* =================================================================
 * 3. STORE
 * ================================================================= */
class Store {
  /**
   * @param {string} dir  data folder
   * @param {object} protect { encrypt(Buffer)->Buffer, decrypt(Buffer)->Buffer, strong:boolean } — Windows DPAPI
   */
  constructor(dir, protect) {
    this.dir = dir;
    this.protect = protect;
    fs.mkdirSync(path.join(dir, 'chats'), { recursive: true });
    try { fs.chmodSync(dir, 0o700); } catch { /* Windows */ }
    this.settings = this._readJson('settings.json') || {};
    this.key = this._dataKey();
    this.vault = this._readEnc('vault.dat') || { identity: null, onionKey: null, contacts: {} };
    if (!this.vault.contacts) this.vault.contacts = {};
    this.chats = new Map();         // contactId -> { messages: [] }
    this.dirty = new Set();
    this.timer = null;
  }

  /* ---------- 2. data key ---------- */
  _dataKey() {
    const f = path.join(this.dir, 'key.bin');
    if (fs.existsSync(f)) {
      const j = JSON.parse(fs.readFileSync(f, 'utf8'));
      const raw = Buffer.from(j.data, 'base64');
      const key = j.kind === 'protected' ? this.protect.decrypt(raw) : raw;
      // upgrade: Windows protection became available after the fact
      if (j.kind !== 'protected' && this.protect.strong) writeAtomic(f, JSON.stringify({ v: 1, kind: 'protected', data: this.protect.encrypt(key).toString('base64') }));
      return key;
    }
    const key = crypto.randomBytes(32);
    const rec = this.protect.strong
      ? { v: 1, kind: 'protected', data: this.protect.encrypt(key).toString('base64') }
      : { v: 1, kind: 'plain', data: key.toString('base64') };
    writeAtomic(f, JSON.stringify(rec));
    return key;
  }

  get protectedByOs() { return !!this.protect.strong; }

  /* ---------- helpers ---------- */
  _readJson(name) { try { return JSON.parse(fs.readFileSync(path.join(this.dir, name), 'utf8')); } catch { return null; } }
  _readEnc(rel) {
    const f = path.join(this.dir, rel);
    if (!fs.existsSync(f)) return null;
    return JSON.parse(openBuf(this.key, fs.readFileSync(f), rel.replace(/\\/g, '/')).toString('utf8'));
  }
  _writeEnc(rel, obj) {
    writeAtomic(path.join(this.dir, rel), sealBuf(this.key, Buffer.from(JSON.stringify(obj), 'utf8'), rel.replace(/\\/g, '/')));
  }

  /* ---------- settings (plain) ---------- */
  setSettings(patch) {
    this.settings = { ...this.settings, ...patch };
    for (const k of Object.keys(this.settings)) if (this.settings[k] === undefined) delete this.settings[k];
    writeAtomic(path.join(this.dir, 'settings.json'), JSON.stringify(this.settings, null, 2));
    return this.settings;
  }

  /* ---------- vault ---------- */
  saveVault() { this.dirty.add('vault'); this._soon(); }

  contact(id) { return this.vault.contacts[id] || null; }
  contacts() { return Object.values(this.vault.contacts); }
  putContact(c) { this.vault.contacts[c.id] = c; this.saveVault(); return c; }
  removeContact(id) {
    delete this.vault.contacts[id];
    this.chats.delete(id);
    try { fs.unlinkSync(path.join(this.dir, 'chats', chatFile(id))); } catch { /* none */ }
    this.saveVault();
  }

  /* ---------- chats ---------- */
  chat(id) {
    let c = this.chats.get(id);
    if (!c) {
      try { c = this._readEnc(path.join('chats', chatFile(id))); } catch (e) { console.error('chat unreadable', id, e.message); c = null; }
      if (!c || !Array.isArray(c.messages)) c = { messages: [] };
      this.chats.set(id, c);
    }
    return c;
  }
  saveChat(id) { this.dirty.add('chat:' + id); this._soon(); }

  /* ---------- 4. batched saving ---------- */
  _soon() { if (!this.timer) this.timer = setTimeout(() => this.flush(), 400); }
  flush() {
    clearTimeout(this.timer); this.timer = null;
    for (const d of this.dirty) {
      try {
        if (d === 'vault') this._writeEnc('vault.dat', this.vault);
        else { const id = d.slice(5); if (this.chats.has(id)) this._writeEnc(path.join('chats', chatFile(id)), this.chats.get(id)); }
      } catch (e) { console.error('save failed', d, e.message); }
    }
    this.dirty.clear();
  }

  /** Deletes everything (used by "Reset Seal Chat"). */
  wipe() {
    this.flush();
    for (const f of fs.readdirSync(path.join(this.dir, 'chats'))) { try { fs.unlinkSync(path.join(this.dir, 'chats', f)); } catch { /* ignore */ } }
    for (const f of ['vault.dat', 'key.bin']) { try { fs.unlinkSync(path.join(this.dir, f)); } catch { /* ignore */ } }
  }
}

/** Contact ids are fingerprints (hex) — safe as file names; hashed anyway. */
function chatFile(id) { return crypto.createHash('sha256').update(String(id)).digest('hex').slice(0, 32) + '.dat'; }

module.exports = { Store, sealBuf, openBuf };
