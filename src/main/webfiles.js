/* =====================================================================
 * Seal Chat — webfiles.js   (files in Seal Chat Web, 1.7.0)
 * ---------------------------------------------------------------------
 * Lets a paired phone (Seal Chat Web 1.2.0+) send and open files, the
 * same as this window can. The phone never talks to your contact
 * directly: files go phone ⇄ your website's relay ⇄ this computer, in
 * pieces of 512 KB, each sealed with the device's key (like every other
 * web-access message), and this computer sends / receives them over
 * Tor exactly as it does for files you pick here.
 *
 *   PHONE → CONTACT   fileUp      start: chat, name, size, type
 *                     fileUpPart  one piece (in order, a few in flight)
 *                     fileUpEnd   all pieces here → sent like any file
 *                     fileUpStop  cancelled on the phone
 *   CONTACT → PHONE   fileGet     one piece of a file that is complete
 *                                 on this computer (images, downloads)
 *                     fileThumb   the small preview of a photo
 *                     fileFetch   "download it" (this computer fetches
 *                                 it from the contact first)
 *
 * Limits: 100 MB per file from/to the phone, 3 uploads at once per
 * device. Pieces being received are kept in  <Seal Chat data>/web-up/
 * (deleted as soon as the file is in Seal Chat's encrypted storage, or
 * after 15 minutes without a new piece, or at start-up).
 *
 * Sections:
 *   1. Sizes + set-up
 *   2. From the phone (uploads)
 *   3. To the phone (pieces, previews, "download it")
 *   4. Tidying up
 * ===================================================================== */

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { safeName } = require('./files');

/* =================================================================
 * 1. SIZES + SET-UP
 * ================================================================= */
const PART = 512 * 1024;                 // bytes per piece between phone and computer
const WEB_FILE_MAX = 100 * 1024 * 1024;  // largest file to / from the phone
const UP_IDLE_MS = 15 * 60e3;            // forget an upload this long after its last piece
const UP_PER_DEVICE = 3;

class WebFiles {
  /**
   * @param o { peer, files (FileVault), dir (temp folder), mimeOf(name),
   *            thumbFor(path, name) → data URL|null, webMsg(m), onSent(cid, msg) }
   */
  constructor(o) {
    this.o = o;
    this.ups = new Map();                // up id → { dev, cid, name, mime, size, n, got:Set, tmp, at }
    fs.mkdirSync(o.dir, { recursive: true });
    try { fs.chmodSync(o.dir, 0o700); } catch { /* Windows */ }
    this.cleanAll();
    this.timer = setInterval(() => this.expire(), 60e3);
    if (this.timer.unref) this.timer.unref();
  }

  /* =================================================================
   * 2. FROM THE PHONE
   * ================================================================= */
  /** fileUp: { cid, name, size, mime } → { up, part, n } */
  async upStart(dev, m) {
    const cid = String(m.cid || ''), size = Number(m.size);
    const c = this.o.peer.store.contact(cid);
    if (!c) throw new Error('Unknown contact');
    if (c.status === 'blocked') throw new Error('You blocked this contact');
    if (c.status === 'pending-in') throw new Error('Accept their request first');
    if (!Number.isInteger(size) || size <= 0) throw new Error('That file is empty');
    if (size > WEB_FILE_MAX) throw new Error(`Files from your phone can be up to ${WEB_FILE_MAX / 1048576} MB — send bigger ones from your computer`);
    const maxMB = Number(this.o.peer.store.settings.maxFileMB ?? 2048);
    if (size > maxMB * 1048576) throw new Error(`The largest file you can send is ${maxMB} MB (Settings → Files on your computer)`);
    if ([...this.ups.values()].filter(u => u.dev === dev).length >= UP_PER_DEVICE) throw new Error('Wait until the files being sent have finished');
    if (this.o.files.freeSpace() < size * 2 + 50 * 1048576) throw new Error('Not enough free disk space on your computer');
    const up = crypto.randomBytes(12).toString('hex');
    const name = safeName(m.name || 'file');
    const tmp = path.join(this.o.dir, up + '.part');
    const fh = await fsp.open(tmp, 'w', 0o600);
    await fh.truncate(size); await fh.close();
    this.ups.set(up, { dev, cid, name, mime: String(m.mime || '').slice(0, 100) || this.o.mimeOf(name), size, n: Math.ceil(size / PART), got: new Set(), tmp, at: Date.now() });
    return { up, part: PART, n: Math.ceil(size / PART) };
  }

  _up(dev, id) {
    const u = this.ups.get(String(id || ''));
    if (!u || u.dev !== dev) throw new Error('That upload has expired — send the file again');
    return u;
  }

  /** fileUpPart: { up, i, d (base64) } → { up, i, got } */
  async upPart(dev, m) {
    const u = this._up(dev, m.up);
    const i = Number(m.i);
    if (!Number.isInteger(i) || i < 0 || i >= u.n) throw new Error('bad piece number');
    const buf = Buffer.from(String(m.d || ''), 'base64');
    const want = i < u.n - 1 ? PART : u.size - (u.n - 1) * PART;
    if (buf.length !== want) throw new Error('bad piece size');
    const fh = await fsp.open(u.tmp, 'r+');
    try { await fh.write(buf, 0, buf.length, i * PART); } finally { await fh.close(); }
    u.got.add(i); u.at = Date.now();
    return { up: m.up, i, got: u.got.size };
  }

  /** fileUpEnd: { up, text } → the new message (as the web interface sees it) */
  async upEnd(dev, m) {
    const u = this._up(dev, m.up);
    if (u.got.size !== u.n) throw new Error(`Only ${u.got.size} of ${u.n} pieces arrived — send the file again`);
    this.ups.delete(m.up);
    let thumb = null;
    try { thumb = this.o.thumbFor(u.tmp, u.name); } catch { /* no preview */ }
    return new Promise((resolve, reject) => {
      let added = false;
      this.o.peer.sendFile(u.cid, { path: u.tmp }, { name: u.name, mime: u.mime, thumb, text: String(m.text || ''), re: m.re ? String(m.re).slice(0, 40) : undefined }   /* 1.8.0: re = reply */, msg => {
        added = true;
        if (this.o.onSent) this.o.onSent(u.cid, msg);
        resolve(this.o.webMsg(msg, u.cid));
      })
        .catch(e => { if (!added) reject(e); })
        .finally(() => fsp.unlink(u.tmp).catch(() => {}));   // now in Seal Chat's encrypted storage
    });
  }

  /** fileUpStop: { up } */
  upStop(dev, m) {
    const u = this.ups.get(String(m.up || ''));
    if (u && u.dev === dev) { this.ups.delete(m.up); fsp.unlink(u.tmp).catch(() => {}); }
    return { up: m.up };
  }

  /* =================================================================
   * 3. TO THE PHONE
   * ================================================================= */
  _known(cid) { if (!this.o.peer.store.contact(String(cid || ''))) throw new Error('Unknown contact'); return String(cid); }

  _msg(cid, id) {
    const m = this.o.peer.store.chat(this._known(cid)).messages.find(x => x.id === String(id || '') && x.kind === 'file');
    if (!m) throw new Error('File not found');
    return m;
  }

  /** fileGet: { cid, id, i } → { cid, id, i, n, size, d } — the file must be complete here */
  async get(m) {
    const ref = this.o.peer.fileRef(this._known(m.cid), String(m.id || ''));
    const meta = ref.meta;
    if (meta.size > WEB_FILE_MAX) throw new Error(`This file is ${Math.round(meta.size / 1048576)} MB — files over ${WEB_FILE_MAX / 1048576} MB can only be opened on your computer`);
    const n = Math.max(1, Math.ceil(meta.size / PART));
    const i = Number(m.i);
    if (!Number.isInteger(i) || i < 0 || i >= n) throw new Error('bad piece number');
    const start = i * PART, end = Math.min(meta.size, start + PART) - 1;
    const parts = [];
    if (meta.size > 0) for await (const b of this.o.files.plainStream(ref.where, ref.msg.id, meta, start, end)) parts.push(b);
    return { cid: m.cid, id: m.id, i, n, size: meta.size, name: meta.name, mime: meta.mime, d: Buffer.concat(parts).toString('base64') };
  }

  /** fileThumb: { cid, id } → { cid, id, thumb } (a small JPEG preview, or null) */
  thumb(m) {
    const msg = this._msg(m.cid, m.id);
    return { cid: m.cid, id: m.id, thumb: (msg.file && msg.file.thumb) || null };
  }

  /** fileFetch: { cid, id } — an incoming file: this computer downloads it from the contact */
  fetch(m) {
    const msg = this.o.peer.download(this._known(m.cid), String(m.id || ''));
    return { cid: m.cid, id: m.id, msg: this.o.webMsg(msg, String(m.cid)) };
  }

  /* =================================================================
   * 4. TIDYING UP
   * ================================================================= */
  expire() {
    for (const [id, u] of this.ups) if (Date.now() - u.at > UP_IDLE_MS) { this.ups.delete(id); fsp.unlink(u.tmp).catch(() => {}); }
  }
  /** A device was removed: forget its uploads. */
  dropDevice(dev) { for (const [id, u] of this.ups) if (u.dev === dev) { this.ups.delete(id); fsp.unlink(u.tmp).catch(() => {}); } }
  cleanAll() { for (const f of fs.readdirSync(this.o.dir)) if (f.endsWith('.part')) { try { fs.unlinkSync(path.join(this.o.dir, f)); } catch { /* ignore */ } } }
  stop() { clearInterval(this.timer); }
}

module.exports = { WebFiles, PART, WEB_FILE_MAX };
