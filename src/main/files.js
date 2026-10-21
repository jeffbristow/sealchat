/* =====================================================================
 * Seal Chat — files.js   (encrypted file storage, 1.1.0)
 * ---------------------------------------------------------------------
 * Every file you send or receive is kept in  %APPDATA%\Seal Chat\files\
 * as a series of encrypted PIECES (256 KB each):
 *
 *   - each file has its own random 256-bit key, stored only inside the
 *     (encrypted) chat history — never next to the file
 *   - each piece is sealed with AES-256-GCM; its nonce and "extra data"
 *     include the piece number and the file's message id, so pieces can't
 *     be swapped, reordered, dropped or altered without being detected
 *   - the SAME sealed pieces travel over Tor, so the receiver stores
 *     exactly what arrived (no re-encryption) and can resume a broken
 *     transfer from the last good piece
 *   - pieces can be decrypted one at a time, so videos can be played and
 *     scrolled through without unpacking the whole file
 *
 * Sections:
 *   1. Sizes + file names
 *   2. Piece encryption
 *   3. Bringing a file in (sending)
 *   4. Reading back (pieces for transfer, plain bytes for viewing / saving)
 *   5. Tidying up + disk usage
 * ===================================================================== */

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { Readable } = require('stream');

/* =================================================================
 * 1. SIZES + NAMES
 * ================================================================= */
const PIECE = 256 * 1024;     // plain bytes per piece
const TAG = 16;               // AES-GCM tag added to each piece
const SLOT = PIECE + TAG;     // bytes per stored piece

const piecesFor = size => Math.ceil(size / PIECE);
/** Length of piece i when stored (encrypted). */
const slotLen = (meta, i) => (i < meta.pieces - 1 ? PIECE : meta.size - (meta.pieces - 1) * PIECE) + TAG;
/** Full size of the stored file when complete. */
const storedSize = meta => meta.size + meta.pieces * TAG;

/** Makes a received file name safe to show and to save under. */
function safeName(name) {
  let n = String(name || 'file').split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, '_').replace(/^[.\s]+|[.\s]+$/g, '').trim();
  if (/^(con|prn|aux|nul|com\d|lpt\d)(\.|$)/i.test(n)) n = '_' + n;
  if (n.length > 180) { const ext = path.extname(n).slice(0, 20); n = n.slice(0, 180 - ext.length) + ext; }
  return n || 'file';
}

/** Program-like files: never opened directly from Seal Chat. */
const RISKY = /\.(exe|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|msi|msp|scr|pif|cpl|hta|jar|lnk|reg|inf|dll|sys|appx|msix|appinstaller|application|gadget|iso|img|vhd|vhdx|docm|xlsm|pptm|chm|url|scf|settingcontent-ms)$/i;
const isRisky = name => RISKY.test(String(name || ''));

/* =================================================================
 * 2. PIECE ENCRYPTION
 * ================================================================= */
/** New per-file secrets. */
function newSecrets() {
  return { key: crypto.randomBytes(32).toString('base64'), nonce: crypto.randomBytes(8).toString('base64') };
}

function ivFor(meta, i) {
  const iv = Buffer.alloc(12);
  Buffer.from(meta.nonce, 'base64').copy(iv, 0, 0, 8);
  iv.writeUInt32BE(i, 8);
  return iv;
}
const aadFor = (fileId, meta, i) => Buffer.from(`sealchat-file-v1|${fileId}|${i}|${meta.pieces}|${meta.size}`);

function sealPiece(meta, fileId, i, plain) {
  const c = crypto.createCipheriv('aes-256-gcm', Buffer.from(meta.key, 'base64'), ivFor(meta, i));
  c.setAAD(aadFor(fileId, meta, i));
  return Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
}

/** Decrypts one stored/received piece; throws if it was changed in any way. */
function openPiece(meta, fileId, i, sealed) {
  if (sealed.length !== slotLen(meta, i)) throw new Error('piece has the wrong size');
  const d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(meta.key, 'base64'), ivFor(meta, i));
  d.setAAD(aadFor(fileId, meta, i));
  d.setAuthTag(sealed.subarray(sealed.length - TAG));
  return Buffer.concat([d.update(sealed.subarray(0, sealed.length - TAG)), d.final()]);
}

/* =================================================================
 * FILE VAULT
 * `where` = "<contactId>|<messageId>" — decides the file's name on disk.
 * ================================================================= */
class FileVault {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true });
    try { fs.chmodSync(dir, 0o700); } catch { /* Windows */ }
  }

  pathFor(where) { return path.join(this.dir, crypto.createHash('sha256').update(String(where)).digest('hex').slice(0, 40) + '.scf'); }
  has(where) { try { return fs.statSync(this.pathFor(where)).isFile(); } catch { return false; } }
  sizeOnDisk(where) { try { return fs.statSync(this.pathFor(where)).size; } catch { return 0; } }

  /* =================================================================
   * 3. BRINGING A FILE IN (sending)
   * source: { path } or { buffer }. Returns meta { size, pieces, key, nonce }.
   * ================================================================= */
  async importFile(where, fileId, source, onProgress) {
    const size = source.buffer ? source.buffer.length : (await fsp.stat(source.path)).size;
    const meta = { size, pieces: piecesFor(size), ...newSecrets() };
    const out = this.pathFor(where);
    const tmp = out + '.part';
    const fh = await fsp.open(tmp, 'w', 0o600);
    try {
      let src = null;
      if (!source.buffer) src = await fsp.open(source.path, 'r');
      try {
        const buf = Buffer.allocUnsafe(PIECE);
        for (let i = 0; i < meta.pieces; i++) {
          const len = i < meta.pieces - 1 ? PIECE : size - i * PIECE;
          let plain;
          if (source.buffer) plain = source.buffer.subarray(i * PIECE, i * PIECE + len);
          else {
            let got = 0;
            while (got < len) { const r = await src.read(buf, got, len - got, i * PIECE + got); if (!r.bytesRead) throw new Error('The file changed while it was being read'); got += r.bytesRead; }
            plain = buf.subarray(0, len);
          }
          await fh.write(sealPiece(meta, fileId, i, plain));
          if (onProgress && (i % 8 === 7 || i === meta.pieces - 1)) onProgress((i + 1) * PIECE > size ? size : (i + 1) * PIECE, size);
        }
      } finally { if (src) await src.close(); }
    } finally { await fh.close(); }
    await fsp.rename(tmp, out);
    return meta;
  }

  /* =================================================================
   * 4. READING BACK
   * ================================================================= */
  /** One stored (still encrypted) piece, exactly as it goes over the wire. */
  async readSealed(where, meta, i) {
    const fh = await fsp.open(this.pathFor(where), 'r');
    try {
      const len = slotLen(meta, i);
      const buf = Buffer.allocUnsafe(len);
      const r = await fh.read(buf, 0, len, i * SLOT);
      if (r.bytesRead !== len) throw new Error('file data incomplete');
      return buf;
    } finally { await fh.close(); }
  }

  /** How many pieces of a download are safely on disk (resume point). */
  completePieces(where, meta) {
    const n = this.sizeOnDisk(where);
    if (n >= storedSize(meta)) return meta.pieces;
    return Math.min(Math.floor(n / SLOT), meta.pieces);
  }

  isComplete(where, meta) { return this.sizeOnDisk(where) === storedSize(meta); }

  /** Opens a download for writing from piece `from` (anything after it is cut off). */
  async openForDownload(where, from) {
    const p = this.pathFor(where);
    const fh = await fsp.open(p, fs.existsSync(p) ? 'r+' : 'w+', 0o600);
    await fh.truncate(from * SLOT);
    return fh;
  }

  /**
   * Plain bytes [start, end] (inclusive) as a stream — used to show images,
   * play audio/video (with seeking) and to save/open files.
   */
  plainStream(where, fileId, meta, start = 0, end = meta.size - 1) {
    const file = this.pathFor(where);
    let fh = null, i = Math.floor(start / PIECE);
    const last = Math.floor(end / PIECE);
    return new Readable({
      async read() {
        try {
          if (!fh) fh = await fsp.open(file, 'r');
          if (i > last || meta.size === 0) { await fh.close(); fh = null; this.push(null); return; }
          const len = slotLen(meta, i);
          const buf = Buffer.allocUnsafe(len);
          const r = await fh.read(buf, 0, len, i * SLOT);
          if (r.bytesRead !== len) throw new Error('file data incomplete');
          let plain = openPiece(meta, fileId, i, buf);
          const pieceStart = i * PIECE;
          const from = Math.max(start - pieceStart, 0), to = Math.min(end - pieceStart + 1, plain.length);
          plain = plain.subarray(from, to);
          i++;
          this.push(plain);
        } catch (e) { if (fh) { fh.close().catch(() => {}); fh = null; } this.destroy(e); }
      },
      destroy(err, cb) { if (fh) fh.close().catch(() => {}); fh = null; cb(err); }
    });
  }

  /** Decrypts the whole file to destPath (Save as… / Open). */
  async exportTo(where, fileId, meta, destPath) {
    const tmp = destPath + '.sealchat-tmp';
    await new Promise((res, rej) => {
      const out = fs.createWriteStream(tmp, { mode: 0o600 });
      const inp = this.plainStream(where, fileId, meta);
      inp.on('error', e => { out.destroy(); rej(e); });
      out.on('error', rej);
      out.on('finish', res);
      inp.pipe(out);
    }).catch(async e => { await fsp.unlink(tmp).catch(() => {}); throw e; });
    await fsp.rm(destPath, { force: true });
    await fsp.rename(tmp, destPath);
    return destPath;
  }

  /* =================================================================
   * 5. TIDYING UP
   * ================================================================= */
  remove(where) { for (const p of [this.pathFor(where), this.pathFor(where) + '.part']) { try { fs.unlinkSync(p); } catch { /* none */ } } }

  usage() {
    let bytes = 0, files = 0;
    for (const f of fs.readdirSync(this.dir)) { try { bytes += fs.statSync(path.join(this.dir, f)).size; files++; } catch { /* ignore */ } }
    return { bytes, files };
  }

  /** Free space on the drive holding the files (bytes), or Infinity if unknown. */
  freeSpace() { try { const s = fs.statfsSync(this.dir); return s.bavail * s.bsize; } catch { return Infinity; } }

  /** Removes leftovers of interrupted "bringing in" (.part) on start. */
  cleanParts() { for (const f of fs.readdirSync(this.dir)) if (f.endsWith('.part')) { try { fs.unlinkSync(path.join(this.dir, f)); } catch { /* ignore */ } } }
}

module.exports = { FileVault, PIECE, SLOT, piecesFor, slotLen, storedSize, sealPiece, openPiece, safeName, isRisky };
