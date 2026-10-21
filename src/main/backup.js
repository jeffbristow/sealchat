/* =====================================================================
 * Seal Chat — backup.js   (backup + restore, 1.0.0)
 * ---------------------------------------------------------------------
 * A backup holds everything needed to carry on from another PC with the
 * SAME Seal Chat ID: your PGP key, your .onion key, contacts and chats.
 * It is encrypted with a backup password you choose
 * (scrypt → AES-256-GCM), so the file is safe to keep on a USB stick
 * or in cloud storage.
 *
 * Only run one copy of an ID at a time: if two PCs use the same ID at
 * once, messages arrive at whichever one Tor happens to reach.
 * ===================================================================== */

const crypto = require('crypto');
const zlib = require('zlib');

const HEAD = 'SEALCHAT-BACKUP-1';
const SCRYPT = { N: 1 << 16, r: 8, p: 1, maxmem: 160 * 1024 * 1024 };

function createBackup(obj, password) {
  if (!password || String(password).length < 8) throw new Error('Backup password must be at least 8 characters');
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(String(password), salt, 32, SCRYPT);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(HEAD));
  const ct = Buffer.concat([c.update(zlib.gzipSync(Buffer.from(JSON.stringify(obj), 'utf8'))), c.final()]);
  return Buffer.concat([Buffer.from(HEAD + '\n'), salt, iv, c.getAuthTag(), ct]);
}

function readBackup(buf, password) {
  const head = Buffer.from(HEAD + '\n');
  if (!buf.subarray(0, head.length).equals(head)) throw new Error('That is not a Seal Chat backup file');
  let o = head.length;
  const salt = buf.subarray(o, o += 16), iv = buf.subarray(o, o += 12), tag = buf.subarray(o, o += 16), ct = buf.subarray(o);
  const key = crypto.scryptSync(String(password || ''), salt, 32, SCRYPT);
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
    d.setAAD(Buffer.from(HEAD)); d.setAuthTag(tag);
    return JSON.parse(zlib.gunzipSync(Buffer.concat([d.update(ct), d.final()])).toString('utf8'));
  } catch { throw new Error('Wrong backup password (or the file is damaged)'); }
}

module.exports = { createBackup, readBackup };
