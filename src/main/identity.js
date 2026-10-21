/* =====================================================================
 * Seal Chat — identity.js   (your PGP key and message encryption, 1.0.0)
 * ---------------------------------------------------------------------
 * Bring your own key (import an OpenPGP private key) or create one.
 * Every chat message is:
 *   - signed with YOUR private key (proves it came from you), and
 *   - encrypted to your CONTACT's public key (only they can read it).
 * Uses OpenPGP.js — the same library as Sealpost.
 *
 * 1.0.1: tolerates PC clocks that disagree (see section 1b). Before, a
 * key or message made on a PC whose clock ran ahead was refused by the
 * other PC as "not valid yet" ("key cannot encrypt").
 *
 * Sections:
 *   1. Reading keys
 *   1b. Clock tolerance (1.0.1)
 *   2. Your identity: create / import / unlock
 *   3. Encrypt + sign / decrypt + verify
 *   4. Fingerprint display helpers
 * ===================================================================== */

const openpgp = require('openpgp');

/* =================================================================
 * 1. READING KEYS
 * ================================================================= */
const pubCache = new Map();   // armored -> parsed key

async function readPublic(armored) {
  if (pubCache.has(armored)) return pubCache.get(armored);
  let key;
  try { key = await openpgp.readKey({ armoredKey: armored }); } catch { throw new Error('That is not a valid OpenPGP public key'); }
  if (key.isPrivate()) key = key.toPublic();
  if (pubCache.size > 500) pubCache.clear();
  pubCache.set(armored, key);
  return key;
}

/* =================================================================
 * 1b. CLOCK TOLERANCE (1.0.1)
 * OpenPGP treats anything time-stamped later than "now" as not valid yet.
 * Two PCs' clocks are rarely identical, so a key or message from a PC
 * whose clock is ahead looked invalid on the other one. Seal Chat now
 * accepts timestamps up to 2 days ahead. (Expiry and revocation are still
 * checked normally.)
 * ================================================================= */
const MAX_SKEW = 2 * 24 * 3600e3;

/** Latest timestamp inside a key (key, subkeys and their signatures). */
function newestTime(key) {
  let t = 0;
  const see = d => { if (d instanceof Date && !isNaN(d)) t = Math.max(t, d.getTime()); };
  const sigs = list => (list || []).forEach(sg => see(sg.created));
  see(key.keyPacket && key.keyPacket.created);
  sigs(key.directSignatures);
  for (const u of key.users || []) { sigs(u.selfCertifications); sigs(u.revocationSignatures); }
  for (const sk of key.subkeys || []) { see(sk.keyPacket && sk.keyPacket.created); sigs(sk.bindingSignatures); }
  return t;
}

/** "Now" — or a little later if any of these keys was made on a PC whose clock is ahead. */
function checkDate(...keys) {
  const now = Date.now();
  let t = now;
  for (const k of keys) if (k) t = Math.max(t, newestTime(k) + 1000);
  return new Date(Math.min(t, now + MAX_SKEW));
}

/** A date just after a timestamp from another PC (capped at 2 days ahead). */
function after(created) {
  const now = Date.now();
  const t = created instanceof Date ? created.getTime() + 1000 : now;
  return new Date(Math.min(Math.max(t, now), now + MAX_SKEW));
}

/** { fp, name, email, created, canEncrypt, armored } for any public key. */
async function describePublic(armored) {
  const key = await readPublic(armored);
  const uid = await primaryUser(key);
  let canEncrypt = true;
  try { await key.getEncryptionKey(undefined, checkDate(key)); } catch { canEncrypt = false; }
  return { fp: key.getFingerprint().toUpperCase(), name: uid.name, email: uid.email, created: key.getCreationTime().toISOString(), canEncrypt, armored: key.armor() };
}

async function primaryUser(key) {
  let id;
  try { id = (await key.getPrimaryUser()).user.userID; } catch { id = key.users[0] && key.users[0].userID; }
  if (!id) return { name: '', email: '' };
  // "Name <email>" is split by OpenPGP.js; a bare "Name" is only in .userID
  const raw = String(id.userID || '').replace(/\s*<[^>]*>\s*/, '').trim();
  return { name: id.name || raw || id.email || '', email: id.email || '' };
}

/* =================================================================
 * 2. YOUR IDENTITY
 * ================================================================= */
class Identity {
  constructor() { this.priv = null; this.pub = null; this.fp = null; this.name = ''; }

  get unlocked() { return !!(this.priv && this.priv.isDecrypted()); }

  /** Creates a new key. Returns the armored private key (encrypted with passphrase). */
  static async generate({ name, email, passphrase }) {
    if (!name || !String(name).trim()) throw new Error('Enter a name for your key');
    if (!passphrase || String(passphrase).length < 8) throw new Error('Passphrase must be at least 8 characters');
    const userIDs = [{ name: String(name).trim(), ...(email ? { email: String(email).trim() } : {}) }];
    // dated 1 day back, so PCs whose clock is a little behind this one accept it straight away
    const { privateKey } = await openpgp.generateKey({ type: 'curve25519', userIDs, passphrase, format: 'armored', date: new Date(Date.now() - 24 * 3600e3) });
    return privateKey;
  }

  /** Checks an imported private key + passphrase. Returns details; throws if unusable. */
  static async inspectPrivate(armored, passphrase) {
    let key;
    try { key = await openpgp.readPrivateKey({ armoredKey: String(armored).trim() }); }
    catch { throw new Error('That is not an OpenPGP PRIVATE key. Export your secret key (it starts with "-----BEGIN PGP PRIVATE KEY BLOCK-----").'); }
    let dec;
    try { dec = key.isDecrypted() ? key : await openpgp.decryptKey({ privateKey: key, passphrase }); }
    catch { throw new Error('Wrong passphrase for that key'); }
    const d = checkDate(dec);
    try { await dec.getSigningKey(undefined, d); } catch { throw new Error('That key cannot sign (it may be expired or revoked)'); }
    try { await dec.getEncryptionKey(undefined, d); } catch { throw new Error('That key has no usable encryption subkey (it may be sign-only, expired or revoked). Add an encryption subkey in your PGP program (e.g. Kleopatra), or create a new key here.'); }
    const uid = await primaryUser(dec);
    return { fp: dec.getFingerprint().toUpperCase(), name: uid.name, email: uid.email, protected: !key.isDecrypted() };
  }

  /** Loads + unlocks your key. */
  async load(armoredPrivate, passphrase) {
    const key = await openpgp.readPrivateKey({ armoredKey: armoredPrivate });
    let dec;
    try { dec = key.isDecrypted() ? key : await openpgp.decryptKey({ privateKey: key, passphrase }); }
    catch { throw new Error('Wrong passphrase'); }
    this.priv = dec;
    this.pub = dec.toPublic();
    this.fp = dec.getFingerprint().toUpperCase();
    this.name = (await primaryUser(dec)).name;
    this.pubArmored = this.pub.armor();
    return this;
  }

  lock() { this.priv = null; }

  /** Detached signature over text (base64). Used to prove who is calling. */
  async signText(text) {
    if (!this.unlocked) throw new Error('Your key is locked');
    const message = await openpgp.createMessage({ text: String(text) });
    const sig = await openpgp.sign({ message, signingKeys: this.priv, detached: true, format: 'binary', date: checkDate(this.priv) });
    return Buffer.from(sig).toString('base64');
  }

  async verifyText(text, sigB64, signerArmored) {
    try {
      const message = await openpgp.createMessage({ text: String(text) });
      const signature = await openpgp.readSignature({ binarySignature: Buffer.from(String(sigB64 || ''), 'base64') });
      const key = await readPublic(signerArmored);
      const { signatures } = await openpgp.verify({ message, signature, verificationKeys: key });
      try { await signatures[0].verified; return true; } catch { /* maybe their clock is ahead: */ }
      const created = signature.packets[0] && signature.packets[0].created;
      const again = await openpgp.verify({ message, signature, verificationKeys: key, date: after(new Date(Math.max(created ? created.getTime() : 0, checkDate(key).getTime() - 1000))) });
      await again.signatures[0].verified;
      return true;
    } catch { return false; }
  }

  /* =================================================================
   * 3. ENCRYPT / DECRYPT
   * ================================================================= */
  /** Signs and encrypts obj (JSON) for one contact. Returns base64 of the binary OpenPGP message. */
  async sealFor(recipientArmored, obj) {
    if (!this.unlocked) throw new Error('Your key is locked');
    const recipient = await readPublic(recipientArmored);
    const message = await openpgp.createMessage({ text: JSON.stringify(obj) });
    const bin = await openpgp.encrypt({ message, encryptionKeys: recipient, signingKeys: this.priv, format: 'binary', date: checkDate(recipient, this.priv) });
    return Buffer.from(bin).toString('base64');
  }

  /**
   * Decrypts a sealed block. senderArmored (optional) is the public key it
   * must be signed by. Returns { obj, signedBy (fp|null), valid }.
   */
  async open(b64, senderArmored) {
    if (!this.unlocked) throw new Error('Your key is locked');
    const bin = Buffer.from(String(b64), 'base64');
    const verificationKeys = senderArmored ? [await readPublic(senderArmored)] : [];
    const { data, signatures } = await openpgp.decrypt({ message: await openpgp.readMessage({ binaryMessage: bin }), decryptionKeys: this.priv, verificationKeys, expectSigned: false });
    let valid = false, signedBy = null;
    if (senderArmored && signatures.length) {
      try { await signatures[0].verified; valid = true; }
      catch {
        // signed on a PC whose clock is ahead of ours? check again just after its timestamp
        try {
          const sig = await signatures[0].signature;
          const created = sig && sig.packets[0] && sig.packets[0].created;
          const date = after(new Date(Math.max(created ? created.getTime() : 0, checkDate(verificationKeys[0]).getTime() - 1000)));
          const r2 = await openpgp.decrypt({ message: await openpgp.readMessage({ binaryMessage: bin }), decryptionKeys: this.priv, verificationKeys, expectSigned: false, date });
          await r2.signatures[0].verified; valid = true;
        } catch { valid = false; }
      }
      if (valid) signedBy = verificationKeys[0].getFingerprint().toUpperCase();
    }
    let obj;
    try { obj = JSON.parse(data); } catch { throw new Error('Unreadable message'); }
    return { obj, signedBy, valid, signerKeyIds: signatures.map(s => s.keyID.toHex()) };
  }
}

/* =================================================================
 * 4. FINGERPRINT DISPLAY
 * ================================================================= */
/** "ABCD 1234 …" groups of 4 for reading aloud. */
function prettyFp(fp) { return String(fp || '').toUpperCase().replace(/(.{4})/g, '$1 ').trim(); }

/**
 * Safety number for a pair of people: the same 60 digits on both PCs.
 * Compare it by phone / in person to be sure nobody is in the middle.
 */
function safetyNumber(fpA, fpB) {
  const crypto = require('crypto');
  const [x, y] = [String(fpA).toUpperCase(), String(fpB).toUpperCase()].sort();
  const h = crypto.createHash('sha512').update('sealchat-safety-v1|' + x + '|' + y).digest();
  let out = '';
  for (let i = 0; i < 12; i++) out += String(h.readUInt32BE(i * 4) % 100000).padStart(5, '0');
  return out.replace(/(\d{5})/g, '$1 ').trim();
}

module.exports = { Identity, describePublic, readPublic, prettyFp, safetyNumber };
