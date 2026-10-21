/* =====================================================================
 * Seal Chat — devices.js   (groundwork for using one ID on several devices, 1.8.0)
 * ---------------------------------------------------------------------
 * Today one Seal Chat ID lives on one computer. A later version will let
 * the same ID run on several devices (another computer, the Android
 * app). That needs three things everyone's Seal Chat must already
 * understand by then — so 1.8.0 adds them now, without changing how
 * messages are delivered:
 *
 *   1. A DEVICE KEY for every installation (Ed25519, made once, kept in
 *      the encrypted vault). Its id is a short hash of the key.
 *   2. A DEVICE LIST — "these are my devices" — signed with your PGP key
 *      (so only you can add a device to your ID). Sent to your contacts
 *      like your profile, again whenever it changes.
 *   3. Contacts CHECK and KEEP each other's device list (newest wins, a
 *      list not signed by that contact's key is refused), and every
 *      message says which device sent it (from.dev).
 *
 * 1.9.0 LINKED DEVICES: each device's entry also carries its own .onion
 * address. Contacts on 1.9 try those addresses when the one they know
 * doesn't answer (any device of yours will do — your devices pass
 * everything on to each other, see peer.js 6e). An older Seal Chat keeps
 * the list without the addresses and simply uses the address it knows.
 *
 * Sections:
 *   1. This device's key
 *   2. The signed device list (make / check)
 *   3. Device signatures (for later: messages signed per device)
 * ===================================================================== */

const crypto = require('crypto');
const os = require('os');

const MAX_DEVICES = 10;
const ONION = /^[a-z2-7]{55}d$/;                 // 1.9.0
const LIST_TEXT = doc => 'sealchat-devices-v1|' + JSON.stringify(doc);

/* =================================================================
 * 1. THIS DEVICE
 * ================================================================= */
/** A new device key: { id, name, pub (base64 raw 32 bytes), priv (base64 PKCS#8), created }. */
function makeDevice(name) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'jwk' }).x;               // base64url, 32 bytes
  const pub = Buffer.from(raw, 'base64url').toString('base64');
  return {
    id: deviceIdOf(pub),
    name: cleanName(name || defaultName()),
    pub,
    priv: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    created: Date.now()
  };
}

/** 16 hex characters from the public key. */
function deviceIdOf(pubB64) { return crypto.createHash('sha256').update('sealchat-device-v1|' + pubB64).digest('hex').slice(0, 16); }

function defaultName() {
  if (process.env.SEALCHAT_DEVICE_NAME) return process.env.SEALCHAT_DEVICE_NAME;   // 1.9.0: the Android app passes the phone's model
  const p = { win32: 'Windows PC', darwin: 'Mac', linux: 'Linux PC' }[process.platform] || 'Computer';
  let h = ''; try { h = os.hostname().replace(/\.local$/, ''); } catch { /* none */ }
  return h ? `${p} (${h})` : p;
}
function cleanName(n) { return String(n || '').replace(/[\x00-\x1f]/g, '').trim().slice(0, 40) || 'Device'; }

/* =================================================================
 * 2. THE SIGNED DEVICE LIST
 * doc = { v: 1, fp, ts, devices: [{ id, pub, name, added, onion (1.9.0) }] }
 * ================================================================= */
/** Builds this ID's list (today: just this device) and signs it with the PGP key. */
async function signedList(identity, devices) {
  const doc = {
    v: 1,
    fp: identity.fp,
    ts: Date.now(),
    devices: devices.slice(0, MAX_DEVICES).map(d => ({ id: d.id, pub: d.pub, name: cleanName(d.name), added: d.created || d.added || Date.now(), ...(ONION.test(d.onion || '') ? { onion: d.onion } : {}) }))
  };
  return { doc, sig: await identity.signText(LIST_TEXT(doc)) };
}

/**
 * Checks a contact's list: signed by THEIR key, for THEIR fingerprint,
 * well-formed, and newer than what we have. Returns the list to keep, or
 * null (and why) to ignore it.
 */
async function checkList(identity, contact, doc, sig) {
  if (!doc || typeof doc !== 'object' || doc.v !== 1) return { keep: null, why: 'unknown format' };
  if (String(doc.fp || '').toUpperCase() !== contact.fp) return { keep: null, why: 'for someone else' };
  if (!Array.isArray(doc.devices) || !doc.devices.length || doc.devices.length > MAX_DEVICES) return { keep: null, why: 'bad list' };
  const ts = Number(doc.ts) || 0;
  if (ts > Date.now() + 2 * 24 * 3600e3) return { keep: null, why: 'from the future' };
  if (contact.devices && ts <= contact.devices.ts) return { keep: null, why: 'not newer' };
  for (const d of doc.devices) {
    const pub = Buffer.from(String(d.pub || ''), 'base64');
    if (pub.length !== 32 || d.id !== deviceIdOf(String(d.pub))) return { keep: null, why: 'bad device' };
  }
  if (!(await identity.verifyText(LIST_TEXT(doc), sig, contact.publicKey))) return { keep: null, why: 'bad signature' };
  return { keep: { ts, devices: doc.devices.map(d => ({ id: d.id, pub: String(d.pub), name: cleanName(d.name), added: Number(d.added) || 0, ...(ONION.test(String(d.onion || '')) ? { onion: String(d.onion) } : {}) })) }, why: null };
}

/** Changes whenever the list's contents change (to know when to send it again). */
function listVersion(devices) {
  return crypto.createHash('sha256').update(devices.map(d => d.id + ':' + cleanName(d.name) + ':' + (d.onion || '')).join('|')).digest('hex').slice(0, 16);   // 1.9.0: + address
}

/* =================================================================
 * 3. DEVICE SIGNATURES (groundwork — not used for delivery yet)
 * ================================================================= */
function deviceSign(device, text) {
  const key = crypto.createPrivateKey({ key: Buffer.from(device.priv, 'base64'), format: 'der', type: 'pkcs8' });
  return crypto.sign(null, Buffer.from(String(text)), key).toString('base64');
}
function deviceVerify(pubB64, text, sigB64) {
  try {
    const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(pubB64, 'base64').toString('base64url') }, format: 'jwk' });
    return crypto.verify(null, Buffer.from(String(text)), key, Buffer.from(String(sigB64), 'base64'));
  } catch { return false; }
}

module.exports = { makeDevice, deviceIdOf, signedList, checkList, listVersion, deviceSign, deviceVerify, MAX_DEVICES, cleanName };
