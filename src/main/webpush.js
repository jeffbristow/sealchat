/* =====================================================================
 * Seal Chat — webpush.js   (phone notifications for Seal Chat Web, 1.6.0)
 * ---------------------------------------------------------------------
 * Sends a notification to a phone that has Seal Chat Web open as a Home
 * Screen app (iPhone, iOS 16.4+) or in Chrome / Edge / Firefox (Android,
 * computers). It is the standard "Web Push" every browser supports:
 *
 *   Seal Chat ──(encrypted)──► the phone maker's push service ──► phone
 *               (Apple: web.push.apple.com · Google: fcm.googleapis.com …)
 *
 * - The notification text is ENCRYPTED for that phone's browser only
 *   (RFC 8291, "aes128gcm"). The push service sees a small sealed blob,
 *   its size and the time — not the words.
 * - What the text says is up to the device's setting: "New message" by
 *   default, or "New message from Alice" if you allowed names. Never the
 *   message itself.
 * - Seal Chat signs each request with its own key ("VAPID", RFC 8292),
 *   so the push service only accepts notifications from this computer.
 *   That key is made on first use and kept in the encrypted vault.
 * - Through Tor when "Connect through Tor" is on (the push service then
 *   doesn't see your home IP address either).
 *
 * Sections:
 *   1. Keys (VAPID key pair, signed token)
 *   2. Encryption (RFC 8291)
 *   3. Which push services are allowed
 *   4. send(): one notification to one subscription
 * ===================================================================== */

const crypto = require('crypto');
const { request } = require('./webhttp');

const b64u = b => Buffer.from(b).toString('base64url');
const unb64u = s => Buffer.from(String(s || ''), 'base64url');

/* =================================================================
 * 1. KEYS
 * ================================================================= */
/** A new VAPID key pair: { pub: 65-byte public key, priv: 32 bytes } (base64url). */
function makeVapid() {
  const ec = crypto.createECDH('prime256v1');
  ec.generateKeys();
  return { pub: b64u(ec.getPublicKey()), priv: b64u(ec.getPrivateKey()) };
}

/** The signed token the push service checks ("JWT", ES256), valid 12 hours. */
function vapidToken(audience, subject, vapid, now = Date.now()) {
  const pub = unb64u(vapid.pub);
  const key = crypto.createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: vapid.priv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) }, format: 'jwk' });
  const head = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const body = b64u(JSON.stringify({ aud: audience, exp: Math.floor(now / 1000) + 12 * 3600, sub: subject }));
  const sig = crypto.sign('sha256', Buffer.from(head + '.' + body), { key, dsaEncoding: 'ieee-p1363' });
  return head + '.' + body + '.' + b64u(sig);
}

/* =================================================================
 * 2. ENCRYPTION (RFC 8291 + RFC 8188 "aes128gcm", one record)
 * ================================================================= */
/**
 * @param {Buffer} plain   the notification (JSON text)
 * @param {string} p256dh  the browser's public key (base64url, 65 bytes)
 * @param {string} auth    the browser's auth secret (base64url, 16 bytes)
 * @param {object} [fixed] tests only: { salt, ecdh } to reproduce known output
 */
function encrypt(plain, p256dh, auth, fixed = {}) {
  const uaPub = unb64u(p256dh), authSecret = unb64u(auth);
  if (uaPub.length !== 65 || uaPub[0] !== 4) throw new Error('bad browser key');
  if (authSecret.length < 16) throw new Error('bad auth secret');
  const ec = fixed.ecdh || crypto.createECDH('prime256v1');
  if (!fixed.ecdh) ec.generateKeys();
  const asPub = ec.getPublicKey();
  const shared = ec.computeSecret(uaPub);
  const salt = fixed.salt || crypto.randomBytes(16);
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), uaPub, asPub]);
  const ikm = Buffer.from(crypto.hkdfSync('sha256', shared, authSecret, keyInfo, 32));
  const cek = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16));
  const nonce = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));
  const rs = 4096;
  if (plain.length + 1 + 16 > rs - 86) throw new Error('notification too long');
  const c = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const ct = Buffer.concat([c.update(Buffer.concat([plain, Buffer.from([2])])), c.final(), c.getAuthTag()]);   // 0x02 = last record
  const header = Buffer.alloc(21);
  salt.copy(header, 0); header.writeUInt32BE(rs, 16); header[20] = asPub.length;
  return Buffer.concat([header, asPub, ct]);
}

/* =================================================================
 * 3. ALLOWED PUSH SERVICES
 * Only the browser makers' own push services. (The address comes from
 * the phone's browser; this stops a tampered web page from making Seal
 * Chat send requests anywhere else.)
 * ================================================================= */
const PUSH_HOSTS = [/\.push\.apple\.com$/, /^fcm\.googleapis\.com$/, /^android\.googleapis\.com$/, /\.push\.services\.mozilla\.com$/, /^push\.services\.mozilla\.com$/, /\.notify\.windows\.com$/];
function checkEndpoint(endpoint, allowAny) {
  let u;
  try { u = new URL(String(endpoint)); } catch { throw new Error('bad push address'); }
  if (allowAny && (u.protocol === 'https:' || u.protocol === 'http:')) return u;
  if (u.protocol !== 'https:') throw new Error('push address must be https');
  if (!PUSH_HOSTS.some(r => r.test(u.hostname))) throw new Error('unknown push service: ' + u.hostname);
  return u;
}

/* =================================================================
 * 4. SEND
 * ================================================================= */
/**
 * @param sub    { endpoint, p256dh, auth }
 * @param note   { title, body, tag }  (small JSON)
 * @param opt    { vapid, subject, socksPort, ca, allowAny, ttl, topic, urgency }
 * @returns      { status, gone }   gone = the phone unsubscribed (404/410)
 */
async function send(sub, note, opt) {
  const u = checkEndpoint(sub.endpoint, opt.allowAny);
  const body = encrypt(Buffer.from(JSON.stringify(note)), sub.p256dh, sub.auth);
  const jwt = vapidToken(u.origin, opt.subject, opt.vapid);
  const headers = {
    'Content-Type': 'application/octet-stream',
    'Content-Encoding': 'aes128gcm',
    'TTL': String(opt.ttl == null ? 6 * 3600 : opt.ttl),     // keep it up to 6 h if the phone is off
    'Urgency': opt.urgency || 'high',
    'Authorization': `vapid t=${jwt}, k=${opt.vapid.pub}`
  };
  if (opt.topic) headers.Topic = opt.topic;                  // a newer one replaces one still waiting
  const r = await request(u.href, { method: 'POST', body, headers, socksPort: opt.socksPort || null, ca: opt.ca, allowHttp: !!opt.allowAny, timeoutMs: 45000, maxBytes: 65536 });
  return { status: r.status, gone: r.status === 404 || r.status === 410, text: r.body.toString('utf8').slice(0, 300) };
}

module.exports = { makeVapid, vapidToken, encrypt, checkEndpoint, send, PUSH_HOSTS };
