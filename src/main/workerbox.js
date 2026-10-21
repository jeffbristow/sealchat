/* =====================================================================
 * Seal Chat — workerbox.js   (your mailbox on Cloudflare, 1.8.5)
 * ---------------------------------------------------------------------
 * A free Cloudflare Worker can be your mailbox instead of (or as well as)
 * Seal Chat Web on your own website. Useful when your web host blocks or
 * challenges visitors that come through Tor: Tor traffic stops at
 * Cloudflare and never reaches your web host.
 *
 * How it fits together:
 *   - Seal Chat makes the Worker script for you (makeScript): it has the
 *     HASH of a mailbox key that only this PC knows, plus a mailbox name.
 *   - You paste it into a new Cloudflare Worker, add a D1 database named
 *     DB, and paste the Worker's address back into Seal Chat (connect).
 *   - The Worker speaks the same language as Seal Chat Web's relay.php
 *     mailbox (mbox_set / mbox_drop / mbox_get), so contacts on any
 *     Seal Chat 1.8 can leave messages there without knowing the difference.
 *   - Everything goes through Tor (directly only if you allow that for
 *     websites that block Tor: Settings → Privacy).
 *
 * Sections:
 *   1. The Worker script (made for this PC)
 *   2. Talking to the Worker
 * ===================================================================== */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { viaFallbacks, pageHint } = require('./webhttp');

const sha256hex = s => crypto.createHash('sha256').update(String(s)).digest('hex');

/* =================================================================
 * 1. THE WORKER SCRIPT
 * ================================================================= */
/** A new mailbox key + name (kept in the encrypted vault until connected). */
function newSetup() { return { owner: crypto.randomBytes(32).toString('base64url'), box: crypto.randomBytes(16).toString('hex') }; }

/** The Worker script for this PC: the template with this PC's key HASH and mailbox name filled in. */
function makeScript(setup) {
  const t = fs.readFileSync(path.join(__dirname, 'worker', 'mailbox-worker.js'), 'utf8');
  return t.replace('__OWNER_HASH__', sha256hex(setup.owner)).replace('__BOX__', setup.box);
}

/** "sealchat-mailbox.name.workers.dev", with or without https:// or a path → "https://host/". */
function cleanUrl(text, allowHttp) {
  let t = String(text || '').trim();
  if (!t) throw new Error('Paste your Worker\'s address (it looks like https://sealchat-mailbox.yourname.workers.dev)');
  if (!/^[a-z]+:\/\//i.test(t)) t = 'https://' + t;
  let u;
  try { u = new URL(t); } catch { throw new Error('That is not a web address'); }
  if (u.protocol !== 'https:' && !(allowHttp && u.protocol === 'http:')) throw new Error('The Worker\'s address must start with https://');
  if (!u.hostname.includes('.')) throw new Error('That is not a web address');
  return u.protocol + '//' + u.host + '/';
}

/* =================================================================
 * 2. TALKING TO THE WORKER
 * o: { socksPort, direct, http (tests), allowHttp (tests) }
 * ================================================================= */
async function call(wb, action, body, o = {}) {
  const url = wb.url + '?a=' + action;
  const host = new URL(wb.url).hostname;
  let r;
  try {
    r = await viaFallbacks(url, {
      method: 'POST', body: JSON.stringify(body || {}),
      headers: { 'Content-Type': 'application/json', 'X-SC-Owner': wb.owner, 'X-SC-Box': wb.box },
      socksPort: o.socksPort, direct: !!o.direct, http: o.http, allowHttp: !!o.allowHttp, timeoutMs: 90e3, maxBytes: 8 * 1024 * 1024
    });
  } catch (e) {
    if (e.code === 'TOR_BLOCKED') throw new Error(`${host} can't be reached through Tor right now. Settings → Privacy can allow contacting it directly.`);
    throw e;
  }
  let j = null; try { j = JSON.parse(r.body.toString('utf8')); } catch { /* not JSON */ }
  if (!j) throw new Error(`${host} answered ${r.status} with a web page instead of the Seal Chat mailbox: ${pageHint(r)} — check the address, and that the Worker has the script from Seal Chat`);
  if (!j.ok) {
    const e = new Error(j.code === 'owner' ? 'That Worker has a script made by a different Seal Chat (or an older script from this one). Copy the Worker script again and paste it into the Worker.'
      : j.code === 'nombox' && action !== 'mbox_drop' ? 'That Worker has a different mailbox script. Copy the Worker script again and paste it into the Worker.'
        : j.code === 'action' ? 'That address doesn\'t have the Seal Chat mailbox script — copy the Worker script again and paste it into the Worker.'
          : (j.error || j.code || 'The mailbox had a problem'));
    e.code = j.code;
    throw e;
  }
  return j;
}

const setDrop = (wb, dropToken, o) => call(wb, 'mbox_set', { drop: dropToken ? sha256hex(dropToken) : null }, o);
const get = (wb, ack, o) => call(wb, 'mbox_get', { ack: Number(ack) || 0 }, o);

module.exports = { newSetup, makeScript, cleanUrl, call, setDrop, get, sha256hex };
