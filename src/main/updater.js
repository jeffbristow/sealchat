/* =====================================================================
 * Seal Chat — updater.js   (checking for and downloading updates, 1.3.0 · GitHub 1.7.0)
 * ---------------------------------------------------------------------
 * How it works:
 *   1. Seal Chat asks GitHub which version is newest (1.7.0; before
 *      that it asked jeffbristow.com/sealchat/update.php):
 *        https://raw.githubusercontent.com/jeffbristow/sealchat-updates/main/update.json
 *      → { version, url, size, sha256, notes, released }
 *   2. If that version is higher than the one running, you're asked
 *      whether to download and install it.
 *   3. The update file (.sealchat) and its signature (.sealchat.sig) are
 *      downloaded. Seal Chat installs it ONLY if:
 *        - the signature was made with Seal Chat's private signing key
 *          (its public half is built into the app, below), and
 *        - the file's SHA-256 and version match what was signed.
 *      So even someone who took over the GitHub repository could not push a fake
 *      update — they don't have the signing key.
 *   4. The verified file goes to the updates folder; bootstrap.js runs it
 *      on the next start (same as "Install update file…").
 *
 * By default all of this goes THROUGH TOR, so GitHub never sees
 * your IP address (a setting can switch that off if a network needs it).
 *
 * 1.7.0 GITHUB: updates come ONLY from the public repository
 * jeffbristow/sealchat-updates (works through Tor; jeffbristow.com is no
 * longer asked). If you set your own update address (Settings →
 * Advanced), only yours is asked. A saved copy of the old default
 * (jeffbristow.com/sealchat/update.php) counts as "not set".
 *
 * 1.9.0 ANDROID: the Android app takes these same files (it unpacks the
 * verified file and runs its code; see the Android project's updates.js).
 * update.json can say which Android apps an update is for:
 *   "android": { "minShell": 2 }   needs Android app (shell) 2 or newer —
 *                                  older phones are told to install the new APK
 *   "android": false               not for phones at all
 * With no "android" entry an update is for phones too.
 *
 * Sections:
 *   1. Signing key + version compare
 *   2. HTTPS GET (through Tor, or direct)
 *   3. Check
 *   4. Download + verify
 * ===================================================================== */

const fs = require('fs');
const path = require('path');
const https = require('https');
const tls = require('tls');
const crypto = require('crypto');
const { socksRaw } = require('./wire');

/* =================================================================
 * 1. SIGNING KEY + VERSIONS
 * Only update files signed with the matching private key are installed.
 * ================================================================= */
const UPDATE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAzEcesiPus1IIakjsDR1oHhXjObb/7SqFeJDXS5ciyYY=
-----END PUBLIC KEY-----`;

// 1.7.0: updates come ONLY from GitHub (the public repository jeffbristow/sealchat-updates)
const DEFAULT_CHECK_URL = 'https://raw.githubusercontent.com/jeffbristow/sealchat-updates/main/update.json';
const WEBSITE_URL = 'https://jeffbristow.com/sealchat/update.php';   // the pre-1.7.0 default — not asked any more
const DEFAULT_MIRRORS = [];                     // no fallback
// addresses earlier versions showed as the default — a saved copy of one is NOT "your own address"
const KNOWN_DEFAULTS = [DEFAULT_CHECK_URL, WEBSITE_URL];

/** What is signed: name of the app, version and the file's SHA-256. */
const signedText = (version, sha256) => `sealchat-update-v1|${version}|${String(sha256).toLowerCase()}`;

function verifySignature(version, sha256, sigB64, publicKeyPem = UPDATE_PUBLIC_KEY) {
  try {
    return crypto.verify(null, Buffer.from(signedText(version, sha256)), crypto.createPublicKey(publicKeyPem), Buffer.from(String(sigB64), 'base64'));
  } catch { return false; }
}

function cmpVersion(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10) || 0), pb = String(b).split('.').map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
  return 0;
}

/* =================================================================
 * 2. HTTPS GET
 * opts: { socksPort (null = direct), maxBytes, onProgress(done,total), timeoutMs }
 * Resolves Buffer, or streams to opts.toFile and resolves its path.
 * ================================================================= */
function httpsGet(url, opts = {}, redirects = 0) {
  let u;
  try { u = new URL(url); } catch { return Promise.reject(new Error('Bad update address')); }
  if (u.protocol !== 'https:' && !opts.allowHttp) return Promise.reject(new Error('Update addresses must start with https://'));
  const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
  // through Tor: open a SOCKS connection first, then TLS on top of it
  const sockP = opts.socksPort
    ? socksRaw(opts.socksPort, u.hostname, port, 90000).then(raw => {
      raw.on('error', () => {});   // errors are reported through the request instead
      if (u.protocol !== 'https:') return raw;
      const t = tls.connect({ socket: raw, servername: require('net').isIP(u.hostname) ? undefined : u.hostname, ca: opts.ca });
      t.on('error', () => {});
      return t;
    })
    : Promise.resolve(null);
  return sockP.then(sock => new Promise((resolve, reject) => {
    const lib = u.protocol === 'https:' ? https : require('http');
    const reqOpts = {
      method: 'GET', hostname: u.hostname, port, path: u.pathname + u.search,
      headers: { 'User-Agent': 'SealChat-Updater', 'Accept': '*/*', 'Cache-Control': 'no-cache', 'Connection': 'close' },
      timeout: opts.timeoutMs || 60000, ca: opts.ca
    };
    // 1.4.1 FIX: the request must use the socket that goes through Tor. (Before, "agent: false"
    // made Node ignore createConnection and connect DIRECTLY — the Tor socket was opened but unused.)
    // A one-off agent whose createConnection hands over our Tor socket is always honoured.
    if (sock) { const A = new (u.protocol === 'https:' ? https : require('http')).Agent({ keepAlive: false }); A.createConnection = () => sock; reqOpts.agent = A; }
    const req = lib.request(reqOpts, res => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if (redirects >= 4) return reject(new Error('Too many redirects'));
        return resolve(httpsGet(new URL(res.headers.location, url).toString(), opts, redirects + 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`The update server answered ${res.statusCode}`)); }
      const total = Number(res.headers['content-length']) || 0;
      const max = opts.maxBytes || 10 * 1024 * 1024;
      if (total > max) { res.destroy(); return reject(new Error('Download is larger than expected')); }
      let done = 0;
      const out = opts.toFile ? fs.createWriteStream(opts.toFile, { mode: 0o600 }) : null;
      const chunks = [];
      res.on('data', d => {
        done += d.length;
        if (done > max) { res.destroy(new Error('Download is larger than expected')); return; }
        if (out) out.write(d); else chunks.push(d);
        if (opts.onProgress) opts.onProgress(done, total);
      });
      res.on('error', e => { if (out) out.destroy(); reject(e); });
      res.on('end', () => {
        if (!res.complete) return reject(new Error('Download was cut off'));
        if (out) out.end(() => resolve(opts.toFile)); else resolve(Buffer.concat(chunks));
      });
    });
    req.on('timeout', () => req.destroy(new Error('The update server did not answer in time')));
    req.on('error', e => reject(new Error(friendlyNetError(e, !!opts.socksPort))));
    req.end();
  }), e => { throw new Error(friendlyNetError(e, true)); });
}

function friendlyNetError(e, viaTor) {
  const m = e && e.message || String(e);
  if (/ENOTFOUND|EAI_AGAIN/.test(m)) return 'Could not find the update server (no internet?)';
  if (/certificate|CERT_|self signed/i.test(m)) return 'The update server\'s security certificate is not valid';
  if (viaTor && /contact|reach|Tor|SOCKS|timed out/i.test(m)) return 'Could not reach the update server through Tor (' + m.replace(/^Could not reach contact:?\s*/, '') + '). If this keeps happening, turn off "Check through Tor" in Settings.';
  return m;
}

/* =================================================================
 * 3 + 4. UPDATER
 * ================================================================= */
class Updater {
  /**
   * @param {object} o { currentVersion, updatesDir, settings() , socksPort() → number|null, publicKey, ca, log }
   */
  constructor(o) {
    this.o = o;
    this.state = { checking: false, available: null, lastCheck: null, error: null, downloading: false, progress: 0, ready: null };
  }

  checkUrl() { const own = (this.o.settings().updateUrl || '').trim(); return own && !KNOWN_DEFAULTS.includes(own) ? own : DEFAULT_CHECK_URL; }
  /** 1.7.0: where to look — GitHub only. Your own update address (Settings → Advanced) is asked instead. */
  sources() {
    const own = (this.o.settings().updateUrl || '').trim();
    const std = this.o.primaryUrl || DEFAULT_CHECK_URL;           // (primaryUrl/mirrors: tests only)
    if (own && own !== std && !KNOWN_DEFAULTS.includes(own)) return [own];
    return [std].concat(this.o.mirrors || DEFAULT_MIRRORS);
  }
  _net() {
    const viaTor = this.o.settings().updateViaTor !== false;
    const socksPort = viaTor ? this.o.socksPort() : null;
    if (viaTor && !socksPort) throw new Error('Waiting for Tor to connect before checking for updates');
    return { socksPort, ca: this.o.ca, allowHttp: !!this.o.allowHttp };
  }

  /** Asks the website for the newest version. Resolves state.available (or null). */
  /** One source's answer → { info, from } (throws if it can't be read). */
  async _ask(src) {
    const body = await httpsGet(src, { ...this._net(), maxBytes: 256 * 1024, timeoutMs: 90000 });
    let info;
    try { info = JSON.parse(body.toString('utf8')); } catch { throw new Error('The update server sent something unexpected'); }
    if (!info || typeof info !== 'object') throw new Error('The update server sent something unexpected');
    return info;
  }

  async check() {
    if (this.state.checking) return this.state;
    this.state.checking = true; this.state.error = null;
    try {
      // 1.7.0: GitHub (or your own address); extra sources only in tests
      let info = null, src = null, errs = [];
      for (const s of this.sources()) {
        try { info = await this._ask(s); src = s; break; } catch (e) { errs.push(e.message); }
      }
      if (!info) throw new Error(errs[0] + (errs.length > 1 ? ' (the other update sources could not be reached either)' : ''));
      this.state.lastCheck = Date.now();
      this.state.source = src === this.sources()[0] ? 'primary' : 'fallback';   // primary = GitHub (or your own address)
      const v = String(info.version || '');
      if (!/^\d+(\.\d+){1,3}$/.test(v) || !info.url) { this.state.available = null; return this.state; }
      const url = new URL(String(info.url), src).toString();
      // 1.9.0: the Android app — is this update for phones, and for this Android app?
      const shell = Number(process.env.SEALCHAT_ANDROID_SHELL || 0);
      const andr = info.android;
      if (shell && (andr === false || (andr && andr.skip))) { this.state.available = null; return this.state; }
      const needsApk = !!(shell && andr && Number(andr.minShell) > shell);
      if (cmpVersion(v, this.o.currentVersion) > 0) {
        this.state.available = {
          version: v, url,
          size: String(info.size || '').slice(0, 20),
          sha256: /^[0-9a-f]{64}$/i.test(info.sha256 || '') ? String(info.sha256).toLowerCase() : null,
          notes: (Array.isArray(info.notes) ? info.notes : String(info.notes || '').split(/\r?\n/)).map(s => String(s).trim()).filter(Boolean).slice(0, 30).map(s => s.slice(0, 300)),
          released: String(info.released || '').slice(0, 20),
          skipped: this.o.settings().skipVersion === v,
          from: src,                                      // 1.7.0: which source said so
          needsApk                                        // 1.9.0: Android — this update needs a newer Android app first
        };
      } else this.state.available = null;
      return this.state;
    } catch (e) {
      this.state.error = e.message;
      throw e;
    } finally { this.state.checking = false; }
  }

  /**
   * Downloads the available update + its signature, verifies both, and puts
   * it where bootstrap.js picks it up. Resolves { version }.
   */
  async downloadAndInstall(onProgress) {
    const a = this.state.available;
    if (!a) throw new Error('No update available');
    if (a.needsApk) throw new Error(`Seal Chat ${a.version} needs a newer Android app. Install the new Seal Chat APK first — your chats and contacts stay.`);
    if (this.state.downloading) throw new Error('Already downloading');
    // 1.7.0: if the file can't be fetched from where the check pointed, try the same version from the other sources
    try { return await this._downloadFrom(a.url, onProgress); }
    catch (first) {
      // a file that failed a CHECK (bad signature, changed file, wrong version) is refused, not fetched elsewhere;
      // one that couldn't be FETCHED (404, blocked, cut off) is tried from the other sources
      if (/NOT valid|does not match|different version|damaged|contains version|already have|not a Seal Chat/i.test(first.message)) throw first;
      for (const s of this.sources().filter(x => x !== a.from)) {
        let info; try { info = await this._ask(s); } catch { continue; }
        if (String(info.version) !== a.version || !info.url) continue;
        try { return await this._downloadFrom(new URL(String(info.url), s).toString(), onProgress); } catch { /* next */ }
      }
      throw first;
    }
  }

  async _downloadFrom(fileUrl, onProgress) {
    const a = { ...this.state.available, url: fileUrl };
    this.state.downloading = true; this.state.progress = 0; this.state.error = null;
    const dir = this.o.updatesDir;
    fs.mkdirSync(dir, { recursive: true });
    const tmp = path.join(dir, 'incoming-' + Date.now() + '.tmp');
    try {
      const net = this._net();
      // a) signature first (small) — no point downloading a file we'd refuse
      let sigInfo;
      try { sigInfo = JSON.parse((await httpsGet(a.url + '.sig', { ...net, maxBytes: 16 * 1024 })).toString('utf8')); }
      catch (e) { throw new Error('The update has no valid signature file (' + e.message + '). Not installed.'); }
      if (String(sigInfo.version) !== a.version) throw new Error('The signature is for a different version. Not installed.');
      if (!/^[0-9a-f]{64}$/.test(String(sigInfo.sha256 || ''))) throw new Error('The signature file is damaged. Not installed.');
      if (!verifySignature(sigInfo.version, sigInfo.sha256, sigInfo.sig, this.o.publicKey)) throw new Error('The update\'s signature is NOT valid — it was not made by the Seal Chat signing key. Not installed.');

      // b) the file itself
      await httpsGet(a.url, { ...net, toFile: tmp, maxBytes: 300 * 1024 * 1024, timeoutMs: 120000, onProgress: (d, t) => { this.state.progress = t ? d / t : 0; if (onProgress) onProgress(d, t); } });
      const sha = crypto.createHash('sha256').update(fs.readFileSync(tmp)).digest('hex');
      if (sha !== String(sigInfo.sha256).toLowerCase()) throw new Error('The downloaded file does not match its signature (damaged or changed). Not installed.');

      // c) same checks as "Install update file…"
      const { readPackageJson } = require('./asarinfo');
      const pkg = readPackageJson(tmp);
      if (pkg.name !== 'sealchat' || !pkg.__hasMain) throw new Error('That is not a Seal Chat update');
      if (pkg.version !== a.version) throw new Error('The file contains version ' + pkg.version + ', not ' + a.version);
      if (cmpVersion(pkg.version, this.o.currentVersion) <= 0) throw new Error('You already have this version');
      const finalPath = path.join(dir, 'sealchat-' + pkg.version + '.asar');
      try { fs.unlinkSync(finalPath); } catch { /* none */ }
      fs.renameSync(tmp, finalPath);
      try { const badFile = path.join(dir, 'bad-versions.json'); fs.writeFileSync(badFile, JSON.stringify(JSON.parse(fs.readFileSync(badFile, 'utf8')).filter(v => v !== pkg.version))); } catch { /* none */ }
      this.state.ready = pkg.version;
      return { version: pkg.version };
    } catch (e) {
      try { fs.unlinkSync(tmp); } catch { /* none */ }
      this.state.error = e.message;
      throw e;
    } finally { this.state.downloading = false; }
  }
}

module.exports = { Updater, verifySignature, signedText, cmpVersion, httpsGet, UPDATE_PUBLIC_KEY, DEFAULT_CHECK_URL, DEFAULT_MIRRORS, WEBSITE_URL };
