/* =====================================================================
 * Seal Chat — build/sign-web-update.js   (1.7.0)
 * ---------------------------------------------------------------------
 * Signs a Seal Chat Web package so Seal Chat Web's "Update now"
 * (admin.php, Web 1.2.0+) will accept it.
 *
 *   node build/sign-web-update.js SealChat-Web-1.2.0.zip [path/to/update-signing-key.pem]
 *
 * Writes  SealChat-Web-1.2.0.zip.sig  next to it. Upload BOTH files to the
 * same folder on your website (and to the GitHub mirror's Release).
 *
 * Uses the SAME private key as the app updates (update-signing-key.pem),
 * but signs a different text ("sealchat-web-update-v1|…"), so an app
 * signature can never be passed off as a web one or the other way round.
 *
 * The private key must stay secret and offline — never on the web
 * server, never in a package or the source zip.
 *
 * Sections:
 *   1. Arguments + version from the file name
 *   2. Check the package looks like Seal Chat Web of that version
 *   3. Sign + self-check + write the .sig
 * ===================================================================== */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { UPDATE_PUBLIC_KEY } = require('../src/main/updater');

/* ---------- 1. arguments ---------- */
const file = process.argv[2];
const keyFile = process.argv[3] || path.join(__dirname, 'update-signing-key.pem');
if (!file || !fs.existsSync(file)) { console.error('usage: node build/sign-web-update.js <SealChat-Web-x.y.z.zip> [key.pem]'); process.exit(1); }
if (!fs.existsSync(keyFile)) { console.error('Signing key not found: ' + keyFile); process.exit(1); }
const m = /^SealChat-Web-(\d+\.\d+\.\d+)\.zip$/.exec(path.basename(file));
if (!m) { console.error('The file name must be SealChat-Web-<version>.zip'); process.exit(1); }
const version = m[1];

/* ---------- 2. quick check of the package (needs "unzip"; skipped if missing) ---------- */
try {
  const lib = execFileSync('unzip', ['-p', file, `SealChat-Web-${version}/lib.php`], { maxBuffer: 1 << 22 }).toString();
  const inner = /SEALCHAT_WEB_VERSION\s*=\s*'([^']+)'/.exec(lib);
  if (!inner || inner[1] !== version) { console.error(`lib.php inside says version ${inner ? inner[1] : '?'}, the file name says ${version}`); process.exit(1); }
} catch (e) {
  if (e.code === 'ENOENT') console.warn('(unzip not found — skipped the inside check; Seal Chat Web checks it again before installing)');
  else { console.error('Could not read SealChat-Web-' + version + '/lib.php inside the zip — is this a Seal Chat Web package?'); process.exit(1); }
}

/* ---------- 3. sign ---------- */
const webSignedText = (v, sha) => `sealchat-web-update-v1|${v}|${String(sha).toLowerCase()}`;
const data = fs.readFileSync(file);
const sha256 = crypto.createHash('sha256').update(data).digest('hex');
const key = crypto.createPrivateKey(fs.readFileSync(keyFile));
const sig = crypto.sign(null, Buffer.from(webSignedText(version, sha256)), key);
const pub = crypto.createPublicKey(key);
if (!crypto.verify(null, Buffer.from(webSignedText(version, sha256)), pub, sig)) { console.error('Self-check failed'); process.exit(1); }
if (!crypto.verify(null, Buffer.from(webSignedText(version, sha256)), crypto.createPublicKey(UPDATE_PUBLIC_KEY), sig)) {
  console.warn('WARNING: this key is NOT the one built into Seal Chat Web (lib.php) — "Update now" will refuse this package.');
}
const out = { v: 1, kind: 'sealchat-web', file: path.basename(file), version, sha256, size: data.length, sig: sig.toString('base64') };
fs.writeFileSync(file + '.sig', JSON.stringify(out, null, 2));
console.log(`Signed ${path.basename(file)} (Seal Chat Web ${version})\n  sha256 ${sha256}\n  → ${path.basename(file)}.sig`);
