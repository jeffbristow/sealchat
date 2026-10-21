/* =====================================================================
 * Seal Chat — build/sign-update.js
 * ---------------------------------------------------------------------
 * Signs an update file so Seal Chat's automatic updater will accept it.
 *
 *   node build/sign-update.js dist/update/SealChat-1.3.0.sealchat [path/to/update-signing-key.pem]
 *
 * Writes  SealChat-1.3.0.sealchat.sig  next to it. Upload BOTH files to
 * the same folder on the website (…/sealchat/update/).
 *
 * The private key (update-signing-key.pem) must stay secret and offline —
 * whoever has it can make updates every Seal Chat will trust. Default
 * location: build/update-signing-key.pem (never packed into the app).
 * ===================================================================== */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { readPackageJson } = require('../src/main/asarinfo');
const { signedText, verifySignature } = require('../src/main/updater');

const file = process.argv[2];
const keyFile = process.argv[3] || path.join(__dirname, 'update-signing-key.pem');
if (!file || !fs.existsSync(file)) { console.error('usage: node build/sign-update.js <update.sealchat> [key.pem]'); process.exit(1); }
if (!fs.existsSync(keyFile)) { console.error('Signing key not found: ' + keyFile); process.exit(1); }

const pkg = readPackageJson(file);
if (pkg.name !== 'sealchat') { console.error('Not a Seal Chat update file'); process.exit(1); }
const sha256 = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const key = crypto.createPrivateKey(fs.readFileSync(keyFile));
const sig = crypto.sign(null, Buffer.from(signedText(pkg.version, sha256)), key).toString('base64');
const pub = crypto.createPublicKey(key).export({ type: 'spki', format: 'pem' });
if (!verifySignature(pkg.version, sha256, sig, pub)) { console.error('Self-check failed'); process.exit(1); }
if (!verifySignature(pkg.version, sha256, sig)) console.warn('WARNING: this key is NOT the one built into Seal Chat (updater.js) — installed apps will refuse this update.');
const out = { v: 1, file: path.basename(file), version: pkg.version, sha256, size: fs.statSync(file).size, sig };
fs.writeFileSync(file + '.sig', JSON.stringify(out, null, 2));
console.log(`Signed ${path.basename(file)} (version ${pkg.version})\n  sha256 ${sha256}\n  → ${path.basename(file)}.sig`);
