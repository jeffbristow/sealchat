/* =====================================================================
 * Seal Chat — build/make-update.js      (run with: npm run update-file)
 * ---------------------------------------------------------------------
 * Builds an update file instead of a full installer:
 *   dist/update/SealChat-<ver>.sealchat   the app code — load it with
 *                                         Settings → About & updates →
 *                                         "Install update file…"
 *   dist/update/SealChat-<ver>.sealchat.sig  its signature (1.3.0) — made
 *                                         automatically when the private key
 *                                         build/update-signing-key.pem exists
 * Upload BOTH to the website's update folder for automatic updates.
 * Tor (tor.exe) is not inside update files; it only changes with a
 * full installer.
 * ===================================================================== */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const version = require('../package.json').version;
const out = path.join(root, 'dist', 'update');

// 1.9.1: openpgp must not contain a \p{…} regex literal (the Android app can't load it) — patch, then check
execSync(`node "${path.join(__dirname, 'patch-openpgp.js')}"`, { cwd: root, stdio: 'inherit' });
execSync(`node "${path.join(root, 'test', 'noicu-test.js')}"`, { cwd: root, stdio: 'inherit' });
// 1.9.2: the engine tests inside Electron's own runtime (its crypto differs from Node's — no SHA3)
execSync(`node "${path.join(__dirname, 'test-in-electron.js')}"`, { cwd: root, stdio: 'inherit' });
console.log('Packing app code for', version, '...');
execSync('npx electron-builder --win --x64 --dir --publish never', { cwd: root, stdio: 'inherit' });

const asar = path.join(root, 'dist', 'win-unpacked', 'resources', 'app.asar');
fs.mkdirSync(out, { recursive: true });
const updFile = path.join(out, `SealChat-${version}.sealchat`);
fs.copyFileSync(asar, updFile);
console.log('\nUpdate ready:\n ', updFile);
if (fs.existsSync(path.join(__dirname, 'update-signing-key.pem'))) execSync(`node "${path.join(__dirname, 'sign-update.js')}" "${updFile}"`, { stdio: 'inherit' });
else console.log('(not signed — build/update-signing-key.pem not found; automatic updates will refuse it)');
