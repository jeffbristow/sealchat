#!/usr/bin/env node
/* =====================================================================
 * Seal Chat — build/test-in-electron.js   (npm run test:electron, 1.9.2)
 * ---------------------------------------------------------------------
 * Runs the engine tests inside ELECTRON's runtime (ELECTRON_RUN_AS_NODE),
 * not plain Node.js. The desktop app runs there, and it differs: its crypto
 * is BoringSSL (no SHA3 — "Digest method not supported" when linking a
 * device in 1.9.0) and its Node/Unicode versions are newer. Runs before
 * every update file is built (make-update.js).
 * ===================================================================== */
'use strict';
const { execFileSync } = require('child_process');
const path = require('path');
const electron = require('electron');          // (in plain Node this is the path to the Electron program)
const root = path.join(__dirname, '..');
const tests = ['core-test', 'devices-test', 'replies-test', 'holds-test', 'invites-test', 'linking-test', 'names-test', 'files-test', 'update-test', 'android-update-test', 'sha3-test', 'noicu-test'];
for (const t of tests) {
  process.stdout.write(`[electron] ${t}: `);
  const out = execFileSync(electron, [path.join(root, 'test', t + '.js')], { cwd: root, env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, encoding: 'utf8', timeout: 15 * 60e3 });
  console.log(out.trim().split('\n').pop());
}
console.log('all engine tests pass inside Electron');
