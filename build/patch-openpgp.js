#!/usr/bin/env node
/* =====================================================================
 * Seal Chat — build/patch-openpgp.js   (1.9.1)
 * openpgp has one regular expression with \p{…} (util.isEmailAddress),
 * which the Android app's Node.js can't compile — openpgp then fails to
 * load and Seal Chat never starts on the phone. This rewrites it the
 * noicu.js way (the same pattern where supported, explicit ranges where
 * not). Safe to run again: an already patched openpgp is left alone.
 *   node build/patch-openpgp.js [node_modules folder]   (default: ./node_modules)
 * Runs by itself after "npm install" (postinstall) and before update files
 * are built (make-update.js).
 * ===================================================================== */
'use strict';
const path = require('path');
const { patchOpenpgp } = require('../src/main/noicu');
const dir = path.resolve(process.argv[2] || path.join(__dirname, '..', 'node_modules'));
const changed = patchOpenpgp(dir);
console.log(changed.length ? 'openpgp patched for Android (no \\p{…} literal): ' + changed.map(f => path.relative(process.cwd(), f)).join(', ') : 'openpgp: already patched');
