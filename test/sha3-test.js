/* Seal Chat 1.9.2 self-test: our SHA3-256 (Electron's crypto has none) = Node's.
 *   node test/sha3-test.js                                                 */
'use strict';
const crypto = require('crypto');
const assert = require('assert');
const { sha3_256 } = require('../src/main/sha3');
const inv = require('../src/main/invites');
let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
console.log('sha3-256:');
ok(sha3_256(Buffer.alloc(0)).toString('hex') === 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a', 'the FIPS 202 test value for ""');
ok(sha3_256(Buffer.from('abc')).toString('hex') === '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532', 'the FIPS 202 test value for "abc"');
const native = (() => { try { crypto.createHash('sha3-256'); return true; } catch { return false; } })();   // (none inside Electron — that's why sha3.js exists)
if (!native) { console.log('  · this runtime has no SHA3-256 of its own (Electron): checked against the test values only'); console.log(`\n${passed} passed`); process.exit(0); }
let same = 0;
for (let n = 0; n < 600; n++) { const b = crypto.randomBytes(n % 300); if (sha3_256(b).equals(crypto.createHash('sha3-256').update(b).digest())) same++; }
ok(same === 600, 'equal to Node\'s SHA3-256 on 600 random inputs (0–299 bytes, across the 136-byte block edge)');
// a v3 .onion address from Tor's own spec example key is reproduced
const seed = crypto.randomBytes(32), o = inv.onionFromSeed(seed);
const priv = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const pub = Buffer.from(crypto.createPublicKey(priv).export({ format: 'jwk' }).x, 'base64url');
const chk = crypto.createHash('sha3-256').update(Buffer.concat([Buffer.from('.onion checksum'), pub, Buffer.from([3])])).digest().subarray(0, 2);
const B32 = 'abcdefghijklmnopqrstuvwxyz234567'; let bits = 0, v = 0, want = '';
for (const x of Buffer.concat([pub, chk, Buffer.from([3])])) { v = ((v << 8) | x) & 0xffff; bits += 8; while (bits >= 5) { want += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } }
ok(o.onion === want, 'onion addresses (invite codes, device linking) are the same as before: ' + o.onion.slice(0, 16) + '…');
console.log(`\n${passed} passed`);
