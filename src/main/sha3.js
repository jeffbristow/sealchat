/* =====================================================================
 * Seal Chat — sha3.js   (SHA3-256 in plain JavaScript, 1.9.2)
 * ---------------------------------------------------------------------
 * A Tor v3 .onion address ends with a SHA3-256 checksum (invite codes and
 * device linking work out temporary addresses with it). Node.js has
 * SHA3-256, but the desktop app runs inside Electron, whose crypto library
 * (BoringSSL) does NOT — "Digest method not supported". So Seal Chat
 * computes it itself: FIPS 202 Keccak-f[1600], rate 136 bytes, suffix 0x06.
 * Only tiny inputs are hashed (an address), so plain BigInt code is plenty.
 * test/sha3-test.js compares it with Node's own SHA3-256.
 * ===================================================================== */
'use strict';
const MASK = (1n << 64n) - 1n;
const rotl = (x, n) => n === 0n ? x : ((x << n) | (x >> (64n - n))) & MASK;

// round constants (from the LFSR in FIPS 202) and rotation offsets
const RC = (() => {
  const out = []; let r = 1;
  const bit = () => { const b = r & 1; r = (r & 0x80) ? ((r << 1) ^ 0x71) & 0xff : (r << 1) & 0xff; return b; };
  for (let i = 0; i < 24; i++) { let c = 0n; for (let j = 0; j < 7; j++) if (bit()) c |= 1n << BigInt((1 << j) - 1); out.push(c); }
  return out;
})();
const ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]].map(r => r.map(BigInt));   // ROT[x][y]

function keccakF(A) {                       // A[x + 5y], 25 lanes of 64 bits
  for (let round = 0; round < 24; round++) {
    const C = [0, 1, 2, 3, 4].map(x => A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20]);
    for (let x = 0; x < 5; x++) { const D = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1n); for (let y = 0; y < 5; y++) A[x + 5 * y] ^= D; }
    const B = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y], ROT[x][y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) A[x + 5 * y] = B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & MASK & B[(x + 2) % 5 + 5 * y]);
    A[0] ^= RC[round];
  }
}

/** SHA3-256 of a Buffer → 32-byte Buffer. */
function sha3_256(data) {
  const rate = 136;
  const msg = Buffer.from(data);
  const padded = Buffer.alloc((Math.floor(msg.length / rate) + 1) * rate);
  msg.copy(padded);
  padded[msg.length] ^= 0x06;
  padded[padded.length - 1] ^= 0x80;
  const A = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) A[i] ^= padded.readBigUInt64LE(off + i * 8);
    keccakF(A);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(A[i], i * 8);
  return out;
}

module.exports = { sha3_256 };
