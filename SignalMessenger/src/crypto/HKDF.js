/**
 * HKDF.js
 * HMAC-based Key Derivation Function (RFC 5869)
 * Used extensively in Signal Protocol for deriving chain keys, message keys, root keys
 */

import nacl from 'tweetnacl';

/**
 * HMAC-SHA256 implementation using tweetnacl
 * @param {Uint8Array} key
 * @param {Uint8Array} data
 * @returns {Uint8Array} 32-byte HMAC
 */
function hmacSHA256(key, data) {
  // tweetnacl's secretbox uses XSalsa20-Poly1305, not HMAC directly.
  // We implement HMAC-SHA256 from scratch using native SubtleCrypto if available,
  // or fall back to a pure-JS SHA256 based approach.
  // In React Native environment, we combine with a polyfill.
  
  // Pure-JS SHA256 HMAC (RFC 2104)
  const BLOCK_SIZE = 64;
  
  // Normalize key
  let keyBytes = key;
  if (keyBytes.length > BLOCK_SIZE) {
    keyBytes = sha256(keyBytes);
  }
  if (keyBytes.length < BLOCK_SIZE) {
    const padded = new Uint8Array(BLOCK_SIZE);
    padded.set(keyBytes);
    keyBytes = padded;
  }
  
  const ipad = new Uint8Array(BLOCK_SIZE);
  const opad = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    ipad[i] = keyBytes[i] ^ 0x36;
    opad[i] = keyBytes[i] ^ 0x5c;
  }
  
  const innerHash = sha256(concat(ipad, data));
  return sha256(concat(opad, innerHash));
}

/**
 * Pure-JS SHA-256 implementation
 * Based on the FIPS 180-4 standard
 */
function sha256(data) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  let H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];

  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const len = bytes.length;
  const bitLen = len * 8;
  
  // Padding
  const paddingNeeded = (64 - ((len + 9) % 64)) % 64;
  const padded = new Uint8Array(len + 1 + paddingNeeded + 8);
  padded.set(bytes);
  padded[len] = 0x80;
  
  // Append bit length as big-endian 64-bit
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 4, bitLen & 0xffffffff, false);
  view.setUint32(padded.length - 8, Math.floor(bitLen / 2 ** 32), false);

  // Process blocks
  for (let i = 0; i < padded.length; i += 64) {
    const W = new Array(64);
    const blockView = new DataView(padded.buffer, i, 64);
    for (let t = 0; t < 16; t++) {
      W[t] = blockView.getUint32(t * 4, false);
    }
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }
    
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      
      h = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }
    
    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }

  const result = new Uint8Array(32);
  const resultView = new DataView(result.buffer);
  H.forEach((val, i) => resultView.setUint32(i * 4, val, false));
  return result;
}

function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function concat(a, b) {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

/**
 * HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
 * @param {Uint8Array} salt - Random salt (or zeros if not provided)
 * @param {Uint8Array} ikm  - Input keying material
 * @returns {Uint8Array} PRK - 32 bytes pseudo-random key
 */
export function hkdfExtract(salt, ikm) {
  const effectiveSalt = salt && salt.length > 0 ? salt : new Uint8Array(32);
  return hmacSHA256(effectiveSalt, ikm);
}

/**
 * HKDF-Expand: Derive `length` bytes of keying material from PRK
 * @param {Uint8Array} prk   - Pseudo-random key from hkdfExtract
 * @param {Uint8Array} info  - Context/application-specific label
 * @param {number} length    - Desired output length in bytes
 * @returns {Uint8Array}
 */
export function hkdfExpand(prk, info, length) {
  const N = Math.ceil(length / 32);
  if (N > 255) throw new Error('HKDF: requested too many bytes');
  
  const okm = new Uint8Array(N * 32);
  let T = new Uint8Array(0);
  
  for (let i = 1; i <= N; i++) {
    const input = concat(concat(T, info), new Uint8Array([i]));
    T = hmacSHA256(prk, input);
    okm.set(T, (i - 1) * 32);
  }
  
  return okm.slice(0, length);
}

/**
 * Full HKDF: Extract + Expand in one call
 * @param {Uint8Array} ikm    - Input keying material
 * @param {Uint8Array} salt   - Optional salt
 * @param {Uint8Array} info   - Context label
 * @param {number} length     - Output length in bytes
 * @returns {Uint8Array}
 */
export function hkdf(ikm, salt, info, length) {
  const prk = hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, length);
}

/**
 * Signal Protocol HKDF with specific encoding
 * Used in X3DH and Double Ratchet
 * @param {Uint8Array} inputKeyMaterial
 * @param {string} info - Label string
 * @param {number} outputLength
 * @returns {Uint8Array}
 */
export function signalHKDF(inputKeyMaterial, info, outputLength) {
  // Signal uses a specific salt: 32 zero bytes
  const salt = new Uint8Array(32);
  const infoBytes = new TextEncoder().encode(info);
  return hkdf(inputKeyMaterial, salt, infoBytes, outputLength);
}

export {hmacSHA256, sha256};
