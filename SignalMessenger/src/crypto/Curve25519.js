/**
 * Curve25519.js
 * Elliptic curve operations on Curve25519 (X25519 key exchange + Ed25519 signatures)
 * Uses tweetnacl for pure-JS production-ready cryptography
 */

import nacl from 'tweetnacl';

/**
 * Generate a fresh Curve25519 Diffie-Hellman key pair
 * Used for Identity Keys, Signed Pre-Keys, and Ephemeral Keys
 * @returns {{ publicKey: Uint8Array, privateKey: Uint8Array }}
 */
export function generateKeyPair() {
  const keyPair = nacl.box.keyPair();
  return {
    publicKey: keyPair.publicKey,   // 32 bytes
    privateKey: keyPair.secretKey,  // 32 bytes
  };
}

/**
 * Perform Diffie-Hellman shared secret computation: DH(privateKey, publicKey)
 * Returns a 32-byte shared secret
 */
export function dh(privateKey, publicKey) {
  const result = nacl.scalarMult(privateKey, publicKey);
  if (!result) {
    throw new Error('DH computation failed - invalid key material');
  }
  return result; // 32 bytes
}

/**
 * Generate an Ed25519 signing key pair for identity signing operations
 * @returns {{ publicKey: Uint8Array, privateKey: Uint8Array }}
 */
export function generateSigningKeyPair() {
  const keyPair = nacl.sign.keyPair();
  return {
    publicKey: keyPair.publicKey,  // 32 bytes
    privateKey: keyPair.secretKey, // 64 bytes (includes public key)
  };
}

/**
 * Sign a message with Ed25519 private key
 * @param {Uint8Array} message
 * @param {Uint8Array} privateKey - 64-byte Ed25519 secret key
 * @returns {Uint8Array} 64-byte signature
 */
export function sign(message, privateKey) {
  return nacl.sign.detached(message, privateKey);
}

/**
 * Verify an Ed25519 signature
 * @param {Uint8Array} message
 * @param {Uint8Array} signature - 64-byte signature
 * @param {Uint8Array} publicKey - 32-byte Ed25519 public key
 * @returns {boolean}
 */
export function verify(message, signature, publicKey) {
  return nacl.sign.detached.verify(message, signature, publicKey);
}

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Convert Base64 string to Uint8Array
 */
export function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert Uint8Array to Base64 string
 */
export function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Concatenate multiple Uint8Arrays into one
 */
export function concat(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Generate cryptographically secure random bytes
 */
export function randomBytes(n) {
  return nacl.randomBytes(n);
}

/**
 * Constant-time equality comparison to prevent timing attacks
 */
export function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}
