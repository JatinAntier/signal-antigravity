/**
 * DoubleRatchet.js
 * Implements the Signal Protocol Double Ratchet Algorithm
 * Specification: https://signal.org/docs/specifications/doubleratchet/
 *
 * The Double Ratchet provides:
 * - Forward secrecy: Compromise of current keys doesn't expose past messages
 * - Break-in recovery: New messages become secure after some ratchet steps
 * - Out-of-order message handling via message key caching
 *
 * It combines two ratchets:
 * 1. Symmetric-key ratchet (KDF chain) for forward secrecy
 * 2. Diffie-Hellman ratchet for break-in recovery
 */

import {generateKeyPair, dh, bytesToBase64, base64ToBytes, concat, randomBytes} from '../Curve25519';
import {hmacSHA256, hkdf, signalHKDF} from '../HKDF';
import {encryptAES256GCM, decryptAES256GCM, serializeEncrypted, deserializeEncrypted} from '../AES256GCM';

// Constants
const MAX_SKIP = 1000;          // Max messages to skip in single chain
const MAX_CACHED_KEYS = 2000;   // Max skipped message keys to cache
const MESSAGE_KEY_SEED = new Uint8Array([0x01]);
const CHAIN_KEY_SEED = new Uint8Array([0x02]);

// HKDF info labels
const ROOT_CHAIN_INFO = 'WhisperRatchet';
const MESSAGE_KEY_INFO = 'WhisperMessageKeys';

/**
 * @typedef {Object} RatchetState
 * @property {Object}         DHs         - Sending DH key pair { publicKey, privateKey }
 * @property {Uint8Array|null} DHr         - Receiving DH public key
 * @property {Uint8Array}     RK          - 32-byte Root Key
 * @property {Uint8Array}     CKs         - Sending Chain Key (32 bytes)
 * @property {Uint8Array}     CKr         - Receiving Chain Key (32 bytes)
 * @property {number}         Ns          - Message number (sending)
 * @property {number}         Nr          - Message number (receiving)
 * @property {number}         PN          - Previous sending chain message count
 * @property {Map}            MKSKIPPED   - Skipped message keys
 */

/**
 * @typedef {Object} MessageHeader
 * @property {Uint8Array} dh  - Sender's current ratchet public key
 * @property {number}     pn  - Previous chain message count
 * @property {number}     n   - Current message number
 */

/**
 * @typedef {Object} EncryptedMessage
 * @property {Object}     header
 * @property {string}     ciphertext  - Base64 encoded ciphertext
 */

// ─────────────────────────────────────────────────────────────────────────────
// KDF CHAIN FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * KDF_RK: Root key ratchet step
 * Inputs: current root key + DH output
 * Outputs: new root key + new chain key
 */
function kdfRK(rootKey, dhOut) {
  const infoBytes = new TextEncoder().encode(ROOT_CHAIN_INFO);
  const output = hkdf(dhOut, rootKey, infoBytes, 64);
  return {
    newRootKey: output.slice(0, 32),
    newChainKey: output.slice(32, 64),
  };
}

/**
 * KDF_CK: Chain key ratchet step
 * Inputs: current chain key
 * Outputs: new chain key + message key
 */
function kdfCK(chainKey) {
  // Message key: HMAC(CK, 0x01)
  const messageKey = hmacSHA256(chainKey, MESSAGE_KEY_SEED);
  // Next chain key: HMAC(CK, 0x02)
  const nextChainKey = hmacSHA256(chainKey, CHAIN_KEY_SEED);
  return {messageKey, nextChainKey};
}

/**
 * Derive actual encryption/MAC keys from a message key
 * Returns: { encKey(32), authKey(32), iv(16) }
 */
function deriveMessageKeys(messageKey) {
  const infoBytes = new TextEncoder().encode(MESSAGE_KEY_INFO);
  const output = hkdf(messageKey, new Uint8Array(32), infoBytes, 80);
  return {
    encKey: output.slice(0, 32),
    authKey: output.slice(32, 64),
    iv: output.slice(64, 80),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// RATCHET INITIALIZATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Initialize Double Ratchet for SENDER (Alice)
 * Called after X3DH completes
 *
 * @param {Uint8Array} masterSecret - Shared secret from X3DH
 * @param {Uint8Array} bobDHPublicKey - Bob's signed pre-key public key
 * @returns {RatchetState}
 */
export function initializeSender(masterSecret, bobDHPublicKey) {
  // Alice performs an initial DH ratchet step
  const dhPair = generateKeyPair();
  const dhOut = dh(dhPair.privateKey, bobDHPublicKey);
  const {newRootKey, newChainKey} = kdfRK(masterSecret, dhOut);

  return {
    DHs: dhPair,             // Alice's current DH key pair (sender)
    DHr: bobDHPublicKey,     // Bob's current DH public key (receiver)
    RK: newRootKey,          // Root key
    CKs: newChainKey,        // Sending chain key
    CKr: null,               // Receiving chain key (not yet)
    Ns: 0,                   // Sending message counter
    Nr: 0,                   // Receiving message counter
    PN: 0,                   // Previous chain length
    MKSKIPPED: new Map(),    // Skipped message keys for out-of-order
  };
}

/**
 * Initialize Double Ratchet for RECEIVER (Bob)
 * Called when Bob receives Alice's first X3DH message
 *
 * @param {Uint8Array} masterSecret - Shared secret from X3DH
 * @param {Object}     bobSignedPreKeyPair - Bob's signed pre-key pair { publicKey, privateKey }
 * @returns {RatchetState}
 */
export function initializeReceiver(masterSecret, bobSignedPreKeyPair) {
  return {
    DHs: bobSignedPreKeyPair, // Bob's current DH key pair (sender role)
    DHr: null,                // Alice's DH public key (will be set from first message)
    RK: masterSecret,         // Root key = X3DH master secret
    CKs: null,                // Sending chain key (not yet)
    CKr: null,                // Receiving chain key (not yet)
    Ns: 0,
    Nr: 0,
    PN: 0,
    MKSKIPPED: new Map(),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// ENCRYPTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Encrypt a message using the Double Ratchet
 *
 * @param {RatchetState} state     - Current ratchet state (mutated)
 * @param {Uint8Array}   plaintext
 * @param {Uint8Array}   [aad]     - Associated data (e.g., message ID)
 * @returns {{ state: RatchetState, header: MessageHeader, ciphertext: string }}
 */
export function ratchetEncrypt(state, plaintext, aad = new Uint8Array(0)) {
  // Advance sending chain
  const {messageKey, nextChainKey} = kdfCK(state.CKs);
  
  // Build header
  const header = {
    dh: state.DHs.publicKey,
    pn: state.PN,
    n: state.Ns,
  };

  // Derive encryption keys
  const {encKey, iv} = deriveMessageKeys(messageKey);

  // Encrypt with AES-256-GCM
  // AAD includes the header for authenticity
  const headerBytes = serializeHeader(header);
  const combinedAAD = concat(aad, headerBytes);
  const encrypted = encryptAES256GCM(plaintext, encKey, combinedAAD);
  const serialized = serializeEncrypted(encrypted);
  
  // Base64 ciphertext for JSON transport
  let binary = '';
  for (let i = 0; i < serialized.length; i++) {
    binary += String.fromCharCode(serialized[i]);
  }
  const ciphertext = btoa(binary);

  // Update state
  const newState = {
    ...state,
    CKs: nextChainKey,
    Ns: state.Ns + 1,
    MKSKIPPED: new Map(state.MKSKIPPED), // Clone map
  };

  return {state: newState, header, ciphertext};
}

// ─────────────────────────────────────────────────────────────────────────────
// DECRYPTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Decrypt a message using the Double Ratchet
 *
 * @param {RatchetState}    state
 * @param {MessageHeader}   header
 * @param {string}          ciphertext - Base64
 * @param {Uint8Array}      [aad]
 * @returns {{ state: RatchetState, plaintext: Uint8Array }}
 */
export function ratchetDecrypt(state, header, ciphertext, aad = new Uint8Array(0)) {
  // Decode ciphertext
  const binary = atob(ciphertext);
  const ciphertextBytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    ciphertextBytes[i] = binary.charCodeAt(i);
  }

  // Try to use a skipped message key first
  const skippedKey = trySkippedMessageKey(state, header);
  if (skippedKey) {
    return {
      state: skippedKey.state,
      plaintext: _decrypt(skippedKey.messageKey, ciphertextBytes, header, aad),
    };
  }

  let newState = {...state, MKSKIPPED: new Map(state.MKSKIPPED)};

  // Check if we need to perform a DH ratchet step
  const dhPubKeyHex = bytesToBase64(header.dh);
  const currentDHrHex = state.DHr ? bytesToBase64(state.DHr) : null;
  
  if (dhPubKeyHex !== currentDHrHex) {
    // New DH ratchet key received → perform DH ratchet
    newState = skipMessageKeys(newState, header.pn);
    newState = dhRatchetStep(newState, header);
  }

  // Skip ahead if needed (out of order messages)
  newState = skipMessageKeys(newState, header.n);

  // Advance receiving chain
  const {messageKey, nextChainKey} = kdfCK(newState.CKr);
  newState = {
    ...newState,
    CKr: nextChainKey,
    Nr: newState.Nr + 1,
  };

  const plaintext = _decrypt(messageKey, ciphertextBytes, header, aad);
  return {state: newState, plaintext};
}

// ─────────────────────────────────────────────────────────────────────────────
// INTERNAL HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * DH Ratchet step
 */
function dhRatchetStep(state, header) {
  const newPN = state.Ns;
  
  // Bob's DH step: compute new receiving root+chain keys
  const dhOut1 = dh(state.DHs.privateKey, header.dh);
  const {newRootKey: rk1, newChainKey: ckr} = kdfRK(state.RK, dhOut1);

  // Generate new DH key pair for next sending
  const newDHs = generateKeyPair();
  
  // Compute new sending root+chain keys
  const dhOut2 = dh(newDHs.privateKey, header.dh);
  const {newRootKey: rk2, newChainKey: cks} = kdfRK(rk1, dhOut2);

  return {
    ...state,
    DHs: newDHs,
    DHr: header.dh,
    RK: rk2,
    CKs: cks,
    CKr: ckr,
    Ns: 0,
    Nr: 0,
    PN: newPN,
  };
}

/**
 * Cache message keys for skipped messages to handle out-of-order delivery
 */
function skipMessageKeys(state, until) {
  if (until - state.Nr > MAX_SKIP) {
    throw new Error(
      `Double Ratchet: refusing to skip ${until - state.Nr} messages (max: ${MAX_SKIP})`,
    );
  }
  
  let newState = state;
  while (newState.Nr < until) {
    if (!newState.CKr) break;
    
    const {messageKey, nextChainKey} = kdfCK(newState.CKr);
    const mapKey = `${bytesToBase64(newState.DHr || new Uint8Array(0))}_${newState.Nr}`;
    
    const newSkipped = new Map(newState.MKSKIPPED);
    newSkipped.set(mapKey, messageKey);
    
    // Enforce max skipped keys to prevent memory exhaustion
    if (newSkipped.size > MAX_CACHED_KEYS) {
      const firstKey = newSkipped.keys().next().value;
      newSkipped.delete(firstKey);
    }
    
    newState = {
      ...newState,
      CKr: nextChainKey,
      Nr: newState.Nr + 1,
      MKSKIPPED: newSkipped,
    };
  }
  
  return newState;
}

/**
 * Try to use a cached skipped message key
 */
function trySkippedMessageKey(state, header) {
  const mapKey = `${bytesToBase64(header.dh)}_${header.n}`;
  const messageKey = state.MKSKIPPED.get(mapKey);
  
  if (messageKey) {
    const newSkipped = new Map(state.MKSKIPPED);
    newSkipped.delete(mapKey);
    return {
      messageKey,
      state: {...state, MKSKIPPED: newSkipped},
    };
  }
  
  return null;
}

/**
 * Internal decrypt helper
 */
function _decrypt(messageKey, ciphertextBytes, header, aad) {
  const {encKey, iv} = deriveMessageKeys(messageKey);
  const headerBytes = serializeHeader(header);
  const combinedAAD = concat(aad, headerBytes);
  
  const {nonce, tag, ciphertext} = deserializeEncrypted(ciphertextBytes);
  return decryptAES256GCM(ciphertext, nonce, tag, encKey, combinedAAD);
}

/**
 * Serialize message header to bytes (for AAD)
 */
function serializeHeader(header) {
  const dhBytes = header.dh;
  const buf = new Uint8Array(dhBytes.length + 8);
  buf.set(dhBytes, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(dhBytes.length, header.pn, false);
  view.setUint32(dhBytes.length + 4, header.n, false);
  return buf;
}

// ─────────────────────────────────────────────────────────────────────────────
// STATE SERIALIZATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Serialize ratchet state for secure storage
 */
export function serializeRatchetState(state) {
  const skipObj = {};
  if (state.MKSKIPPED) {
    for (const [k, v] of state.MKSKIPPED.entries()) {
      skipObj[k] = bytesToBase64(v);
    }
  }
  
  return {
    DHs_pub: state.DHs ? bytesToBase64(state.DHs.publicKey) : null,
    DHs_priv: state.DHs ? bytesToBase64(state.DHs.privateKey) : null,
    DHr: state.DHr ? bytesToBase64(state.DHr) : null,
    RK: state.RK ? bytesToBase64(state.RK) : null,
    CKs: state.CKs ? bytesToBase64(state.CKs) : null,
    CKr: state.CKr ? bytesToBase64(state.CKr) : null,
    Ns: state.Ns,
    Nr: state.Nr,
    PN: state.PN,
    MKSKIPPED: skipObj,
  };
}

/**
 * Deserialize ratchet state from storage
 */
export function deserializeRatchetState(data) {
  const skipMap = new Map();
  if (data.MKSKIPPED) {
    for (const [k, v] of Object.entries(data.MKSKIPPED)) {
      skipMap.set(k, base64ToBytes(v));
    }
  }
  
  return {
    DHs: data.DHs_pub && data.DHs_priv
      ? {publicKey: base64ToBytes(data.DHs_pub), privateKey: base64ToBytes(data.DHs_priv)}
      : null,
    DHr: data.DHr ? base64ToBytes(data.DHr) : null,
    RK: data.RK ? base64ToBytes(data.RK) : null,
    CKs: data.CKs ? base64ToBytes(data.CKs) : null,
    CKr: data.CKr ? base64ToBytes(data.CKr) : null,
    Ns: data.Ns || 0,
    Nr: data.Nr || 0,
    PN: data.PN || 0,
    MKSKIPPED: skipMap,
  };
}
