/**
 * X3DH.js  (Extended Triple Diffie-Hellman)
 * Implements Signal Protocol's X3DH key agreement as specified at:
 * https://signal.org/docs/specifications/x3dh/
 *
 * X3DH establishes a shared secret between two parties (Alice and Bob)
 * where Bob can be offline. The shared secret is then used to initialize
 * the Double Ratchet Algorithm.
 *
 * Input: Alice's identity key, Bob's pre-key bundle from server
 * Output: shared master secret + associated data
 */

import {dh, generateKeyPair, verify, bytesToBase64, base64ToBytes, concat, randomBytes} from '../Curve25519';
import {hkdf} from '../HKDF';

// Signal X3DH info string
const X3DH_INFO = 'WhisperText';
const X3DH_F = new Uint8Array(32).fill(0xff); // 32 bytes of 0xFF - Signal's constant prefix

/**
 * @typedef {Object} PreKeyBundle
 * @property {number}     userId
 * @property {number}     deviceId
 * @property {Uint8Array} identityKey       - IK_B public key (32 bytes)
 * @property {Object}     signedPreKey
 * @property {number}     signedPreKey.keyId
 * @property {Uint8Array} signedPreKey.publicKey  (32 bytes)
 * @property {Uint8Array} signedPreKey.signature  (64 bytes) - IK_B signs SPK_B
 * @property {Object}     [oneTimePreKey]
 * @property {number}     [oneTimePreKey.keyId]
 * @property {Uint8Array} [oneTimePreKey.publicKey] (32 bytes)
 */

/**
 * @typedef {Object} X3DHSenderResult
 * @property {Uint8Array} masterSecret     - 32-byte shared secret → feeds DoubleRatchet
 * @property {Uint8Array} associatedData   - AD = IK_A || IK_B (64 bytes)
 * @property {Object}    initialMessage    - Data Alice includes in her first message
 * @property {Uint8Array} initialMessage.ephemeralPublicKey
 * @property {number}     initialMessage.signedPreKeyId
 * @property {number}     [initialMessage.oneTimePreKeyId]
 */

/**
 * X3DH Sender Side (Alice)
 * Called when Alice wants to send first message to Bob.
 *
 * Computes:
 *   DH1 = DH(IK_A, SPK_B)     - Alice identity    × Bob signed pre-key
 *   DH2 = DH(EK_A, IK_B)      - Alice ephemeral   × Bob identity
 *   DH3 = DH(EK_A, SPK_B)     - Alice ephemeral   × Bob signed pre-key
 *   DH4 = DH(EK_A, OPK_B)     - Alice ephemeral   × Bob one-time pre-key (optional)
 *   MasterSecret = HKDF(F || DH1 || DH2 || DH3 [|| DH4])
 *
 * @param {Object} aliceIdentityKeyPair   - { publicKey, privateKey } - IK_A
 * @param {PreKeyBundle} bobBundle         - Bob's fetched key bundle
 * @returns {X3DHSenderResult}
 */
export async function x3dhSender(aliceIdentityKeyPair, bobBundle) {
  // Step 1: Verify Bob's signed prekey signature
  // Bob signed SPK_B with his identity key IK_B
  const signatureValid = verify(
    bobBundle.signedPreKey.publicKey,
    bobBundle.signedPreKey.signature,
    bobBundle.identityKey,
  );
  
  if (!signatureValid) {
    throw new Error(
      'X3DH: Signed pre-key signature verification failed. ' +
      'Possible MITM attack or corrupted bundle.',
    );
  }

  // Step 2: Generate Alice's ephemeral key pair EK_A
  const ephemeralKeyPair = generateKeyPair();

  // Step 3: Compute four DH values
  // DH1 = DH(IK_A_priv, SPK_B_pub)
  const dh1 = dh(aliceIdentityKeyPair.privateKey, bobBundle.signedPreKey.publicKey);
  
  // DH2 = DH(EK_A_priv, IK_B_pub)
  const dh2 = dh(ephemeralKeyPair.privateKey, bobBundle.identityKey);
  
  // DH3 = DH(EK_A_priv, SPK_B_pub)
  const dh3 = dh(ephemeralKeyPair.privateKey, bobBundle.signedPreKey.publicKey);

  // Build DH material: F || DH1 || DH2 || DH3 [|| DH4]
  let dhMaterial = concat(X3DH_F, dh1, dh2, dh3);

  let oneTimePreKeyId = undefined;
  if (bobBundle.oneTimePreKey) {
    // DH4 = DH(EK_A_priv, OPK_B_pub)
    const dh4 = dh(ephemeralKeyPair.privateKey, bobBundle.oneTimePreKey.publicKey);
    dhMaterial = concat(dhMaterial, dh4);
    oneTimePreKeyId = bobBundle.oneTimePreKey.keyId;
  }

  // Step 4: Derive master secret using HKDF
  const infoBytes = new TextEncoder().encode(X3DH_INFO);
  const masterSecret = hkdf(
    dhMaterial,
    new Uint8Array(32), // salt = 32 zero bytes
    infoBytes,
    32,                  // output 32 bytes
  );

  // Step 5: Build Associated Data = encode(IK_A) || encode(IK_B)
  const associatedData = concat(aliceIdentityKeyPair.publicKey, bobBundle.identityKey);

  return {
    masterSecret,
    associatedData,
    initialMessage: {
      ephemeralPublicKey: ephemeralKeyPair.publicKey,
      signedPreKeyId: bobBundle.signedPreKey.keyId,
      oneTimePreKeyId,
    },
  };
}

/**
 * @typedef {Object} X3DHInitialMessage
 * @property {Uint8Array} senderIdentityKey     - IK_A public
 * @property {Uint8Array} ephemeralPublicKey     - EK_A public
 * @property {number}     signedPreKeyId         - which SPK_B was used
 * @property {number}     [oneTimePreKeyId]       - which OPK_B was used (if any)
 * @property {Uint8Array} encryptedMessage        - first message ciphertext
 */

/**
 * X3DH Receiver Side (Bob)
 * Called when Bob receives Alice's first message.
 *
 * Computes the same four DH values as Alice but using Bob's private keys.
 *
 * @param {Object}         bobIdentityKeyPair    - { publicKey, privateKey } - IK_B
 * @param {Object}         bobSignedPreKeyPair   - { publicKey, privateKey } - SPK_B
 * @param {Object|null}    bobOneTimePreKeyPair  - { publicKey, privateKey } - OPK_B or null
 * @param {X3DHInitialMessage} initialMessage
 * @returns {{ masterSecret: Uint8Array, associatedData: Uint8Array }}
 */
export async function x3dhReceiver(
  bobIdentityKeyPair,
  bobSignedPreKeyPair,
  bobOneTimePreKeyPair,
  initialMessage,
) {
  const {senderIdentityKey, ephemeralPublicKey} = initialMessage;

  // DH1 = DH(SPK_B_priv, IK_A_pub)
  const dh1 = dh(bobSignedPreKeyPair.privateKey, senderIdentityKey);
  
  // DH2 = DH(IK_B_priv, EK_A_pub)
  const dh2 = dh(bobIdentityKeyPair.privateKey, ephemeralPublicKey);
  
  // DH3 = DH(SPK_B_priv, EK_A_pub)
  const dh3 = dh(bobSignedPreKeyPair.privateKey, ephemeralPublicKey);

  let dhMaterial = concat(X3DH_F, dh1, dh2, dh3);

  if (bobOneTimePreKeyPair) {
    // DH4 = DH(OPK_B_priv, EK_A_pub)
    const dh4 = dh(bobOneTimePreKeyPair.privateKey, ephemeralPublicKey);
    dhMaterial = concat(dhMaterial, dh4);
  }

  // Derive master secret (same HKDF as Alice)
  const infoBytes = new TextEncoder().encode(X3DH_INFO);
  const masterSecret = hkdf(
    dhMaterial,
    new Uint8Array(32),
    infoBytes,
    32,
  );

  // Associated Data = encode(IK_A) || encode(IK_B)
  const associatedData = concat(senderIdentityKey, bobIdentityKeyPair.publicKey);

  return {masterSecret, associatedData};
}

/**
 * Serialize X3DH initial message header for transmission
 */
export function serializeX3DHHeader(initialMessage, senderIdentityKey) {
  return {
    sender_identity_key: bytesToBase64(senderIdentityKey),
    ephemeral_public_key: bytesToBase64(initialMessage.ephemeralPublicKey),
    signed_pre_key_id: initialMessage.signedPreKeyId,
    one_time_pre_key_id: initialMessage.oneTimePreKeyId || null,
  };
}

/**
 * Deserialize X3DH initial message header
 */
export function deserializeX3DHHeader(header) {
  return {
    senderIdentityKey: base64ToBytes(header.sender_identity_key),
    ephemeralPublicKey: base64ToBytes(header.ephemeral_public_key),
    signedPreKeyId: header.signed_pre_key_id,
    oneTimePreKeyId: header.one_time_pre_key_id || null,
  };
}
