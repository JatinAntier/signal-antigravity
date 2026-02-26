/**
 * KeyManager.js
 * Manages generation, storage, and rotation of all Signal Protocol keys
 *
 * Key Types:
 *   - Identity Key Pair      (IK)  - Long-lived, permanent
 *   - Signed Pre-Key Pair    (SPK) - Rotated every 30 days
 *   - One-Time Pre-Keys      (OPK) - Used once per session initiation
 *   - Session keys           - Derived per-conversation
 */

import 'react-native-get-random-values'; // polyfill for crypto.getRandomValues
import {
  generateKeyPair,
  generateSigningKeyPair,
  sign,
  bytesToBase64,
  base64ToBytes,
  randomBytes,
} from '../Curve25519';
import SecureStorage from '../../services/SecureStorage';
import Logger from '../../utils/Logger';

// Storage key prefixes
const STORAGE_KEYS = {
  IDENTITY_KEY_PAIR: 'signal_ik',
  SIGNED_PRE_KEYS: 'signal_spk_',
  ONE_TIME_PRE_KEYS: 'signal_opk_',
  OPK_IDS: 'signal_opk_ids',
  CURRENT_SPK_ID: 'signal_current_spk_id',
  SPK_ROTATION_TIMESTAMP: 'signal_spk_rotation_ts',
};

// Constants
const OPK_BATCH_SIZE = 100;
const OPK_REFILL_THRESHOLD = 20;
const SPK_ROTATION_DAYS = 30;

class KeyManager {
  constructor() {
    this._initialized = false;
    this._identityKeyPair = null;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // INITIALIZATION
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Initialize key manager - load or generate all keys
   * Called once at app start / first login
   * @returns {{ isNewDevice: boolean }}
   */
  async initialize() {
    Logger.info('KeyManager', 'Initializing...');
    
    const existingIK = await SecureStorage.getItem(STORAGE_KEYS.IDENTITY_KEY_PAIR);
    
    if (existingIK) {
      // Existing user - load keys
      await this._loadIdentityKey(existingIK);
      this._initialized = true;
      Logger.info('KeyManager', 'Loaded existing identity key');
      return {isNewDevice: false};
    } else {
      // New device / reinstall - generate all keys
      await this._generateAllKeys();
      this._initialized = true;
      Logger.info('KeyManager', 'Generated new identity key');
      return {isNewDevice: true};
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // IDENTITY KEY
  // ─────────────────────────────────────────────────────────────────────────

  async _generateAllKeys() {
    // 1. Generate Identity Key Pair (Curve25519 for DH + Ed25519 for signing)
    const ikDH = generateKeyPair();       // For DH operations in X3DH
    const ikSign = generateSigningKeyPair(); // For signing SPK

    const identityKeyData = {
      dh: {
        publicKey: bytesToBase64(ikDH.publicKey),
        privateKey: bytesToBase64(ikDH.privateKey),
      },
      sign: {
        publicKey: bytesToBase64(ikSign.publicKey),
        privateKey: bytesToBase64(ikSign.privateKey),
      },
      createdAt: Date.now(),
    };

    await SecureStorage.setItem(
      STORAGE_KEYS.IDENTITY_KEY_PAIR,
      JSON.stringify(identityKeyData),
    );

    this._identityKeyPair = {
      dh: ikDH,
      sign: ikSign,
    };

    // 2. Generate initial Signed Pre-Key
    await this.generateSignedPreKey();

    // 3. Generate One-Time Pre-Keys
    await this.generateOneTimePreKeys(OPK_BATCH_SIZE);
  }

  async _loadIdentityKey(rawData) {
    const data = JSON.parse(rawData);
    this._identityKeyPair = {
      dh: {
        publicKey: base64ToBytes(data.dh.publicKey),
        privateKey: base64ToBytes(data.dh.privateKey),
      },
      sign: {
        publicKey: base64ToBytes(data.sign.publicKey),
        privateKey: base64ToBytes(data.sign.privateKey),
      },
    };
  }

  /**
   * Get Identity Key Pair (in-memory, never store full object in AsyncStorage)
   */
  getIdentityKeyPair() {
    if (!this._identityKeyPair) {
      throw new Error('KeyManager not initialized');
    }
    return this._identityKeyPair;
  }

  /**
   * Get the public identity key as base64 (safe to share)
   */
  getIdentityPublicKey() {
    return bytesToBase64(this._identityKeyPair.dh.publicKey);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // SIGNED PRE-KEY
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Generate a new Signed Pre-Key pair, signed by Identity Key
   * Returns the data ready for server upload
   */
  async generateSignedPreKey() {
    const spkPair = generateKeyPair();
    const spkId = Date.now(); // Use timestamp as ID

    // Sign SPK public key with Identity signing key
    const signature = sign(
      spkPair.publicKey,
      this._identityKeyPair.sign.privateKey,
    );

    const spkData = {
      keyId: spkId,
      publicKey: bytesToBase64(spkPair.publicKey),
      privateKey: bytesToBase64(spkPair.privateKey),
      signature: bytesToBase64(signature),
      createdAt: Date.now(),
    };

    // Store in secure storage
    await SecureStorage.setItem(
      `${STORAGE_KEYS.SIGNED_PRE_KEYS}${spkId}`,
      JSON.stringify(spkData),
    );
    await SecureStorage.setItem(STORAGE_KEYS.CURRENT_SPK_ID, String(spkId));
    await SecureStorage.setItem(
      STORAGE_KEYS.SPK_ROTATION_TIMESTAMP,
      String(Date.now()),
    );

    Logger.info('KeyManager', `Generated SPK with ID: ${spkId}`);

    return {
      keyId: spkId,
      publicKey: spkPair.publicKey,
      signature,
    };
  }

  /**
   * Get current Signed Pre-Key pair (private key included for session creation)
   */
  async getCurrentSignedPreKey() {
    const spkId = await SecureStorage.getItem(STORAGE_KEYS.CURRENT_SPK_ID);
    if (!spkId) throw new Error('No signed pre-key found');
    return this.getSignedPreKey(parseInt(spkId, 10));
  }

  /**
   * Get a specific Signed Pre-Key by ID
   */
  async getSignedPreKey(keyId) {
    const raw = await SecureStorage.getItem(`${STORAGE_KEYS.SIGNED_PRE_KEYS}${keyId}`);
    if (!raw) throw new Error(`Signed pre-key ${keyId} not found`);
    
    const data = JSON.parse(raw);
    return {
      keyId: data.keyId,
      publicKey: base64ToBytes(data.publicKey),
      privateKey: base64ToBytes(data.privateKey),
      signature: base64ToBytes(data.signature),
    };
  }

  /**
   * Check if SPK needs rotation (30 days)
   */
  async shouldRotateSignedPreKey() {
    const lastRotationStr = await SecureStorage.getItem(STORAGE_KEYS.SPK_ROTATION_TIMESTAMP);
    if (!lastRotationStr) return true;

    const lastRotation = parseInt(lastRotationStr, 10);
    const daysSinceRotation = (Date.now() - lastRotation) / (1000 * 60 * 60 * 24);
    return daysSinceRotation >= SPK_ROTATION_DAYS;
  }

  /**
   * Rotate SPK if needed
   * @returns {{ rotated: boolean, newSpkBundle?: Object }}
   */
  async rotateSignedPreKeyIfNeeded() {
    if (await this.shouldRotateSignedPreKey()) {
      Logger.info('KeyManager', 'Rotating signed pre-key (30-day cycle)');
      const newSpk = await this.generateSignedPreKey();
      return {rotated: true, newSpkBundle: newSpk};
    }
    return {rotated: false};
  }

  // ─────────────────────────────────────────────────────────────────────────
  // ONE-TIME PRE-KEYS
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Generate a batch of One-Time Pre-Keys
   * @param {number} count
   * @returns {Array} Array of { keyId, publicKey } for server upload
   */
  async generateOneTimePreKeys(count = OPK_BATCH_SIZE) {
    Logger.info('KeyManager', `Generating ${count} one-time pre-keys`);

    const existingIdsRaw = await SecureStorage.getItem(STORAGE_KEYS.OPK_IDS);
    const existingIds = existingIdsRaw ? JSON.parse(existingIdsRaw) : [];

    const newKeys = [];
    const allIds = [...existingIds];

    for (let i = 0; i < count; i++) {
      const opkPair = generateKeyPair();
      const keyId = Date.now() + i; // Unique ID per key

      const opkData = {
        keyId,
        publicKey: bytesToBase64(opkPair.publicKey),
        privateKey: bytesToBase64(opkPair.privateKey),
        createdAt: Date.now(),
      };

      await SecureStorage.setItem(
        `${STORAGE_KEYS.ONE_TIME_PRE_KEYS}${keyId}`,
        JSON.stringify(opkData),
      );

      allIds.push(keyId);
      newKeys.push({
        keyId,
        publicKey: opkPair.publicKey,
      });
    }

    await SecureStorage.setItem(STORAGE_KEYS.OPK_IDS, JSON.stringify(allIds));
    return newKeys;
  }

  /**
   * Get a One-Time Pre-Key by ID and delete it (single use)
   * @returns {{ keyId, publicKey, privateKey }}
   */
  async consumeOneTimePreKey(keyId) {
    const raw = await SecureStorage.getItem(`${STORAGE_KEYS.ONE_TIME_PRE_KEYS}${keyId}`);
    if (!raw) throw new Error(`One-time pre-key ${keyId} not found`);

    const data = JSON.parse(raw);

    // Delete after use (one-time semantics)
    await SecureStorage.removeItem(`${STORAGE_KEYS.ONE_TIME_PRE_KEYS}${keyId}`);

    // Remove from IDs list
    const existingIdsRaw = await SecureStorage.getItem(STORAGE_KEYS.OPK_IDS);
    if (existingIdsRaw) {
      const ids = JSON.parse(existingIdsRaw).filter(id => id !== keyId);
      await SecureStorage.setItem(STORAGE_KEYS.OPK_IDS, JSON.stringify(ids));
    }

    return {
      keyId: data.keyId,
      publicKey: base64ToBytes(data.publicKey),
      privateKey: base64ToBytes(data.privateKey),
    };
  }

  /**
   * Get the current count of available One-Time Pre-Keys
   */
  async getOneTimePreKeyCount() {
    const raw = await SecureStorage.getItem(STORAGE_KEYS.OPK_IDS);
    return raw ? JSON.parse(raw).length : 0;
  }

  /**
   * Check if OPK refill is needed (< 20 remaining)
   */
  async needsOneTimePreKeyRefill() {
    const count = await this.getOneTimePreKeyCount();
    return count < OPK_REFILL_THRESHOLD;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // KEY BUNDLE (for server upload)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Build the full public key bundle for server registration
   * Private keys are NEVER included
   */
  async buildPublicKeyBundle(oneTimePreKeys) {
    const spk = await this.getCurrentSignedPreKey();

    return {
      identity_key: bytesToBase64(this._identityKeyPair.dh.publicKey),
      identity_signing_key: bytesToBase64(this._identityKeyPair.sign.publicKey),
      signed_pre_key: {
        key_id: spk.keyId,
        public_key: bytesToBase64(spk.publicKey),
        signature: bytesToBase64(spk.signature),
      },
      one_time_pre_keys: (oneTimePreKeys || []).map(k => ({
        key_id: k.keyId,
        public_key: bytesToBase64(k.publicKey),
      })),
    };
  }

  /**
   * Wipe all keys from secure storage (on logout or account deletion)
   */
  async wipeAllKeys() {
    Logger.warn('KeyManager', 'WIPING ALL KEYS');
    const opkIdsRaw = await SecureStorage.getItem(STORAGE_KEYS.OPK_IDS);
    if (opkIdsRaw) {
      const ids = JSON.parse(opkIdsRaw);
      for (const id of ids) {
        await SecureStorage.removeItem(`${STORAGE_KEYS.ONE_TIME_PRE_KEYS}${id}`);
      }
    }
    await SecureStorage.removeItem(STORAGE_KEYS.IDENTITY_KEY_PAIR);
    await SecureStorage.removeItem(STORAGE_KEYS.OPK_IDS);
    await SecureStorage.removeItem(STORAGE_KEYS.CURRENT_SPK_ID);
    await SecureStorage.removeItem(STORAGE_KEYS.SPK_ROTATION_TIMESTAMP);
    this._identityKeyPair = null;
    this._initialized = false;
  }
}

export default new KeyManager();
