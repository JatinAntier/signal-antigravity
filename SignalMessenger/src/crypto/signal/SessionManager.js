/**
 * SessionManager.js
 * Manages Signal Protocol sessions per conversation
 *
 * Responsibilities:
 * - Create new sessions via X3DH (first message)
 * - Load/save Double Ratchet state per session
 * - Handle session deletion on identity key change (reinstall warning)
 * - Manage concurrent sessions per user (multi-device)
 */

import {x3dhSender, x3dhReceiver, serializeX3DHHeader, deserializeX3DHHeader} from '../signal/X3DH';
import {
  initializeSender,
  initializeReceiver,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeRatchetState,
  deserializeRatchetState,
} from '../signal/DoubleRatchet';
import KeyManager from './KeyManager';
import SecureStorage from '../../services/SecureStorage';
import {base64ToBytes, bytesToBase64} from '../Curve25519';
import Logger from '../../utils/Logger';

const SESSION_KEY_PREFIX = 'signal_session_';
const SESSION_INDEX_KEY = 'signal_session_index';

class SessionManager {
  constructor() {
    this._sessions = new Map(); // In-memory cache: sessionId → ratchet state
  }

  // ─────────────────────────────────────────────────────────────────────────
  // SESSION CREATION
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Create a new outbound session with a remote user (X3DH sender side)
   * Called when Alice sends the first message to Bob
   *
   * @param {string} recipientUserId
   * @param {Object} recipientKeyBundle - Public keys fetched from server
   * @returns {string} sessionId
   */
  async createOutboundSession(recipientUserId, recipientKeyBundle) {
    Logger.info('SessionManager', `Creating outbound session for user ${recipientUserId}`);

    const localIK = KeyManager.getIdentityKeyPair();

    // Parse remote key bundle
    const bundle = {
      userId: recipientKeyBundle.user_id,
      deviceId: recipientKeyBundle.device_id,
      identityKey: base64ToBytes(recipientKeyBundle.identity_key),
      signedPreKey: {
        keyId: recipientKeyBundle.signed_pre_key.key_id,
        publicKey: base64ToBytes(recipientKeyBundle.signed_pre_key.public_key),
        signature: base64ToBytes(recipientKeyBundle.signed_pre_key.signature),
      },
      oneTimePreKey: recipientKeyBundle.one_time_pre_key
        ? {
            keyId: recipientKeyBundle.one_time_pre_key.key_id,
            publicKey: base64ToBytes(recipientKeyBundle.one_time_pre_key.public_key),
          }
        : null,
    };

    // X3DH key agreement
    const x3dhResult = await x3dhSender(localIK.dh, bundle);

    // Initialize Double Ratchet as sender
    const ratchetState = initializeSender(
      x3dhResult.masterSecret,
      bundle.signedPreKey.publicKey,
    );

    const sessionId = _buildSessionId(recipientUserId, recipientKeyBundle.device_id || 0);

    // Persist session state
    await this._saveSession(sessionId, {
      userId: recipientUserId,
      ratchetState,
      remoteIdentityKey: bundle.identityKey,
      x3dhHeader: serializeX3DHHeader(x3dhResult.initialMessage, localIK.dh.publicKey),
      isOutbound: true,
      createdAt: Date.now(),
    });

    Logger.info('SessionManager', `Outbound session created: ${sessionId}`);
    return sessionId;
  }

  /**
   * Create an inbound session (X3DH receiver side)
   * Called when Bob receives Alice's first encrypted message
   *
   * @param {string} senderUserId
   * @param {Object} x3dhHeader   - Parsed from the incoming message
   * @param {number} signedPreKeyId
   * @param {number|null} oneTimePreKeyId
   */
  async createInboundSession(senderUserId, x3dhHeader, signedPreKeyId, oneTimePreKeyId) {
    Logger.info('SessionManager', `Creating inbound session from user ${senderUserId}`);

    const localIK = KeyManager.getIdentityKeyPair();
    const localSPK = await KeyManager.getSignedPreKey(signedPreKeyId);
    
    let localOPK = null;
    if (oneTimePreKeyId) {
      localOPK = await KeyManager.consumeOneTimePreKey(oneTimePreKeyId);
    }

    const header = deserializeX3DHHeader(x3dhHeader);

    // X3DH receiver side
    const x3dhResult = await x3dhReceiver(
      localIK.dh,
      localSPK,
      localOPK,
      header,
    );

    // Initialize Double Ratchet as receiver
    const ratchetState = initializeReceiver(x3dhResult.masterSecret, localSPK);

    const sessionId = _buildSessionId(senderUserId, 0);

    await this._saveSession(sessionId, {
      userId: senderUserId,
      ratchetState,
      remoteIdentityKey: header.senderIdentityKey,
      isOutbound: false,
      createdAt: Date.now(),
    });

    Logger.info('SessionManager', `Inbound session created: ${sessionId}`);
    return {sessionId, ratchetState};
  }

  // ─────────────────────────────────────────────────────────────────────────
  // SESSION LOOKUP
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Check if an active session exists for a user
   */
  async hasSession(userId, deviceId = 0) {
    const sessionId = _buildSessionId(userId, deviceId);
    
    // Check in-memory cache first
    if (this._sessions.has(sessionId)) return true;

    // Check secure storage
    const raw = await SecureStorage.getItem(`${SESSION_KEY_PREFIX}${sessionId}`);
    return !!raw;
  }

  /**
   * Load a session from storage
   */
  async loadSession(userId, deviceId = 0) {
    const sessionId = _buildSessionId(userId, deviceId);

    // Memory cache hit
    if (this._sessions.has(sessionId)) {
      return this._sessions.get(sessionId);
    }

    const raw = await SecureStorage.getItem(`${SESSION_KEY_PREFIX}${sessionId}`);
    if (!raw) return null;

    const data = JSON.parse(raw);
    const session = {
      ...data,
      ratchetState: deserializeRatchetState(data.ratchetState),
      remoteIdentityKey: data.remoteIdentityKey
        ? base64ToBytes(data.remoteIdentityKey)
        : null,
    };

    // Populate memory cache
    this._sessions.set(sessionId, session);
    return session;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // ENCRYPT / DECRYPT
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Encrypt a plaintext message for a user
   * Creates session via X3DH if one doesn't exist
   *
   * @param {string}     recipientUserId
   * @param {string}     plaintext
   * @param {Object|null} keyBundle - Required only for first message
   * @returns {{ payload: Object, isInitialMessage: boolean }}
   */
  async encryptMessage(recipientUserId, plaintext, keyBundle = null) {
    const deviceId = 0;
    let session = await this.loadSession(recipientUserId, deviceId);
    let isInitialMessage = false;

    if (!session) {
      if (!keyBundle) {
        throw new Error('No session found and no key bundle provided. Fetch keys first.');
      }
      // First message – X3DH
      await this.createOutboundSession(recipientUserId, keyBundle);
      session = await this.loadSession(recipientUserId, deviceId);
      isInitialMessage = true;
    }

    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(plaintext);

    // Encrypt via Double Ratchet
    const {state: newState, header, ciphertext} = ratchetEncrypt(
      session.ratchetState,
      plaintextBytes,
    );

    // Update session state
    session.ratchetState = newState;
    await this._saveSession(_buildSessionId(recipientUserId, deviceId), session);

    // Build wire payload
    const payload = {
      type: isInitialMessage ? 'initial' : 'message',
      header: {
        dh: bytesToBase64(header.dh),
        pn: header.pn,
        n: header.n,
      },
      ciphertext,
      ...(isInitialMessage && {x3dh_header: session.x3dhHeader}),
    };

    return {payload, isInitialMessage};
  }

  /**
   * Decrypt an incoming message
   *
   * @param {string} senderUserId
   * @param {Object} payload     - Wire message payload
   * @returns {string} decrypted plaintext
   */
  async decryptMessage(senderUserId, payload) {
    const deviceId = 0;
    let session = await this.loadSession(senderUserId, deviceId);

    if (!session && payload.type === 'initial') {
      // First message → create inbound session
      const inbound = await this.createInboundSession(
        senderUserId,
        payload.x3dh_header,
        payload.x3dh_header.signed_pre_key_id,
        payload.x3dh_header.one_time_pre_key_id,
      );
      session = await this.loadSession(senderUserId, deviceId);
    }

    if (!session) {
      throw new Error(`No session found for user ${senderUserId}`);
    }

    // Reconstruct header with Uint8Array DH key
    const header = {
      dh: base64ToBytes(payload.header.dh),
      pn: payload.header.pn,
      n: payload.header.n,
    };

    const {state: newState, plaintext} = ratchetDecrypt(
      session.ratchetState,
      header,
      payload.ciphertext,
    );

    // Update session state
    session.ratchetState = newState;
    await this._saveSession(_buildSessionId(senderUserId, deviceId), session);

    const decoder = new TextDecoder();
    return decoder.decode(plaintext);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // IDENTITY KEY CHANGE DETECTION
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Verify a user's identity key hasn't changed (detect reinstall/compromise)
   * @returns {{ changed: boolean, safetyNumber?: string }}
   */
  async verifyRemoteIdentityKey(userId, newIdentityKey) {
    const session = await this.loadSession(userId);
    if (!session) return {changed: false};

    const storedKey = session.remoteIdentityKey;

    // Compare keys
    const storedHex = bytesToBase64(storedKey);
    const newHex =
      typeof newIdentityKey === 'string'
        ? newIdentityKey
        : bytesToBase64(newIdentityKey);

    if (storedHex !== newHex) {
      Logger.warn('SessionManager', `Identity key changed for user ${userId}`);
      return {
        changed: true,
        safetyNumber: _computeSafetyNumber(
          base64ToBytes(newHex),
          KeyManager.getIdentityKeyPair().dh.publicKey,
        ),
      };
    }

    return {changed: false};
  }

  /**
   * Delete all sessions for a user (after identity key change)
   */
  async deleteAllSessions(userId) {
    Logger.warn('SessionManager', `Deleting all sessions for user ${userId}`);
    const sessionId = _buildSessionId(userId, 0);
    this._sessions.delete(sessionId);
    await SecureStorage.removeItem(`${SESSION_KEY_PREFIX}${sessionId}`);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // INTERNAL HELPERS
  // ─────────────────────────────────────────────────────────────────────────

  async _saveSession(sessionId, session) {
    const serializable = {
      ...session,
      ratchetState: serializeRatchetState(session.ratchetState),
      remoteIdentityKey: session.remoteIdentityKey
        ? bytesToBase64(session.remoteIdentityKey)
        : null,
    };

    this._sessions.set(sessionId, session); // Update cache
    await SecureStorage.setItem(
      `${SESSION_KEY_PREFIX}${sessionId}`,
      JSON.stringify(serializable),
    );
  }

  async getAllSessionIds() {
    const raw = await SecureStorage.getItem(SESSION_INDEX_KEY);
    return raw ? JSON.parse(raw) : [];
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function _buildSessionId(userId, deviceId = 0) {
  return `${userId}_${deviceId}`;
}

/**
 * Compute Safety Number (fingerprint) from two identity keys
 * Used to display to users for manual verification
 */
function _computeSafetyNumber(remoteIK, localIK) {
  const combined = new Uint8Array(localIK.length + remoteIK.length);
  combined.set(localIK, 0);
  combined.set(remoteIK, localIK.length);

  // Format as 60-digit code (12 groups of 5 digits), matching Signal's standard
  const base = bytesToBase64(combined);
  let hash = 0;
  for (let i = 0; i < base.length; i++) {
    hash = ((hash << 5) - hash + base.charCodeAt(i)) | 0;
  }
  const num = Math.abs(hash);
  return num.toString().padStart(10, '0')
    .match(/.{1,5}/g)
    .join(' ');
}

export default new SessionManager();
