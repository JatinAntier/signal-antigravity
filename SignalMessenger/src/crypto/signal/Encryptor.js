/**
 * Encryptor.js
 * High-level encryption API used by the messaging layer
 * Wraps SessionManager to provide simple encrypt/decrypt interface
 */

import SessionManager from './SessionManager';
import {bytesToBase64, base64ToBytes} from '../Curve25519';
import Logger from '../../utils/Logger';

/**
 * @typedef {Object} EncryptedPayload
 * @property {string} type         - 'initial' | 'message'
 * @property {Object} header       - Double Ratchet header
 * @property {string} ciphertext   - Base64 encrypted body
 * @property {Object} [x3dh_header] - Only for initial messages
 */

/**
 * Encrypt a message string for a recipient user
 * Automatically handles session creation (X3DH) and ratcheting
 *
 * @param {string}     recipientId   - Target user ID
 * @param {string}     plaintext     - Plaintext message
 * @param {Object|null} keyBundle    - Server key bundle (required for first message)
 * @returns {Promise<{ payload: EncryptedPayload, isInitialMessage: boolean }>}
 */
export async function encryptMessage(recipientId, plaintext, keyBundle = null) {
  try {
    Logger.info('Encryptor', `Encrypting message for user ${recipientId}`);

    const result = await SessionManager.encryptMessage(
      String(recipientId),
      plaintext,
      keyBundle,
    );

    Logger.info('Encryptor', `Message encrypted (initial=${result.isInitialMessage})`);
    return result;
  } catch (error) {
    Logger.error('Encryptor', `Encryption failed: ${error.message}`);
    throw new Error(`Encryption failed: ${error.message}`);
  }
}

/**
 * Decrypt an incoming encrypted payload
 *
 * @param {string}          senderId  - Sender user ID
 * @param {EncryptedPayload} payload  - Wire format payload
 * @returns {Promise<string>} Decrypted plaintext
 */
export async function decryptMessage(senderId, payload) {
  try {
    Logger.info('Encryptor', `Decrypting message from user ${senderId}`);

    const plaintext = await SessionManager.decryptMessage(
      String(senderId),
      payload,
    );

    Logger.info('Encryptor', 'Message decrypted successfully');
    return plaintext;
  } catch (error) {
    Logger.error('Encryptor', `Decryption failed: ${error.message}`);
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

/**
 * Encrypt binary file data for sending as attachment
 * @param {Uint8Array} fileBytes
 * @param {string}     recipientId
 * @param {Object|null} keyBundle
 * @returns {Promise<string>} Base64 encrypted attachment
 */
export async function encryptAttachment(fileBytes, recipientId, keyBundle = null) {
  // Convert binary to base64 for string-based encryption channel
  const b64 = bytesToBase64(fileBytes);
  const {payload} = await encryptMessage(recipientId, `__ATTACHMENT__${b64}`, keyBundle);
  return payload;
}

/**
 * Decrypt an encrypted attachment payload
 * @returns {Uint8Array} Raw file bytes
 */
export async function decryptAttachment(senderId, payload) {
  const plaintext = await decryptMessage(senderId, payload);
  if (!plaintext.startsWith('__ATTACHMENT__')) {
    throw new Error('Payload is not an attachment');
  }
  return base64ToBytes(plaintext.slice(14));
}

/**
 * Serialize an encrypted payload for WebSocket transmission
 */
export function serializePayload(payload) {
  return JSON.stringify(payload);
}

/**
 * Deserialize an incoming WebSocket payload
 */
export function deserializePayload(raw) {
  return JSON.parse(raw);
}
