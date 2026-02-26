/**
 * keyService.js
 * API calls for Signal Protocol key management
 */

import {keysAPI} from './api';

/**
 * Upload initial key bundle or refresh keys
 * @param {Object} bundle - { identity_key, identity_signing_key, signed_pre_key, one_time_pre_keys }
 */
export async function uploadKeys(bundle) {
  const response = await keysAPI.uploadKeys(bundle);
  return response.data;
}

/**
 * Get remaining OPK count from server
 * @returns {{ count: number }}
 */
export async function getKeyCount() {
  const response = await keysAPI.getKeyCount();
  return response.data;
}

/**
 * Fetch a user's public key bundle for session initiation (X3DH sender side)
 * Server returns one OPK (and removes it from pool - one-time use)
 * @param {string|number} userId
 * @returns {Object} key bundle
 */
export async function fetchUserKeyBundle(userId) {
  const response = await keysAPI.getUserKeys(userId);
  return response.data;
}
