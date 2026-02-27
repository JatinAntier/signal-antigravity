/**
 * PreKeyManager.js
 * Manages One-Time Pre-Key lifecycle:
 *   - Tracking server-side counts
 *   - Auto-refill when < 20 remaining
 *   - Integration with backend API
 */

import KeyManager from './KeyManager';
import {uploadKeys, getKeyCount} from '../../services/keyService';
import Logger from '../../utils/Logger';

const REFILL_THRESHOLD = 20;
const BATCH_SIZE = 100;

class PreKeyManager {
  constructor() {
    this._checkingRefill = false;
  }

  /**
   * Check server-side OPK count and refill if needed.
   * Called after every message sent / periodically.
   */
  async checkAndRefillPreKeys() {
    if (this._checkingRefill) return; // Prevent concurrent refills
    
    try {
      this._checkingRefill = true;
      
      // Query server for remaining count
      const {count} = await getKeyCount();
      Logger.info('PreKeyManager', `Server has ${count} one-time pre-keys remaining`);

      if (count < REFILL_THRESHOLD) {
        Logger.info('PreKeyManager', `Refilling pre-keys (${count} < ${REFILL_THRESHOLD})`);
        
        const newKeys = await KeyManager.generateOneTimePreKeys(BATCH_SIZE);
        await uploadKeys({oneTimePreKeys: newKeys});
        
        Logger.info('PreKeyManager', `Uploaded ${newKeys.length} new one-time pre-keys`);
      }
    } catch (error) {
      Logger.error('PreKeyManager', `Failed to refill pre-keys: ${error.message}`);
      // Non-fatal: next check will retry
    } finally {
      this._checkingRefill = false;
    }
  }

  /**
   * Rotate Signed Pre-Key if needed (30 days)
   * and upload new one to server
   */
  async rotateSignedPreKeyIfNeeded() {
    try {
      const {rotated, newSpkBundle} = await KeyManager.rotateSignedPreKeyIfNeeded();
      
      if (rotated && newSpkBundle) {
        await uploadKeys({signedPreKey: newSpkBundle});
        Logger.info('PreKeyManager', 'Uploaded new signed pre-key after rotation');
      }
      
      return rotated;
    } catch (error) {
      Logger.error('PreKeyManager', `SPK rotation failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Initial key upload after registration
   */
  async uploadInitialKeys(bundle) {
    await uploadKeys(bundle);
    Logger.info('PreKeyManager', 'Initial key bundle uploaded successfully');
  }
}

export default new PreKeyManager();
