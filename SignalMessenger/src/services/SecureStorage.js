/**
 * SecureStorage.js
 * Production-grade secure key-value storage
 * Uses react-native-keychain for sensitive data (private keys)
 * Uses react-native-encrypted-storage as fallback for larger data
 *
 * CRITICAL: Private keys NEVER touch AsyncStorage (unencrypted)
 */

import EncryptedStorage from 'react-native-encrypted-storage';
import * as Keychain from 'react-native-keychain';
import Logger from '../utils/Logger';

// Keychain service name
const KEYCHAIN_SERVICE = 'com.signalmessenger.keys';

class SecureStorage {
  /**
   * Store a sensitive value securely
   * Uses EncryptedStorage (AES-256 backed by Android Keystore / iOS Secure Enclave)
   */
  async setItem(key, value) {
    try {
      await EncryptedStorage.setItem(key, value);
    } catch (error) {
      Logger.error('SecureStorage', `setItem failed for key ${key}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Retrieve a value from secure storage
   */
  async getItem(key) {
    try {
      return await EncryptedStorage.getItem(key);
    } catch (error) {
      Logger.error('SecureStorage', `getItem failed for key ${key}: ${error.message}`);
      return null;
    }
  }

  /**
   * Remove a value from secure storage
   */
  async removeItem(key) {
    try {
      await EncryptedStorage.removeItem(key);
    } catch (error) {
      Logger.error('SecureStorage', `removeItem failed for key ${key}: ${error.message}`);
    }
  }

  /**
   * Store the most sensitive credentials in iOS Keychain / Android Keystore
   * (higher security than EncryptedStorage for small critical values)
   */
  async setCredentials(username, password) {
    try {
      await Keychain.setGenericPassword(username, password, {
        service: KEYCHAIN_SERVICE,
        accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE,
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
      });
    } catch (error) {
      Logger.error('SecureStorage', `setCredentials failed: ${error.message}`);
      throw error;
    }
  }

  async getCredentials() {
    try {
      return await Keychain.getGenericPassword({service: KEYCHAIN_SERVICE});
    } catch (error) {
      Logger.error('SecureStorage', `getCredentials failed: ${error.message}`);
      return null;
    }
  }

  async removeCredentials() {
    try {
      await Keychain.resetGenericPassword({service: KEYCHAIN_SERVICE});
    } catch (error) {
      Logger.error('SecureStorage', `removeCredentials failed: ${error.message}`);
    }
  }

  /**
   * Store JWT tokens securely
   */
  async storeTokens(accessToken, refreshToken) {
    await this.setItem('jwt_access_token', accessToken);
    await this.setItem('jwt_refresh_token', refreshToken);
  }

  async getAccessToken() {
    return this.getItem('jwt_access_token');
  }

  async getRefreshToken() {
    return this.getItem('jwt_refresh_token');
  }

  async clearTokens() {
    await this.removeItem('jwt_access_token');
    await this.removeItem('jwt_refresh_token');
  }

  /**
   * Clear all app data (on logout)
   */
  async clearAll() {
    await EncryptedStorage.clear();
    await this.removeCredentials();
    Logger.warn('SecureStorage', 'All secure storage cleared');
  }
}

export default new SecureStorage();
