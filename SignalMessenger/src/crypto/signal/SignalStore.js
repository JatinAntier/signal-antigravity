import {
  SessionStore,
  IdentityKeyStore,
  PreKeyStore,
  SignedPreKeyStore,
  IdentityChange,
  PrivateKey,
  PublicKey,
  SessionRecord,
  PreKeyRecord,
  SignedPreKeyRecord,
} from '@signalapp/libsignal-client';
import SecureStorage from '../../services/SecureStorage';

class StoreHelper {
  static async get(key) {
    const data = await SecureStorage.getItem(key);
    if (!data) return null;
    // Data is assumed to be stored as a hex string or base64. Let's use hex/base64 conversions
    return Buffer.from(data, 'base64');
  }
  static async set(key, uint8array) {
    const data = Buffer.from(uint8array).toString('base64');
    await SecureStorage.setItem(key, data);
  }
  static async remove(key) {
    await SecureStorage.removeItem(key);
  }
}

export class AppSessionStore extends SessionStore {
  async saveSession(name, record) {
    const key = `session_${name.name()}_${name.deviceId()}`;
    await StoreHelper.set(key, record.serialize());
  }

  async getSession(name) {
    const key = `session_${name.name()}_${name.deviceId()}`;
    const data = await StoreHelper.get(key);
    if (data) return SessionRecord.deserialize(data);
    return null;
  }

  async getExistingSessions(addresses) {
    const sessions = [];
    for (const addr of addresses) {
      const sess = await this.getSession(addr);
      if (sess) sessions.push(sess);
    }
    return sessions;
  }
}

export class AppIdentityKeyStore extends IdentityKeyStore {
  async getIdentityKey() {
    const data = await StoreHelper.get('identity_private_key');
    if (!data) throw new Error("No identity key found");
    return PrivateKey.deserialize(data);
  }

  async getLocalRegistrationId() {
    const data = await SecureStorage.getItem('registration_id');
    return parseInt(data, 10) || 0;
  }

  async saveIdentity(name, key) {
    const storageKey = `identity_${name.name()}`;
    const existing = await StoreHelper.get(storageKey);
    await StoreHelper.set(storageKey, key.serialize());
    if (existing) {
      const oldKey = PublicKey.deserialize(existing);
      if (oldKey.compare(key) !== 0) {
        return IdentityChange.ReplacedExisting;
      }
    }
    return IdentityChange.NewOrUnchanged;
  }

  async isTrustedIdentity(name, key, direction) {
    const storageKey = `identity_${name.name()}`;
    const trusted = await StoreHelper.get(storageKey);
    if (trusted) {
      const trustedKey = PublicKey.deserialize(trusted);
      return trustedKey.compare(key) === 0;
    }
    return true; // Trust on first use (TOFU)
  }

  async getIdentity(name) {
    const storageKey = `identity_${name.name()}`;
    const data = await StoreHelper.get(storageKey);
    if (data) return PublicKey.deserialize(data);
    return null;
  }
}

export class AppPreKeyStore extends PreKeyStore {
  async savePreKey(id, record) {
    await StoreHelper.set(`prekey_${id}`, record.serialize());
  }

  async getPreKey(id) {
    const data = await StoreHelper.get(`prekey_${id}`);
    if (!data) throw new Error(`PreKey ${id} not found`);
    return PreKeyRecord.deserialize(data);
  }

  async removePreKey(id) {
    await StoreHelper.remove(`prekey_${id}`);
  }
}

export class AppSignedPreKeyStore extends SignedPreKeyStore {
  async saveSignedPreKey(id, record) {
    await StoreHelper.set(`signed_prekey_${id}`, record.serialize());
  }

  async getSignedPreKey(id) {
    const data = await StoreHelper.get(`signed_prekey_${id}`);
    if (!data) throw new Error(`SignedPreKey ${id} not found`);
    return SignedPreKeyRecord.deserialize(data);
  }
}

export const sessionStore = new AppSessionStore();
export const identityKeyStore = new AppIdentityKeyStore();
export const preKeyStore = new AppPreKeyStore();
export const signedPreKeyStore = new AppSignedPreKeyStore();
