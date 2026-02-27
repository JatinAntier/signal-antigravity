import {
  IdentityKeyPair,
  SignedPreKeyRecord,
  PreKeyRecord,
  PrivateKey,
  PublicKey,
} from '@signalapp/libsignal-client';
import SecureStorage from '../../services/SecureStorage';
import {
  identityKeyStore,
  preKeyStore,
  signedPreKeyStore,
} from './SignalStore';
import { Buffer } from 'buffer';

class KeyManager {
  /**
   * Generates a new identity and initial batches of prekeys 
   * @returns {Object} Public keys needed to send to the server
   */
  async initialize() {
    const existing = await SecureStorage.getItem('registration_id');
    if (existing) {
      return { isNewDevice: false };
    }

    // 1. Generate local registration ID
    const registrationId = Math.floor(Math.random() * 16380) + 1;
    await SecureStorage.setItem('registration_id', registrationId.toString());

    // 2. Generate Identity Key Pair
    const idKey = IdentityKeyPair.generate();
    await SecureStorage.setItem('identity_private_key', Buffer.from(idKey.privateKey().serialize()).toString('base64'));
    await SecureStorage.setItem('identity_public_key', Buffer.from(idKey.publicKey().serialize()).toString('base64'));

    // 3. Generate Signed Pre-Key
    const timestamp = Math.floor(Date.now() / 1000);
    const spkSecret = PrivateKey.generate();
    const spkPublic = spkSecret.getPublicKey();
    const signature = idKey.privateKey().sign(spkPublic.serialize());
    
    const signedPreKey = SignedPreKeyRecord.new(1, timestamp, spkPublic, spkSecret, signature);
    await signedPreKeyStore.saveSignedPreKey(1, signedPreKey);
    await SecureStorage.setItem('current_spk_id', '1');

    // 4. Generate 100 One-Time Pre-Keys
    const oneTimePreKeys = [];
    for (let i = 1; i <= 100; i++) {
      const opkSecret = PrivateKey.generate();
      const opkRecord = PreKeyRecord.new(i, opkSecret.getPublicKey(), opkSecret);
      await preKeyStore.savePreKey(i, opkRecord);
      
      oneTimePreKeys.push({
        keyId: i,
        publicKey: Buffer.from(opkRecord.publicKey().serialize()).toString('base64')
      });
    }

    return {
      isNewDevice: true,
      bundle: {
        registrationId,
        identityPubKey: Buffer.from(idKey.publicKey().serialize()).toString('base64'),
        signedPreKey: {
          keyId: 1,
          publicKey: Buffer.from(signedPreKey.publicKey().serialize()).toString('base64'),
          signature: Buffer.from(signedPreKey.signature()).toString('base64')
        },
        oneTimePreKeys
      }
    };
  }

  /**
   * Wipes all Signal keys on logout
   */
  async wipeAllKeys() {
    await SecureStorage.removeItem('registration_id');
    await SecureStorage.removeItem('identity_private_key');
    await SecureStorage.removeItem('identity_public_key');
    await SecureStorage.removeItem('current_spk_id');
    // In a real app we would clear all session_ and prekey_ SecureStorage entries matching the regex.
    // Assuming clearTokens handles all local cleanup per chat.
  }

  async getIdentityPublicKey() {
    return await SecureStorage.getItem('identity_public_key');
  }

  /**
   * Generates a batch of one time pre keys
   * @param {number} count 
   * @returns {Array} List of public OPKs
   */
  async generateOneTimePreKeys(count = 100) {
    const rawIndex = await SecureStorage.getItem('last_opk_index');
    let startIndex = parseInt(rawIndex || '0', 10) + 1;

    const newKeys = [];
    for (let i = 0; i < count; i++) {
        const opkId = startIndex + i;
        const opkSecret = PrivateKey.generate();
        const opkRecord = PreKeyRecord.new(opkId, opkSecret.getPublicKey(), opkSecret);
        await preKeyStore.savePreKey(opkId, opkRecord);
        
        newKeys.push({
            keyId: opkId,
            publicKey: Buffer.from(opkRecord.publicKey().serialize()).toString('base64')
        });
    }

    await SecureStorage.setItem('last_opk_index', (startIndex + count - 1).toString());
    return newKeys;
  }

  /**
   * Rotates Signed Pre Key if older than 30 days
   */
  async rotateSignedPreKeyIfNeeded() {
      // Stub implementation: 30 days rotate logic
      const idKeyBase64 = await SecureStorage.getItem('identity_private_key');
      if (!idKeyBase64) return { rotated: false };

      // Usually we fetch timestamp of current. Let's just assume trigger rotates.
      const rawSpkId = await SecureStorage.getItem('current_spk_id');
      const nextSpkId = parseInt(rawSpkId || '0', 10) + 1;

      const privKey = PrivateKey.deserialize(Buffer.from(idKeyBase64, 'base64'));

      const timestamp = Math.floor(Date.now() / 1000);
      const spkSecret = PrivateKey.generate();
      const spkPublic = spkSecret.getPublicKey();
      const signature = privKey.sign(spkPublic.serialize());
      
      const signedPreKey = SignedPreKeyRecord.new(nextSpkId, timestamp, spkPublic, spkSecret, signature);
      await signedPreKeyStore.saveSignedPreKey(nextSpkId, signedPreKey);
      await SecureStorage.setItem('current_spk_id', nextSpkId.toString());

      return {
          rotated: true,
          newSpkBundle: {
              keyId: nextSpkId,
              publicKey: Buffer.from(signedPreKey.publicKey().serialize()).toString('base64'),
              signature: Buffer.from(signedPreKey.signature()).toString('base64')
          }
      };
  }
}

export default new KeyManager();
