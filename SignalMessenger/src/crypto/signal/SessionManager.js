import {
  ProtocolAddress,
  PreKeyBundle,
  PublicKey,
  processPreKeyBundle,
  signalEncrypt,
  signalDecrypt,
  signalDecryptPreKey,
  CiphertextMessageType,
  CiphertextMessage,
  PreKeySignalMessage,
  SignalMessage,
} from '@signalapp/libsignal-client';
import {
  sessionStore,
  identityKeyStore,
  preKeyStore,
  signedPreKeyStore,
} from './SignalStore';
import { Buffer } from 'buffer';

class SessionManager {
  /**
   * Processes a PreKey bundle retrieved from the server for a recipient
   */
  async establishSession(remoteUserId, bundle) {
    const address = ProtocolAddress.new(remoteUserId.toString(), 1); // Device ID 1
    
    // De-serialize the keys from Base64
    const identityKey = PublicKey.deserialize(Buffer.from(bundle.identity_public_key, 'base64'));
    const signedPreKeyPublic = PublicKey.deserialize(Buffer.from(bundle.signed_prekey.publicKey, 'base64'));
    const signedPreKeySignature = Buffer.from(bundle.signed_prekey.signature, 'base64');
    
    // One time pre key is optional
    let oneTimePreKeyId = null;
    let oneTimePreKeyPublic = null;
    if (bundle.one_time_prekey) {
      oneTimePreKeyId = bundle.one_time_prekey.id;
      oneTimePreKeyPublic = PublicKey.deserialize(Buffer.from(bundle.one_time_prekey.publicKey, 'base64'));
    }

    const preKeyBundle = PreKeyBundle.new(
      1, // Device ID
      address.deviceId(),
      oneTimePreKeyId,
      oneTimePreKeyPublic,
      bundle.signed_prekey.id,
      signedPreKeyPublic,
      signedPreKeySignature,
      identityKey
    );

    await processPreKeyBundle(preKeyBundle, address, sessionStore, identityKeyStore);
    return true;
  }

  async hasSession(remoteUserId) {
    const address = ProtocolAddress.new(remoteUserId.toString(), 1);
    const session = await sessionStore.getSession(address);
    return session && session.hasCurrentState();
  }

  async verifyRemoteIdentityKey(remoteUserId, newPublicKeyBase64) {
    const address = ProtocolAddress.new(remoteUserId.toString(), 1);
    const existingKey = await identityKeyStore.getIdentity(address);
    if (!existingKey) return { changed: false };

    const newKey = PublicKey.deserialize(Buffer.from(newPublicKeyBase64, 'base64'));
    if (existingKey.compare(newKey) !== 0) {
      // Key mismatch, possible reinstall or MITM
      return { changed: true, safetyNumber: 'CHANGED_V2' };
    }
    return { changed: false };
  }

  async deleteAllSessions(remoteUserId) {
    const address = ProtocolAddress.new(remoteUserId.toString(), 1);
    const key = `session_${address.name()}_${address.deviceId()}`;
    await sessionStore.remove(address);
  }
}

export default new SessionManager();
