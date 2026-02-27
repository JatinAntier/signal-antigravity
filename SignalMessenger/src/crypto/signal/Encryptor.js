import {
  signalEncrypt,
  signalDecrypt,
  signalDecryptPreKey,
  PreKeySignalMessage,
  SignalMessage,
  CiphertextMessageType,
  ProtocolAddress,
} from '@signalapp/libsignal-client';
import { Buffer } from 'buffer';
import {
  sessionStore,
  identityKeyStore,
  preKeyStore,
  signedPreKeyStore,
} from './SignalStore';
import SessionManager from './SessionManager';

export async function encryptMessage(remoteUserId, plaintext, bundle) {
  const address = ProtocolAddress.new(remoteUserId.toString(), 1);
  const session = await sessionStore.getSession(address);

  if (!session || !session.hasCurrentState()) {
    if (!bundle) throw new Error("No session exists and no key bundle was fetched to initiate X3DH");
    await SessionManager.establishSession(remoteUserId, bundle);
  }

  const plainMessageBytes = Buffer.from(plaintext, 'utf8');
  
  // Encrypt directly using libsignal (applies Double Ratchet automatically)
  const ciphertextMessage = await signalEncrypt(
    plainMessageBytes,
    address,
    sessionStore,
    identityKeyStore
  );

  return {
    type: ciphertextMessage.type() === CiphertextMessageType.PreKey ? "prekey" : "message",
    payload: Buffer.from(ciphertextMessage.serialize()).toString('base64'),
  };
}

export async function decryptMessage(remoteUserId, encryptedPayloadObject) {
  const address = ProtocolAddress.new(remoteUserId.toString(), 1);
  const dataBytes = Buffer.from(encryptedPayloadObject.payload, 'base64');
  const msgType = encryptedPayloadObject.type;

  let plaintextBytes;

  if (msgType === "prekey") {
    // This is the first message carrying the X3DH pre-key payload
    const preKeyMessage = PreKeySignalMessage.deserialize(dataBytes);
    plaintextBytes = await signalDecryptPreKey(
      preKeyMessage,
      address,
      sessionStore,
      identityKeyStore,
      preKeyStore,
      signedPreKeyStore,
      null // kyberPreKeyStore NOT used in this basic implementation
    );
  } else {
    // This is a normal message using the Double Ratchet
    const signalMessage = SignalMessage.deserialize(dataBytes);
    plaintextBytes = await signalDecrypt(
      signalMessage,
      address,
      sessionStore,
      identityKeyStore
    );
  }

  return Buffer.from(plaintextBytes).toString('utf8');
}
