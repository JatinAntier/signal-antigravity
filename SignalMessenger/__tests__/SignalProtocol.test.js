import {
  PrivateKey,
  PublicKey,
  IdentityKeyPair,
  SignedPreKeyRecord,
  PreKeyRecord,
  PreKeyBundle,
  ProtocolAddress,
  processPreKeyBundle,
  signalEncrypt,
  signalDecrypt,
  signalDecryptPreKey,
  CiphertextMessageType,
  SessionStore,
  IdentityKeyStore,
  PreKeyStore,
  SignedPreKeyStore,
  IdentityChange,
} from '@signalapp/libsignal-client';

// Simple in-memory stores for testing
class MemSessionStore extends SessionStore {
  constructor() {
    super();
    this.sessions = new Map();
  }
  async saveSession(name, record) {
    this.sessions.set(`${name.name()}_${name.deviceId()}`, record.serialize());
  }
  async getSession(name) {
    const data = this.sessions.get(`${name.name()}_${name.deviceId()}`);
    return data ? require('@signalapp/libsignal-client').SessionRecord.deserialize(data) : null;
  }
  async getExistingSessions(addresses) { return []; }
}

class MemIdentityStore extends IdentityKeyStore {
  constructor(identityKey, localId) {
    super();
    this.idKey = identityKey;
    this.localId = localId;
    this.identities = new Map();
  }
  async getIdentityKey() { return this.idKey.privateKey(); }
  async getLocalRegistrationId() { return this.localId; }
  async saveIdentity(name, key) {
    this.identities.set(name.name(), key.serialize());
    return IdentityChange.NewOrUnchanged;
  }
  async isTrustedIdentity(name, key, direction) { return true; }
  async getIdentity(name) {
    const data = this.identities.get(name.name());
    return data ? PublicKey.deserialize(data) : null;
  }
}

class MemPreKeyStore extends PreKeyStore {
  constructor() { super(); this.keys = new Map(); }
  async savePreKey(id, record) { this.keys.set(id, record.serialize()); }
  async getPreKey(id) { 
    const data = this.keys.get(id);
    if (!data) throw new Error("not found");
    return PreKeyRecord.deserialize(data);
  }
  async removePreKey(id) { this.keys.delete(id); }
}

class MemSignedPreKeyStore extends SignedPreKeyStore {
  constructor() { super(); this.keys = new Map(); }
  async saveSignedPreKey(id, record) { this.keys.set(id, record.serialize()); }
  async getSignedPreKey(id) {
    const data = this.keys.get(id);
    if (!data) throw new Error("not found");
    return SignedPreKeyRecord.deserialize(data);
  }
}

describe('Signal Protocol Integration via @signalapp/libsignal-client', () => {
  it('Should successfully establish the X3DH shared session and execute Double Ratchet message exchanges', async () => {
    
    // --- STEP 1: KEY GENERATION ---

    // Alice
    const aliceId = IdentityKeyPair.generate();
    const aliceSessionStore = new MemSessionStore();
    const aliceIdentityStore = new MemIdentityStore(aliceId, 111);

    // Bob
    const bobId = IdentityKeyPair.generate();
    const bobSessionStore = new MemSessionStore();
    const bobIdentityStore = new MemIdentityStore(bobId, 222);
    const bobPreKeyStore = new MemPreKeyStore();
    const bobSignedStore = new MemSignedPreKeyStore();

    // Bob generates Pre-Keys
    const spkSecret = PrivateKey.generate();
    const signature = bobId.privateKey().sign(spkSecret.getPublicKey().serialize());
    const bobSPK = SignedPreKeyRecord.new(1, Date.now(), spkSecret.getPublicKey(), spkSecret, signature);
    await bobSignedStore.saveSignedPreKey(1, bobSPK);

    const opkSecret = PrivateKey.generate();
    const bobOPK = PreKeyRecord.new(10, opkSecret.getPublicKey(), opkSecret);
    await bobPreKeyStore.savePreKey(10, bobOPK);

    // --- STEP 2: ALICE INITIATES X3DH ---
    // Alice builds a PreKeyBundle representing Bob's keys fetched from the server
    const bundle = PreKeyBundle.new(
      222, // registrationId
      1, // deviceId
      10, // prekeyId
      bobOPK.publicKey(), // prekeyPublic
      1, // signedPrekeyId
      bobSPK.publicKey(), // signedPrekeyPublic
      signature, // signedPrekeySignature
      bobId.publicKey() // identityKey
    );

    const bobAddress = ProtocolAddress.new('bob', 1);

    await processPreKeyBundle(bundle, bobAddress, aliceSessionStore, aliceIdentityStore);

    // --- STEP 3: ALICE ENCRYPTS FIRST MESSAGE ---
    const msg1Text = "Hello Bob! This is securely E2EE.";
    const plainMessageBytes = Buffer.from(msg1Text, 'utf8');

    const aliceCiphertextMsg = await signalEncrypt(
      plainMessageBytes,
      bobAddress,
      aliceSessionStore,
      aliceIdentityStore
    );

    expect(aliceCiphertextMsg.type()).toBe(CiphertextMessageType.PreKey);

    // --- STEP 4: BOB RECEIVES FIRST MESSAGE ---
    const aliceAddress = ProtocolAddress.new('alice', 1);

    // Bob processes the PreKey message
    const preKeyMessage = require('@signalapp/libsignal-client').PreKeySignalMessage.deserialize(aliceCiphertextMsg.serialize());
    
    const bobPlaintextBytes = await signalDecryptPreKey(
      preKeyMessage,
      aliceAddress,
      bobSessionStore,
      bobIdentityStore,
      bobPreKeyStore,
      bobSignedStore,
      null
    );

    const decodedBob = Buffer.from(bobPlaintextBytes).toString('utf8');
    expect(decodedBob).toBe(msg1Text);

    // --- STEP 5: BOB REPLIES ---
    const msg2Text = "Hey Alice, I got your encrypted message!";
    const bobCiphertextMsg = await signalEncrypt(
      Buffer.from(msg2Text, 'utf8'),
      aliceAddress,
      bobSessionStore,
      bobIdentityStore
    );

    expect(bobCiphertextMsg.type()).toBe(CiphertextMessageType.Whisper); // Normal Message

    // --- STEP 6: ALICE DECRYPTS REPLY ---
    const signalMessage = require('@signalapp/libsignal-client').SignalMessage.deserialize(bobCiphertextMsg.serialize());
    
    const aliceDecryptedBytes = await signalDecrypt(
      signalMessage,
      bobAddress,
      aliceSessionStore,
      aliceIdentityStore
    );

    expect(Buffer.from(aliceDecryptedBytes).toString('utf8')).toBe(msg2Text);

  });
});
