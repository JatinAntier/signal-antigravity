import {generateKeyPair} from '../src/crypto/Curve25519';
import {x3dhSender, x3dhReceiver} from '../src/crypto/signal/X3DH';
import {initializeSender, initializeReceiver, ratchetEncrypt, ratchetDecrypt} from '../src/crypto/signal/DoubleRatchet';

describe('Signal Protocol Integration', () => {
  it('Should successfully establish the X3DH shared session and execute Double Ratchet message exchanges', async () => {
    
    // --- STEP 1: KEY GENERATION ---

    // Alice generates long-term and ephemeral keys
    const aliceIK = generateKeyPair();

    // Bob generates long-term, pre-key, and one-time pre key
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();
    const bobOPK = generateKeyPair();

    // Bob publishes his public bundle to server
    const bobBundle = {
      userId: 100,
      deviceId: 1,
      identityKey: bobIK.publicKey,
      signedPreKey: {
        keyId: 1,
        publicKey: bobSPK.publicKey,
        // Mocking the signature since we are bypassing Ed25519 verification just to test the KDF/Ratchet flow.
        // We will temporarily comment out `verify` in X3DH for the test, or mock tweetnacl.
        signature: new Uint8Array(64).fill(1), 
      },
      oneTimePreKey: {
        keyId: 10,
        publicKey: bobOPK.publicKey,
      }
    };

    // --- STEP 2: ALICE INITIATES X3DH ---

    // For integration test purposes, we mock `verify()` inside X3DH to safely pass 
    // since we bypassed Ed25519 signing for simplicity in this setup block.
    jest.spyOn(require('../src/crypto/Curve25519'), 'verify').mockReturnValue(true);

    const senderX3DH = await x3dhSender(aliceIK, bobBundle);
    
    // Alice initializes Double Ratchet Sender state
    let aliceState = initializeSender(senderX3DH.masterSecret, bobBundle.signedPreKey.publicKey);

    // --- STEP 3: ALICE ENCRYPTS FIRST MESSAGE ---
    
    // The very first message "Hello Bob!"
    const msg1Text = "Hello Bob! This is securely E2EE.";
    const encoder = new TextEncoder();
    
    const encResult1 = ratchetEncrypt(aliceState, encoder.encode(msg1Text));
    aliceState = encResult1.state;

    // --- STEP 4: BOB RECEIVES FIRST MESSAGE ---

    // Bob runs X3DH using the header Alice sent
    const receiverX3DH = await x3dhReceiver(
      bobIK,
      bobSPK,
      bobOPK,
      {
        senderIdentityKey: aliceIK.publicKey,
        ephemeralPublicKey: senderX3DH.initialMessage.ephemeralPublicKey,
        signedPreKeyId: 1,
        oneTimePreKeyId: 10,
      }
    );

    // Ensure Master Secrets strictly match
    expect(receiverX3DH.masterSecret).toEqual(senderX3DH.masterSecret);

    // Bob initializes Double Ratchet Receiver state
    let bobState = initializeReceiver(receiverX3DH.masterSecret, bobSPK);

    // Bob decrypts the first payload
    const decResult1 = ratchetDecrypt(
      bobState,
      encResult1.header,
      encResult1.ciphertext
    );
    bobState = decResult1.state;

    const decoder = new TextDecoder();
    expect(decoder.decode(decResult1.plaintext)).toEqual(msg1Text);

    // --- STEP 5: BOB REPLIES ---
    const msg2Text = "Hey Alice, I got your encrypted message!";
    const encResult2 = ratchetEncrypt(bobState, encoder.encode(msg2Text));
    bobState = encResult2.state;

    const decResult2 = ratchetDecrypt(
      aliceState, 
      encResult2.header, 
      encResult2.ciphertext
    );
    aliceState = decResult2.state;

    expect(decoder.decode(decResult2.plaintext)).toEqual(msg2Text);

    // --- STEP 6: ALICE REPLIES (Checking continuous session cycling) ---
    const msg3Text = "Perfect, the Double Ratchet works.";
    const encResult3 = ratchetEncrypt(aliceState, encoder.encode(msg3Text));
    aliceState = encResult3.state;

    const decResult3 = ratchetDecrypt(
      bobState,
      encResult3.header,
      encResult3.ciphertext
    );
    bobState = decResult3.state;

    expect(decoder.decode(decResult3.plaintext)).toEqual(msg3Text);
  });
});
