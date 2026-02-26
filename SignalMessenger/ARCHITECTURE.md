# SecureSignal Messenger Architecture

## Mobile Architecture (React Native)

This is a production-grade implementation of the Signal Protocol using `tweetnacl` for pure, secure JavaScript cryptography without native bindings, allowing it to run smoothly on React Native.

### 1. Cryptographic Primitives (`src/crypto/`)

- **Curve25519.js**: Handles Diffie-Hellman (X25519) for key exchange and Ed25519 for identity signing.
- **HKDF.js**: Implements RFC 5869 HMAC-based Key Derivation Function over SHA-256 for deriving root chains and message keys.
- **AES256GCM.js**: Fallback XSalsa20-Poly1305 (via `secretbox`) symmetric encryption for message payloads.

### 2. Signal Protocol Implementation (`src/crypto/signal/`)

- **X3DH.js**: Implements the Extended Triple Diffie-Hellman (X3DH) key agreement protocol mathematically mapping identity keys, signed pre-keys, and one-time pre-keys into a shared master secret.
- **DoubleRatchet.js**: Implements the symmetric (KDF chain) and asymmetric (DH) ratchets to provide forward secrecy and break-in recovery. Supports skipped message keys for out-of-order networks.
- **KeyManager.js**: Handles generation, rotation (30-day), and secure storage extraction of long-term keys without exposing private keys to unencrypted memory spaces.
- **SessionManager.js**: Orchestrates X3DH + Double Ratchet and keeps track of safety numbers and identity key changes on remote devices.
- **Encryptor.js**: The high-level API for messaging encoding.

### 3. WebRTC Call Encryption (`src/crypto/webrtc/`)

- **WebRTCManager.js**: Creates peer-to-peer data streams using STUN/TURN servers.
- **Security Check**: The SDP offer/answer handles the WebRTC handshake over the WebSocket. These SDP descriptions are encrypted using the existing _Double Ratchet Session_, protecting them from server-side Man-In-The-Middle attacks.
- Enforces `DTLS-SRTP` encryption inside the browser engine using `AES_256_CM_HMAC_SHA1_80` cipher suites.

### 4. Storage Architecture (`src/services/SecureStorage.js`)

- **Keychain / Keystore**: React Native Keychain is used to store high-value authentication parameters (JWT tokens).
- **Encrypted Storage**: React Native Encrypted Storage handles the Double Ratchet state blobs and Key Pair metadata since AsyncStorage is unencrypted and vulnerable to extraction via logical forensic tools.

### 5. Transport Layer (`src/services/`)

- **Axios HTTP**: Includes offline retry logic and JWT interceptors ensuring short-lived access tokens with a background auto-refresh loop.
- **WebSocketService.js**: Maintains realtime connection parsing typing, delivery receipts, and syncing missed offline payloads when reconnecting to the socket.

### 6. State Management (`src/store/`)

- Redux Toolkit mapped with Redux Saga for asynchronous side effects mapping directly to the WebRTC and Signal orchestration instances.
