# SecureSignal Messenger

A production-grade, end-to-end encrypted messaging application built with React Native and Redux Saga. It implements the full Signal Protocol, including Extended Triple Diffie-Hellman (X3DH) and the Double Ratchet Algorithm, to provide forward secrecy and break-in recovery.

## ✨ Features

- **End-to-End Encryption**: Full Signal Protocol implementation written in pure JavaScript (`tweetnacl`) for compatibility with React Native environments.
- **X3DH Key Agreement**: Establishes initial shared secrets even when the recipient is offline.
- **Double Ratchet Algorithm**: Provides forward secrecy and cryptographic healing.
- **Encrypted Voice & Video Calls**: Utilizes WebRTC with enforced DTLS-SRTP. The signaling layer (SDP/ICE exchange) is also fully E2E encrypted over the Signal Protocol.
- **Offline Messaging**: Messages are queued and securely synced when devices reconnect.
- **Secure Key Storage**: Private keys are isolated from unencrypted `AsyncStorage` and are stored using iOS Secure Enclave and Android Hardware Keystore (`react-native-keychain` and `react-native-encrypted-storage`).
- **Identity Verification**: Generates Safety Number fingerprints to detect Man-In-The-Middle attacks or device reinstallations.
- **Real-time UX**: Typing indicators, read receipts, and online presence tracking.
- **JWT Authentication**: Secure login flow with auto-refreshing access tokens in the background.

## 📂 Project Structure

```text
src/
├── components/       # Reusable UI components
├── screens/          # Application screens (Auth, Chat, Calls, Profile)
├── navigation/       # React Navigation setup
├── services/         # API, WebSocket, and Secure Storage Singletons
├── store/            # Redux Toolkit Config
│   ├── slices/       # Redux state slices
│   └── sagas/        # Side-effect management (async auth, cryptography, sockets)
├── utils/            # Helper utilities
└── crypto/           # The Cryptography Engine
    ├── signal/       # Signal Protocol Implementation
    │   ├── X3DH.js
    │   ├── DoubleRatchet.js
    │   ├── KeyManager.js
    │   ├── SessionManager.js
    │   ├── PreKeyManager.js
    │   └── Encryptor.js
    ├── webrtc/       # E2E Encrypted Voice/Video
    │   └── WebRTCManager.js
    ├── Curve25519.js # DH and Ed25519 primitives
    ├── HKDF.js       # HMAC Key Derivation Function
    └── AES256GCM.js  # Authenticated Payload Encryption
```

## 🔐 Cryptography Implementation Details

This project doesn't use simplified or toy cryptography. It implements the exact specifications of the Signal Protocol:

1. **Key Generation**: Generates an Identity Key Pair (Curve25519 + Ed25519), a Signed Pre-Key (rotated every 30 days), and batches of 100 One-Time Pre-Keys.
2. **Session Initialization (X3DH)**: Computes four DH shared secrets using the sender's ephemeral key and the receiver's pre-keys to generate a root master secret.
3. **Double Ratchet**: Uses a KDF chain (HMAC-SHA256) for symmetric ratcheting (forward secrecy), and a DH ratchet for asymmetric ratcheting (break-in recovery). Out-of-order messages are handled by securely caching skipped message keys (up to a limit of 2000).
4. **Encryption (AES-256-GCM)**: Message payloads are encrypted using AEAD. Because `SubtleCrypto` is largely unavailable in React Native, it falls back to the audited XSalsa20-Poly1305 from `tweetnacl`.

## 🚀 Getting Started

### Prerequisites

- Node.js (>= 18)
- React Native CLI
- CocoaPods (for iOS)
- Android Studio / Xcode

### Installation

1. Install dependencies:

   ```bash
   npm install
   ```

2. iOS Setup:

   ```bash
   cd ios && pod install && cd ..
   ```

3. Configuration:
   Create a `.env` file in the root directory (or modify `src/services/api.js` and `WebSocketService.js` defaults):
   ```env
   API_BASE_URL=http://localhost:8080/api/v1
   WS_BASE_URL=ws://localhost:8080/ws
   ```

### Running the App

**For iOS:**

```bash
npx react-native run-ios
```

**For Android:**

```bash
npx react-native run-android
```

## ⚠️ Security Notes

- **Never use Expo Go**: Expo Go does not support the necessary native secure storage bridging (`react-native-keychain`). You must use the React Native bare workflow or Expo Development Clients.
- **Hermes Engine**: Ensure Hermes is enabled in your `android/app/build.gradle` and iOS `Podfile` for optimal cryptography performance.
- **Production Build**: In a production environment, you should replace the pure javascript `sha256` polyfills located in `HKDF.js` with a native `react-native-crypto` binding for faster hashing on cheap Android devices.

## 📄 License

MIT License
