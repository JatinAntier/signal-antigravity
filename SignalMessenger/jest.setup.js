jest.mock('react-native', () => ({
  Platform: {
    OS: 'ios',
  },
  StyleSheet: {
    create: (styles) => styles,
  },
  NativeModules: {
    RNGetRandomValues: {
      getRandomBase64: jest.fn(() => 'deadbeef'),
    },
  },
}));

jest.mock('react-native-keychain', () => ({
  setGenericPassword: jest.fn(),
  getGenericPassword: jest.fn(),
  resetGenericPassword: jest.fn(),
}));

jest.mock('react-native-encrypted-storage', () => ({
  setItem: jest.fn(),
  getItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
}));

jest.mock('react-native-webrtc', () => ({
  RTCPeerConnection: jest.fn(),
  RTCIceCandidate: jest.fn(),
  RTCSessionDescription: jest.fn(),
  mediaDevices: {
    getUserMedia: jest.fn(),
  },
}));

// Mock TextEncoder / TextDecoder
if (typeof TextEncoder === 'undefined') {
  global.TextEncoder = require('util').TextEncoder;
  global.TextDecoder = require('util').TextDecoder;
}
