/**
 * authSaga.js
 * Handles authentication flows:
 * - OTP request
 * - Login with OTP
 * - Token management
 * - Key initialization on first login
 * - Logout + key wipe
 */

import {call, put, takeLatest, takeEvery, all} from 'redux-saga/effects';
import {authAPI} from '../../services/api';
import SecureStorage from '../../services/SecureStorage';
import KeyManager from '../../crypto/signal/KeyManager';
import PreKeyManager from '../../crypto/signal/PreKeyManager';
import {
  requestOTPStart,
  requestOTPSuccess,
  requestOTPFailure,
  loginStart,
  loginSuccess,
  loginFailure,
  logoutStart,
  logoutSuccess,
} from '../slices/authSlice';
import Logger from '../../utils/Logger';

// ─────────────────────────────────────────────────────────────────────────────
// OTP REQUEST
// ─────────────────────────────────────────────────────────────────────────────

function* handleRequestOTP(action) {
  try {
    yield call([authAPI, 'requestOTP'], action.payload.email);
    yield put(requestOTPSuccess());
    Logger.info('AuthSaga', `OTP sent to ${action.payload.email}`);
  } catch (error) {
    const message = error.response?.data?.message || 'Failed to send OTP';
    yield put(requestOTPFailure(message));
    Logger.error('AuthSaga', `OTP request failed: ${message}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────────────────────────────────────

function* handleLogin(action) {
  const {email, otp, deviceId} = action.payload;
  try {
    // 1. Authenticate with server
    const response = yield call([authAPI, 'login'], email, otp, deviceId);
    const {user, access_token, refresh_token} = response.data;

    // 2. Store tokens securely
    yield call([SecureStorage, 'storeTokens'], access_token, refresh_token);

    // 3. Initialize Signal Protocol keys
    Logger.info('AuthSaga', 'Initializing Signal Protocol keys...');
    const {isNewDevice, bundle} = yield call([KeyManager, 'initialize']);

    if (isNewDevice) {
      // 4a. New device: Upload initial key bundle to server
      Logger.info('AuthSaga', 'New device - uploading initial key bundle');
      yield call([PreKeyManager, 'uploadInitialKeys'], bundle);
    } else {
      // 4b. Existing device: Check if keys need rotation/refill
      Logger.info('AuthSaga', 'Existing device - checking key rotation');
      yield all([
        call([PreKeyManager, 'rotateSignedPreKeyIfNeeded']),
        call([PreKeyManager, 'checkAndRefillPreKeys']),
      ]);
    }

    yield put(loginSuccess({
      user,
      accessToken: access_token,
      refreshToken: refresh_token,
    }));

    Logger.info('AuthSaga', `Login successful for ${email}`);
  } catch (error) {
    const message = error.response?.data?.message || 'Login failed';
    yield put(loginFailure(message));
    Logger.error('AuthSaga', `Login failed: ${message}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// LOGOUT
// ─────────────────────────────────────────────────────────────────────────────

function* handleLogout() {
  try {
    // Invalidate token on server
    yield call([authAPI, 'logout']);
  } catch (error) {
    // Non-fatal: proceed with local cleanup regardless
    Logger.warn('AuthSaga', 'Server logout failed, proceeding with local cleanup');
  }

  // Wipe all locally stored keys (private keys, sessions)
  yield call([KeyManager, 'wipeAllKeys']);
  yield call([SecureStorage, 'clearTokens']);
  yield put(logoutSuccess());

  Logger.info('AuthSaga', 'Logged out and cleared all local keys');
}

// ─────────────────────────────────────────────────────────────────────────────
// ROOT AUTH SAGA
// ─────────────────────────────────────────────────────────────────────────────

export default function* authSaga() {
  yield all([
    takeLatest(requestOTPStart.type, handleRequestOTP),
    takeLatest(loginStart.type, handleLogin),
    takeLatest(logoutStart.type, handleLogout),
  ]);
}
