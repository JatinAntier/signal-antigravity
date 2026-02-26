/**
 * authSlice.js
 * Redux slice for authentication state
 */

import {createSlice} from '@reduxjs/toolkit';

const initialState = {
  isAuthenticated: false,
  user: null,
  accessToken: null,
  refreshToken: null,
  isLoading: false,
  error: null,
  otpSent: false,
  otpEmail: null,
};

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    // OTP Request
    requestOTPStart: (state, action) => {
      state.isLoading = true;
      state.error = null;
      state.otpEmail = action.payload.email;
    },
    requestOTPSuccess: (state) => {
      state.isLoading = false;
      state.otpSent = true;
    },
    requestOTPFailure: (state, action) => {
      state.isLoading = false;
      state.error = action.payload;
    },

    // Login
    loginStart: (state) => {
      state.isLoading = true;
      state.error = null;
    },
    loginSuccess: (state, action) => {
      const {user, accessToken, refreshToken} = action.payload;
      state.isLoading = false;
      state.isAuthenticated = true;
      state.user = user;
      state.accessToken = accessToken;
      state.refreshToken = refreshToken;
      state.otpSent = false;
      state.error = null;
    },
    loginFailure: (state, action) => {
      state.isLoading = false;
      state.error = action.payload;
    },

    // Token refresh
    setTokens: (state, action) => {
      state.accessToken = action.payload.accessToken;
      state.refreshToken = action.payload.refreshToken;
    },

    // Logout
    logoutStart: (state) => {
      state.isLoading = true;
    },
    logoutSuccess: (state) => {
      return {...initialState};
    },

    // Profile update
    updateUserProfile: (state, action) => {
      state.user = {...state.user, ...action.payload};
    },

    clearError: (state) => {
      state.error = null;
    },

    resetOTP: (state) => {
      state.otpSent = false;
      state.otpEmail = null;
    },
  },
});

export const {
  requestOTPStart,
  requestOTPSuccess,
  requestOTPFailure,
  loginStart,
  loginSuccess,
  loginFailure,
  setTokens,
  logoutStart,
  logoutSuccess,
  updateUserProfile,
  clearError,
  resetOTP,
} = authSlice.actions;

// Selectors
export const selectIsAuthenticated = state => state.auth.isAuthenticated;
export const selectCurrentUser = state => state.auth.user;
export const selectAuthLoading = state => state.auth.isLoading;
export const selectAuthError = state => state.auth.error;
export const selectOtpSent = state => state.auth.otpSent;
export const selectOtpEmail = state => state.auth.otpEmail;

export default authSlice.reducer;
