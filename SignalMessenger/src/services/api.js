/**
 * api.js
 * Axios HTTP client with JWT authentication + auto token refresh
 * Follows a request interceptor pattern for transparent auth
 */

import axios from 'axios';
import SecureStorage from './SecureStorage';
import {store} from '../store';
import {logoutSuccess, setTokens} from '../store/slices/authSlice';
import Logger from '../utils/Logger';
import {API_BASE_URL} from '@env';

const BASE_URL = API_BASE_URL || 'http://localhost:8080/api/v1';
const REFRESH_ENDPOINT = '/auth/refresh';

// ─────────────────────────────────────────────────────────────────────────────
// AXIOS INSTANCE
// ─────────────────────────────────────────────────────────────────────────────

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST INTERCEPTOR - Attach JWT
// ─────────────────────────────────────────────────────────────────────────────

api.interceptors.request.use(
  async config => {
    const token = await SecureStorage.getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    Logger.debug('API', `→ ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  error => {
    Logger.error('API', `Request error: ${error.message}`);
    return Promise.reject(error);
  },
);

// ─────────────────────────────────────────────────────────────────────────────
// RESPONSE INTERCEPTOR - Auto token refresh on 401
// ─────────────────────────────────────────────────────────────────────────────

let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  response => {
    Logger.debug('API', `← ${response.status} ${response.config.url}`);
    return response;
  },
  async error => {
    const originalRequest = error.config;

    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !originalRequest.url?.includes(REFRESH_ENDPOINT)
    ) {
      if (isRefreshing) {
        // Queue the request until refresh completes
        return new Promise((resolve, reject) => {
          failedQueue.push({resolve, reject});
        }).then(token => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const refreshToken = await SecureStorage.getRefreshToken();
        if (!refreshToken) throw new Error('No refresh token');

        Logger.info('API', 'Refreshing JWT token...');

        const {data} = await axios.post(`${BASE_URL}${REFRESH_ENDPOINT}`, {
          refresh_token: refreshToken,
        });

        const {access_token, refresh_token: newRefreshToken} = data;

        // Persist new tokens securely
        await SecureStorage.storeTokens(access_token, newRefreshToken);
        store.dispatch(setTokens({accessToken: access_token, refreshToken: newRefreshToken}));

        processQueue(null, access_token);
        originalRequest.headers.Authorization = `Bearer ${access_token}`;

        Logger.info('API', 'Token refreshed successfully');
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError);
        Logger.error('API', 'Token refresh failed - logging out');
        store.dispatch(logoutSuccess());
        await SecureStorage.clearAll();
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    // Handle other error responses
    const errorMessage = error.response?.data?.message || error.message;
    Logger.error('API', `← ${error.response?.status} ${error.config?.url}: ${errorMessage}`);

    return Promise.reject(error);
  },
);

// ─────────────────────────────────────────────────────────────────────────────
// API METHODS
// ─────────────────────────────────────────────────────────────────────────────

export const authAPI = {
  /** Request OTP to email */
  requestOTP: email => api.post('/auth/otp/request', {email}),

  /** Login with email + OTP */
  login: (email, otp, deviceId) =>
    api.post('/auth/login', {email, otp, device_id: deviceId}),

  /** Refresh tokens */
  refresh: refreshToken =>
    api.post(REFRESH_ENDPOINT, {refresh_token: refreshToken}),

  /** Logout (invalidate refresh token on server) */
  logout: () => api.post('/auth/logout'),

  /** Get current user profile */
  getProfile: () => api.get('/auth/me'),
};

export const keysAPI = {
  /** Upload public key bundle (initial registration or refresh) */
  uploadKeys: bundle => api.post('/keys/upload', bundle),

  /** Get server-side OPK count */
  getKeyCount: () => api.get('/keys/count'),

  /** Fetch a user's public key bundle for session initiation */
  getUserKeys: userId => api.get(`/keys/${userId}`),
};

export const messagesAPI = {
  /** Fetch messages since timestamp (for offline sync) */
  getMessagesSince: (timestamp) =>
    api.get('/messages', {params: {since: timestamp}}),

  /** Get conversation list */
  getConversations: () => api.get('/conversations'),

  /** Get messages for a specific conversation */
  getConversationMessages: (conversationId, page = 1, limit = 50) =>
    api.get(`/conversations/${conversationId}/messages`, {
      params: {page, limit},
    }),

  /** Mark messages as read */
  markAsRead: (conversationId, messageIds) =>
    api.post(`/conversations/${conversationId}/read`, {message_ids: messageIds}),
};

export const usersAPI = {
  /** Search users by email or name */
  searchUsers: query => api.get('/users/search', {params: {q: query}}),

  /** Get user profile by ID */
  getUserById: userId => api.get(`/users/${userId}`),

  /** Update profile */
  updateProfile: data => api.put('/users/profile', data),
};

export const callsAPI = {
  /** Get TURN server credentials */
  getTurnCredentials: () => api.get('/calls/turn-credentials'),
};

export default api;
