/**
 * WebSocketService.js
 * Production WebSocket client with:
 * - Automatic reconnection with exponential backoff
 * - JWT authentication on connect
 * - Message queuing while offline
 * - Presence tracking
 * - Typed event handling
 */

import SecureStorage from './SecureStorage';
import Logger from '../utils/Logger';
import {EventEmitter} from 'events';
import {WS_BASE_URL as ENV_WS_BASE_URL} from '@env';

const WS_BASE_URL = ENV_WS_BASE_URL || 'ws://localhost:8080/ws';
const RECONNECT_BASE_DELAY = 1000;    // 1s
const RECONNECT_MAX_DELAY = 30000;    // 30s
const MAX_RECONNECT_ATTEMPTS = Infinity;
const PING_INTERVAL = 25000;          // 25s heartbeat
const PONG_TIMEOUT = 10000;           // 10s pong timeout

/**
 * WebSocket message types (must match backend)
 */
export const WS_EVENTS = {
  // Outbound
  MESSAGE: 'message',
  TYPING_START: 'typing_start',
  TYPING_STOP: 'typing_stop',
  READ_RECEIPT: 'read_receipt',
  PRESENCE: 'presence',
  WEBRTC_SIGNAL: 'webrtc_signal',

  // Inbound
  NEW_MESSAGE: 'new_message',
  MESSAGE_DELIVERED: 'message_delivered',
  MESSAGE_READ: 'message_read',
  TYPING_INDICATOR: 'typing_indicator',
  USER_PRESENCE: 'user_presence',
  WEBRTC_SIGNAL_IN: 'webrtc_signal',
  KEY_REQUEST: 'key_request',
  ERROR: 'error',
};

class WebSocketService extends EventEmitter {
  constructor() {
    super();
    this.socket = null;
    this.isConnected = false;
    this.isConnecting = false;
    this._reconnectAttempts = 0;
    this._reconnectTimer = null;
    this._pingTimer = null;
    this._pongTimer = null;
    this._messageQueue = [];  // Messages queued while offline
    this._shouldReconnect = false;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // CONNECTION MANAGEMENT
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Connect to the WebSocket server
   * Authenticates using JWT in the URL query parameter
   */
  async connect() {
    if (this.isConnected || this.isConnecting) return;

    const token = await SecureStorage.getAccessToken();
    if (!token) {
      Logger.warn('WS', 'No token available - cannot connect');
      return;
    }

    this.isConnecting = true;
    this._shouldReconnect = true;

    const wsUrl = `${WS_BASE_URL}?token=${encodeURIComponent(token)}`;
    Logger.info('WS', `Connecting to ${WS_BASE_URL}...`);

    try {
      this.socket = new WebSocket(wsUrl);
      this._attachHandlers();
    } catch (error) {
      Logger.error('WS', `WebSocket creation failed: ${error.message}`);
      this.isConnecting = false;
      this._scheduleReconnect();
    }
  }

  /**
   * Gracefully disconnect
   */
  disconnect() {
    this._shouldReconnect = false;
    this._cancelTimers();
    
    if (this.socket) {
      this.socket.close(1000, 'User logout');
      this.socket = null;
    }

    this.isConnected = false;
    this.isConnecting = false;
    this._reconnectAttempts = 0;
    Logger.info('WS', 'Disconnected');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // SENDING
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Send an encrypted message to a recipient
   * @param {number|string} receiverId
   * @param {Object} encryptedPayload - Output from Encryptor.encryptMessage
   * @param {string} [clientMessageId] - Idempotency key
   */
  sendMessage(receiverId, encryptedPayload, clientMessageId) {
    this._send({
      type: WS_EVENTS.MESSAGE,
      receiver_id: Number(receiverId),
      encrypted_payload: JSON.stringify(encryptedPayload),
      client_message_id: clientMessageId,
      timestamp: Date.now(),
    });
  }

  /**
   * Send a WebRTC signaling message (encrypted via Signal Protocol)
   */
  sendWebRTCSignal(receiverId, encryptedSignal) {
    this._send({
      type: WS_EVENTS.WEBRTC_SIGNAL,
      receiver_id: Number(receiverId),
      encrypted_payload: encryptedSignal,
    });
  }

  /**
   * Send typing indicator
   */
  sendTypingStart(conversationId) {
    this._send({type: WS_EVENTS.TYPING_START, conversation_id: conversationId});
  }

  sendTypingStop(conversationId) {
    this._send({type: WS_EVENTS.TYPING_STOP, conversation_id: conversationId});
  }

  /**
   * Send read receipt for messages
   */
  sendReadReceipt(conversationId, messageIds) {
    this._send({
      type: WS_EVENTS.READ_RECEIPT,
      conversation_id: conversationId,
      message_ids: messageIds,
    });
  }

  /**
   * Broadcast presence status
   */
  sendPresence(status) {
    this._send({type: WS_EVENTS.PRESENCE, status});
  }

  // ─────────────────────────────────────────────────────────────────────────
  // INTERNALS
  // ─────────────────────────────────────────────────────────────────────────

  _attachHandlers() {
    this.socket.onopen = () => {
      Logger.info('WS', 'Connected!');
      this.isConnected = true;
      this.isConnecting = false;
      this._reconnectAttempts = 0;

      // Flush queued messages
      this._flushQueue();

      // Start heartbeat
      this._startPing();

      this.emit('connected');
    };

    this.socket.onclose = (event) => {
      Logger.warn('WS', `Disconnected: code=${event.code}, reason=${event.reason}`);
      this.isConnected = false;
      this.isConnecting = false;
      this._cancelTimers();

      this.emit('disconnected', event);

      if (this._shouldReconnect && event.code !== 1000) {
        this._scheduleReconnect();
      }
    };

    this.socket.onerror = (error) => {
      Logger.error('WS', `WebSocket error: ${error.message}`);
      this.emit('error', error);
    };

    this.socket.onmessage = (event) => {
      this._handleMessage(event.data);
    };
  }

  _handleMessage(rawData) {
    try {
      const message = JSON.parse(rawData);
      Logger.debug('WS', `← ${message.type}`);

      // Handle pong (heartbeat response)
      if (message.type === 'pong') {
        this._cancelPongTimer();
        return;
      }

      // Emit typed event for saga/store to handle
      this.emit(message.type, message);
      this.emit('message', message); // Generic handler
    } catch (error) {
      Logger.error('WS', `Failed to parse message: ${error.message}`);
    }
  }

  _send(data) {
    if (this.isConnected && this.socket?.readyState === WebSocket.OPEN) {
      const json = JSON.stringify(data);
      this.socket.send(json);
      Logger.debug('WS', `→ ${data.type}`);
    } else {
      // Queue for when reconnected
      Logger.debug('WS', `Queuing ${data.type} (offline)`);
      this._messageQueue.push(data);
    }
  }

  _flushQueue() {
    if (this._messageQueue.length === 0) return;
    Logger.info('WS', `Flushing ${this._messageQueue.length} queued messages`);
    
    const queue = [...this._messageQueue];
    this._messageQueue = [];
    
    for (const msg of queue) {
      this._send(msg);
    }
  }

  _startPing() {
    this._pingTimer = setInterval(() => {
      if (this.isConnected) {
        this._send({type: 'ping'});
        
        // Expect pong within 10s
        this._pongTimer = setTimeout(() => {
          Logger.warn('WS', 'Pong timeout - reconnecting');
          this.socket?.close();
        }, PONG_TIMEOUT);
      }
    }, PING_INTERVAL);
  }

  _cancelPongTimer() {
    if (this._pongTimer) {
      clearTimeout(this._pongTimer);
      this._pongTimer = null;
    }
  }

  _cancelTimers() {
    if (this._pingTimer) clearInterval(this._pingTimer);
    if (this._pongTimer) clearTimeout(this._pongTimer);
    if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
  }

  _scheduleReconnect() {
    if (!this._shouldReconnect) return;

    this._reconnectAttempts++;
    const delay = Math.min(
      RECONNECT_BASE_DELAY * Math.pow(2, this._reconnectAttempts - 1),
      RECONNECT_MAX_DELAY,
    );

    Logger.info('WS', `Reconnecting in ${delay}ms (attempt ${this._reconnectAttempts})`);

    this._reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }
}

export default new WebSocketService();
