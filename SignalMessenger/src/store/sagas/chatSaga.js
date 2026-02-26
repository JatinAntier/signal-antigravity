/**
 * chatSaga.js
 * Handles all chat-related side effects:
 * - Sending encrypted messages
 * - Receiving and decrypting incoming messages
 * - WebSocket event handling
 * - Offline message sync
 * - Read receipts and typing indicators
 */

import {
  call,
  put,
  take,
  fork,
  all,
  takeLatest,
  takeEvery,
  select,
  race,
  delay,
} from 'redux-saga/effects';
import {eventChannel, END} from 'redux-saga';
import {messagesAPI} from '../../services/api';
import WebSocketService, {WS_EVENTS} from '../../services/WebSocketService';
import {encryptMessage, decryptMessage} from '../../crypto/signal/Encryptor';
import SessionManager from '../../crypto/signal/SessionManager';
import PreKeyManager from '../../crypto/signal/PreKeyManager';
import {fetchUserKeyBundle} from '../../services/keyService';
import {
  fetchConversationsStart,
  fetchConversationsSuccess,
  fetchConversationsFailure,
  fetchMessagesStart,
  fetchMessagesSuccess,
  fetchMessagesFailure,
  sendMessageStart,
  sendMessageOptimistic,
  sendMessageFailure,
  receiveMessage,
  updateMessageStatus,
  setTypingUser,
  setUserOnline,
  setUserOffline,
  setIdentityKeyChanged,
} from '../slices/chatSlice';
import {selectCurrentUser} from '../slices/authSlice';
import Logger from '../../utils/Logger';
import {generateUUID} from '../../utils/uuid';

// ─────────────────────────────────────────────────────────────────────────────
// FETCH CONVERSATIONS
// ─────────────────────────────────────────────────────────────────────────────

function* handleFetchConversations() {
  try {
    const response = yield call([messagesAPI, 'getConversations']);
    yield put(fetchConversationsSuccess(response.data));
  } catch (error) {
    yield put(fetchConversationsFailure(error.message));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SEND MESSAGE
// ─────────────────────────────────────────────────────────────────────────────

function* handleSendMessage(action) {
  const {recipientId, recipientUserId, conversationId, plaintext} = action.payload;
  const currentUser = yield select(selectCurrentUser);
  const clientMessageId = generateUUID();

  // Optimistic UI - show message immediately as "sending"
  const optimisticMessage = {
    id: null,
    clientId: clientMessageId,
    conversationId,
    senderId: currentUser.id,
    content: plaintext,
    status: 'sending',
    timestamp: new Date().toISOString(),
  };
  yield put(sendMessageOptimistic({conversationId, message: optimisticMessage}));

  try {
    // Check if we have a session; if not, fetch key bundle
    const hasSession = yield call(
      [SessionManager, 'hasSession'],
      String(recipientUserId),
    );

    let keyBundle = null;
    if (!hasSession) {
      Logger.info('ChatSaga', `No session for ${recipientUserId} - fetching keys`);
      keyBundle = yield call(fetchUserKeyBundle, recipientUserId);

      // Check for identity key changes (reinstall detection)
      const verification = yield call(
        [SessionManager, 'verifyRemoteIdentityKey'],
        String(recipientUserId),
        keyBundle.identity_key,
      );

      if (verification.changed) {
        Logger.warn('ChatSaga', `Identity key changed for user ${recipientUserId}!`);
        yield put(setIdentityKeyChanged({
          userId: recipientUserId,
          safetyNumber: verification.safetyNumber,
        }));
        // Delete old sessions and start fresh
        yield call([SessionManager, 'deleteAllSessions'], String(recipientUserId));
      }
    }

    // Encrypt the message through Signal Protocol
    const {payload: encryptedPayload} = yield call(
      encryptMessage,
      String(recipientUserId),
      plaintext,
      keyBundle,
    );

    // Send via WebSocket
    yield call(
      [WebSocketService, 'sendMessage'],
      recipientId,
      encryptedPayload,
      clientMessageId,
    );

    // Update message status to 'sent'
    yield put(updateMessageStatus({
      conversationId,
      messageId: clientMessageId,
      status: 'sent',
    }));

    // Background: check if we need to refill OPKs
    yield fork(function* () {
      yield call([PreKeyManager, 'checkAndRefillPreKeys']);
    });

    Logger.info('ChatSaga', 'Message sent successfully');
  } catch (error) {
    Logger.error('ChatSaga', `Failed to send message: ${error.message}`);
    yield put(sendMessageFailure(error.message));
    
    // Mark optimistic message as failed
    yield put(updateMessageStatus({
      conversationId,
      messageId: clientMessageId,
      status: 'failed',
    }));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HANDLE INCOMING MESSAGE (from WebSocket)
// ─────────────────────────────────────────────────────────────────────────────

function* handleIncomingMessage(wsMessage) {
  const {sender_id, conversation_id, message_id, encrypted_payload, timestamp} = wsMessage;

  try {
    const payload = JSON.parse(encrypted_payload);

    // Decrypt through Signal Protocol
    const plaintext = yield call(decryptMessage, String(sender_id), payload);

    const decryptedMessage = {
      id: message_id,
      conversationId: conversation_id,
      senderId: sender_id,
      content: plaintext,
      status: 'received',
      timestamp: timestamp || new Date().toISOString(),
    };

    yield put(receiveMessage({conversationId: conversation_id, message: decryptedMessage}));

    // Send delivery receipt
    yield call(
      [WebSocketService, 'sendReadReceipt'],
      conversation_id,
      [message_id],
    );

    Logger.info('ChatSaga', `Message received and decrypted from user ${sender_id}`);
  } catch (error) {
    Logger.error('ChatSaga', `Failed to decrypt message: ${error.message}`);
    // Show error placeholder
    yield put(receiveMessage({
      conversationId: wsMessage.conversation_id,
      message: {
        id: wsMessage.message_id,
        conversationId: wsMessage.conversation_id,
        senderId: sender_id,
        content: '[Unable to decrypt message]',
        status: 'error',
        timestamp: wsMessage.timestamp,
        isDecryptionError: true,
      },
    }));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// OFFLINE MESSAGE SYNC
// ─────────────────────────────────────────────────────────────────────────────

function* handleOfflineSync(lastSyncTimestamp) {
  try {
    Logger.info('ChatSaga', `Syncing offline messages since ${lastSyncTimestamp}`);
    const response = yield call(
      [messagesAPI, 'getMessagesSince'],
      lastSyncTimestamp,
    );

    const encryptedMessages = response.data || [];
    Logger.info('ChatSaga', `Found ${encryptedMessages.length} offline messages`);

    for (const msg of encryptedMessages) {
      yield call(handleIncomingMessage, msg);
    }
  } catch (error) {
    Logger.error('ChatSaga', `Offline sync failed: ${error.message}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// WEBSOCKET CHANNEL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Creates an eventChannel that bridges WebSocket events to sagas
 */
function createWebSocketChannel() {
  return eventChannel(emit => {
    const handlers = {
      [WS_EVENTS.NEW_MESSAGE]: msg => emit({type: WS_EVENTS.NEW_MESSAGE, payload: msg}),
      [WS_EVENTS.MESSAGE_DELIVERED]: msg => emit({type: WS_EVENTS.MESSAGE_DELIVERED, payload: msg}),
      [WS_EVENTS.MESSAGE_READ]: msg => emit({type: WS_EVENTS.MESSAGE_READ, payload: msg}),
      [WS_EVENTS.TYPING_INDICATOR]: msg => emit({type: WS_EVENTS.TYPING_INDICATOR, payload: msg}),
      [WS_EVENTS.USER_PRESENCE]: msg => emit({type: WS_EVENTS.USER_PRESENCE, payload: msg}),
      connected: () => emit({type: 'WS_CONNECTED'}),
      disconnected: () => emit({type: 'WS_DISCONNECTED'}),
    };

    Object.entries(handlers).forEach(([event, handler]) => {
      WebSocketService.on(event, handler);
    });

    // Return unsubscribe function
    return () => {
      Object.entries(handlers).forEach(([event, handler]) => {
        WebSocketService.off(event, handler);
      });
    };
  });
}

function* watchWebSocket() {
  const channel = yield call(createWebSocketChannel);

  try {
    while (true) {
      const event = yield take(channel);

      switch (event.type) {
        case WS_EVENTS.NEW_MESSAGE:
          yield fork(handleIncomingMessage, event.payload);
          break;

        case WS_EVENTS.MESSAGE_DELIVERED:
          yield put(updateMessageStatus({
            conversationId: event.payload.conversation_id,
            messageId: event.payload.message_id,
            status: 'delivered',
          }));
          break;

        case WS_EVENTS.MESSAGE_READ:
          yield put(updateMessageStatus({
            conversationId: event.payload.conversation_id,
            messageId: event.payload.message_id,
            status: 'read',
          }));
          break;

        case WS_EVENTS.TYPING_INDICATOR:
          yield put(setTypingUser({
            conversationId: event.payload.conversation_id,
            userId: event.payload.user_id,
            isTyping: event.payload.is_typing,
          }));
          // Auto-clear typing after 3s
          if (event.payload.is_typing) {
            yield fork(function* () {
              yield delay(3000);
              yield put(setTypingUser({
                conversationId: event.payload.conversation_id,
                userId: event.payload.user_id,
                isTyping: false,
              }));
            });
          }
          break;

        case WS_EVENTS.USER_PRESENCE:
          if (event.payload.status === 'online') {
            yield put(setUserOnline(String(event.payload.user_id)));
          } else {
            yield put(setUserOffline(String(event.payload.user_id)));
          }
          break;

        case 'WS_CONNECTED':
          // Sync missed messages on reconnect
          const lastSync = yield call([SecureStorage, 'getItem'], 'last_sync_ts');
          yield fork(handleOfflineSync, lastSync || 0);
          break;

        default:
          break;
      }
    }
  } finally {
    channel.close();
  }
}

import SecureStorage from '../../services/SecureStorage';

// ─────────────────────────────────────────────────────────────────────────────
// FETCH MESSAGES
// ─────────────────────────────────────────────────────────────────────────────

function* handleFetchMessages(action) {
  const {conversationId, page} = action.payload;
  try {
    const response = yield call(
      [messagesAPI, 'getConversationMessages'],
      conversationId,
      page,
    );
    // Messages come encrypted - decrypt each one
    const encryptedMessages = response.data || [];
    const decryptedMessages = [];

    for (const msg of encryptedMessages) {
      try {
        const payload = JSON.parse(msg.encrypted_payload);
        const plaintext = yield call(decryptMessage, String(msg.sender_id), payload);
        decryptedMessages.push({...msg, content: plaintext});
      } catch {
        decryptedMessages.push({
          ...msg,
          content: '[Unable to decrypt]',
          isDecryptionError: true,
        });
      }
    }

    yield put(fetchMessagesSuccess({conversationId, messages: decryptedMessages}));
  } catch (error) {
    yield put(fetchMessagesFailure(error.message));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ROOT CHAT SAGA
// ─────────────────────────────────────────────────────────────────────────────

export default function* chatSaga() {
  yield all([
    takeLatest(fetchConversationsStart.type, handleFetchConversations),
    takeLatest(fetchMessagesStart.type, handleFetchMessages),
    takeLatest(sendMessageStart.type, handleSendMessage),
    fork(watchWebSocket),
  ]);
}
