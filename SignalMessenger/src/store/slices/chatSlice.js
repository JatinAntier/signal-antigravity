/**
 * chatSlice.js
 * Redux slice for conversations and messages
 * Stores only metadata - encrypted messages stored separately
 */

import {createSlice} from '@reduxjs/toolkit';

const initialState = {
  conversations: [],           // List of conversations
  messages: {},                // keyed by conversationId
  loading: false,
  sendingMessage: false,
  typingUsers: {},             // { conversationId: [userId...] }
  onlineUsers: new Set(),      // Set of online userIds
  error: null,
  currentConversationId: null,
  unreadCounts: {},            // { conversationId: count }
};

const chatSlice = createSlice({
  name: 'chat',
  initialState,
  reducers: {
    // Conversations
    fetchConversationsStart: state => {
      state.loading = true;
    },
    fetchConversationsSuccess: (state, action) => {
      state.loading = false;
      state.conversations = action.payload;
    },
    fetchConversationsFailure: (state, action) => {
      state.loading = false;
      state.error = action.payload;
    },
    
    setCurrentConversation: (state, action) => {
      state.currentConversationId = action.payload;
      // Clear unread count
      if (action.payload) {
        state.unreadCounts[action.payload] = 0;
      }
    },

    // Messages
    fetchMessagesStart: state => {
      state.loading = true;
    },
    fetchMessagesSuccess: (state, action) => {
      const {conversationId, messages} = action.payload;
      state.loading = false;
      state.messages[conversationId] = messages;
    },
    fetchMessagesFailure: (state, action) => {
      state.loading = false;
      state.error = action.payload;
    },

    // Sending
    sendMessageStart: state => {
      state.sendingMessage = true;
    },
    sendMessageOptimistic: (state, action) => {
      // Add message optimistically before server confirm
      const {conversationId, message} = action.payload;
      state.sendingMessage = false;
      if (!state.messages[conversationId]) {
        state.messages[conversationId] = [];
      }
      state.messages[conversationId].push(message);
    },
    sendMessageFailure: (state, action) => {
      state.sendingMessage = false;
      state.error = action.payload;
    },

    // Incoming messages
    receiveMessage: (state, action) => {
      const {conversationId, message} = action.payload;
      if (!state.messages[conversationId]) {
        state.messages[conversationId] = [];
      }
      // Avoid duplicates
      const exists = state.messages[conversationId].find(m => m.id === message.id);
      if (!exists) {
        state.messages[conversationId].push(message);
        
        // Update unread count if not in current conversation
        if (state.currentConversationId !== conversationId) {
          state.unreadCounts[conversationId] = 
            (state.unreadCounts[conversationId] || 0) + 1;
        }
        
        // Update last message in conversation list
        const convIdx = state.conversations.findIndex(c => c.id === conversationId);
        if (convIdx !== -1) {
          state.conversations[convIdx].lastMessage = message;
          state.conversations[convIdx].updatedAt = message.timestamp;
          // Move to top
          const conv = state.conversations.splice(convIdx, 1)[0];
          state.conversations.unshift(conv);
        }
      }
    },

    // Message status updates
    updateMessageStatus: (state, action) => {
      const {conversationId, messageId, status} = action.payload;
      const msgs = state.messages[conversationId];
      if (msgs) {
        const msg = msgs.find(m => m.id === messageId || m.clientId === messageId);
        if (msg) msg.status = status;
      }
    },

    // Typing indicators
    setTypingUser: (state, action) => {
      const {conversationId, userId, isTyping} = action.payload;
      if (!state.typingUsers[conversationId]) {
        state.typingUsers[conversationId] = [];
      }
      if (isTyping) {
        if (!state.typingUsers[conversationId].includes(userId)) {
          state.typingUsers[conversationId].push(userId);
        }
      } else {
        state.typingUsers[conversationId] = 
          state.typingUsers[conversationId].filter(id => id !== userId);
      }
    },

    // Presence
    setUserOnline: (state, action) => {
      const online = new Set(Array.from(state.onlineUsers));
      online.add(action.payload);
      state.onlineUsers = Array.from(online);
    },
    setUserOffline: (state, action) => {
      const online = new Set(Array.from(state.onlineUsers));
      online.delete(action.payload);
      state.onlineUsers = Array.from(online);
    },

    // Identity key change warning
    setIdentityKeyChanged: (state, action) => {
      const {userId, safetyNumber} = action.payload;
      const conv = state.conversations.find(c => c.participantId === userId);
      if (conv) {
        conv.identityKeyChanged = true;
        conv.safetyNumber = safetyNumber;
      }
    },

    clearError: state => {
      state.error = null;
    },
    
    clearConversation: (state, action) => {
      delete state.messages[action.payload];
    },
  },
});

export const {
  fetchConversationsStart,
  fetchConversationsSuccess,
  fetchConversationsFailure,
  setCurrentConversation,
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
  clearError,
  clearConversation,
} = chatSlice.actions;

// Selectors
export const selectConversations = state => state.chat.conversations;
export const selectMessages = (state, conversationId) =>
  state.chat.messages[conversationId] || [];
export const selectChatLoading = state => state.chat.loading;
export const selectSendingMessage = state => state.chat.sendingMessage;
export const selectTypingUsers = (state, conversationId) =>
  state.chat.typingUsers[conversationId] || [];
export const selectOnlineUsers = state => new Set(state.chat.onlineUsers);
export const selectIsUserOnline = (state, userId) =>
  state.chat.onlineUsers.includes(String(userId));
export const selectUnreadCount = (state, conversationId) =>
  state.chat.unreadCounts[conversationId] || 0;
export const selectCurrentConversationId = state => state.chat.currentConversationId;
export const selectTotalUnread = state =>
  Object.values(state.chat.unreadCounts).reduce((a, b) => a + b, 0);

export default chatSlice.reducer;
