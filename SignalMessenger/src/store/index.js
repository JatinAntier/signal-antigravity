/**
 * store/index.js
 * Redux store configuration with redux-saga middleware
 */

import {configureStore} from '@reduxjs/toolkit';
import createSagaMiddleware from 'redux-saga';
import authReducer from './slices/authSlice';
import chatReducer from './slices/chatSlice';
import callsReducer from './slices/callsSlice';
import rootSaga from './sagas/rootSaga';

const sagaMiddleware = createSagaMiddleware({
  onError: (error, {sagaStack}) => {
    console.error('Unhandled saga error:', error);
    console.error('Saga stack:', sagaStack);
  },
});

export const store = configureStore({
  reducer: {
    auth: authReducer,
    chat: chatReducer,
    calls: callsReducer,
  },
  middleware: getDefaultMiddleware =>
    getDefaultMiddleware({
      thunk: false,            // Use sagas, not thunks
      serializableCheck: {
        // WebRTC streams and crypto keys are not serializable
        ignoredActions: [
          'chat/receiveMessage',
          'calls/setIncomingCall',
        ],
        ignoredPaths: ['calls.localStream', 'calls.remoteStream'],
      },
    }).concat(sagaMiddleware),
  devTools: __DEV__, // Enable Redux DevTools only in development
});

// Run the root saga
sagaMiddleware.run(rootSaga);

export default store;
