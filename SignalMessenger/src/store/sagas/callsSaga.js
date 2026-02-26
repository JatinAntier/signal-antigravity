/**
 * callsSaga.js
 * Handles WebRTC call orchestration
 */

import {call, put, takeLatest, takeEvery, all, select} from 'redux-saga/effects';
import {eventChannel} from 'redux-saga';
import WebRTCManager, {CALL_STATES} from '../../crypto/webrtc/WebRTCManager';
import WebSocketService, {WS_EVENTS} from '../../services/WebSocketService';
import {
  initiateCallStart,
  setCallState,
  callConnected,
  callEnded,
  callFailed,
  setIncomingCall,
  clearIncomingCall,
} from '../slices/callsSlice';
import Logger from '../../utils/Logger';

function* handleInitiateCall(action) {
  const {remoteUser, callType} = action.payload;
  try {
    yield call(
      [WebRTCManager, 'initiateCall'],
      String(remoteUser.id),
      callType,
      WebSocketService, // pass WS instance as signaling channel
    );
  } catch (error) {
    Logger.error('CallsSaga', `Initiate call failed: ${error.message}`);
    yield put(callFailed(error.message));
  }
}

function* handleEndCall() {
  try {
    yield call([WebRTCManager, 'endCall']);
  } catch (error) {
    Logger.error('CallsSaga', `End call failed: ${error.message}`);
  }
}

function* handleAnswerCall(action) {
  const incomingCall = yield select(state => state.calls.incomingCall);
  if (!incomingCall) return;

  try {
    yield call(
      [WebRTCManager, 'answerCall'],
      incomingCall.callerUser.id,
      incomingCall.offerSignal,
    );
    yield put(clearIncomingCall());
  } catch (error) {
    Logger.error('CallsSaga', `Answer call failed: ${error.message}`);
    yield put(callFailed(error.message));
  }
}

export default function* callsSaga() {
  yield all([
    takeLatest(initiateCallStart.type, handleInitiateCall),
    takeLatest(callEnded.type, handleEndCall),
    // Additional handlers could be added for answering
  ]);
}
