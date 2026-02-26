/**
 * callsSlice.js
 * Redux slice for voice and video call state
 */

import {createSlice} from '@reduxjs/toolkit';
import {CALL_STATES, CALL_TYPES} from '../../crypto/webrtc/WebRTCManager';

const initialState = {
  callState: CALL_STATES.IDLE,
  callType: null,              // 'voice' | 'video'
  remoteUser: null,            // { id, name, avatar }
  isLocalAudioMuted: false,
  isLocalVideoOff: false,
  isSpeakerOn: false,
  callDuration: 0,             // seconds
  incomingCall: null,          // { callType, callerUser, offerSignal }
  error: null,
};

const callsSlice = createSlice({
  name: 'calls',
  initialState,
  reducers: {
    setCallState: (state, action) => {
      state.callState = action.payload;
    },
    initiateCallStart: (state, action) => {
      state.callState = CALL_STATES.INITIATING;
      state.callType = action.payload.callType;
      state.remoteUser = action.payload.remoteUser;
      state.error = null;
    },
    callConnected: (state) => {
      state.callState = CALL_STATES.CONNECTED;
      state.callDuration = 0;
    },
    callEnded: (state) => {
      return {...initialState};
    },
    callFailed: (state, action) => {
      state.callState = CALL_STATES.FAILED;
      state.error = action.payload;
    },
    setIncomingCall: (state, action) => {
      state.incomingCall = action.payload;
      state.callState = CALL_STATES.RINGING;
    },
    clearIncomingCall: (state) => {
      state.incomingCall = null;
    },
    toggleAudio: (state) => {
      state.isLocalAudioMuted = !state.isLocalAudioMuted;
    },
    toggleVideo: (state) => {
      state.isLocalVideoOff = !state.isLocalVideoOff;
    },
    toggleSpeaker: (state) => {
      state.isSpeakerOn = !state.isSpeakerOn;
    },
    tickCallDuration: (state) => {
      state.callDuration += 1;
    },
  },
});

export const {
  setCallState,
  initiateCallStart,
  callConnected,
  callEnded,
  callFailed,
  setIncomingCall,
  clearIncomingCall,
  toggleAudio,
  toggleVideo,
  toggleSpeaker,
  tickCallDuration,
} = callsSlice.actions;

// Selectors
export const selectCallState = state => state.calls.callState;
export const selectCallType = state => state.calls.callType;
export const selectRemoteUser = state => state.calls.remoteUser;
export const selectIncomingCall = state => state.calls.incomingCall;
export const selectIsCallActive = state =>
  state.calls.callState !== CALL_STATES.IDLE &&
  state.calls.callState !== CALL_STATES.ENDED;
export const selectCallDuration = state => state.calls.callDuration;
export const selectIsLocalAudioMuted = state => state.calls.isLocalAudioMuted;
export const selectIsLocalVideoOff = state => state.calls.isLocalVideoOff;

export default callsSlice.reducer;
