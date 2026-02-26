import React, {useEffect, useRef} from 'react';
import {View, Text, StyleSheet, TouchableOpacity} from 'react-native';
import {RTCView} from 'react-native-webrtc';
import {useDispatch, useSelector} from 'react-redux';
import {
  selectCallState,
  selectCallType,
  selectRemoteUser,
  callEnded,
  toggleAudio,
  toggleVideo,
  selectIsLocalAudioMuted,
  selectIsLocalVideoOff,
} from '../../store/slices/callsSlice';
import WebRTCManager, {CALL_STATES, CALL_TYPES} from '../../crypto/webrtc/WebRTCManager';

const CallScreen = ({navigation}) => {
  const dispatch = useDispatch();
  const callState = useSelector(selectCallState);
  const callType = useSelector(selectCallType);
  const remoteUser = useSelector(selectRemoteUser);
  const isAudioMuted = useSelector(selectIsLocalAudioMuted);
  const isVideoOff = useSelector(selectIsLocalVideoOff);

  const localStream = WebRTCManager.localStream;
  const remoteStream = WebRTCManager.remoteStream;

  useEffect(() => {
    if (callState === CALL_STATES.ENDED || callState === CALL_STATES.FAILED || callState === CALL_STATES.IDLE) {
      navigation.goBack();
    }
  }, [callState, navigation]);

  const handleEndCall = () => {
    WebRTCManager.endCall();
    dispatch(callEnded());
  };

  const handleToggleAudio = () => {
    WebRTCManager.toggleAudio();
    dispatch(toggleAudio());
  };

  const handleToggleVideo = () => {
    WebRTCManager.toggleVideo();
    dispatch(toggleVideo());
  };

  const handleSwitchCamera = () => {
    WebRTCManager.switchCamera();
  };

  const renderVideo = () => (
    <View style={styles.videoContainer}>
      {remoteStream && !remoteStream.getVideoTracks()[0]?.muted ? (
        <RTCView streamURL={remoteStream.toURL()} style={styles.remoteVideo} objectFit="cover" />
      ) : (
        <View style={styles.audioPlaceholder}>
          <Text style={styles.avatarText}>{remoteUser?.name?.[0]}</Text>
        </View>
      )}

      {localStream && !isVideoOff && (
        <RTCView streamURL={localStream.toURL()} style={styles.localVideo} objectFit="cover" zOrder={1} />
      )}
    </View>
  );

  const renderAudio = () => (
    <View style={styles.audioContainer}>
      <View style={styles.audioPlaceholderLarge}>
        <Text style={styles.avatarTextLarge}>{remoteUser?.name?.[0]}</Text>
      </View>
      <Text style={styles.callStateText}>{callState.toUpperCase()}</Text>
    </View>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>{remoteUser?.name || 'Unknown'}</Text>
        <Text style={styles.headerSubtitle}>Signal {callType === CALL_TYPES.VIDEO ? 'Video' : 'Voice'} Call</Text>
      </View>

      {callType === CALL_TYPES.VIDEO ? renderVideo() : renderAudio()}

      <View style={styles.controlsContainer}>
        {callType === CALL_TYPES.VIDEO && (
          <TouchableOpacity style={styles.controlBtn} onPress={handleSwitchCamera}>
            <Text style={styles.controlIcon}>🔄</Text>
          </TouchableOpacity>
        )}

        <TouchableOpacity 
          style={[styles.controlBtn, isAudioMuted && styles.controlBtnActive]} 
          onPress={handleToggleAudio}>
          <Text style={styles.controlIcon}>{isAudioMuted ? '🔇' : '🎤'}</Text>
        </TouchableOpacity>

        {callType === CALL_TYPES.VIDEO && (
          <TouchableOpacity 
            style={[styles.controlBtn, isVideoOff && styles.controlBtnActive]} 
            onPress={handleToggleVideo}>
            <Text style={styles.controlIcon}>{isVideoOff ? '🚫📹' : '📹'}</Text>
          </TouchableOpacity>
        )}

        <TouchableOpacity style={[styles.controlBtn, styles.endCallBtn]} onPress={handleEndCall}>
          <Text style={styles.controlIcon}>📞</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#1c1c1e'},
  header: {
    position: 'absolute',
    top: 60,
    width: '100%',
    alignItems: 'center',
    zIndex: 10,
  },
  headerTitle: {color: '#fff', fontSize: 24, fontWeight: 'bold'},
  headerSubtitle: {color: 'rgba(255,255,255,0.7)', fontSize: 16, marginTop: 4},
  videoContainer: {flex: 1},
  remoteVideo: {flex: 1},
  localVideo: {
    position: 'absolute',
    bottom: 120,
    right: 20,
    width: 100,
    height: 150,
    borderRadius: 8,
    backgroundColor: '#000',
  },
  audioContainer: {flex: 1, justifyContent: 'center', alignItems: 'center'},
  audioPlaceholder: {
    flex: 1,
    backgroundColor: '#2c2c2e',
    justifyContent: 'center',
    alignItems: 'center',
  },
  audioPlaceholderLarge: {
    width: 150,
    height: 150,
    borderRadius: 75,
    backgroundColor: '#007AFF',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 40,
  },
  avatarText: {fontSize: 48, color: '#fff', fontWeight: 'bold'},
  avatarTextLarge: {fontSize: 80, color: '#fff', fontWeight: 'bold'},
  callStateText: {color: '#fff', fontSize: 18, letterSpacing: 2},
  controlsContainer: {
    position: 'absolute',
    bottom: 40,
    width: '100%',
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 20,
    gap: 20,
  },
  controlBtn: {
    width: 60,
    height: 60,
    borderRadius: 30,
    backgroundColor: 'rgba(255,255,255,0.2)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  controlBtnActive: {backgroundColor: '#fff'},
  endCallBtn: {backgroundColor: '#ff3b30'},
  controlIcon: {fontSize: 24},
});

export default CallScreen;
