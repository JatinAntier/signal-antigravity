import React, {useEffect, useState, useRef} from 'react';
import {
  View,
  Text,
  FlatList,
  TextInput,
  TouchableOpacity,
  KeyboardAvoidingView,
  Platform,
  StyleSheet,
  ActivityIndicator,
} from 'react-native';
import {useDispatch, useSelector} from 'react-redux';
import {
  fetchMessagesStart,
  sendMessageStart,
  setCurrentConversation,
  selectMessages,
  selectChatLoading,
  selectTypingUsers,
  selectIsUserOnline,
  selectSendingMessage,
  setTypingUser,
} from '../../store/slices/chatSlice';
import {initiateCallStart} from '../../store/slices/callsSlice';
import WebSocketService from '../../services/WebSocketService';
import {CALL_TYPES} from '../../crypto/webrtc/WebRTCManager';
import {selectCurrentUser} from '../../store/slices/authSlice';

const ChatScreen = ({route, navigation}) => {
  const {id: conversationId, name, participantId} = route.params;
  const dispatch = useDispatch();
  const currentUser = useSelector(selectCurrentUser);
  
  const messages = useSelector(state => selectMessages(state, conversationId)) || [];
  const loading = useSelector(selectChatLoading);
  const typingUsers = useSelector(state => selectTypingUsers(state, conversationId));
  const isOnline = useSelector(state => selectIsUserOnline(state, participantId));
  const sendingMessage = useSelector(selectSendingMessage);

  const [text, setText] = useState('');
  const flatListRef = useRef();
  const typingTimer = useRef(null);

  useEffect(() => {
    dispatch(setCurrentConversation(conversationId));
    dispatch(fetchMessagesStart({conversationId, page: 1}));

    navigation.setOptions({
      headerRight: () => (
        <View style={{flexDirection: 'row', marginRight: 15}}>
          <TouchableOpacity onPress={handleVoiceCall} style={{marginHorizontal: 10}}>
            <Text style={{color: '#007AFF', fontSize: 16}}>📞</Text>
          </TouchableOpacity>
          <TouchableOpacity onPress={handleVideoCall}>
            <Text style={{color: '#007AFF', fontSize: 16}}>📹</Text>
          </TouchableOpacity>
        </View>
      ),
      headerTitle: () => (
        <View>
          <Text style={{fontSize: 18, fontWeight: 'bold'}}>{name}</Text>
          <Text style={{fontSize: 12, color: isOnline ? 'green' : 'gray'}}>
            {isOnline ? 'Online' : 'Offline'}
          </Text>
        </View>
      )
    });

    return () => {
      dispatch(setCurrentConversation(null));
      clearTimeout(typingTimer.current);
      WebSocketService.sendTypingStop(conversationId);
    };
  }, [conversationId, participantId, isOnline]);

  const handleVoiceCall = () => {
    dispatch(initiateCallStart({
      callType: CALL_TYPES.VOICE,
      remoteUser: {id: participantId, name},
    }));
    navigation.navigate('Call');
  };

  const handleVideoCall = () => {
    dispatch(initiateCallStart({
      callType: CALL_TYPES.VIDEO,
      remoteUser: {id: participantId, name},
    }));
    navigation.navigate('Call');
  };

  const handleSend = () => {
    if (!text.trim()) return;

    dispatch(sendMessageStart({
      conversationId,
      recipientId: participantId,
      recipientUserId: participantId,
      plaintext: text.trim(),
    }));
    setText('');
    WebSocketService.sendTypingStop(conversationId);
  };

  const handleTextChange = (val) => {
    setText(val);
    WebSocketService.sendTypingStart(conversationId);
    
    clearTimeout(typingTimer.current);
    typingTimer.current = setTimeout(() => {
      WebSocketService.sendTypingStop(conversationId);
    }, 2000);
  };

  const renderMessage = ({item}) => {
    const isMe = item.senderId === currentUser?.id || item.status === 'sending';
    return (
      <View style={[styles.messageBubble, isMe ? styles.messageMe : styles.messageThem]}>
        <Text style={[styles.messageText, isMe ? styles.messageTextMe : styles.messageTextThem]}>
          {item.content}
        </Text>
        <View style={styles.messageFooter}>
          <Text style={styles.timestamp}>
            {new Date(item.timestamp).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})}
          </Text>
          {isMe && (
            <Text style={styles.status}>
               {item.status === 'sending' ? ' 🕒' : item.status === 'sent' ? ' ✓' : item.status === 'delivered' ? ' ✓✓' : item.status === 'read' ? ' 👀' : ''}
            </Text>
          )}
        </View>
        {item.isDecryptionError && (
          <Text style={styles.errorText}>Decryption error. Keys out of sync.</Text>
        )}
      </View>
    );
  };

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      keyboardVerticalOffset={Platform.OS === 'ios' ? 90 : 0}>
      
      {loading && messages.length === 0 ? (
        <ActivityIndicator style={{marginTop: 20}} />
      ) : (
        <FlatList
          ref={flatListRef}
          data={messages}
          keyExtractor={item => item.id || item.clientId}
          renderItem={renderMessage}
          contentContainerStyle={{padding: 16}}
          onContentSizeChange={() => flatListRef.current?.scrollToEnd({animated: true})}
          onLayout={() => flatListRef.current?.scrollToEnd({animated: false})}
        />
      )}

      {typingUsers.length > 0 && (
        <Text style={styles.typingIndicator}>User is typing...</Text>
      )}

      <View style={styles.inputContainer}>
        <TextInput
          style={styles.input}
          placeholder="Signal message"
          value={text}
          onChangeText={handleTextChange}
          multiline
        />
        <TouchableOpacity style={styles.sendButton} onPress={handleSend} disabled={!text.trim() || sendingMessage}>
            <Text style={styles.sendText}>Send</Text>
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#f2f2f6'},
  messageBubble: {
    maxWidth: '80%',
    padding: 12,
    borderRadius: 20,
    marginBottom: 8,
  },
  messageMe: {
    alignSelf: 'flex-end',
    backgroundColor: '#007AFF',
    borderBottomRightRadius: 4,
  },
  messageThem: {
    alignSelf: 'flex-start',
    backgroundColor: '#fff',
    borderBottomLeftRadius: 4,
    borderWidth: 1,
    borderColor: '#e5e5ea',
  },
  messageText: {fontSize: 16},
  messageTextMe: {color: '#fff'},
  messageTextThem: {color: '#000'},
  messageFooter: {flexDirection: 'row', justifyContent: 'flex-end', marginTop: 4},
  timestamp: {fontSize: 10, color: 'rgba(255,255,255,0.7)'},
  status: {fontSize: 10, color: 'rgba(255,255,255,0.9)'},
  errorText: {fontSize: 10, color: '#ff3b30', marginTop: 4, fontWeight: 'bold'},
  typingIndicator: {paddingHorizontal: 16, paddingBottom: 8, fontSize: 12, color: '#8e8e93', fontStyle: 'italic'},
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    padding: 12,
    backgroundColor: '#fff',
    borderTopWidth: 1,
    borderTopColor: '#e5e5ea',
  },
  input: {
    flex: 1,
    borderWidth: 1,
    borderColor: '#e5e5ea',
    borderRadius: 20,
    paddingHorizontal: 16,
    paddingTop: 10,
    paddingBottom: 10,
    maxHeight: 100,
    fontSize: 16,
    backgroundColor: '#fafafa',
  },
  sendButton: {
    marginLeft: 12,
    marginBottom: 8,
    backgroundColor: '#007AFF',
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderRadius: 20,
  },
  sendText: {color: '#fff', fontWeight: 'bold'},
});

export default ChatScreen;
