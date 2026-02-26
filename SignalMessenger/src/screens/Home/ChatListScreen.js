import React, {useEffect} from 'react';
import {View, Text, FlatList, TouchableOpacity, StyleSheet, ActivityIndicator} from 'react-native';
import {useDispatch, useSelector} from 'react-redux';
import {fetchConversationsStart, selectConversations, selectChatLoading} from '../../store/slices/chatSlice';

const ChatListScreen = ({navigation}) => {
  const dispatch = useDispatch();
  const conversations = useSelector(selectConversations) || [];
  const loading = useSelector(selectChatLoading);

  useEffect(() => {
    dispatch(fetchConversationsStart());
  }, [dispatch]);

  const renderItem = ({item}) => (
    <TouchableOpacity
      style={styles.chatRow}
      onPress={() => navigation.navigate('Chat', {id: item.id, name: item.name, participantId: item.participantId})}>
      <View style={styles.avatar}>
        <Text style={styles.avatarText}>{item.name?.[0]?.toUpperCase()}</Text>
      </View>
      <View style={styles.chatInfo}>
        <Text style={styles.chatName}>{item.name}</Text>
        <Text style={styles.lastMessage} numberOfLines={1}>
          {item.lastMessage?.content || 'No messages yet'}
        </Text>
      </View>
    </TouchableOpacity>
  );

  return (
    <View style={styles.container}>
      {loading && conversations.length === 0 ? (
        <ActivityIndicator style={{marginTop: 20}} />
      ) : (
        <FlatList
          data={[...conversations, {id: 'demo-1', name: 'Alice (Demo)', participantId: 1}]} // fallback demo data
          keyExtractor={item => item.id.toString()}
          renderItem={renderItem}
          contentContainerStyle={{padding: 16}}
        />
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#fff'},
  chatRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  avatar: {
    width: 50,
    height: 50,
    borderRadius: 25,
    backgroundColor: '#007AFF',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 16,
  },
  avatarText: {color: '#fff', fontSize: 20, fontWeight: 'bold'},
  chatInfo: {flex: 1},
  chatName: {fontSize: 16, fontWeight: '600', color: '#000'},
  lastMessage: {fontSize: 14, color: '#666', marginTop: 4},
});

export default ChatListScreen;
