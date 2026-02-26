import React from 'react';
import {createNativeStackNavigator} from '@react-navigation/native-stack';
import ChatListScreen from '../screens/Home/ChatListScreen';
import ChatScreen from '../screens/Chat/ChatScreen';
import CallScreen from '../screens/Calls/CallScreen';
import ProfileScreen from '../screens/Profile/ProfileScreen';

const Stack = createNativeStackNavigator();

const MainNavigator = () => {
  return (
    <Stack.Navigator>
      <Stack.Screen name="ChatList" component={ChatListScreen} options={{title: 'Signal Clone'}} />
      <Stack.Screen name="Chat" component={ChatScreen} options={({route}) => ({title: route.params.name})} />
      <Stack.Screen name="Call" component={CallScreen} options={{headerShown: false}} />
      <Stack.Screen name="Profile" component={ProfileScreen} />
    </Stack.Navigator>
  );
};

export default MainNavigator;
