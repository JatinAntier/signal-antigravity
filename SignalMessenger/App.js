import React, {useEffect} from 'react';
import {NavigationContainer} from '@react-navigation/native';
import {Provider, useDispatch, useSelector} from 'react-redux';
import {SafeAreaProvider} from 'react-native-safe-area-context';
import store from './src/store';
import {selectIsAuthenticated} from './src/store/slices/authSlice';
import AuthNavigator from './src/navigation/AuthNavigator';
import MainNavigator from './src/navigation/MainNavigator';
import WebSocketService from './src/services/WebSocketService';

const AppNavigator = () => {
  const isAuthenticated = useSelector(selectIsAuthenticated);

  useEffect(() => {
    if (isAuthenticated) {
      WebSocketService.connect();
    } else {
      WebSocketService.disconnect();
    }
    return () => WebSocketService.disconnect();
  }, [isAuthenticated]);

  return (
    <NavigationContainer>
      {isAuthenticated ? <MainNavigator /> : <AuthNavigator />}
    </NavigationContainer>
  );
};

const App = () => {
  return (
    <Provider store={store}>
      <SafeAreaProvider>
        <AppNavigator />
      </SafeAreaProvider>
    </Provider>
  );
};

export default App;
