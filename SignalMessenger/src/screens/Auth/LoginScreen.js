import React, {useState} from 'react';
import {View, Text, TextInput, TouchableOpacity, StyleSheet, ActivityIndicator} from 'react-native';
import {useDispatch, useSelector} from 'react-redux';
import {requestOTPStart, selectAuthLoading, selectAuthError} from '../../store/slices/authSlice';

const LoginScreen = ({navigation}) => {
  const [email, setEmail] = useState('');
  const dispatch = useDispatch();
  const loading = useSelector(selectAuthLoading);
  const error = useSelector(selectAuthError);

  const handleSendOTP = () => {
    if (!email) return;
    dispatch(requestOTPStart({email}));
    navigation.navigate('OTP', {email});
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Welcome to SecureChat</Text>
      <Text style={styles.subtitle}>Enter your email to continue</Text>

      {error ? <Text style={styles.error}>{error}</Text> : null}

      <TextInput
        style={styles.input}
        placeholder="Email Address"
        value={email}
        onChangeText={setEmail}
        keyboardType="email-address"
        autoCapitalize="none"
      />

      <TouchableOpacity
        style={styles.button}
        onPress={handleSendOTP}
        disabled={loading || !email}>
        {loading ? (
          <ActivityIndicator color="#fff" />
        ) : (
          <Text style={styles.buttonText}>Continue</Text>
        )}
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {flex: 1, padding: 24, justifyContent: 'center', backgroundColor: '#fff'},
  title: {fontSize: 32, fontWeight: 'bold', marginBottom: 8, color: '#000'},
  subtitle: {fontSize: 16, color: '#666', marginBottom: 32},
  error: {color: 'red', marginBottom: 16},
  input: {
    borderWidth: 1,
    borderColor: '#ddd',
    padding: 16,
    borderRadius: 8,
    fontSize: 16,
    marginBottom: 24,
    color: '#000',
  },
  button: {
    backgroundColor: '#007AFF',
    padding: 16,
    borderRadius: 8,
    alignItems: 'center',
  },
  buttonText: {color: '#fff', fontSize: 16, fontWeight: 'bold'},
});

export default LoginScreen;
