import React, {useState} from 'react';
import {View, Text, TextInput, TouchableOpacity, StyleSheet, ActivityIndicator} from 'react-native';
import {useDispatch, useSelector} from 'react-redux';
import {loginStart, selectAuthLoading, selectAuthError} from '../../store/slices/authSlice';
import DeviceInfo from 'react-native-device-info'; // Placeholder for device ID fetching
import {generateUUID} from '../../utils/uuid';

const OTPScreen = ({route}) => {
  const {email} = route.params;
  const [otp, setOtp] = useState('');
  const dispatch = useDispatch();
  const loading = useSelector(selectAuthLoading);
  const error = useSelector(selectAuthError);

  const handleVerifyOTP = async () => {
    if (!otp || otp.length < 6) return;
    
    // In production, use standard library for device ID
    // const deviceId = await DeviceInfo.getUniqueId(); 
    const deviceId = 'device_' + generateUUID(); 

    dispatch(loginStart({email, otp, deviceId}));
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Enter OTP</Text>
      <Text style={styles.subtitle}>Sent to {email}</Text>

      {error ? <Text style={styles.error}>{error}</Text> : null}

      <TextInput
        style={styles.input}
        placeholder="6-digit code"
        value={otp}
        onChangeText={setOtp}
        keyboardType="numeric"
        maxLength={6}
      />

      <TouchableOpacity
        style={styles.button}
        onPress={handleVerifyOTP}
        disabled={loading || otp.length < 6}>
        {loading ? (
          <ActivityIndicator color="#fff" />
        ) : (
          <Text style={styles.buttonText}>Verify</Text>
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
    fontSize: 24,
    marginBottom: 24,
    textAlign: 'center',
    letterSpacing: 8,
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

export default OTPScreen;
