import React from 'react';
import {View, Text, TouchableOpacity, StyleSheet} from 'react-native';
import {useDispatch, useSelector} from 'react-redux';
import {logoutStart} from '../../store/slices/authSlice';
import KeyManager from '../../crypto/signal/KeyManager';

const ProfileScreen = () => {
  const dispatch = useDispatch();

  const handleLogout = () => {
    dispatch(logoutStart());
  };

  let fingerprint = 'Loading...';
  try {
    const pubKey = KeyManager.getIdentityPublicKey();
    if (pubKey) {
      // Rough approximation of standard hex fingerprint from base64 representation
      fingerprint = Array.from(atob(pubKey)).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join(':').substr(0,47).toUpperCase();
    }
  } catch (e) {
    fingerprint = 'N/A';
  }

  return (
    <View style={styles.container}>
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Security</Text>
        <View style={styles.infoBox}>
          <Text style={styles.label}>Identity Public Key Fingerprint</Text>
          <Text style={styles.value} selectable>{fingerprint}</Text>
          <Text style={styles.description}>
            This is your Signal Protocol identity key. It never leaves your device unencrypted. 
            Others use this to verify they are talking to you.
          </Text>
        </View>
      </View>

      <TouchableOpacity style={styles.logoutButton} onPress={handleLogout}>
        <Text style={styles.logoutText}>Log Out & Wipe Data</Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#f2f2f6', padding: 16},
  section: {marginBottom: 24},
  sectionTitle: {fontSize: 14, fontWeight: 'bold', color: '#666', marginBottom: 8, marginLeft: 8, textTransform: 'uppercase'},
  infoBox: {
    backgroundColor: '#fff',
    padding: 16,
    borderRadius: 12,
  },
  label: {fontSize: 14, fontWeight: '600', color: '#000', marginBottom: 4},
  value: {fontSize: 14, color: '#007AFF', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', marginBottom: 8},
  description: {fontSize: 12, color: '#8e8e93', lineHeight: 18},
  logoutButton: {
    backgroundColor: '#ff3b30',
    padding: 16,
    borderRadius: 12,
    alignItems: 'center',
    marginTop: 'auto',
    marginBottom: 20,
  },
  logoutText: {color: '#fff', fontSize: 16, fontWeight: 'bold'},
});

export default ProfileScreen;
