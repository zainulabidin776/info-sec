import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import { generateKeyPair, generateSigningKeyPair, generateECDHKeyPair, exportPublicKey, exportPrivateKey, storeKeys } from '../crypto/keyManager';
import './Login.css';

const Login = ({ onLogin }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isLogin) {
        // Login
        const response = await authAPI.login({ username, password });
        const { token, user } = response.data;
        
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(user));
        
        if (onLogin) {
          onLogin(user);
        }
        navigate('/chat');
      } else {
        // Register
        if (password.length < 8) {
          setError('Password must be at least 8 characters');
          setLoading(false);
          return;
        }

        // Generate keys
        const rsaKeyPair = await generateKeyPair();
        const signingKeyPair = await generateSigningKeyPair();
        const ecdhKeyPair = await generateECDHKeyPair();

        // Export keys
        const publicKeyJWK = await exportPublicKey(rsaKeyPair.publicKey);
        const privateKeyJWK = await exportPrivateKey(rsaKeyPair.privateKey);
        const signingPublicKeyJWK = await exportPublicKey(signingKeyPair.publicKey);
        const signingPrivateKeyJWK = await exportPrivateKey(signingKeyPair.privateKey);
        const ecdhPublicKeyJWK = await exportPublicKey(ecdhKeyPair.publicKey);
        const ecdhPrivateKeyJWK = await exportPrivateKey(ecdhKeyPair.privateKey);

        // Store keys locally
        await storeKeys(username, publicKeyJWK, privateKeyJWK, ecdhPublicKeyJWK, ecdhPrivateKeyJWK, signingPublicKeyJWK, signingPrivateKeyJWK);

        // Register with server
        const response = await authAPI.register({
          username,
          password,
          publicKey: JSON.stringify(publicKeyJWK),
          publicKeyJWK,
          signingPublicKeyJWK
        });

        const { token, user } = response.data;
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(user));

        if (onLogin) {
          onLogin(user);
        }
        navigate('/chat');
      }
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h1>Secure E2EE Messaging</h1>
        <div className="login-tabs">
          <button
            className={isLogin ? 'active' : ''}
            onClick={() => setIsLogin(true)}
          >
            Login
          </button>
          <button
            className={!isLogin ? 'active' : ''}
            onClick={() => setIsLogin(false)}
          >
            Register
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              minLength={3}
              maxLength={30}
              pattern="[a-zA-Z0-9_]+"
            />
          </div>

          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
            />
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" disabled={loading} className="submit-btn">
            {loading ? 'Processing...' : (isLogin ? 'Login' : 'Register')}
          </button>
        </form>

        {!isLogin && (
          <div className="info-box">
            <p>🔐 Your private keys will be generated and stored securely on your device only.</p>
            <p>⚠️ Make sure to backup your keys if you need to access your account from another device.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Login;

