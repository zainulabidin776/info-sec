import React, { useState, useEffect, useRef } from 'react';
import { usersAPI, messagesAPI, filesAPI, keyExchangeAPI } from '../services/api';
import { connectSocket, disconnectSocket, sendMessageViaSocket, onReceiveMessage, offReceiveMessage } from '../services/socket';
import { retrieveKeys, importPrivateKey, importPublicKey, importSigningPrivateKey, importSigningPublicKey, importECDHPrivateKey, importECDHPublicKey } from '../crypto/keyManager';
import { encryptMessage, decryptMessage, generateNonce, encryptFile, decryptFile } from '../crypto/encryption';
import { getSessionKey, storeSessionKey, getNextSequenceNumber, isNonceUsed, storeNonce } from '../utils/storage';
import { 
  createKeyExchangeInit, 
  processKeyExchangeInit, 
  completeKeyExchange 
} from '../crypto/keyExchange';
import { generateECDHKeyPair } from '../crypto/keyManager';
import './Chat.css';

const Chat = ({ user }) => {
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionKey, setSessionKey] = useState(null);
  const [keyExchangeStatus, setKeyExchangeStatus] = useState('idle'); // idle, initiating, responding, completed
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);

  useEffect(() => {
    loadUsers();
    if (user) {
      connectSocket(user.id);
    }

    return () => {
      disconnectSocket();
    };
  }, [user]);

  useEffect(() => {
    if (selectedUser) {
      loadMessages();
      setupMessageListener();
      checkPendingKeyExchanges();
      checkExistingSessionKey();
    }

    return () => {
      if (selectedUser) {
        offReceiveMessage(handleReceiveMessage);
      }
    };
  }, [selectedUser]);

  const checkExistingSessionKey = async () => {
    if (!selectedUser) return;
    const sessionKeyData = getSessionKey(selectedUser._id);
    if (sessionKeyData) {
      try {
        const sessionKey = await window.crypto.subtle.importKey(
          'jwk',
          sessionKeyData.key,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
        setSessionKey(sessionKey);
        setKeyExchangeStatus('completed');
      } catch (error) {
        console.error('Error importing session key:', error);
      }
    }
  };

  const checkPendingKeyExchanges = async () => {
    if (!selectedUser) return;
    try {
      const response = await keyExchangeAPI.getPending();
      const keyExchanges = response.data;
      
      // Find key exchange where we are the responder
      const pendingExchange = keyExchanges.find(
        ke => ke.responderId._id === selectedUser._id && 
              ke.status === 'initiated' &&
              ke.initiatorId._id === user.id
      );

      if (pendingExchange) {
        // Auto-respond to key exchange
        await respondToKeyExchange(pendingExchange);
      }
    } catch (error) {
      console.error('Error checking pending key exchanges:', error);
    }
  };

  const respondToKeyExchange = async (keyExchange) => {
    try {
      const keys = await retrieveKeys(user.username);
      const rsaPrivateKey = await importSigningPrivateKey(keys.signingPrivateKeyJWK);
      const initiatorRSAPublicKey = await importSigningPublicKey(keyExchange.initiatorId.signingPublicKeyJWK);

      // Generate ECDH key pair
      const ecdhKeyPair = await generateECDHKeyPair();

      // Process key exchange initiation
      const result = await processKeyExchangeInit(
        {
          initiatorId: keyExchange.initiatorId._id,
          responderId: keyExchange.responderId._id,
          ecdhPublicKey: keyExchange.initiatorECDHPublicKey,
          timestamp: keyExchange.initiatorTimestamp,
          nonce: keyExchange.initiatorNonce,
          signature: keyExchange.initiatorSignature
        },
        ecdhKeyPair,
        rsaPrivateKey,
        initiatorRSAPublicKey
      );

      // Send response to server
      const response = await keyExchangeAPI.respond({
        keyExchangeId: keyExchange._id,
        ecdhPublicKey: result.response.ecdhPublicKey,
        timestamp: result.response.timestamp,
        nonce: result.response.nonce,
        initNonce: result.response.initNonce,
        signature: result.response.signature,
        salt: result.response.salt
      });

      // Store session key
      const sessionKeyJWK = await window.crypto.subtle.exportKey('jwk', result.sessionKey);
      storeSessionKey(keyExchange.initiatorId._id, sessionKeyJWK);
      setSessionKey(result.sessionKey);
      setKeyExchangeStatus('completed');
    } catch (error) {
      console.error('Error responding to key exchange:', error);
    }
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const loadUsers = async () => {
    try {
      const response = await usersAPI.getAll();
      setUsers(response.data);
    } catch (error) {
      console.error('Error loading users:', error);
    }
  };

  const loadMessages = async () => {
    if (!selectedUser) return;

    try {
      setLoading(true);
      const response = await messagesAPI.getConversation(selectedUser._id);
      const msgs = response.data;

      // Decrypt messages if we have session key
      if (sessionKey) {
        const decryptedMessages = await Promise.all(
          msgs.map(async (msg) => {
            try {
              if (msg.senderId._id === user.id) {
                // We sent this, no need to decrypt (or we could store plaintext temporarily)
                return { ...msg, decrypted: true, content: '[Your message]' };
              }

              const decrypted = await decryptMessage(
                msg.ciphertext,
                sessionKey,
                msg.iv,
                msg.authTag
              );

              // Check nonce for replay protection
              if (isNonceUsed(msg.nonce)) {
                console.warn('Replay attack detected for nonce:', msg.nonce);
                return { ...msg, decrypted: true, content: '[Replay detected - message ignored]' };
              }
              storeNonce(msg.nonce);

              return { ...msg, decrypted: true, content: decrypted };
            } catch (error) {
              console.error('Error decrypting message:', error);
              return { ...msg, decrypted: false, content: '[Decryption failed]' };
            }
          })
        );
        setMessages(decryptedMessages);
      } else {
        setMessages(msgs.map(msg => ({ ...msg, decrypted: false, content: '[Encrypted - establish key exchange]' })));
      }
    } catch (error) {
      console.error('Error loading messages:', error);
    } finally {
      setLoading(false);
    }
  };

  const setupMessageListener = () => {
    onReceiveMessage(async (data) => {
      if (data.senderId === selectedUser._id) {
        // Decrypt and add to messages
        if (sessionKey) {
          try {
            const decrypted = await decryptMessage(
              data.ciphertext,
              sessionKey,
              data.iv,
              data.authTag
            );

            // Check nonce
            if (!isNonceUsed(data.nonce)) {
              storeNonce(data.nonce);
              setMessages(prev => [...prev, {
                ...data,
                decrypted: true,
                content: decrypted,
                senderId: { _id: data.senderId, username: selectedUser.username }
              }]);
            }
          } catch (error) {
            console.error('Error decrypting received message:', error);
          }
        }
      }
    });
  };

  const handleReceiveMessage = async (data) => {
    // Handle real-time message reception
    if (data.senderId === selectedUser._id && sessionKey) {
      try {
        const decrypted = await decryptMessage(
          data.ciphertext,
          sessionKey,
          data.iv,
          data.authTag
        );

        if (!isNonceUsed(data.nonce)) {
          storeNonce(data.nonce);
          setMessages(prev => [...prev, {
            ...data,
            decrypted: true,
            content: decrypted
          }]);
        }
      } catch (error) {
        console.error('Error handling received message:', error);
      }
    }
  };

  const initiateKeyExchange = async () => {
    if (!selectedUser) return;

    try {
      setKeyExchangeStatus('initiating');
      const keys = await retrieveKeys(user.username);
      const rsaPrivateKey = await importSigningPrivateKey(keys.signingPrivateKeyJWK);
      
      // Generate new ECDH key pair for this session
      const { generateECDHKeyPair } = await import('../crypto/keyManager');
      const ecdhKeyPair = await generateECDHKeyPair();

      const initMessage = await createKeyExchangeInit(
        ecdhKeyPair,
        rsaPrivateKey,
        user.id,
        selectedUser._id
      );

      // Store ECDH key pair temporarily for later use
      const ecdhKeyPairJWK = {
        publicKey: await window.crypto.subtle.exportKey('jwk', ecdhKeyPair.publicKey),
        privateKey: await window.crypto.subtle.exportKey('jwk', ecdhKeyPair.privateKey)
      };
      localStorage.setItem(`ecdh_temp_${selectedUser._id}`, JSON.stringify(ecdhKeyPairJWK));

      // Send to server
      const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:5000/api'}/key-exchange/initiate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(initMessage)
      });

      if (!response.ok) {
        throw new Error('Failed to initiate key exchange');
      }

      const data = await response.json();
      
      // Poll for response (in production, use WebSocket or long polling)
      pollForKeyExchangeResponse(data.keyExchangeId, ecdhKeyPair, rsaPrivateKey, selectedUser);
      
    } catch (error) {
      console.error('Error initiating key exchange:', error);
      setKeyExchangeStatus('idle');
      alert('Failed to initiate key exchange: ' + error.message);
    }
  };

  const pollForKeyExchangeResponse = async (keyExchangeId, ecdhKeyPair, rsaPrivateKey, responder) => {
    const maxAttempts = 30;
    let attempts = 0;

    const poll = async () => {
      try {
        const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:5000/api'}/key-exchange/${keyExchangeId}`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        });

        if (!response.ok) {
          throw new Error('Failed to fetch key exchange status');
        }

        const keyExchange = await response.json();

        if (keyExchange.status === 'completed') {
          // Import responder's RSA-PSS public key for signature verification
          const responderRSAPublicKey = await importSigningPublicKey(responder.signingPublicKeyJWK);
          
          // Complete key exchange
          const sessionKey = await completeKeyExchange(
            {
              initiatorId: keyExchange.initiatorId._id,
              responderId: keyExchange.responderId._id,
              ecdhPublicKey: keyExchange.responderECDHPublicKey,
              timestamp: keyExchange.responderTimestamp,
              nonce: keyExchange.responderNonce,
              initNonce: keyExchange.initiatorNonce,
              signature: keyExchange.responderSignature
            },
            ecdhKeyPair,
            rsaPrivateKey,
            responderRSAPublicKey,
            keyExchange.salt
          );

          // Store session key
          const sessionKeyJWK = await window.crypto.subtle.exportKey('jwk', sessionKey);
          storeSessionKey(responder._id, sessionKeyJWK);
          setSessionKey(sessionKey);
          setKeyExchangeStatus('completed');
          
          // Clean up temporary ECDH key
          localStorage.removeItem(`ecdh_temp_${responder._id}`);
        } else if (attempts < maxAttempts) {
          attempts++;
          setTimeout(poll, 2000); // Poll every 2 seconds
        } else {
          setKeyExchangeStatus('idle');
          alert('Key exchange timed out');
        }
      } catch (error) {
        console.error('Error polling for key exchange:', error);
        setKeyExchangeStatus('idle');
      }
    };

    poll();
  };

  const sendMessage = async () => {
    if (!newMessage.trim() || !selectedUser || !sessionKey) {
      if (!sessionKey) {
        alert('Please establish key exchange first');
        return;
      }
      return;
    }

    try {
      const nonce = generateNonce();
      const sequenceNumber = getNextSequenceNumber(selectedUser._id);

      // Encrypt message
      const encrypted = await encryptMessage(newMessage, sessionKey);

      // Send to server
      const messageData = {
        recipientId: selectedUser._id,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        nonce,
        sequenceNumber,
        messageType: 'text'
      };

      await messagesAPI.send(messageData);

      // Also send via socket for real-time
      sendMessageViaSocket({
        ...messageData,
        senderId: user.id
      });

      // Add to local messages
      setMessages(prev => [...prev, {
        ...messageData,
        senderId: { _id: user.id, username: user.username },
        recipientId: { _id: selectedUser._id, username: selectedUser.username },
        decrypted: true,
        content: newMessage,
        timestamp: new Date()
      }]);

      setNewMessage('');
      storeNonce(nonce);
    } catch (error) {
      console.error('Error sending message:', error);
      alert('Failed to send message');
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file || !selectedUser || !sessionKey) return;

    try {
      setLoading(true);
      
      // Encrypt file
      const encryptedFile = await encryptFile(file, sessionKey);
      
      // Create form data
      const formData = new FormData();
      formData.append('file', new Blob([encryptedFile.chunks.map(c => 
        atob(c.ciphertext)
      ).join('')], { type: 'application/octet-stream' }));
      formData.append('originalFilename', encryptedFile.originalFilename);
      formData.append('mimeType', encryptedFile.mimeType);
      formData.append('iv', encryptedFile.chunks[0]?.iv || '');
      formData.append('authTag', encryptedFile.chunks[0]?.authTag || '');
      formData.append('chunks', JSON.stringify(encryptedFile.chunks));

      // Upload file
      const uploadResponse = await filesAPI.upload(formData);
      const fileId = uploadResponse.data.fileId;

      // Send file message
      const nonce = generateNonce();
      const sequenceNumber = getNextSequenceNumber(selectedUser._id);

      await messagesAPI.send({
        recipientId: selectedUser._id,
        ciphertext: '', // File message doesn't need text ciphertext
        iv: encryptedFile.chunks[0]?.iv || '',
        authTag: encryptedFile.chunks[0]?.authTag || '',
        nonce,
        sequenceNumber,
        messageType: 'file',
        fileId
      });

      // Add to local messages
      setMessages(prev => [...prev, {
        senderId: { _id: user.id, username: user.username },
        recipientId: { _id: selectedUser._id, username: selectedUser.username },
        decrypted: true,
        content: `📎 ${file.name}`,
        messageType: 'file',
        fileId,
        timestamp: new Date()
      }]);

      storeNonce(nonce);
      e.target.value = ''; // Reset file input
    } catch (error) {
      console.error('Error uploading file:', error);
      alert('Failed to upload file');
    } finally {
      setLoading(false);
    }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="chat-container">
      <div className="chat-sidebar">
        <div className="chat-header">
          <h2>Users</h2>
          <div className="user-info">
            <span>👤 {user.username}</span>
          </div>
        </div>
        <div className="users-list">
          {users.map(u => (
            <div
              key={u._id}
              className={`user-item ${selectedUser?._id === u._id ? 'active' : ''}`}
              onClick={() => setSelectedUser(u)}
            >
              <div className="user-avatar">{u.username[0].toUpperCase()}</div>
              <div className="user-details">
                <div className="user-name">{u.username}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="chat-main">
        {selectedUser ? (
          <>
            <div className="chat-header-main">
              <h3>{selectedUser.username}</h3>
              {!sessionKey && (
                <button onClick={initiateKeyExchange} className="key-exchange-btn">
                  🔐 Establish Secure Connection
                </button>
              )}
              {sessionKey && (
                <span className="secure-indicator">🔒 Encrypted</span>
              )}
            </div>

            <div className="messages-container">
              {loading ? (
                <div className="loading">Loading messages...</div>
              ) : (
                messages.map((msg, idx) => (
                  <div
                    key={idx}
                    className={`message ${msg.senderId._id === user.id ? 'sent' : 'received'}`}
                  >
                    <div className="message-content">
                      {msg.decrypted ? msg.content : '[Encrypted]'}
                    </div>
                    <div className="message-time">
                      {new Date(msg.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                ))
              )}
              <div ref={messagesEndRef} />
            </div>

            <div className="message-input-container">
              {sessionKey && (
                <div className="file-upload-btn" onClick={() => fileInputRef.current?.click()}>
                  📎 Attach File
                </div>
              )}
              <input
                type="file"
                ref={fileInputRef}
                style={{ display: 'none' }}
                onChange={handleFileUpload}
              />
              <input
                type="text"
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                placeholder={sessionKey ? "Type a message..." : "Establish key exchange first"}
                disabled={!sessionKey}
                className="message-input"
              />
              <button onClick={sendMessage} disabled={!sessionKey} className="send-btn">
                Send
              </button>
            </div>
          </>
        ) : (
          <div className="no-selection">
            <p>Select a user to start chatting</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Chat;

