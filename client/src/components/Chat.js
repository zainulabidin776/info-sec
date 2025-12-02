import React, { useState, useEffect, useRef } from 'react';
import { usersAPI, messagesAPI, filesAPI, keyExchangeAPI } from '../services/api';
import { connectSocket, disconnectSocket, sendMessageViaSocket, onReceiveMessage, offReceiveMessage } from '../services/socket';
import { retrieveKeys, importPrivateKey, importPublicKey, importSigningPrivateKey, importSigningPublicKey, importECDHPrivateKey, importECDHPublicKey } from '../crypto/keyManager';
import { encryptMessage, decryptMessage, generateNonce, encryptFile, decryptFile } from '../crypto/encryption';
import { getSessionKey, storeSessionKey, removeSessionKey, getNextSequenceNumber, isNonceUsed, storeNonce } from '../utils/storage';
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
  const [sending, setSending] = useState(false); // Prevent double-submission
  const [sessionKey, setSessionKey] = useState(null);
  const [keyExchangeStatus, setKeyExchangeStatus] = useState('idle'); // idle, initiating, responding, completed
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);

  useEffect(() => {
    loadUsers();
    if (user) {
      console.log('🔌 Connecting socket for user:', user.id);
      connectSocket(user.id);
    }

    return () => {
      console.log('🔌 Disconnecting socket');
      disconnectSocket();
    };
  }, [user]);

  useEffect(() => {
    if (selectedUser) {
      // Load session key first, then load messages
      const initChat = async () => {
        await checkExistingSessionKey();
        await loadMessages();
        setupMessageListener();
        await checkPendingKeyExchanges();
      };
      initChat();
    }

    return () => {
      if (selectedUser) {
        offReceiveMessage(handleReceiveMessage);
      }
    };
  }, [selectedUser]);

  // Reload messages when session key changes (after key exchange completes)
  useEffect(() => {
    if (sessionKey && selectedUser) {
      console.log('🔄 Session key updated, reloading messages...');
      loadMessages();
    }
  }, [sessionKey]);

  const checkExistingSessionKey = async () => {
    if (!selectedUser) return;
    const sessionKeyData = getSessionKey(selectedUser._id);
    if (sessionKeyData) {
      try {
        const sessionKey = await window.crypto.subtle.importKey(
          'jwk',
          sessionKeyData.key,
          { name: 'AES-GCM', length: 256 },
          true, // Extractable for future export if needed
          ['encrypt', 'decrypt']
        );
        setSessionKey(sessionKey);
        setKeyExchangeStatus('completed');
        console.log('✅ Session key loaded from storage');
      } catch (error) {
        console.error('Error importing session key:', error);
      }
    } else {
      console.log('ℹ️ No existing session key found');
    }
  };

  const checkPendingKeyExchanges = async () => {
    if (!selectedUser) return;
    try {
      const response = await keyExchangeAPI.getPending();
      const keyExchanges = response.data;
      
      console.log('📋 Checking for pending key exchanges...', keyExchanges);
      
      // Find key exchange where WE are the responder and THEY are the initiator
      const pendingExchange = keyExchanges.find(
        ke => ke.responderId._id === user.id && 
              ke.status === 'initiated' &&
              ke.initiatorId._id === selectedUser._id
      );

      if (pendingExchange) {
        console.log('✅ Found pending key exchange! Auto-responding...');
        setKeyExchangeStatus('responding');
        // Auto-respond to key exchange
        await respondToKeyExchange(pendingExchange);
      } else {
        console.log('ℹ️ No pending key exchange found for this conversation');
      }
    } catch (error) {
      console.error('Error checking pending key exchanges:', error);
    }
  };

  const respondToKeyExchange = async (keyExchange) => {
    try {
      console.log('🔐 Starting automatic key exchange response...');
      
      const keys = await retrieveKeys(user.username);
      if (!keys || !keys.signingPrivateKeyJWK) {
        throw new Error('Keys not found in IndexedDB');
      }
      
      const rsaPrivateKey = await importSigningPrivateKey(keys.signingPrivateKeyJWK);
      const initiatorRSAPublicKey = await importSigningPublicKey(keyExchange.initiatorId.signingPublicKeyJWK);

      // Generate ECDH key pair
      const ecdhKeyPair = await generateECDHKeyPair();
      console.log('🔑 Generated ECDH key pair');

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
      console.log('✓ Signature verified and shared secret derived');

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
      console.log('✓ Response sent to server');

      // Store session key
      const sessionKeyJWK = await window.crypto.subtle.exportKey('jwk', result.sessionKey);
      storeSessionKey(keyExchange.initiatorId._id, sessionKeyJWK);
      setSessionKey(result.sessionKey);
      setKeyExchangeStatus('completed');
      
      console.log('✅ Key exchange completed successfully! (Auto-responded)');
      
      // Reload messages to decrypt them
      await loadMessages();
      
      alert('✅ Secure connection established! You can now send encrypted messages.');
    } catch (error) {
      console.error('❌ Error responding to key exchange:', error);
      setKeyExchangeStatus('idle');
      alert('⚠️ Failed to respond to key exchange: ' + error.message);
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
        console.log(`🔓 Decrypting ${msgs.length} messages...`);
        const decryptedMessages = await Promise.all(
          msgs.map(async (msg) => {
            try {
              // Decrypt ALL messages (including ones we sent)
              // Server stores everything encrypted
              const decrypted = await decryptMessage(
                msg.ciphertext,
                sessionKey,
                msg.iv,
                msg.authTag
              );

              // Check nonce for replay protection (only for received messages)
              if (msg.senderId._id !== user.id) {
                if (isNonceUsed(msg.nonce)) {
                  console.warn('Replay attack detected for nonce:', msg.nonce);
                  return { ...msg, decrypted: true, content: '[Replay detected - message ignored]' };
                }
                storeNonce(msg.nonce);
              }

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
    console.log('📡 Setting up message listener for:', selectedUser?.username);
    onReceiveMessage(async (data) => {
      console.log('📨 Received message via Socket.io:', {
        from: data.senderId,
        expectedFrom: selectedUser?._id,
        hasSessionKey: !!sessionKey,
        nonce: data.nonce?.substring(0, 8)
      });

      if (data.senderId === selectedUser._id) {
        // IMPORTANT: Load session key fresh from storage (don't rely on closure)
        let currentSessionKey = sessionKey;
        
        if (!currentSessionKey) {
          console.log('🔍 Session key not in state, checking localStorage...');
          const sessionKeyData = getSessionKey(selectedUser._id);
          if (sessionKeyData) {
            try {
              currentSessionKey = await window.crypto.subtle.importKey(
                'jwk',
                sessionKeyData.key,
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
              );
              setSessionKey(currentSessionKey); // Update state for future use
              console.log('✅ Session key loaded from localStorage');
            } catch (error) {
              console.error('❌ Failed to import session key:', error);
            }
          }
        }

        // Decrypt and add to messages
        if (currentSessionKey) {
          try {
            console.log('🔓 Attempting to decrypt received message...');
            const decrypted = await decryptMessage(
              data.ciphertext,
              currentSessionKey,
              data.iv,
              data.authTag
            );

            // Check nonce
            if (!isNonceUsed(data.nonce)) {
              storeNonce(data.nonce);
              console.log('✅ Message decrypted and added to chat:', decrypted.substring(0, 30));
              setMessages(prev => [...prev, {
                ...data,
                decrypted: true,
                content: decrypted,
                timestamp: new Date(data.timestamp || Date.now()), // Parse timestamp properly
                senderId: { _id: data.senderId, username: selectedUser.username }
              }]);
            } else {
              console.warn('⚠️ Duplicate nonce detected in received message - ignoring');
            }
          } catch (error) {
            console.error('❌ Error decrypting received message:', error);
            // Still add the message but mark as encrypted
            setMessages(prev => [...prev, {
              ...data,
              decrypted: false,
              content: '[Decryption failed]',
              timestamp: new Date(data.timestamp || Date.now()), // Parse timestamp properly
              senderId: { _id: data.senderId, username: selectedUser.username }
            }]);
          }
        } else {
          console.warn('⚠️ Received message but no session key available in state or localStorage');
          setMessages(prev => [...prev, {
            ...data,
            decrypted: false,
            content: '[Encrypted - establish key exchange first]',
            senderId: { _id: data.senderId, username: selectedUser.username }
          }]);
        }
      } else {
        console.log('📭 Ignoring message from different user:', data.senderId);
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

    // Check if session key already exists
    if (sessionKey) {
      const confirmNew = window.confirm('⚠️ A secure session already exists with this user. Starting a new key exchange will invalidate old messages. Continue?');
      if (!confirmNew) return;
      
      // Clear old session key
      removeSessionKey(selectedUser._id);
      setSessionKey(null);
      setKeyExchangeStatus('idle');
    }

    try {
      setKeyExchangeStatus('initiating');
      
      // Check if keys exist in IndexedDB
      const keys = await retrieveKeys(user.username);
      if (!keys || !keys.signingPrivateKeyJWK) {
        alert('⚠️ Keys not found! Please logout and login again to generate keys.');
        setKeyExchangeStatus('idle');
        return;
      }
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
    const maxAttempts = 60; // Increased from 30 to 60 (2 minutes)
    let attempts = 0;
    
    console.log('⏳ Waiting for other user to respond to key exchange...');

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
          
          console.log('✅ Key exchange completed successfully!');
          
          // Reload messages to decrypt them
          await loadMessages();
          
          alert('✅ Secure connection established! You can now send encrypted messages.');
          
          // Clean up temporary ECDH key
          localStorage.removeItem(`ecdh_temp_${responder._id}`);
        } else if (attempts < maxAttempts) {
          attempts++;
          console.log(`⏳ Polling for key exchange response... (${attempts}/${maxAttempts})`);
          setTimeout(poll, 2000); // Poll every 2 seconds
        } else {
          setKeyExchangeStatus('idle');
          console.error('❌ Key exchange timed out after 2 minutes');
          alert('⚠️ Key exchange timed out! Make sure the other user is online and has clicked on your chat.');
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

    // Prevent double-submission
    if (sending) {
      console.log('⚠️ Already sending a message, ignoring duplicate call');
      return;
    }

    const messageText = newMessage; // Save before clearing
    const sendTimestamp = Date.now();
    setSending(true); // Lock immediately
    
    try {
      const nonce = generateNonce();
      const sequenceNumber = getNextSequenceNumber(selectedUser._id);

      console.log(`📤 [${sendTimestamp}] Sending message with nonce: ${nonce.substring(0, 8)}..., seq: ${sequenceNumber}, text: "${messageText.substring(0, 20)}..."`);

      // Encrypt message
      const encrypted = await encryptMessage(messageText, sessionKey);

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

      const response = await messagesAPI.send(messageData);
      console.log('✅ Message sent successfully:', response.data);

      const messageTimestamp = new Date();

      // Also send via socket for real-time
      sendMessageViaSocket({
        ...messageData,
        senderId: user.id,
        timestamp: messageTimestamp.toISOString() // Include timestamp for receiver
      });

      // Add to local messages
      setMessages(prev => [...prev, {
        ...messageData,
        senderId: { _id: user.id, username: user.username },
        recipientId: { _id: selectedUser._id, username: selectedUser.username },
        decrypted: true,
        content: messageText,
        timestamp: messageTimestamp
      }]);

      // SUCCESS - Clear message and store nonce
      setNewMessage('');
      storeNonce(nonce);
      console.log('✅ Nonce stored successfully:', nonce.substring(0, 8));
    } catch (error) {
      console.error('❌ Error sending message:', error);
      console.error('Error details:', error.response?.data);
      
      // Check if it's a replay attack error
      if (error.response?.data?.error?.includes('Duplicate nonce')) {
        console.error('🚨 REPLAY DETECTED - Nonce already exists in database');
        console.error('Possible causes: 1) React double-render, 2) Network retry, 3) Button double-click');
        alert('⚠️ Duplicate message detected! This is a security feature preventing replay attacks. The message was NOT sent. Please try again with a new message.');
        // Clear the message - user needs to type again to get NEW nonce
        setNewMessage('');
      } else {
        alert('Failed to send message: ' + (error.response?.data?.error || error.message));
        // Keep message for other errors so user can retry
      }
    } finally {
      setSending(false); // Always unlock
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
              {keyExchangeStatus === 'idle' && !sessionKey && (
                <button onClick={initiateKeyExchange} className="key-exchange-btn">
                  🔐 Establish Secure Connection
                </button>
              )}
              {keyExchangeStatus === 'initiating' && (
                <span className="key-exchange-status">⏳ Initiating key exchange...</span>
              )}
              {keyExchangeStatus === 'responding' && (
                <span className="key-exchange-status">⏳ Responding to key exchange...</span>
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
                onKeyPress={(e) => e.key === 'Enter' && !sending && sendMessage()}
                placeholder={sessionKey ? "Type a message..." : "Establish key exchange first"}
                disabled={!sessionKey}
                className="message-input"
              />
              <button onClick={sendMessage} disabled={!sessionKey || sending} className="send-btn">
                {sending ? 'Sending...' : 'Send'}
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

