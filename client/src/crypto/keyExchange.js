/**
 * Key Exchange Protocol
 * Custom ECDH-based key exchange with digital signatures for MITM protection
 * 
 * Protocol Flow:
 * 1. Initiator generates ECDH key pair and sends public key + signature
 * 2. Responder generates ECDH key pair, derives shared secret, sends public key + signature
 * 3. Initiator derives shared secret and verifies responder's signature
 * 4. Both parties derive session key using HKDF
 * 5. Key confirmation message exchange
 */

import { 
  generateECDHKeyPair, 
  importECDHPublicKey, 
  importECDHPrivateKey,
  importPrivateKey 
} from './keyManager';
import { deriveAESKey, generateNonce } from './encryption';

/**
 * Derive shared secret using ECDH
 * @param {CryptoKey} privateKey - Our private key
 * @param {CryptoKey} publicKey - Other party's public key
 * @returns {Promise<ArrayBuffer>}
 */
export const deriveSharedSecret = async (privateKey, publicKey) => {
  try {
    const sharedSecret = await window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKey
      },
      privateKey,
      256 // 256 bits
    );

    return sharedSecret;
  } catch (error) {
    console.error('Error deriving shared secret:', error);
    throw new Error('Failed to derive shared secret');
  }
};

/**
 * Sign data using RSA-PSS
 * @param {string} data - Data to sign (as string)
 * @param {CryptoKey} privateKey - RSA private key
 * @returns {Promise<string>}
 */
export const signData = async (data, privateKey) => {
  try {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    const signature = await window.crypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: 32
      },
      privateKey,
      dataBuffer
    );

    // Convert to base64
    const bytes = new Uint8Array(signature);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  } catch (error) {
    console.error('Error signing data:', error);
    throw new Error('Failed to sign data');
  }
};

/**
 * Verify signature using RSA-PSS
 * @param {string} data - Original data
 * @param {string} signatureBase64 - Signature in base64
 * @param {CryptoKey} publicKey - RSA public key
 * @returns {Promise<boolean>}
 */
export const verifySignature = async (data, signatureBase64, publicKey) => {
  try {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    // Convert signature from base64
    const binary = atob(signatureBase64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    const isValid = await window.crypto.subtle.verify(
      {
        name: 'RSA-PSS',
        saltLength: 32
      },
      publicKey,
      bytes.buffer,
      dataBuffer
    );

    return isValid;
  } catch (error) {
    console.error('Error verifying signature:', error);
    return false;
  }
};

/**
 * Create key exchange initiation message
 * @param {Object} ecdhKeyPair - ECDH key pair
 * @param {CryptoKey} rsaPrivateKey - RSA private key for signing
 * @param {string} initiatorId - Initiator user ID
 * @param {string} responderId - Responder user ID
 * @returns {Promise<Object>}
 */
export const createKeyExchangeInit = async (ecdhKeyPair, rsaPrivateKey, initiatorId, responderId) => {
  try {
    // Export ECDH public key
    const ecdhPublicKeyJWK = await window.crypto.subtle.exportKey('jwk', ecdhKeyPair.publicKey);

    // Create message to sign
    const timestamp = Date.now();
    const nonce = generateNonce();
    const messageToSign = JSON.stringify({
      type: 'key-exchange-init',
      initiatorId,
      responderId,
      ecdhPublicKey: ecdhPublicKeyJWK,
      timestamp,
      nonce
    });

    // Sign the message
    const signature = await signData(messageToSign, rsaPrivateKey);

    return {
      initiatorId,
      responderId,
      ecdhPublicKey: ecdhPublicKeyJWK,
      timestamp,
      nonce,
      signature
    };
  } catch (error) {
    console.error('Error creating key exchange init:', error);
    throw new Error('Failed to create key exchange initiation');
  }
};

/**
 * Process key exchange initiation and create response
 * @param {Object} initMessage - Initiation message from initiator
 * @param {Object} ecdhKeyPair - Our ECDH key pair
 * @param {CryptoKey} rsaPrivateKey - Our RSA private key
 * @param {CryptoKey} initiatorRSAPublicKey - Initiator's RSA public key
 * @returns {Promise<{response: Object, sessionKey: CryptoKey}>}
 */
export const processKeyExchangeInit = async (initMessage, ecdhKeyPair, rsaPrivateKey, initiatorRSAPublicKey) => {
  try {
    // Verify initiator's signature
    const messageToVerify = JSON.stringify({
      type: 'key-exchange-init',
      initiatorId: initMessage.initiatorId,
      responderId: initMessage.responderId,
      ecdhPublicKey: initMessage.ecdhPublicKey,
      timestamp: initMessage.timestamp,
      nonce: initMessage.nonce
    });

    const isValid = await verifySignature(messageToVerify, initMessage.signature, initiatorRSAPublicKey);
    if (!isValid) {
      throw new Error('Invalid signature in key exchange initiation');
    }

    // Check timestamp (prevent replay attacks - allow 5 minute window)
    const now = Date.now();
    const messageTime = initMessage.timestamp;
    if (Math.abs(now - messageTime) > 5 * 60 * 1000) {
      throw new Error('Key exchange message expired');
    }

    // Import initiator's ECDH public key
    const initiatorECDHPublicKey = await importECDHPublicKey(initMessage.ecdhPublicKey);

    // Derive shared secret
    const sharedSecret = await deriveSharedSecret(ecdhKeyPair.privateKey, initiatorECDHPublicKey);

    // Export our ECDH public key
    const responderECDHPublicKeyJWK = await window.crypto.subtle.exportKey('jwk', ecdhKeyPair.publicKey);

    // Create response message
    const timestamp = Date.now();
    const nonce = generateNonce();
    const responseMessage = JSON.stringify({
      type: 'key-exchange-response',
      initiatorId: initMessage.initiatorId,
      responderId: initMessage.responderId,
      ecdhPublicKey: responderECDHPublicKeyJWK,
      timestamp,
      nonce,
      initNonce: initMessage.nonce
    });

    // Sign response
    const signature = await signData(responseMessage, rsaPrivateKey);

    // Derive session key using HKDF
    const salt = new Uint8Array(32); // Use zero salt or derive from nonces
    window.crypto.getRandomValues(salt);
    const info = new TextEncoder().encode('E2EE-Session-Key');
    const sessionKey = await deriveAESKey(sharedSecret, salt, info);

    return {
      response: {
        initiatorId: initMessage.initiatorId,
        responderId: initMessage.responderId,
        ecdhPublicKey: responderECDHPublicKeyJWK,
        timestamp,
        nonce,
        initNonce: initMessage.nonce,
        signature,
        salt: Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
      },
      sessionKey,
      sharedSecret: Array.from(new Uint8Array(sharedSecret)).map(b => b.toString(16).padStart(2, '0')).join('')
    };
  } catch (error) {
    console.error('Error processing key exchange init:', error);
    throw error;
  }
};

/**
 * Complete key exchange on initiator side
 * @param {Object} responseMessage - Response from responder
 * @param {Object} ecdhKeyPair - Our ECDH key pair
 * @param {CryptoKey} rsaPrivateKey - Our RSA private key
 * @param {CryptoKey} responderRSAPublicKey - Responder's RSA public key
 * @param {string} saltHex - Salt from responder
 * @returns {Promise<CryptoKey>}
 */
export const completeKeyExchange = async (responseMessage, ecdhKeyPair, rsaPrivateKey, responderRSAPublicKey, saltHex) => {
  try {
    // Verify responder's signature
    const messageToVerify = JSON.stringify({
      type: 'key-exchange-response',
      initiatorId: responseMessage.initiatorId,
      responderId: responseMessage.responderId,
      ecdhPublicKey: responseMessage.ecdhPublicKey,
      timestamp: responseMessage.timestamp,
      nonce: responseMessage.nonce,
      initNonce: responseMessage.initNonce
    });

    const isValid = await verifySignature(messageToVerify, responseMessage.signature, responderRSAPublicKey);
    if (!isValid) {
      throw new Error('Invalid signature in key exchange response');
    }

    // Check timestamp
    const now = Date.now();
    const messageTime = responseMessage.timestamp;
    if (Math.abs(now - messageTime) > 5 * 60 * 1000) {
      throw new Error('Key exchange response expired');
    }

    // Import responder's ECDH public key
    const responderECDHPublicKey = await importECDHPublicKey(responseMessage.ecdhPublicKey);

    // Derive shared secret
    const sharedSecret = await deriveSharedSecret(ecdhKeyPair.privateKey, responderECDHPublicKey);

    // Derive session key using HKDF with same salt
    const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const info = new TextEncoder().encode('E2EE-Session-Key');
    const sessionKey = await deriveAESKey(sharedSecret, salt, info);

    return sessionKey;
  } catch (error) {
    console.error('Error completing key exchange:', error);
    throw error;
  }
};

