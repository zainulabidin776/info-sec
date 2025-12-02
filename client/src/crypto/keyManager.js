/**
 * Key Manager - Handles generation, storage, and retrieval of cryptographic keys
 * Uses Web Crypto API and IndexedDB for secure client-side storage
 */

const DB_NAME = 'E2EEKeyStore';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

/**
 * Initialize IndexedDB database
 */
const initDB = () => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const objectStore = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
        objectStore.createIndex('username', 'username', { unique: false });
      }
    };
  });
};

/**
 * Generate RSA key pair for user (encryption)
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
export const generateKeyPair = async () => {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true, // extractable
      ['encrypt', 'decrypt']
    );

    return keyPair;
  } catch (error) {
    console.error('Error generating key pair:', error);
    throw new Error('Failed to generate key pair');
  }
};

/**
 * Generate RSA-PSS key pair for signing
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
export const generateSigningKeyPair = async () => {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true, // extractable
      ['sign', 'verify']
    );

    return keyPair;
  } catch (error) {
    console.error('Error generating signing key pair:', error);
    throw new Error('Failed to generate signing key pair');
  }
};

/**
 * Generate ECDH key pair for key exchange
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
export const generateECDHKeyPair = async () => {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true, // extractable
      ['deriveKey', 'deriveBits']
    );

    return keyPair;
  } catch (error) {
    console.error('Error generating ECDH key pair:', error);
    throw new Error('Failed to generate ECDH key pair');
  }
};

/**
 * Export public key to JWK format
 * @param {CryptoKey} publicKey
 * @returns {Promise<Object>}
 */
export const exportPublicKey = async (publicKey) => {
  try {
    const jwk = await window.crypto.subtle.exportKey('jwk', publicKey);
    return jwk;
  } catch (error) {
    console.error('Error exporting public key:', error);
    throw new Error('Failed to export public key');
  }
};

/**
 * Export private key to JWK format (for storage)
 * @param {CryptoKey} privateKey
 * @returns {Promise<Object>}
 */
export const exportPrivateKey = async (privateKey) => {
  try {
    const jwk = await window.crypto.subtle.exportKey('jwk', privateKey);
    return jwk;
  } catch (error) {
    console.error('Error exporting private key:', error);
    throw new Error('Failed to export private key');
  }
};

/**
 * Import public key from JWK format
 * @param {Object} jwk
 * @returns {Promise<CryptoKey>}
 */
export const importPublicKey = async (jwk) => {
  try {
    // Remove key_ops from JWK if present to avoid conflicts
    const cleanJwk = { ...jwk };
    delete cleanJwk.key_ops;
    
    const key = await window.crypto.subtle.importKey(
      'jwk',
      cleanJwk,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      true,
      ['encrypt']
    );
    return key;
  } catch (error) {
    console.error('Error importing public key:', error);
    throw new Error('Failed to import public key');
  }
};

/**
 * Import ECDH public key from JWK format
 * @param {Object} jwk
 * @returns {Promise<CryptoKey>}
 */
export const importECDHPublicKey = async (jwk) => {
  try {
    // Remove key_ops from JWK if present (public keys shouldn't have operations)
    const cleanJwk = { ...jwk };
    delete cleanJwk.key_ops;
    
    const key = await window.crypto.subtle.importKey(
      'jwk',
      cleanJwk,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      [] // Public keys have empty key operations
    );
    return key;
  } catch (error) {
    console.error('Error importing ECDH public key:', error);
    throw new Error('Failed to import ECDH public key');
  }
};

/**
 * Import private key from JWK format
 * @param {Object} jwk
 * @returns {Promise<CryptoKey>}
 */
export const importPrivateKey = async (jwk) => {
  try {
    const key = await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      true,
      ['decrypt']
    );
    return key;
  } catch (error) {
    console.error('Error importing private key:', error);
    throw new Error('Failed to import private key');
  }
};

/**
 * Import RSA-PSS private key for signing from JWK format
 * @param {Object} jwk
 * @returns {Promise<CryptoKey>}
 */
export const importSigningPrivateKey = async (jwk) => {
  try {
    const key = await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256',
      },
      true,
      ['sign']
    );
    return key;
  } catch (error) {
    console.error('Error importing signing private key:', error);
    throw new Error('Failed to import signing private key');
  }
};

/**
 * Import RSA-PSS public key for verification from JWK format
 * @param {Object} jwk
 * @returns {Promise<CryptoKey>}
 */
export const importSigningPublicKey = async (jwk) => {
  try {
    // Remove key_ops from JWK if present to avoid conflicts
    const cleanJwk = { ...jwk };
    delete cleanJwk.key_ops;
    
    const key = await window.crypto.subtle.importKey(
      'jwk',
      cleanJwk,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256',
      },
      true,
      ['verify']
    );
    return key;
  } catch (error) {
    console.error('Error importing signing public key:', error);
    throw new Error('Failed to import signing public key');
  }
};

/**
 * Import ECDH private key from JWK format
 * @param {Object} jwk
 * @returns {Promise<CryptoKey>}
 */
export const importECDHPrivateKey = async (jwk) => {
  try {
    const key = await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveKey', 'deriveBits']
    );
    return key;
  } catch (error) {
    console.error('Error importing ECDH private key:', error);
    throw new Error('Failed to import ECDH private key');
  }
};

/**
 * Store keys in IndexedDB
 * @param {string} username
 * @param {Object} publicKeyJWK
 * @param {Object} privateKeyJWK
 * @param {Object} ecdhPublicKeyJWK
 * @param {Object} ecdhPrivateKeyJWK
 * @param {Object} signingPublicKeyJWK
 * @param {Object} signingPrivateKeyJWK
 */
export const storeKeys = async (username, publicKeyJWK, privateKeyJWK, ecdhPublicKeyJWK, ecdhPrivateKeyJWK, signingPublicKeyJWK, signingPrivateKeyJWK) => {
  try {
    const db = await initDB();
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    const keyData = {
      id: username,
      username,
      publicKeyJWK,
      privateKeyJWK,
      ecdhPublicKeyJWK,
      ecdhPrivateKeyJWK,
      signingPublicKeyJWK,
      signingPrivateKeyJWK,
      createdAt: new Date().toISOString()
    };

    await store.put(keyData);
    return true;
  } catch (error) {
    console.error('Error storing keys:', error);
    throw new Error('Failed to store keys');
  }
};

/**
 * Retrieve keys from IndexedDB
 * @param {string} username
 * @returns {Promise<Object>}
 */
export const retrieveKeys = async (username) => {
  try {
    const db = await initDB();
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);

    return new Promise((resolve, reject) => {
      const request = store.get(username);
      request.onsuccess = () => {
        if (request.result) {
          resolve(request.result);
        } else {
          reject(new Error('Keys not found'));
        }
      };
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    console.error('Error retrieving keys:', error);
    throw new Error('Failed to retrieve keys');
  }
};

/**
 * Check if keys exist for user
 * @param {string} username
 * @returns {Promise<boolean>}
 */
export const keysExist = async (username) => {
  try {
    await retrieveKeys(username);
    return true;
  } catch {
    return false;
  }
};

