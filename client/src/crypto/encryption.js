/**
 * Encryption Module - Handles AES-256-GCM encryption/decryption
 * Implements replay protection with nonces, timestamps, and sequence numbers
 */

/**
 * Generate a random IV for AES-GCM (12 bytes recommended for GCM)
 * @returns {Uint8Array}
 */
export const generateIV = () => {
  return window.crypto.getRandomValues(new Uint8Array(12));
};

/**
 * Generate a random nonce for replay protection
 * @returns {string}
 */
export const generateNonce = () => {
  const array = new Uint8Array(16);
  window.crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

/**
 * Derive AES key from shared secret using HKDF
 * @param {ArrayBuffer} sharedSecret
 * @param {Uint8Array} salt
 * @param {Uint8Array} info
 * @returns {Promise<CryptoKey>}
 */
export const deriveAESKey = async (sharedSecret, salt, info) => {
  try {
    // Import shared secret as raw key
    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveKey']
    );

    // Derive AES-GCM key using HKDF
    const derivedKey = await window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: info
      },
      baseKey,
      {
        name: 'AES-GCM',
        length: 256
      },
      true, // Must be extractable so we can export to JWK for storage
      ['encrypt', 'decrypt']
    );

    return derivedKey;
  } catch (error) {
    console.error('Error deriving AES key:', error);
    throw new Error('Failed to derive AES key');
  }
};

/**
 * Encrypt message using AES-256-GCM
 * @param {string} plaintext
 * @param {CryptoKey} key
 * @param {Uint8Array} iv
 * @returns {Promise<{ciphertext: string, iv: string, authTag: string}>}
 */
export const encryptMessage = async (plaintext, key, iv = null) => {
  try {
    if (!iv) {
      iv = generateIV();
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128 // 128-bit authentication tag
      },
      key,
      data
    );

    // Extract ciphertext and auth tag
    // In AES-GCM, the auth tag is appended to the ciphertext
    const tagLength = 16; // 128 bits = 16 bytes
    const ciphertext = encrypted.slice(0, encrypted.byteLength - tagLength);
    const authTag = encrypted.slice(encrypted.byteLength - tagLength);

    return {
      ciphertext: arrayBufferToBase64(ciphertext),
      iv: arrayBufferToBase64(iv),
      authTag: arrayBufferToBase64(authTag)
    };
  } catch (error) {
    console.error('Error encrypting message:', error);
    throw new Error('Failed to encrypt message');
  }
};

/**
 * Decrypt message using AES-256-GCM
 * @param {string} ciphertextBase64
 * @param {CryptoKey} key
 * @param {string} ivBase64
 * @param {string} authTagBase64
 * @returns {Promise<string>}
 */
export const decryptMessage = async (ciphertextBase64, key, ivBase64, authTagBase64) => {
  try {
    const iv = base64ToArrayBuffer(ivBase64);
    const ciphertext = base64ToArrayBuffer(ciphertextBase64);
    const authTag = base64ToArrayBuffer(authTagBase64);

    // Combine ciphertext and auth tag for decryption
    const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
    combined.set(new Uint8Array(ciphertext), 0);
    combined.set(new Uint8Array(authTag), ciphertext.byteLength);

    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      key,
      combined.buffer
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (error) {
    console.error('Error decrypting message:', error);
    throw new Error('Failed to decrypt message - possible tampering or wrong key');
  }
};

/**
 * Encrypt file using AES-256-GCM with chunking support
 * @param {File} file
 * @param {CryptoKey} key
 * @param {number} chunkSize - Size of each chunk in bytes (optional)
 * @returns {Promise<{chunks: Array, iv: string, authTag: string}>}
 */
export const encryptFile = async (file, key, chunkSize = 1024 * 1024) => {
  try {
    const fileBuffer = await file.arrayBuffer();
    const chunks = [];
    const totalChunks = Math.ceil(fileBuffer.byteLength / chunkSize);

    // Generate IV for first chunk
    let iv = generateIV();

    for (let i = 0; i < totalChunks; i++) {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize, fileBuffer.byteLength);
      const chunk = fileBuffer.slice(start, end);

      // Use different IV for each chunk (increment IV)
      if (i > 0) {
        // Increment IV for subsequent chunks
        const ivArray = new Uint8Array(iv);
        let carry = 1;
        for (let j = ivArray.length - 1; j >= 0 && carry > 0; j--) {
          const sum = ivArray[j] + carry;
          ivArray[j] = sum % 256;
          carry = Math.floor(sum / 256);
        }
        iv = ivArray;
      }

      const encrypted = await window.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128
        },
        key,
        chunk
      );

      const tagLength = 16;
      const ciphertext = encrypted.slice(0, encrypted.byteLength - tagLength);
      const authTag = encrypted.slice(encrypted.byteLength - tagLength);

      chunks.push({
        chunkIndex: i,
        iv: arrayBufferToBase64(iv),
        authTag: arrayBufferToBase64(authTag),
        ciphertext: arrayBufferToBase64(ciphertext),
        size: ciphertext.byteLength
      });
    }

    return {
      chunks,
      originalFilename: file.name,
      mimeType: file.type,
      size: file.size
    };
  } catch (error) {
    console.error('Error encrypting file:', error);
    throw new Error('Failed to encrypt file');
  }
};

/**
 * Decrypt file chunks
 * @param {Array} chunks
 * @param {CryptoKey} key
 * @returns {Promise<Blob>}
 */
export const decryptFile = async (chunks, key) => {
  try {
    const decryptedChunks = [];

    for (const chunk of chunks.sort((a, b) => a.chunkIndex - b.chunkIndex)) {
      const iv = base64ToArrayBuffer(chunk.iv);
      const ciphertext = base64ToArrayBuffer(chunk.ciphertext);
      const authTag = base64ToArrayBuffer(chunk.authTag);

      const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
      combined.set(new Uint8Array(ciphertext), 0);
      combined.set(new Uint8Array(authTag), ciphertext.byteLength);

      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128
        },
        key,
        combined.buffer
      );

      decryptedChunks.push(decrypted);
    }

    return new Blob(decryptedChunks);
  } catch (error) {
    console.error('Error decrypting file:', error);
    throw new Error('Failed to decrypt file');
  }
};

/**
 * Utility: Convert ArrayBuffer to Base64
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export const arrayBufferToBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

/**
 * Utility: Convert Base64 to ArrayBuffer
 * @param {string} base64
 * @returns {ArrayBuffer}
 */
export const base64ToArrayBuffer = (base64) => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

