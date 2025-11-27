/**
 * Storage utilities for managing session keys and message sequence numbers
 */

const STORAGE_PREFIX = 'e2ee_';

/**
 * Store session key for a conversation
 * @param {string} userId - Other user's ID
 * @param {string} sessionKeyJWK - Session key in JWK format (base64 encoded)
 */
export const storeSessionKey = (userId, sessionKeyJWK) => {
  try {
    const key = `${STORAGE_PREFIX}session_${userId}`;
    localStorage.setItem(key, JSON.stringify({
      key: sessionKeyJWK,
      timestamp: Date.now()
    }));
  } catch (error) {
    console.error('Error storing session key:', error);
  }
};

/**
 * Retrieve session key for a conversation
 * @param {string} userId - Other user's ID
 * @returns {Object|null}
 */
export const getSessionKey = (userId) => {
  try {
    const key = `${STORAGE_PREFIX}session_${userId}`;
    const data = localStorage.getItem(key);
    if (data) {
      return JSON.parse(data);
    }
    return null;
  } catch (error) {
    console.error('Error retrieving session key:', error);
    return null;
  }
};

/**
 * Remove session key
 * @param {string} userId
 */
export const removeSessionKey = (userId) => {
  try {
    const key = `${STORAGE_PREFIX}session_${userId}`;
    localStorage.removeItem(key);
  } catch (error) {
    console.error('Error removing session key:', error);
  }
};

/**
 * Get next sequence number for a conversation
 * @param {string} userId - Other user's ID
 * @returns {number}
 */
export const getNextSequenceNumber = (userId) => {
  try {
    const key = `${STORAGE_PREFIX}seq_${userId}`;
    const current = localStorage.getItem(key);
    const next = current ? parseInt(current, 10) + 1 : 1;
    localStorage.setItem(key, next.toString());
    return next;
  } catch (error) {
    console.error('Error getting sequence number:', error);
    return 1;
  }
};

/**
 * Reset sequence number
 * @param {string} userId
 */
export const resetSequenceNumber = (userId) => {
  try {
    const key = `${STORAGE_PREFIX}seq_${userId}`;
    localStorage.removeItem(key);
  } catch (error) {
    console.error('Error resetting sequence number:', error);
  }
};

/**
 * Store used nonces to prevent replay attacks
 * @param {string} nonce
 */
export const storeNonce = (nonce) => {
  try {
    const key = `${STORAGE_PREFIX}nonces`;
    const nonces = JSON.parse(localStorage.getItem(key) || '[]');
    nonces.push({
      nonce,
      timestamp: Date.now()
    });
    // Keep only last 1000 nonces
    if (nonces.length > 1000) {
      nonces.shift();
    }
    localStorage.setItem(key, JSON.stringify(nonces));
  } catch (error) {
    console.error('Error storing nonce:', error);
  }
};

/**
 * Check if nonce has been used
 * @param {string} nonce
 * @returns {boolean}
 */
export const isNonceUsed = (nonce) => {
  try {
    const key = `${STORAGE_PREFIX}nonces`;
    const nonces = JSON.parse(localStorage.getItem(key) || '[]');
    return nonces.some(n => n.nonce === nonce);
  } catch (error) {
    console.error('Error checking nonce:', error);
    return false;
  }
};

