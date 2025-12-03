/**
 * Replay Attack Demonstration Script
 * 
 * This script demonstrates how replay attacks work and how they are prevented
 * using nonces, timestamps, and sequence numbers.
 */

const crypto = require('crypto');

console.log('='.repeat(60));
console.log('REPLAY ATTACK DEMONSTRATION');
console.log('='.repeat(60));
console.log();

// Simulate a message without replay protection
console.log('SCENARIO 1: Message WITHOUT Replay Protection');
console.log('-'.repeat(60));

const sessionKey = crypto.randomBytes(32); // AES-256 key
const iv = crypto.randomBytes(12); // GCM IV

function encryptMessage(message, key, iv) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}

function decryptMessage(encryptedData, key) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encryptedData.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Original message
const originalMessage = 'Transfer $1000 to account 12345';
const encrypted1 = encryptMessage(originalMessage, sessionKey, iv);

console.log('1. Hamdan sends encrypted message:');
console.log('   Plaintext:', originalMessage);
console.log('   Ciphertext:', encrypted1.encrypted.substring(0, 32) + '...');
console.log('   IV:', encrypted1.iv.substring(0, 16) + '...');

console.log('\n2. Attacker (Eve) intercepts and stores the message');
console.log('   Eve stores:', encrypted1.encrypted.substring(0, 32) + '...');

console.log('\n3. Later, Eve replays the same message');
const replayedMessage = decryptMessage(encrypted1, sessionKey);
console.log('   Zain receives and decrypts:', replayedMessage);
console.log('   ❌ Zain executes the command AGAIN!');
console.log('   ❌ $1000 transferred TWICE!');

console.log('\n' + '='.repeat(60));
console.log('SCENARIO 2: Message WITH Replay Protection');
console.log('-'.repeat(60));

// Message with replay protection
let nonceCounter = 0;
const usedNonces = new Set();
const messageTimestamps = new Map();

function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

function createProtectedMessage(message, key) {
  const nonce = generateNonce();
  const timestamp = Date.now();
  const sequenceNumber = ++nonceCounter;
  
  const messageData = {
    message,
    nonce,
    timestamp,
    sequenceNumber
  };
  
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(JSON.stringify(messageData), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    nonce,
    timestamp,
    sequenceNumber
  };
}

function verifyAndDecryptProtectedMessage(encryptedData, key) {
  // Check 1: Verify nonce hasn't been used
  if (usedNonces.has(encryptedData.nonce)) {
    throw new Error('REPLAY ATTACK DETECTED: Nonce already used!');
  }
  
  // Check 2: Verify timestamp is recent (within 5 minutes)
  const now = Date.now();
  const messageTime = encryptedData.timestamp;
  if (Math.abs(now - messageTime) > 5 * 60 * 1000) {
    throw new Error('REPLAY ATTACK DETECTED: Message timestamp expired!');
  }
  
  // Check 3: Verify sequence number is in order
  const lastSequence = messageTimestamps.get('lastSequence') || 0;
  if (encryptedData.sequenceNumber <= lastSequence) {
    throw new Error('REPLAY ATTACK DETECTED: Sequence number out of order!');
  }
  
  // Decrypt
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encryptedData.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  const messageData = JSON.parse(decrypted);
  
  // Mark nonce as used
  usedNonces.add(encryptedData.nonce);
  messageTimestamps.set('lastSequence', encryptedData.sequenceNumber);
  
  return messageData.message;
}

console.log('1. Hamdan sends protected message:');
const protectedMessage = createProtectedMessage('Transfer $1000 to account 12345', sessionKey);
console.log('   Plaintext: Transfer $1000 to account 12345');
console.log('   Nonce:', protectedMessage.nonce.substring(0, 16) + '...');
console.log('   Timestamp:', new Date(protectedMessage.timestamp).toISOString());
console.log('   Sequence Number:', protectedMessage.sequenceNumber);

console.log('\n2. Zain receives and verifies:');
try {
  const decrypted = verifyAndDecryptProtectedMessage(protectedMessage, sessionKey);
  console.log('   ✅ Message verified and decrypted:', decrypted);
  console.log('   ✅ Nonce stored to prevent reuse');
} catch (error) {
  console.log('   ❌', error.message);
}

console.log('\n3. Attacker (Eve) tries to replay the same message:');
console.log('   Eve sends the same encrypted message again...');
try {
  const replayed = verifyAndDecryptProtectedMessage(protectedMessage, sessionKey);
  console.log('   Decrypted:', replayed);
} catch (error) {
  console.log('   ❌', error.message);
  console.log('   ✅ Replay attack PREVENTED!');
}

console.log('\n4. Eve tries to replay with old timestamp:');
const oldMessage = { ...protectedMessage };
oldMessage.timestamp = Date.now() - 10 * 60 * 1000; // 10 minutes ago
try {
  const replayed = verifyAndDecryptProtectedMessage(oldMessage, sessionKey);
  console.log('   Decrypted:', replayed);
} catch (error) {
  console.log('   ❌', error.message);
  console.log('   ✅ Timestamp check PREVENTED replay!');
}

console.log('\n5. Eve tries to replay with out-of-order sequence number:');
const outOfOrderMessage = { ...protectedMessage };
outOfOrderMessage.nonce = generateNonce(); // New nonce
outOfOrderMessage.sequenceNumber = 0; // Lower than last sequence
try {
  const replayed = verifyAndDecryptProtectedMessage(outOfOrderMessage, sessionKey);
  console.log('   Decrypted:', replayed);
} catch (error) {
  console.log('   ❌', error.message);
  console.log('   ✅ Sequence number check PREVENTED replay!');
}

console.log('\n' + '='.repeat(60));
console.log('CONCLUSION');
console.log('='.repeat(60));
console.log('Replay attacks are prevented by:');
console.log('1. Nonces: Each message has a unique nonce that cannot be reused');
console.log('2. Timestamps: Messages expire after a time window (e.g., 5 minutes)');
console.log('3. Sequence Numbers: Messages must be in order');
console.log('4. Server-side checks: Server verifies all three before processing');
console.log('='.repeat(60));

