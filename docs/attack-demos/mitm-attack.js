/**
 * MITM Attack Demonstration Script
 * 
 * This script demonstrates how a Man-in-the-Middle attack can break
 * a key exchange protocol that doesn't use digital signatures.
 * 
 * It also shows how digital signatures prevent MITM attacks.
 */

const crypto = require('crypto');

console.log('='.repeat(60));
console.log('MITM ATTACK DEMONSTRATION');
console.log('='.repeat(60));
console.log();

// Simulate a key exchange WITHOUT signatures (vulnerable)
console.log('SCENARIO 1: Key Exchange WITHOUT Digital Signatures');
console.log('-'.repeat(60));

// Alice and Bob want to establish a shared secret
const alicePrivateKey = crypto.createECDH('prime256v1');
alicePrivateKey.generateKeys();

const bobPrivateKey = crypto.createECDH('prime256v1');
bobPrivateKey.generateKeys();

// Attacker (Mallory) intercepts the communication
const malloryPrivateKey = crypto.createECDH('prime256v1');
malloryPrivateKey.generateKeys();

console.log('1. Alice generates her ECDH key pair');
console.log('   Alice Public Key:', alicePrivateKey.getPublicKey('hex').substring(0, 32) + '...');

console.log('\n2. Alice sends her public key to Bob');
console.log('   ⚠️  Mallory intercepts the message!');

console.log('\n3. Mallory performs MITM attack:');
console.log('   - Mallory receives Alice\'s public key');
console.log('   - Mallory sends HER OWN public key to Bob (pretending to be Alice)');
console.log('   - Mallory sends HER OWN public key to Alice (pretending to be Bob)');

// Mallory intercepts and replaces keys
const malloryPublicKeyToBob = malloryPrivateKey.getPublicKey();
const malloryPublicKeyToAlice = malloryPrivateKey.getPublicKey();

console.log('\n4. Key Exchange Results:');
const aliceSharedSecret = alicePrivateKey.computeSecret(malloryPublicKeyToAlice);
const bobSharedSecret = bobPrivateKey.computeSecret(malloryPublicKeyToBob);
const mallorySharedSecretWithAlice = malloryPrivateKey.computeSecret(alicePrivateKey.getPublicKey());
const mallorySharedSecretWithBob = malloryPrivateKey.computeSecret(bobPrivateKey.getPublicKey());

console.log('   Alice thinks she shares secret with Bob:', aliceSharedSecret.toString('hex').substring(0, 16) + '...');
console.log('   Bob thinks he shares secret with Alice:', bobSharedSecret.toString('hex').substring(0, 16) + '...');
console.log('   ❌ Alice and Bob have DIFFERENT shared secrets!');
console.log('   ✅ Mallory can decrypt and read all messages!');
console.log('   Mallory-Alice secret:', mallorySharedSecretWithAlice.toString('hex').substring(0, 16) + '...');
console.log('   Mallory-Bob secret:', mallorySharedSecretWithBob.toString('hex').substring(0, 16) + '...');

console.log('\n' + '='.repeat(60));
console.log('SCENARIO 2: Key Exchange WITH Digital Signatures (Protected)');
console.log('-'.repeat(60));

// Now with digital signatures
const { generateKeyPairSync } = require('crypto');

// Alice and Bob have RSA key pairs for signing
const aliceRSAKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const bobRSAKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const malloryRSAKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });

console.log('1. Alice generates ECDH key pair and signs it with her RSA private key');
const aliceECDHKey = crypto.createECDH('prime256v1');
aliceECDHKey.generateKeys();

const aliceMessage = JSON.stringify({
  publicKey: aliceECDHKey.getPublicKey('hex'),
  timestamp: Date.now(),
  from: 'alice',
  to: 'bob'
});

const aliceSignature = crypto.sign('SHA256', Buffer.from(aliceMessage), aliceRSAKeys.privateKey);

console.log('   Alice\'s message:', aliceMessage.substring(0, 50) + '...');
console.log('   Alice\'s signature:', aliceSignature.toString('hex').substring(0, 32) + '...');

console.log('\n2. Mallory intercepts and tries to replace the message');
console.log('   Mallory creates fake message with her own ECDH key');
const malloryECDHKey = crypto.createECDH('prime256v1');
malloryECDHKey.generateKeys();

const malloryFakeMessage = JSON.stringify({
  publicKey: malloryECDHKey.getPublicKey('hex'),
  timestamp: Date.now(),
  from: 'alice',
  to: 'bob'
});

// Mallory tries to sign with her own key (but Bob will verify with Alice's public key)
const malloryFakeSignature = crypto.sign('SHA256', Buffer.from(malloryFakeMessage), malloryRSAKeys.privateKey);

console.log('\n3. Bob receives the message and verifies the signature');
console.log('   Bob verifies signature with Alice\'s RSA public key...');

const isValidAliceSignature = crypto.verify(
  'SHA256',
  Buffer.from(aliceMessage),
  aliceRSAKeys.publicKey,
  aliceSignature
);

const isValidMalloryFakeSignature = crypto.verify(
  'SHA256',
  Buffer.from(malloryFakeMessage),
  aliceRSAKeys.publicKey, // Bob uses Alice's public key
  malloryFakeSignature
);

console.log('   ✅ Alice\'s original message signature is valid:', isValidAliceSignature);
console.log('   ❌ Mallory\'s fake message signature is INVALID:', isValidMalloryFakeSignature);

console.log('\n4. Result:');
console.log('   ✅ MITM attack PREVENTED!');
console.log('   ✅ Bob detects that the signature doesn\'t match');
console.log('   ✅ Bob rejects the fake message');
console.log('   ✅ Mallory cannot successfully perform MITM attack');

console.log('\n' + '='.repeat(60));
console.log('CONCLUSION');
console.log('='.repeat(60));
console.log('Digital signatures prevent MITM attacks by:');
console.log('1. Authenticating the sender of the key exchange message');
console.log('2. Ensuring message integrity (any tampering invalidates the signature)');
console.log('3. Providing non-repudiation (sender cannot deny sending the message)');
console.log('='.repeat(60));

