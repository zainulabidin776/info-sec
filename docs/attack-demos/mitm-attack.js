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

// Hamdan and Zain want to establish a shared secret
const HamdanPrivateKey = crypto.createECDH('prime256v1');
HamdanPrivateKey.generateKeys();

const ZainPrivateKey = crypto.createECDH('prime256v1');
ZainPrivateKey.generateKeys();

// Attacker (Mallory) intercepts the communication
const malloryPrivateKey = crypto.createECDH('prime256v1');
malloryPrivateKey.generateKeys();

console.log('1. Hamdan generates her ECDH key pair');
console.log('   Hamdan Public Key:', HamdanPrivateKey.getPublicKey('hex').substring(0, 32) + '...');

console.log('\n2. Hamdan sends her public key to Zain');
console.log('   ⚠️  Mallory intercepts the message!');

console.log('\n3. Mallory performs MITM attack:');
console.log('   - Mallory receives Hamdan\'s public key');
console.log('   - Mallory sends HER OWN public key to Zain (pretending to be Hamdan)');
console.log('   - Mallory sends HER OWN public key to Hamdan (pretending to be Zain)');

// Mallory intercepts and replaces keys
const malloryPublicKeyToZain = malloryPrivateKey.getPublicKey();
const malloryPublicKeyToHamdan = malloryPrivateKey.getPublicKey();

console.log('\n4. Key Exchange Results:');
const HamdanSharedSecret = HamdanPrivateKey.computeSecret(malloryPublicKeyToHamdan);
const ZainSharedSecret = ZainPrivateKey.computeSecret(malloryPublicKeyToZain);
const mallorySharedSecretWithHamdan = malloryPrivateKey.computeSecret(HamdanPrivateKey.getPublicKey());
const mallorySharedSecretWithZain = malloryPrivateKey.computeSecret(ZainPrivateKey.getPublicKey());

console.log('   Hamdan thinks she shares secret with Zain:', HamdanSharedSecret.toString('hex').substring(0, 16) + '...');
console.log('   Zain thinks he shares secret with Hamdan:', ZainSharedSecret.toString('hex').substring(0, 16) + '...');
console.log('   ❌ Hamdan and Zain have DIFFERENT shared secrets!');
console.log('   ✅ Mallory can decrypt and read all messages!');
console.log('   Mallory-Hamdan secret:', mallorySharedSecretWithHamdan.toString('hex').substring(0, 16) + '...');
console.log('   Mallory-Zain secret:', mallorySharedSecretWithZain.toString('hex').substring(0, 16) + '...');

console.log('\n' + '='.repeat(60));
console.log('SCENARIO 2: Key Exchange WITH Digital Signatures (Protected)');
console.log('-'.repeat(60));

// Now with digital signatures
const { generateKeyPairSync } = require('crypto');

// Hamdan and Zain have RSA key pairs for signing
const HamdanRSAKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ZainRSAKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const malloryRSAKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });

console.log('1. Hamdan generates ECDH key pair and signs it with her RSA private key');
const HamdanECDHKey = crypto.createECDH('prime256v1');
HamdanECDHKey.generateKeys();

const HamdanMessage = JSON.stringify({
  publicKey: HamdanECDHKey.getPublicKey('hex'),
  timestamp: Date.now(),
  from: 'Hamdan',
  to: 'Zain'
});

const HamdanSignature = crypto.sign('SHA256', Buffer.from(HamdanMessage), HamdanRSAKeys.privateKey);

console.log('   Hamdan\'s message:', HamdanMessage.substring(0, 50) + '...');
console.log('   Hamdan\'s signature:', HamdanSignature.toString('hex').substring(0, 32) + '...');

console.log('\n2. Mallory intercepts and tries to replace the message');
console.log('   Mallory creates fake message with her own ECDH key');
const malloryECDHKey = crypto.createECDH('prime256v1');
malloryECDHKey.generateKeys();

const malloryFakeMessage = JSON.stringify({
  publicKey: malloryECDHKey.getPublicKey('hex'),
  timestamp: Date.now(),
  from: 'Hamdan',
  to: 'Zain'
});

// Mallory tries to sign with her own key (but Zain will verify with Hamdan's public key)
const malloryFakeSignature = crypto.sign('SHA256', Buffer.from(malloryFakeMessage), malloryRSAKeys.privateKey);

console.log('\n3. Zain receives the message and verifies the signature');
console.log('   Zain verifies signature with Hamdan\'s RSA public key...');

const isValidHamdanSignature = crypto.verify(
  'SHA256',
  Buffer.from(HamdanMessage),
  HamdanRSAKeys.publicKey,
  HamdanSignature
);

const isValidMalloryFakeSignature = crypto.verify(
  'SHA256',
  Buffer.from(malloryFakeMessage),
  HamdanRSAKeys.publicKey, // Zain uses Hamdan's public key
  malloryFakeSignature
);

console.log('   ✅ Hamdan\'s original message signature is valid:', isValidHamdanSignature);
console.log('   ❌ Mallory\'s fake message signature is INVALID:', isValidMalloryFakeSignature);

console.log('\n4. Result:');
console.log('   ✅ MITM attack PREVENTED!');
console.log('   ✅ Zain detects that the signature doesn\'t match');
console.log('   ✅ Zain rejects the fake message');
console.log('   ✅ Mallory cannot successfully perform MITM attack');

console.log('\n' + '='.repeat(60));
console.log('CONCLUSION');
console.log('='.repeat(60));
console.log('Digital signatures prevent MITM attacks by:');
console.log('1. Authenticating the sender of the key exchange message');
console.log('2. Ensuring message integrity (any tampering invalidates the signature)');
console.log('3. Providing non-repudiation (sender cannot deny sending the message)');
console.log('='.repeat(60));

