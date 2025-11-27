# Key Exchange Protocol Specification

## Overview

This document describes the custom ECDH-based key exchange protocol with digital signatures used in the Secure E2EE Messaging System.

## Protocol Goals

1. Establish a shared secret between two parties
2. Prevent Man-in-the-Middle (MITM) attacks
3. Ensure authenticity of key exchange messages
4. Derive a session key for message encryption

## Cryptographic Primitives

- **Asymmetric Encryption**: RSA-2048 with OAEP padding
- **Key Exchange**: ECDH over P-256 curve
- **Digital Signatures**: RSA-PSS with SHA-256
- **Key Derivation**: HKDF with SHA-256
- **Symmetric Encryption**: AES-256-GCM

## Protocol Flow

### Phase 1: Key Exchange Initiation

**Initiator (Alice) → Server → Responder (Bob)**

1. **Alice generates ephemeral ECDH key pair**
   ```
   ecdhKeyPair = generateECDHKeyPair('P-256')
   ```

2. **Alice creates initiation message**
   ```json
   {
     "type": "key-exchange-init",
     "initiatorId": "alice_user_id",
     "responderId": "bob_user_id",
     "ecdhPublicKey": <ECDH public key in JWK format>,
     "timestamp": 1234567890,
     "nonce": "random_32_byte_nonce"
   }
   ```

3. **Alice signs the message**
   ```
   signature = RSA-PSS-Sign(
     privateKey: alice_rsa_private_key,
     message: JSON.stringify(initMessage),
     saltLength: 32
   )
   ```

4. **Alice sends to server**
   ```
   POST /api/key-exchange/initiate
   {
     "responderId": "bob_user_id",
     "ecdhPublicKey": <JWK>,
     "timestamp": 1234567890,
     "nonce": "random_nonce",
     "signature": <base64_signature>
   }
   ```

5. **Server stores key exchange request**

### Phase 2: Key Exchange Response

**Responder (Bob) → Server → Initiator (Alice)**

1. **Bob retrieves pending key exchange**

2. **Bob verifies Alice's signature**
   ```
   isValid = RSA-PSS-Verify(
     publicKey: alice_rsa_public_key,
     message: original_message,
     signature: alice_signature
   )
   ```
   - If invalid, reject key exchange

3. **Bob checks timestamp**
   ```
   if (currentTime - messageTimestamp > 5 minutes) {
     reject("Message expired");
   }
   ```

4. **Bob generates ephemeral ECDH key pair**
   ```
   ecdhKeyPair = generateECDHKeyPair('P-256')
   ```

5. **Bob derives shared secret**
   ```
   sharedSecret = ECDH-Derive(
     privateKey: bob_ecdh_private_key,
     publicKey: alice_ecdh_public_key
   )
   ```

6. **Bob generates random salt**
   ```
   salt = randomBytes(32)
   ```

7. **Bob derives session key using HKDF**
   ```
   sessionKey = HKDF-Derive(
     inputKeyMaterial: sharedSecret,
     salt: salt,
     info: "E2EE-Session-Key",
     hash: SHA-256,
     length: 256 bits
   )
   ```

8. **Bob creates response message**
   ```json
   {
     "type": "key-exchange-response",
     "initiatorId": "alice_user_id",
     "responderId": "bob_user_id",
     "ecdhPublicKey": <Bob's ECDH public key in JWK>,
     "timestamp": 1234567891,
     "nonce": "random_32_byte_nonce",
     "initNonce": <Alice's nonce from init>,
     "salt": <hex_encoded_salt>
   }
   ```

9. **Bob signs the response**
   ```
   signature = RSA-PSS-Sign(
     privateKey: bob_rsa_private_key,
     message: JSON.stringify(responseMessage),
     saltLength: 32
   )
   ```

10. **Bob sends to server**
    ```
    POST /api/key-exchange/respond
    {
      "keyExchangeId": "exchange_id",
      "ecdhPublicKey": <JWK>,
      "timestamp": 1234567891,
      "nonce": "random_nonce",
      "initNonce": <alice_nonce>,
      "signature": <base64_signature>,
      "salt": <hex_salt>
    }
    ```

### Phase 3: Key Exchange Completion

**Initiator (Alice) receives response**

1. **Alice retrieves key exchange response**

2. **Alice verifies Bob's signature**
   ```
   isValid = RSA-PSS-Verify(
     publicKey: bob_rsa_public_key,
     message: response_message,
     signature: bob_signature
   )
   ```

3. **Alice checks timestamp**
   ```
   if (currentTime - responseTimestamp > 5 minutes) {
     reject("Response expired");
   }
   ```

4. **Alice derives shared secret**
   ```
   sharedSecret = ECDH-Derive(
     privateKey: alice_ecdh_private_key,
     publicKey: bob_ecdh_public_key
   )
   ```

5. **Alice derives session key using same HKDF parameters**
   ```
   sessionKey = HKDF-Derive(
     inputKeyMaterial: sharedSecret,
     salt: <salt_from_bob>,
     info: "E2EE-Session-Key",
     hash: SHA-256,
     length: 256 bits
   )
   ```

6. **Alice stores session key locally**
   - Store in localStorage with user ID as key
   - Session key in JWK format

## Message Flow Diagram

```
Alice                          Server                          Bob
  |                              |                              |
  |--[1] Initiate Key Exchange-->|                              |
  |                              |--[2] Store Request---------->|
  |                              |                              |
  |                              |<--[3] Retrieve Request-------|
  |                              |                              |
  |                              |<--[4] Respond----------------|
  |                              |                              |
  |<--[5] Get Response-----------|                              |
  |                              |                              |
  |[6] Derive Session Key        |                              |[6] Derive Session Key
  |                              |                              |
```

## Security Properties

### 1. Authenticity
- **Mechanism**: RSA-PSS digital signatures
- **Protection**: Prevents MITM attacks
- **Verification**: Both parties verify signatures before accepting keys

### 2. Integrity
- **Mechanism**: Digital signatures + AES-GCM authentication tags
- **Protection**: Detects tampering of key exchange messages
- **Verification**: Signature verification fails if message is modified

### 3. Replay Protection
- **Mechanism**: Nonces + Timestamps
- **Protection**: Prevents reuse of old key exchange messages
- **Verification**: Timestamp checked (5-minute window), nonces must be unique

### 4. Forward Secrecy (Partial)
- **Mechanism**: Ephemeral ECDH keys
- **Protection**: Each session uses new key pair
- **Limitation**: If long-term RSA keys are compromised, past sessions can be decrypted

### 5. Confidentiality
- **Mechanism**: ECDH key exchange + HKDF
- **Protection**: Shared secret known only to Alice and Bob
- **Verification**: Server never sees shared secret or session key

## Implementation Details

### Key Storage
- **RSA Keys**: Generated on registration, stored in IndexedDB
- **ECDH Keys**: Generated per session, stored temporarily
- **Session Keys**: Derived client-side, stored in localStorage

### Error Handling
- Invalid signature → Reject key exchange
- Expired timestamp → Reject key exchange
- Duplicate nonce → Reject key exchange
- Network errors → Retry with exponential backoff

### Logging
- Key exchange initiation logged
- Key exchange completion logged
- Failed key exchanges logged with reason
- Replay attack attempts logged

## Attack Mitigations

### MITM Attack
- **Attack**: Attacker intercepts and replaces ECDH public keys
- **Mitigation**: Digital signatures prevent key replacement
- **Result**: Attacker cannot forge valid signatures without RSA private key

### Replay Attack
- **Attack**: Attacker replays old key exchange message
- **Mitigation**: Timestamps + nonces prevent reuse
- **Result**: Old messages rejected due to expired timestamp

### Key Compromise
- **Attack**: Attacker steals long-term RSA private key
- **Mitigation**: Ephemeral ECDH keys provide partial forward secrecy
- **Limitation**: Past sessions can be decrypted if RSA key is compromised

## Protocol Variants

This is a custom variant that combines:
- ECDH for key exchange (efficient, forward-secret)
- RSA signatures for authentication (proven, widely supported)
- HKDF for key derivation (standard, secure)

Alternative approaches considered:
- Pure RSA key exchange (slower, no forward secrecy)
- Pure ECDH with ECDSA signatures (more efficient, but less widely supported)
- Signal Protocol (too complex for this project scope)

## Testing

### Unit Tests
- Key generation
- Signature creation/verification
- Shared secret derivation
- Session key derivation

### Integration Tests
- Full key exchange flow
- Error handling
- Replay attack prevention
- MITM attack prevention

### Attack Demonstrations
- MITM attack script (shows failure without signatures)
- Replay attack script (shows prevention mechanisms)

