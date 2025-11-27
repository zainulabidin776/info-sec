# Threat Modeling - STRIDE Analysis

## System Overview
Secure End-to-End Encrypted Messaging & File-Sharing System

## STRIDE Threat Model

### S - Spoofing Identity

**Threat**: An attacker impersonates a legitimate user to gain unauthorized access.

**Vulnerable Components**:
- User authentication endpoints
- Key exchange protocol
- Message sending endpoints

**Attack Scenarios**:
1. Attacker steals or guesses user credentials
2. Attacker intercepts and replays authentication tokens
3. Attacker performs MITM during key exchange

**Countermeasures Implemented**:
- ✅ Password hashing with bcrypt (12 rounds)
- ✅ JWT tokens with expiration
- ✅ Digital signatures in key exchange protocol
- ✅ RSA-PSS signatures for key exchange messages
- ✅ Public key verification before establishing session

**Evidence**:
- Passwords stored as bcrypt hashes (never plaintext)
- Key exchange requires valid RSA signature verification
- JWT tokens expire after 7 days

---

### T - Tampering with Data

**Threat**: An attacker modifies data in transit or at rest.

**Vulnerable Components**:
- Network communication
- Stored encrypted messages
- File uploads/downloads
- Key exchange messages

**Attack Scenarios**:
1. Attacker modifies encrypted messages in transit
2. Attacker modifies key exchange messages
3. Attacker modifies stored files

**Countermeasures Implemented**:
- ✅ AES-GCM provides authentication tag (MAC) for integrity
- ✅ Digital signatures on key exchange messages
- ✅ Message authentication tags (authTag) verified on decryption
- ✅ HTTPS for all communications
- ✅ Server-side nonce uniqueness checks

**Evidence**:
- All messages encrypted with AES-256-GCM (includes authentication)
- Key exchange messages signed with RSA-PSS
- Decryption fails if message is tampered (authTag verification)

---

### R - Repudiation

**Threat**: A user denies performing an action.

**Vulnerable Components**:
- Message sending
- File uploads
- Key exchange initiation

**Attack Scenarios**:
1. User denies sending a message
2. User denies uploading a file
3. User denies initiating key exchange

**Countermeasures Implemented**:
- ✅ Digital signatures provide non-repudiation
- ✅ Server-side logging of all security events
- ✅ Message timestamps and sequence numbers
- ✅ Key exchange signatures stored in database

**Evidence**:
- All key exchange messages signed with RSA-PSS
- Security logs record all actions with timestamps
- Messages include sender ID and timestamp

---

### I - Information Disclosure

**Threat**: Sensitive information is exposed to unauthorized parties.

**Vulnerable Components**:
- Message content
- File content
- Private keys
- Session keys
- User credentials

**Attack Scenarios**:
1. Attacker intercepts encrypted messages
2. Attacker gains access to server database
3. Attacker steals private keys from client
4. Attacker performs side-channel attacks

**Countermeasures Implemented**:
- ✅ End-to-end encryption (server never sees plaintext)
- ✅ Private keys stored only on client (IndexedDB)
- ✅ Session keys derived client-side only
- ✅ Passwords hashed with bcrypt
- ✅ HTTPS for all communications
- ✅ No plaintext logging

**Evidence**:
- Server stores only ciphertext, IV, and authTag
- Private keys never transmitted to server
- Session keys derived using HKDF from ECDH shared secret
- Security logs contain no plaintext message content

---

### D - Denial of Service

**Threat**: System becomes unavailable or unusable.

**Vulnerable Components**:
- Server endpoints
- Database
- File storage
- Key exchange process

**Attack Scenarios**:
1. Attacker floods server with requests
2. Attacker exhausts database connections
3. Attacker uploads large files to fill storage
4. Attacker initiates many key exchanges

**Countermeasures Implemented**:
- ✅ File size limits (100MB per file)
- ✅ Rate limiting on authentication endpoints
- ✅ Database connection pooling
- ✅ Input validation and sanitization
- ✅ Request timeout handling

**Evidence**:
- Multer configured with 100MB file size limit
- Express body parser limits (50MB)
- MongoDB connection pooling enabled

---

### E - Elevation of Privilege

**Threat**: An attacker gains elevated privileges or access.

**Vulnerable Components**:
- Authentication system
- Authorization middleware
- Key exchange protocol
- Message access control

**Attack Scenarios**:
1. Attacker bypasses authentication
2. Attacker accesses other users' messages
3. Attacker performs unauthorized key exchange
4. Attacker gains admin privileges

**Countermeasures Implemented**:
- ✅ JWT token verification on all protected routes
- ✅ User ID verification in message/file access
- ✅ Key exchange requires valid authentication
- ✅ Message access restricted to sender/recipient
- ✅ File access restricted to authorized users

**Evidence**:
- All routes protected with `authenticate` middleware
- Message queries filter by senderId/recipientId
- Key exchange requires valid JWT token
- File downloads verify user authorization

---

## Threat Mapping to Implemented Defenses

| Threat | Component | Defense | Status |
|--------|-----------|---------|--------|
| Spoofing | Authentication | bcrypt + JWT | ✅ Implemented |
| Spoofing | Key Exchange | RSA-PSS Signatures | ✅ Implemented |
| Tampering | Messages | AES-GCM authTag | ✅ Implemented |
| Tampering | Key Exchange | RSA-PSS Signatures | ✅ Implemented |
| Repudiation | All Actions | Digital Signatures + Logging | ✅ Implemented |
| Information Disclosure | Messages | E2EE (AES-256-GCM) | ✅ Implemented |
| Information Disclosure | Keys | Client-side storage only | ✅ Implemented |
| Denial of Service | File Upload | Size limits | ✅ Implemented |
| Elevation of Privilege | Access Control | JWT + User verification | ✅ Implemented |

---

## Additional Security Considerations

### Key Management
- ✅ Private keys never leave client device
- ✅ Session keys derived using HKDF
- ✅ Keys stored in IndexedDB (browser sandbox)
- ⚠️  No key rotation mechanism (future improvement)

### Replay Protection
- ✅ Nonces for message uniqueness
- ✅ Timestamps for expiration
- ✅ Sequence numbers for ordering
- ✅ Server-side nonce tracking

### MITM Protection
- ✅ Digital signatures in key exchange
- ✅ Public key verification
- ✅ HTTPS for transport security
- ⚠️  No certificate pinning (future improvement)

### Logging and Auditing
- ✅ Security event logging
- ✅ Failed authentication attempts logged
- ✅ Replay attack detection logged
- ✅ Key exchange events logged
- ⚠️  No log rotation policy (future improvement)

---

## Risk Assessment

### High Risk (Mitigated)
- ✅ Message interception → E2EE encryption
- ✅ Key theft → Client-side storage only
- ✅ MITM attacks → Digital signatures

### Medium Risk (Mitigated)
- ✅ Replay attacks → Nonces + timestamps + sequence numbers
- ✅ Authentication bypass → JWT verification
- ✅ Data tampering → AES-GCM authentication

### Low Risk (Mitigated)
- ✅ DoS attacks → Rate limiting + size limits
- ✅ Information leakage → No plaintext storage

---

## Future Improvements

1. **Key Rotation**: Implement periodic key rotation
2. **Certificate Pinning**: Add certificate pinning for HTTPS
3. **2FA**: Implement two-factor authentication
4. **Forward Secrecy**: Implement forward secrecy with ephemeral keys
5. **Log Rotation**: Implement automated log rotation
6. **Rate Limiting**: Enhanced rate limiting on all endpoints
7. **Intrusion Detection**: Automated detection of suspicious patterns

