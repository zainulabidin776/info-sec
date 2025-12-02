# Requirements Traceability Matrix

## Document Information
- **Project**: Secure End-to-End Encrypted Messaging & File-Sharing System
- **Course**: Information Security - BSSE (7th Semester)
- **Last Updated**: December 2, 2025

## How to Use This Matrix
Each requirement is mapped to:
- **Requirement ID**: Unique identifier
- **Implementation File(s)**: Exact file path(s)
- **Function/Component**: Specific function or component name
- **Line Numbers**: Approximate line numbers (may shift with edits)
- **Verification Method**: How to verify the implementation

---

## 1. FUNCTIONAL REQUIREMENTS

### 1.1 User Authentication

| Req ID | Requirement | Implementation Location | Function/Component | Lines | Verification |
|--------|-------------|------------------------|-------------------|-------|--------------|
| FR-1.1.1 | User Registration | `server/routes/auth.js` | `router.post('/register')` | 11-78 | Register new user via UI or API |
| FR-1.1.2 | Username Validation | `server/routes/auth.js` | Express validator middleware | 12-15 | Try invalid usernames |
| FR-1.1.3 | Password Validation | `server/routes/auth.js` | Express validator | 13 | Try short passwords |
| FR-1.1.4 | Password Hashing (bcrypt) | `server/routes/auth.js` | `bcrypt.hash()` | 39-40 | Check DB - passwords are hashed |
| FR-1.1.5 | Salt Rounds (12) | `server/routes/auth.js` | `saltRounds = 12` | 39 | Verify constant value |
| FR-1.1.6 | User Login | `server/routes/auth.js` | `router.post('/login')` | 80-155 | Login via UI |
| FR-1.1.7 | Password Verification | `server/routes/auth.js` | `bcrypt.compare()` | 101-103 | Login with wrong password |
| FR-1.1.8 | JWT Token Generation | `server/routes/auth.js` | `jwt.sign()` | 108-112 | Check token in localStorage |
| FR-1.1.9 | JWT Token Validation | `server/middleware/auth.js` | `authenticate` middleware | 8-33 | Access protected route |
| FR-1.1.10 | Token Expiration (7 days) | `server/routes/auth.js` | JWT options | 111 | Wait 7 days or modify |
| FR-1.1.11 | User Model Schema | `server/models/User.js` | `userSchema` | 3-41 | Check MongoDB schema |
| FR-1.1.12 | Login UI Component | `client/src/components/Login.js` | `Login` component | 1-145 | View login page |

### 1.2 Key Generation & Secure Storage

| Req ID | Requirement | Implementation Location | Function/Component | Lines | Verification |
|--------|-------------|------------------------|-------------------|-------|--------------|
| FR-1.2.1 | RSA-2048 Key Pair (Encryption) | `client/src/crypto/keyManager.js` | `generateKeyPair()` | 31-47 | Check key in IndexedDB |
| FR-1.2.2 | RSA-2048 Key Pair (Signing) | `client/src/crypto/keyManager.js` | `generateSigningKeyPair()` | 49-68 | Check key in IndexedDB |
| FR-1.2.3 | ECDH P-256 Key Pair | `client/src/crypto/keyManager.js` | `generateECDHKeyPair()` | 70-85 | Check during key exchange |
| FR-1.2.4 | Key Generation on Registration | `client/src/components/Login.js` | `handleSubmit()` register block | 43-49 | Register new user |
| FR-1.2.5 | IndexedDB Initialization | `client/src/crypto/keyManager.js` | `initDB()` | 12-28 | Check browser DevTools |
| FR-1.2.6 | Store Keys in IndexedDB | `client/src/crypto/keyManager.js` | `storeKeys()` | 274-305 | Register and check IndexedDB |
| FR-1.2.7 | Retrieve Keys from IndexedDB | `client/src/crypto/keyManager.js` | `retrieveKeys()` | 307-330 | Login and check keys loaded |
| FR-1.2.8 | Public Key Export (JWK) | `client/src/crypto/keyManager.js` | `exportPublicKey()` | 87-96 | Check server DB |
| FR-1.2.9 | Private Key Export (JWK) | `client/src/crypto/keyManager.js` | `exportPrivateKey()` | 98-107 | Check IndexedDB only |
| FR-1.2.10 | Public Key Storage on Server | `server/models/User.js` | `publicKeyJWK` field | 19-22 | Check MongoDB users collection |
| FR-1.2.11 | Signing Public Key Storage | `server/models/User.js` | `signingPublicKeyJWK` field | 24-27 | Check MongoDB users collection |
| FR-1.2.12 | Private Key Never on Server | ALL CODE | N/A | N/A | Search codebase for "privateKey" uploads |

### 1.3 Secure Key Exchange Protocol

| Req ID | Requirement | Implementation Location | Function/Component | Lines | Verification |
|--------|-------------|------------------------|-------------------|-------|--------------|
| FR-1.3.1 | ECDH Shared Secret Derivation | `client/src/crypto/keyExchange.js` | `deriveSharedSecret()` | 23-40 | Check during key exchange |
| FR-1.3.2 | RSA-PSS Signature Creation | `client/src/crypto/keyExchange.js` | `signData()` | 42-71 | Check key exchange messages |
| FR-1.3.3 | RSA-PSS Signature Verification | `client/src/crypto/keyExchange.js` | `verifySignature()` | 73-106 | Tamper with signature |
| FR-1.3.4 | Key Exchange Initiation | `client/src/crypto/keyExchange.js` | `createKeyExchangeInit()` | 108-146 | Initiate key exchange |
| FR-1.3.5 | Initiator Signature | `client/src/crypto/keyExchange.js` | Line in `createKeyExchangeInit()` | 130-131 | Check message signature |
| FR-1.3.6 | Key Exchange Response Processing | `client/src/crypto/keyExchange.js` | `processKeyExchangeInit()` | 148-237 | Respond to key exchange |
| FR-1.3.7 | Responder Signature Verification | `client/src/crypto/keyExchange.js` | Line in `processKeyExchangeInit()` | 160-171 | Invalid signature test |
| FR-1.3.8 | Timestamp Validation (5 min) | `client/src/crypto/keyExchange.js` | Line in `processKeyExchangeInit()` | 173-178 | Old message test |
| FR-1.3.9 | HKDF Key Derivation | `client/src/crypto/encryption.js` | `deriveAESKey()` | 32-64 | Check session key |
| FR-1.3.10 | Session Key Derivation | `client/src/crypto/keyExchange.js` | Line in `processKeyExchangeInit()` | 214-216 | Check derived key |
| FR-1.3.11 | Key Exchange Completion | `client/src/crypto/keyExchange.js` | `completeKeyExchange()` | 239-291 | Complete full exchange |
| FR-1.3.12 | Nonce Generation | `client/src/crypto/encryption.js` | `generateNonce()` | 19-23 | Check each message |
| FR-1.3.13 | Server Key Exchange Initiate | `server/routes/keyExchange.js` | `router.post('/initiate')` | 9-51 | POST to /api/key-exchange/initiate |
| FR-1.3.14 | Server Key Exchange Response | `server/routes/keyExchange.js` | `router.post('/respond')` | 53-107 | POST to /api/key-exchange/respond |
| FR-1.3.15 | Key Exchange Model | `server/models/KeyExchange.js` | `keyExchangeSchema` | 3-73 | Check MongoDB keyexchanges collection |
| FR-1.3.16 | UI Key Exchange Button | `client/src/components/Chat.js` | Button in render | 547 | Click "Establish Secure Connection" |
| FR-1.3.17 | Key Exchange Flow (Client) | `client/src/components/Chat.js` | `initiateKeyExchange()` | 259-305 | Initiate from UI |
| FR-1.3.18 | Key Exchange Protocol Docs | `docs/protocols/key-exchange-protocol.md` | Full document | 1-313 | Read protocol specification |

### 1.4 End-to-End Message Encryption

| Req ID | Requirement | Implementation Location | Function/Component | Lines | Verification |
|--------|-------------|------------------------|-------------------|-------|--------------|
| FR-1.4.1 | AES-256-GCM Encryption | `client/src/crypto/encryption.js` | `encryptMessage()` | 66-103 | Send message and check DB |
| FR-1.4.2 | Random IV Generation | `client/src/crypto/encryption.js` | `generateIV()` | 8-10 | Each message has unique IV |
| FR-1.4.3 | Authentication Tag Generation | `client/src/crypto/encryption.js` | Line in `encryptMessage()` | 91-92 | Check authTag in DB |
| FR-1.4.4 | AES-256-GCM Decryption | `client/src/crypto/encryption.js` | `decryptMessage()` | 105-142 | Receive and decrypt message |
| FR-1.4.5 | Auth Tag Verification | `client/src/crypto/encryption.js` | Line in `decryptMessage()` | 121-134 | Tamper with ciphertext |
| FR-1.4.6 | Message Sending (Client) | `client/src/components/Chat.js` | `sendMessage()` | 368-410 | Send message via UI |
| FR-1.4.7 | Message Encryption Before Send | `client/src/components/Chat.js` | Line in `sendMessage()` | 375-376 | Check network payload |
| FR-1.4.8 | Message Receiving (Client) | `client/src/components/Chat.js` | `handleReceiveMessage()` | 187-227 | Receive message |
| FR-1.4.9 | Message Decryption on Receive | `client/src/components/Chat.js` | Line in `handleReceiveMessage()` | 215-216 | Check decrypted content |
| FR-1.4.10 | Server Message Storage | `server/routes/messages.js` | `router.post('/')` | 8-59 | POST to /api/messages |
| FR-1.4.11 | Message Model (Ciphertext Only) | `server/models/Message.js` | `messageSchema` | 3-66 | Check MongoDB messages collection |
| FR-1.4.12 | No Plaintext on Server | `server/models/Message.js` | Absence of plaintext field | N/A | Search for "plaintext" in model |
| FR-1.4.13 | Message Metadata Storage | `server/models/Message.js` | Schema fields | 4-51 | Check DB documents |
| FR-1.4.14 | Real-time Message Delivery | `server/index.js` | Socket.io `send-message` event | 80-84 | Send message and see real-time |
| FR-1.4.15 | Message History Retrieval | `server/routes/messages.js` | `router.get('/:otherUserId')` | 61-102 | Load chat history |

### 1.5 End-to-End Encrypted File Sharing

| Req ID | Requirement | Implementation Location | Function/Component | Lines | Verification |
|--------|-------------|------------------------|-------------------|-------|--------------|
| FR-1.5.1 | Client-Side File Encryption | `client/src/crypto/encryption.js` | `encryptFile()` | 144-200 | Upload file and check |
| FR-1.5.2 | File Chunking (1MB chunks) | `client/src/crypto/encryption.js` | Line in `encryptFile()` | 148-149 | Upload large file |
| FR-1.5.3 | AES-GCM Per Chunk | `client/src/crypto/encryption.js` | Line in `encryptFile()` loop | 164-174 | Check chunk metadata |
| FR-1.5.4 | File Decryption | `client/src/crypto/encryption.js` | `decryptFile()` | 202-242 | Download and decrypt file |
| FR-1.5.5 | File Upload (Client) | `client/src/components/Chat.js` | `handleFileUpload()` | 412-470 | Click attach file |
| FR-1.5.6 | File Encryption Before Upload | `client/src/components/Chat.js` | Line in `handleFileUpload()` | 419 | Check network payload |
| FR-1.5.7 | Server File Upload Endpoint | `server/routes/files.js` | `router.post('/upload')` | 31-77 | POST to /api/files/upload |
| FR-1.5.8 | Multer Configuration | `server/routes/files.js` | `storage` configuration | 11-26 | Check upload handling |
| FR-1.5.9 | File Storage (Encrypted Only) | `server/routes/files.js` | File save logic | 53-60 | Check uploads/ directory |
| FR-1.5.10 | File Model (Metadata) | `server/models/File.js` | `fileSchema` | 1-50 | Check MongoDB files collection |
| FR-1.5.11 | File Download Endpoint | `server/routes/files.js` | `router.get('/:fileId')` | 79-122 | GET /api/files/:fileId |
| FR-1.5.12 | File Message Type | `server/models/Message.js` | `messageType` enum | 42-45 | Send file and check DB |
| FR-1.5.13 | File Reference in Message | `server/models/Message.js` | `fileId` field | 47-51 | Link file to message |

### 1.6 Replay Attack Protection

| Req ID | Requirement | Implementation Location | Function/Component | Lines | Verification |
|--------|-------------|------------------------|-------------------|-------|--------------|
| FR-1.6.1 | Nonce Generation | `client/src/crypto/encryption.js` | `generateNonce()` | 19-23 | Each message has nonce |
| FR-1.6.2 | Nonce Uniqueness (DB) | `server/models/Message.js` | `nonce` field with unique index | 32-35 | Try duplicate nonce |
| FR-1.6.3 | Nonce Duplicate Detection | `server/routes/messages.js` | Duplicate check logic | 19-27 | Send same message twice |
| FR-1.6.4 | Timestamp in Messages | `server/models/Message.js` | `timestamp` field | 37-41 | Check message timestamp |
| FR-1.6.5 | Sequence Numbers | `server/models/Message.js` | `sequenceNumber` field | 33-36 | Check incrementing sequence |
| FR-1.6.6 | Sequence Number Generation | `client/src/utils/storage.js` | `getNextSequenceNumber()` | 49-63 | Send multiple messages |
| FR-1.6.7 | Nonce Storage (Client) | `client/src/utils/storage.js` | `storeNonce()` | 87-98 | Check localStorage |
| FR-1.6.8 | Nonce Verification (Client) | `client/src/utils/storage.js` | `isNonceUsed()` | 100-116 | Check duplicate locally |
| FR-1.6.9 | Replay Attack Logging | `server/routes/messages.js` | `logSecurityEvent` calls | 22-26, 56-60 | Trigger replay attack |
| FR-1.6.10 | Replay Attack Demo Script | `docs/attack-demos/replay-attack.js` | Full script | 1-190 | Run: node replay-attack.js |
| FR-1.6.11 | Replay Protection in Key Exchange | `client/src/crypto/keyExchange.js` | Timestamp checks | 173-178, 268-273 | Old key exchange message |

### 1.7 MITM Attack Demonstration

| Req ID | Requirement | Implementation Location | Function/Component | Lines | Verification |
|--------|-------------|------------------------|-------------------|-------|--------------|
| FR-1.7.1 | MITM Attack Script | `docs/attack-demos/mitm-attack.js` | Full script | 1-138 | Run: node mitm-attack.js |
| FR-1.7.2 | MITM Without Signatures Demo | `docs/attack-demos/mitm-attack.js` | Scenario 1 | 16-53 | Read console output |
| FR-1.7.3 | MITM With Signatures Demo | `docs/attack-demos/mitm-attack.js` | Scenario 2 | 55-138 | Read console output |
| FR-1.7.4 | Signature-based MITM Prevention | `client/src/crypto/keyExchange.js` | `verifySignature()` usage | 165-171, 254-260 | Tamper with public key |
| FR-1.7.5 | Digital Signature Documentation | `docs/protocols/key-exchange-protocol.md` | Signature sections | 45-70, 95-115 | Read documentation |

### 1.8 Logging & Security Auditing

| Req ID | Requirement | Implementation Location | Function/Component | Lines | Verification |
|--------|-------------|------------------------|-------------------|-------|--------------|
| FR-1.8.1 | Winston Logger Setup | `server/utils/logger.js` | Logger configuration | 1-80 | Check logs/ directory |
| FR-1.8.2 | Security Logger | `server/utils/logger.js` | `securityLogger` | 34-42 | Check security.log |
| FR-1.8.3 | Log Helper Function | `server/utils/logger.js` | `logSecurityEvent()` | 67-73 | Call function |
| FR-1.8.4 | Authentication Logging | `server/routes/auth.js` | `logSecurityEvent` calls | 31-34, 52-56, 95-99, 123-127 | Login/register |
| FR-1.8.5 | Key Exchange Logging | `server/routes/keyExchange.js` | `logSecurityEvent` calls | 37-43, 92-97 | Perform key exchange |
| FR-1.8.6 | Message Sending Logging | `server/routes/messages.js` | `logSecurityEvent` calls | 45-50 | Send message |
| FR-1.8.7 | Replay Attack Logging | `server/routes/messages.js` | Replay detection logs | 22-26, 56-60 | Trigger replay |
| FR-1.8.8 | File Upload Logging | `server/routes/files.js` | `logSecurityEvent` calls | 61-67 | Upload file |
| FR-1.8.9 | Failed Decryption Logging | `client/src/components/Chat.js` | Console.error in catch blocks | 220-221 | Tamper with message |
| FR-1.8.10 | Log File Rotation | `server/utils/logger.js` | Winston maxsize/maxFiles config | 39-40 | Check configuration |
| FR-1.8.11 | Separate Error Logs | `server/utils/logger.js` | error.log transport | 28-30 | Trigger error |
| FR-1.8.12 | Combined Activity Logs | `server/utils/logger.js` | combined.log transport | 31-33 | Check all events |

### 1.9 Threat Modeling

| Req ID | Requirement | Implementation Location | Function/Component | Lines | Verification |
|--------|-------------|------------------------|-------------------|-------|--------------|
| FR-1.9.1 | STRIDE Analysis Document | `docs/threat-model.md` | Full document | 1-259 | Read document |
| FR-1.9.2 | Spoofing Threats | `docs/threat-model.md` | Spoofing section | 9-35 | Review threats |
| FR-1.9.3 | Tampering Threats | `docs/threat-model.md` | Tampering section | 37-65 | Review threats |
| FR-1.9.4 | Repudiation Threats | `docs/threat-model.md` | Repudiation section | 67-92 | Review threats |
| FR-1.9.5 | Information Disclosure | `docs/threat-model.md` | Info Disclosure section | 94-130 | Review threats |
| FR-1.9.6 | Denial of Service | `docs/threat-model.md` | DoS section | 132-160 | Review threats |
| FR-1.9.7 | Elevation of Privilege | `docs/threat-model.md` | EoP section | 162-185 | Review threats |
| FR-1.9.8 | Countermeasures Mapping | `docs/threat-model.md` | Each threat section | Throughout | Check implemented defenses |
| FR-1.9.9 | Vulnerability Assessment | `docs/threat-model.md` | Summary section | 187-259 | Review assessment |

### 1.10 System Architecture & Documentation

| Req ID | Requirement | Implementation Location | Function/Component | Lines | Verification |
|--------|-------------|------------------------|-------------------|-------|--------------|
| FR-1.10.1 | High-Level Architecture | `docs/architecture/system-architecture.md` | ASCII diagram | 3-46 | View diagram |
| FR-1.10.2 | Component Architecture | `docs/architecture/system-architecture.md` | Components section | 48-107 | Read components |
| FR-1.10.3 | Client-Side Flow | `docs/architecture/system-architecture.md` | Message flow diagrams | 191-281 | Follow flow |
| FR-1.10.4 | Server-Side Flow | `docs/architecture/system-architecture.md` | Server flow | 109-142 | Follow flow |
| FR-1.10.5 | Database Schema | `docs/architecture/system-architecture.md` | Schema section | 144-189 | Review schema |
| FR-1.10.6 | Deployment Architecture | `docs/architecture/system-architecture.md` | Deployment section | 283-320 | Review deployment |
| FR-1.10.7 | Security Architecture | `docs/architecture/system-architecture.md` | Security layers | 322-364 | Review security |
| FR-1.10.8 | Setup Instructions | `SETUP.md` | Full document | 1-277 | Follow setup |
| FR-1.10.9 | Project Overview | `README.md` | Full document | 1-171 | Read README |
| FR-1.10.10 | API Documentation | `docs/architecture/system-architecture.md` | API section | Throughout | Review APIs |

---

## 2. TECHNICAL REQUIREMENTS

### 2.1 Frontend Technologies

| Req ID | Requirement | Implementation Location | Evidence | Lines | Verification |
|--------|-------------|------------------------|----------|-------|--------------|
| TR-2.1.1 | React.js | `client/package.json` | "react": "^18.2.0" | 6 | Check package.json |
| TR-2.1.2 | React Components | `client/src/components/` | Chat.js, Login.js | All | View source files |
| TR-2.1.3 | Web Crypto API Usage | `client/src/crypto/` | window.crypto.subtle calls | Throughout | Search for "crypto.subtle" |
| TR-2.1.4 | SubtleCrypto for Encryption | `client/src/crypto/encryption.js` | encrypt/decrypt calls | 75-86, 121-134 | View implementation |
| TR-2.1.5 | SubtleCrypto for Key Gen | `client/src/crypto/keyManager.js` | generateKey calls | 33-44, 56-65, 73-82 | View implementation |
| TR-2.1.6 | IndexedDB for Key Storage | `client/src/crypto/keyManager.js` | indexedDB.open() | 13-28 | Check browser DevTools |
| TR-2.1.7 | IndexedDB Store Keys | `client/src/crypto/keyManager.js` | storeKeys() function | 274-305 | Register user |
| TR-2.1.8 | Axios HTTP Client | `client/src/services/api.js` | axios.create() | 5-11 | Check imports |
| TR-2.1.9 | Socket.io Client | `client/src/services/socket.js` | io() connection | 7-24 | Check imports |
| TR-2.1.10 | React Router | `client/src/App.js` | BrowserRouter, Routes | 28-69 | View routing |

### 2.2 Backend Technologies

| Req ID | Requirement | Implementation Location | Evidence | Lines | Verification |
|--------|-------------|------------------------|----------|-------|--------------|
| TR-2.2.1 | Node.js + Express | `server/package.json` | "express": "^4.18.2" | 11 | Check package.json |
| TR-2.2.2 | Express Server Setup | `server/index.js` | const app = express() | 17 | View server setup |
| TR-2.2.3 | MongoDB | `server/package.json` | "mongoose": "^7.5.0" | 12 | Check package.json |
| TR-2.2.4 | Mongoose Connection | `server/index.js` | mongoose.connect() | 43-52 | View connection |
| TR-2.2.5 | Socket.io Server | `server/package.json` | "socket.io": "^4.6.1" | 15 | Check package.json |
| TR-2.2.6 | Socket.io Setup | `server/index.js` | socketIo(server) | 20-24 | View setup |
| TR-2.2.7 | bcrypt for Passwords | `server/package.json` | "bcrypt": "^5.1.1" | 13 | Check package.json |
| TR-2.2.8 | JWT Authentication | `server/package.json` | "jsonwebtoken": "^9.0.2" | 16 | Check package.json |
| TR-2.2.9 | Winston Logging | `server/package.json` | "winston": "^3.10.0" | 20 | Check package.json |
| TR-2.2.10 | Multer File Upload | `server/package.json` | "multer": "^1.4.5-lts.1" | 18 | Check package.json |

### 2.3 Forbidden Technologies (Compliance Check)

| Req ID | Requirement | Status | Evidence | Verification |
|--------|-------------|--------|----------|--------------|
| TR-2.3.1 | No Firebase Auth | ✅ NOT USED | Search codebase | grep -r "firebase" |
| TR-2.3.2 | No Signal Library | ✅ NOT USED | package.json files | No signal dependency |
| TR-2.3.3 | No Libsodium | ✅ NOT USED | package.json files | No libsodium dependency |
| TR-2.3.4 | No OpenPGP.js | ✅ NOT USED | package.json files | No openpgp dependency |
| TR-2.3.5 | No CryptoJS (for RSA/ECC) | ✅ NOT USED | Only Web Crypto API used | Search for "CryptoJS" |
| TR-2.3.6 | No NodeForge | ✅ NOT USED | package.json files | No node-forge dependency |
| TR-2.3.7 | Only Web Crypto API | ✅ COMPLIANT | All crypto/ files | Check implementations |
| TR-2.3.8 | Node crypto (optional) | ✅ ONLY IN DEMOS | attack-demos/ only | Check server code |

---

## 3. SECURITY CONSTRAINTS

### 3.1 Development Constraints

| Req ID | Requirement | Implementation Location | Evidence | Lines | Verification |
|--------|-------------|------------------------|----------|-------|--------------|
| SC-3.1.1 | Client-Side Encryption Only | `client/src/crypto/encryption.js` | All encrypt functions | Throughout | No server-side encryption |
| SC-3.1.2 | Private Keys Never Leave Client | `client/src/crypto/keyManager.js` | storeKeys() IndexedDB only | 274-305 | Search server code |
| SC-3.1.3 | No Plaintext Logged | ALL CODE | No console.log of plaintext | N/A | Search for plaintext logs |
| SC-3.1.4 | No Plaintext Stored | `server/models/Message.js` | Only ciphertext field | 16-19 | Check schema |
| SC-3.1.5 | No Plaintext Transmitted | Network layer | HTTPS + encryption | N/A | Check network tab |
| SC-3.1.6 | HTTPS Support | `server/index.js` | Production configuration | Ready | Enable in production |
| SC-3.1.7 | 70%+ Custom Crypto Logic | `client/src/crypto/` | All functions | All files | Review implementation |

### 3.2 Cryptographic Constraints

| Req ID | Requirement | Implementation Location | Evidence | Lines | Verification |
|--------|-------------|------------------------|----------|-------|--------------|
| SC-3.2.1 | AES-256-GCM Only | `client/src/crypto/encryption.js` | Algorithm name | 77-82, 123-128 | Check algorithm param |
| SC-3.2.2 | No CBC Mode | ALL CODE | No AES-CBC usage | N/A | Search for "CBC" |
| SC-3.2.3 | No ECB Mode | ALL CODE | No AES-ECB usage | N/A | Search for "ECB" |
| SC-3.2.4 | RSA Key Size ≥2048 | `client/src/crypto/keyManager.js` | modulusLength: 2048 | 36, 55 | Check key generation |
| SC-3.2.5 | ECC P-256 Curve | `client/src/crypto/keyManager.js` | namedCurve: 'P-256' | 76 | Check ECDH params |
| SC-3.2.6 | Unpredictable IVs | `client/src/crypto/encryption.js` | crypto.getRandomValues() | 9 | Check IV generation |
| SC-3.2.7 | Non-Repeating IVs | `client/src/crypto/encryption.js` | Fresh IV per message | 69-70 | Each message unique |
| SC-3.2.8 | Signature Timestamp Check | `client/src/crypto/keyExchange.js` | Timestamp validation | 173-178, 268-273 | Old message test |
| SC-3.2.9 | Auth Tag Verification | `client/src/crypto/encryption.js` | GCM tag check | 121-134 | Tamper test |
| SC-3.2.10 | 128-bit Auth Tag | `client/src/crypto/encryption.js` | tagLength: 128 | 79, 125 | Check parameter |

---

## 4. CRYPTOGRAPHIC PRIMITIVES REFERENCE

| Primitive | Algorithm/Size | Implementation | Location | Line | Usage |
|-----------|---------------|----------------|----------|------|-------|
| Asymmetric Encryption | RSA-2048 OAEP | Web Crypto API | `keyManager.js` | 31-47 | User key pair |
| Digital Signatures | RSA-2048 PSS | Web Crypto API | `keyManager.js` | 49-68 | Signing key pair |
| Key Exchange | ECDH P-256 | Web Crypto API | `keyManager.js` | 70-85 | Session establishment |
| Symmetric Encryption | AES-256-GCM | Web Crypto API | `encryption.js` | 66-142 | Message/file encryption |
| Key Derivation | HKDF-SHA256 | Web Crypto API | `encryption.js` | 32-64 | Session key derivation |
| Hash Function | SHA-256 | Web Crypto API | Various | Throughout | Signatures, HKDF |
| Random Generation | CSPRNG | crypto.getRandomValues | `encryption.js` | 9, 20 | IVs, nonces |

---

## 5. ATTACK DEMONSTRATIONS

| Attack Type | Demo File | Function/Section | Lines | How to Run | Expected Output |
|-------------|-----------|------------------|-------|------------|-----------------|
| MITM - Without Signatures | `docs/attack-demos/mitm-attack.js` | Scenario 1 | 16-53 | `node mitm-attack.js` | Attack succeeds |
| MITM - With Signatures | `docs/attack-demos/mitm-attack.js` | Scenario 2 | 55-138 | `node mitm-attack.js` | Attack fails |
| Replay - Without Protection | `docs/attack-demos/replay-attack.js` | Scenario 1 | 16-59 | `node replay-attack.js` | Attack succeeds |
| Replay - With Protection | `docs/attack-demos/replay-attack.js` | Scenario 2 | 61-135 | `node replay-attack.js` | Attack detected |
| Replay Detection (Server) | `server/routes/messages.js` | Nonce check | 19-27 | Send duplicate message | 400 error logged |
| Signature Verification | `client/src/crypto/keyExchange.js` | verifySignature() | 165-171 | Tamper with key exchange | Verification fails |
| Timestamp Validation | `client/src/crypto/keyExchange.js` | Timestamp check | 173-178 | Old message replay | Rejected as expired |

---

## 6. DATABASE SCHEMA REFERENCE

### Users Collection
| Field | Type | Location | Purpose | Line |
|-------|------|----------|---------|------|
| username | String | `server/models/User.js` | User identifier | 4-10 |
| passwordHash | String | `server/models/User.js` | Hashed password | 11-14 |
| publicKeyJWK | Object | `server/models/User.js` | RSA public key (encryption) | 19-22 |
| signingPublicKeyJWK | Object | `server/models/User.js` | RSA public key (signing) | 24-27 |

### Messages Collection
| Field | Type | Location | Purpose | Line |
|-------|------|----------|---------|------|
| ciphertext | String | `server/models/Message.js` | Encrypted message | 16-19 |
| iv | String | `server/models/Message.js` | Initialization vector | 20-23 |
| authTag | String | `server/models/Message.js` | Authentication tag | 24-27 |
| nonce | String (unique) | `server/models/Message.js` | Replay protection | 29-33 |
| sequenceNumber | Number | `server/models/Message.js` | Message ordering | 34-37 |

### KeyExchange Collection
| Field | Type | Location | Purpose | Line |
|-------|------|----------|---------|------|
| initiatorECDHPublicKey | Object | `server/models/KeyExchange.js` | Initiator's ephemeral key | 15-18 |
| responderECDHPublicKey | Object | `server/models/KeyExchange.js` | Responder's ephemeral key | 19-22 |
| initiatorSignature | String | `server/models/KeyExchange.js` | MITM prevention | 23-26 |
| responderSignature | String | `server/models/KeyExchange.js` | MITM prevention | 27-30 |

### Files Collection
| Field | Type | Location | Purpose | Line |
|-------|------|----------|---------|------|
| filePath | String | `server/models/File.js` | Encrypted file location | ~15 |
| iv | String | `server/models/File.js` | File encryption IV | ~20 |
| chunks | Array | `server/models/File.js` | Chunk metadata | ~25 |

---

## 7. API ENDPOINTS REFERENCE

| Endpoint | Method | File | Function | Line | Purpose |
|----------|--------|------|----------|------|---------|
| /api/auth/register | POST | `server/routes/auth.js` | router.post('/register') | 11 | User registration |
| /api/auth/login | POST | `server/routes/auth.js` | router.post('/login') | 80 | User authentication |
| /api/users | GET | `server/routes/users.js` | router.get('/') | ~10 | Get all users |
| /api/messages | POST | `server/routes/messages.js` | router.post('/') | 8 | Send encrypted message |
| /api/messages/:userId | GET | `server/routes/messages.js` | router.get('/:otherUserId') | 61 | Get message history |
| /api/key-exchange/initiate | POST | `server/routes/keyExchange.js` | router.post('/initiate') | 9 | Start key exchange |
| /api/key-exchange/respond | POST | `server/routes/keyExchange.js` | router.post('/respond') | 53 | Respond to key exchange |
| /api/key-exchange/:id | GET | `server/routes/keyExchange.js` | router.get('/:id') | ~109 | Get key exchange status |
| /api/files/upload | POST | `server/routes/files.js` | router.post('/upload') | 31 | Upload encrypted file |
| /api/files/:fileId | GET | `server/routes/files.js` | router.get('/:fileId') | 79 | Download encrypted file |

---

## 8. TESTING & VERIFICATION GUIDE

### Quick Verification Commands

```bash
# Check React is used
grep "react" client/package.json

# Check Web Crypto API usage
grep -r "window.crypto.subtle" client/src/

# Check AES-256-GCM usage
grep -r "AES-GCM" client/src/

# Check RSA-2048
grep -r "modulusLength: 2048" client/src/

# Check ECDH P-256
grep -r "P-256" client/src/

# Check bcrypt usage
grep -r "bcrypt" server/

# Check no forbidden libraries
grep -r "firebase\|libsodium\|openpgp\|node-forge" package.json client/package.json server/package.json

# Check IndexedDB usage
grep -r "indexedDB" client/src/

# Check Winston logging
grep -r "winston" server/

# Check replay protection
grep -r "nonce.*unique" server/models/
```

### Manual Testing Checklist

1. **User Registration** → `client/src/components/Login.js:38-78`
2. **Key Generation** → Open browser DevTools → Application → IndexedDB → E2EEKeyStore
3. **Key Exchange** → Chat UI → "Establish Secure Connection" button
4. **Message Encryption** → Send message → Network tab → Check payload is encrypted
5. **File Encryption** → Upload file → Check `uploads/` folder → File is encrypted
6. **Replay Attack** → Send same message twice → Check logs for replay detection
7. **MITM Demo** → Run `node docs/attack-demos/mitm-attack.js`
8. **Replay Demo** → Run `node docs/attack-demos/replay-attack.js`

---

## 9. DOCUMENTATION REFERENCE

| Document | Purpose | Location | Key Sections |
|----------|---------|----------|--------------|
| README.md | Project overview | Root | Features, tech stack, quick start |
| SETUP.md | Installation guide | Root | Step-by-step setup |
| threat-model.md | STRIDE analysis | `docs/` | All 6 threat categories |
| key-exchange-protocol.md | Protocol specification | `docs/protocols/` | Complete protocol flow |
| system-architecture.md | System design | `docs/architecture/` | Architecture diagrams |
| PROJECT_SUMMARY.md | Completion status | `docs/` | Requirements checklist |
| TRACEABILITY_MATRIX.md | This document | Root | All requirements mapped |

---

## 10. LOG FILES REFERENCE

| Log File | Purpose | Location | Key Events | Access |
|----------|---------|----------|------------|--------|
| security.log | Security events | `server/logs/` | Auth, key exchange, replay | Server filesystem |
| error.log | Error events | `server/logs/` | Failed operations | Server filesystem |
| combined.log | All events | `server/logs/` | Everything | Server filesystem |

---

## USAGE INSTRUCTIONS

### For Teacher/Evaluator:
1. Find requirement in table (e.g., "AES-256-GCM Encryption")
2. Note the file path and line numbers
3. Open file and navigate to specified lines
4. Verify implementation matches requirement

### For Quick Search:
- Use Ctrl+F to search this document for keywords
- Use provided grep commands to search codebase
- Follow line numbers to exact implementation

### For Demonstration:
1. Identify requirement to demonstrate
2. Follow "Verification" column instructions
3. Use manual testing checklist for end-to-end demos

---

## REVISION HISTORY

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | Dec 2, 2025 | Initial comprehensive matrix | Team |

---

**END OF TRACEABILITY MATRIX**
