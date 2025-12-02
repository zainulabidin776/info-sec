# Comprehensive Testing Guide

## Document Information
- **Project**: Secure End-to-End Encrypted Messaging & File-Sharing System
- **Testing Date**: December 2, 2025
- **Purpose**: Step-by-step testing of all functionalities with screenshot requirements

---

## Pre-Testing Setup

### 1. Start MongoDB
```bash
# Windows
mongod

# Or if MongoDB is installed as service, it should be running
```

### 2. Start Backend Server
```bash
# Terminal 1 - In project root
cd server
npm run dev
```
**Expected Output:**
```
Server running on port 5000
MongoDB connected successfully
Environment: development
```

### 3. Start Frontend Client
```bash
# Terminal 2 - In project root
cd client
npm start
```
**Expected Output:**
```
Compiled successfully!
Local: http://localhost:3000
```

### 4. Clear Previous Data (Fresh Start)
```bash
# Optional - Clear MongoDB collections for fresh testing
# In MongoDB shell or Compass:
use e2ee_messaging
db.users.drop()
db.messages.drop()
db.keyexchanges.drop()
db.files.drop()
```

---

## TEST SUITE 1: User Authentication & Key Generation

### TEST 1.1: User Registration with Key Generation

**Location:** Browser - http://localhost:3000

**Steps:**
1. Open Chrome browser (regular window)
2. Navigate to http://localhost:3000
3. Click "Register" tab
4. Enter username: `alice_test`
5. Enter password: `SecurePass123`
6. Click "Register" button
7. Wait for key generation (2-3 seconds)

**Expected Results:**
- ✅ Registration successful message
- ✅ Redirected to /chat page
- ✅ User logged in

**Browser DevTools Verification:**
1. Open DevTools (F12)
2. Go to **Application** tab → **IndexedDB** → **E2EEKeyStore** → **keys**
3. Verify entry for `alice_test` exists with:
   - `publicKeyJWK`
   - `privateKeyJWK` 
   - `ecdhPublicKeyJWK`
   - `ecdhPrivateKeyJWK`
   - `signingPublicKeyJWK`
   - `signingPrivateKeyJWK`

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 1.1a: Registration form filled
- ✅ Screenshot 1.1b: Successful registration (chat page loaded)
- ✅ Screenshot 1.1c: IndexedDB showing stored keys
- ✅ Screenshot 1.1d: localStorage showing token and user

**Server Logs to Check:**
```bash
# In server terminal
# Should see:
USER_REGISTERED - userId: <id>, username: alice_test
```

**MongoDB Verification:**
```bash
# In MongoDB shell or Compass
use e2ee_messaging
db.users.findOne({username: "alice_test"})

# Verify fields exist:
# - username
# - passwordHash (bcrypt hash, NOT plaintext)
# - publicKeyJWK (RSA-OAEP public key)
# - signingPublicKeyJWK (RSA-PSS public key)
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 1.1e: MongoDB document showing user with hashed password
- ✅ Screenshot 1.1f: Server logs showing USER_REGISTERED event

---

### TEST 1.2: Second User Registration (for messaging)

**Location:** Browser - Incognito/Private Window

**Steps:**
1. Open Chrome **Incognito window** (Ctrl+Shift+N)
2. Navigate to http://localhost:3000
3. Click "Register" tab
4. Enter username: `bob_test`
5. Enter password: `SecurePass456`
6. Click "Register" button

**Expected Results:**
- ✅ Second user registered successfully
- ✅ Separate keys in IndexedDB for bob_test

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 1.2a: Bob's registration successful
- ✅ Screenshot 1.2b: Bob's keys in IndexedDB

---

### TEST 1.3: User Login

**Steps:**
1. Logout Alice (if logged in)
2. Click "Login" tab
3. Enter username: `alice_test`
4. Enter password: `SecurePass123`
5. Click "Login" button

**Expected Results:**
- ✅ Login successful
- ✅ JWT token stored in localStorage
- ✅ Keys loaded from IndexedDB

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 1.3a: Login form
- ✅ Screenshot 1.3b: Successful login
- ✅ Screenshot 1.3c: Network tab showing POST /api/auth/login (200 OK)

**Server Logs:**
```
USER_LOGIN - userId: <id>, username: alice_test
```

---

### TEST 1.4: Invalid Login Attempt

**Steps:**
1. Logout
2. Try login with username: `alice_test`, password: `WrongPassword`

**Expected Results:**
- ❌ Login failed error message
- ❌ "Invalid credentials" displayed

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 1.4: Failed login error message

**Server Logs:**
```
LOGIN_FAILED - reason: Invalid password
```

---

## TEST SUITE 2: Secure Key Exchange Protocol

### TEST 2.1: Key Exchange Initiation

**Location:** Browser - Alice's window

**Steps:**
1. Ensure Alice is logged in (regular window)
2. Ensure Bob is logged in (incognito window)
3. In Alice's window, click on "bob_test" in the Users list
4. Click "🔐 Establish Secure Connection" button
5. Wait 2-5 seconds for key exchange to complete

**Expected Results:**
- ✅ Button changes to "🔒 Encrypted"
- ✅ Key exchange completed
- ✅ Session key stored in localStorage

**DevTools Verification (Alice's window):**
1. Console tab - Look for key exchange logs
2. Network tab - Check requests:
   - POST `/api/key-exchange/initiate` (201 Created)
   - GET `/api/key-exchange/:id` (polling until complete)
3. Application → localStorage → Check `e2ee_session_<bob_id>` key exists

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 2.1a: Before key exchange (button visible)
- ✅ Screenshot 2.1b: After key exchange (encrypted indicator)
- ✅ Screenshot 2.1c: Network tab showing key exchange requests
- ✅ Screenshot 2.1d: localStorage showing session key
- ✅ Screenshot 2.1e: Console logs showing key exchange process

**MongoDB Verification:**
```bash
db.keyexchanges.findOne({status: "completed"})

# Verify fields:
# - initiatorId: Alice's ID
# - responderId: Bob's ID
# - initiatorECDHPublicKey (JWK object)
# - responderECDHPublicKey (JWK object)
# - initiatorSignature (base64 string)
# - responderSignature (base64 string)
# - status: "completed"
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 2.1f: MongoDB keyexchange document with signatures

**Server Logs:**
```
KEY_EXCHANGE_INITIATED - initiatorId: <alice_id>, responderId: <bob_id>
KEY_EXCHANGE_COMPLETED - keyExchangeId: <id>
```

---

### TEST 2.2: Verify Digital Signatures (MITM Prevention)

**Location:** MongoDB or Browser DevTools

**Steps:**
1. Open MongoDB Compass or shell
2. Find the completed key exchange document
3. Verify signature fields exist and are non-empty:
   - `initiatorSignature`
   - `responderSignature`

**Expected Results:**
- ✅ Both signatures present (base64 encoded strings)
- ✅ Signatures are long (300+ characters each)

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 2.2: Key exchange document showing signatures

---

### TEST 2.3: Verify HKDF Key Derivation

**Location:** Browser DevTools Console

**Steps:**
1. In Alice's console, type:
```javascript
localStorage.getItem('e2ee_session_' + '<bob_user_id>')
```
2. Verify JSON contains `key` field with JWK object
3. Check JWK has `k` property (key material in base64)

**Expected Results:**
- ✅ Session key is present
- ✅ Key is AES-GCM type
- ✅ Key length is 256 bits

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 2.3: Console showing session key JWK

---

## TEST SUITE 3: End-to-End Message Encryption

### TEST 3.1: Send Encrypted Text Message

**Location:** Browser - Alice's window

**Steps:**
1. Ensure key exchange is completed (🔒 Encrypted indicator visible)
2. Type message: `Hello Bob, this is a secret message!`
3. Click "Send" button
4. Observe message appears in chat

**Expected Results:**
- ✅ Message appears in Alice's chat window
- ✅ Message shows as "sent" (right side)
- ✅ Bob receives message in real-time (if both windows open)

**Network Tab Verification:**
1. Open Network tab
2. Find POST `/api/messages` request
3. Check payload - should show:
   - `ciphertext` (base64 encrypted string)
   - `iv` (initialization vector)
   - `authTag` (authentication tag)
   - `nonce` (unique nonce)
   - `sequenceNumber` (incrementing)
   - NO plaintext visible

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 3.1a: Message typed in input
- ✅ Screenshot 3.1b: Message sent and displayed
- ✅ Screenshot 3.1c: Network request showing encrypted payload (NO PLAINTEXT)
- ✅ Screenshot 3.1d: Request payload details showing ciphertext, iv, authTag

**MongoDB Verification:**
```bash
db.messages.findOne()

# Verify:
# - ciphertext: base64 string (NOT readable plaintext)
# - iv: base64 string
# - authTag: base64 string
# - nonce: unique hex string
# - sequenceNumber: number
# - senderId: Alice's ObjectId
# - recipientId: Bob's ObjectId
# - NO plaintext field exists
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 3.1e: MongoDB message document showing encrypted data only

**Server Logs:**
```
MESSAGE_SENT - senderId: <alice_id>, recipientId: <bob_id>
```

---

### TEST 3.2: Receive and Decrypt Message

**Location:** Browser - Bob's window (incognito)

**Steps:**
1. In Bob's window, ensure he's on chat with Alice
2. If key exchange not done, establish it first
3. Observe message received from Alice
4. Message should be decrypted and readable

**Expected Results:**
- ✅ Message appears on left side (received)
- ✅ Message content is decrypted: "Hello Bob, this is a secret message!"
- ✅ Decryption happens client-side only

**Console Verification:**
1. Check console for decryption logs
2. Look for Web Crypto API decrypt operation

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 3.2a: Bob's view showing decrypted message
- ✅ Screenshot 3.2b: Console showing decryption process

---

### TEST 3.3: Verify AES-256-GCM Algorithm

**Location:** Browser DevTools - Network Tab

**Steps:**
1. Send another message from Alice to Bob
2. Open Network tab
3. Find the POST `/api/messages` request
4. Check the encrypted payload size

**Expected Results:**
- ✅ Ciphertext length ≈ message length + padding
- ✅ IV is 12 bytes (16 chars base64)
- ✅ authTag is 16 bytes (22 chars base64)

**Code Verification:**
```javascript
// In browser console
// Check encryption algorithm used
// Open client/src/crypto/encryption.js in Sources tab
// Verify line ~77-82 shows: name: 'AES-GCM', length: 256
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 3.3: Code showing AES-256-GCM in encryption.js

---

### TEST 3.4: Multiple Messages (Sequence Numbers)

**Steps:**
1. Send 5 messages from Alice to Bob:
   - "Message 1"
   - "Message 2"
   - "Message 3"
   - "Message 4"
   - "Message 5"

**Expected Results:**
- ✅ All messages encrypted and sent
- ✅ Each has unique nonce
- ✅ Sequence numbers increment: 1, 2, 3, 4, 5

**MongoDB Verification:**
```bash
db.messages.find({senderId: ObjectId("<alice_id>")}).sort({sequenceNumber: 1})

# Verify sequence numbers are incremental
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 3.4a: All 5 messages in chat
- ✅ Screenshot 3.4b: MongoDB showing sequence numbers 1-5

---

## TEST SUITE 4: Replay Attack Protection

### TEST 4.1: Nonce Uniqueness Test

**Steps:**
1. Send a message from Alice to Bob
2. Open MongoDB and copy the message document
3. Try to insert the same document again (duplicate nonce)

**MongoDB Command:**
```bash
db.messages.insertOne({
  senderId: ObjectId("<alice_id>"),
  recipientId: ObjectId("<bob_id>"),
  ciphertext: "<same_ciphertext>",
  iv: "<same_iv>",
  authTag: "<same_authTag>",
  nonce: "<same_nonce>",  // Duplicate!
  sequenceNumber: 10,
  timestamp: new Date()
})
```

**Expected Results:**
- ❌ MongoDB rejects with duplicate key error
- ✅ Unique index on nonce prevents replay

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 4.1: MongoDB error showing duplicate nonce rejected

---

### TEST 4.2: Replay Attack Detection via API

**Location:** Postman or curl

**Steps:**
1. Capture a legitimate POST `/api/messages` request from Network tab
2. Copy the request body (ciphertext, iv, authTag, nonce, etc.)
3. Try to send the same request again using Postman or curl

**Example curl command:**
```bash
curl -X POST http://localhost:5000/api/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <alice_token>" \
  -d '{
    "recipientId": "<bob_id>",
    "ciphertext": "<captured_ciphertext>",
    "iv": "<captured_iv>",
    "authTag": "<captured_authTag>",
    "nonce": "<same_nonce_again>",
    "sequenceNumber": 1
  }'
```

**Expected Results:**
- ❌ 400 Bad Request
- ✅ Error: "Duplicate nonce detected - possible replay attack"

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 4.2a: Postman/curl request with duplicate nonce
- ✅ Screenshot 4.2b: 400 error response with replay attack message

**Server Logs:**
```
REPLAY_ATTACK_DETECTED - userId: <alice_id>, nonce: <nonce>
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 4.2c: Server security.log showing REPLAY_ATTACK_DETECTED

---

### TEST 4.3: Run Replay Attack Demo Script

**Location:** Terminal

**Steps:**
```bash
cd docs/attack-demos
node replay-attack.js
```

**Expected Output:**
```
============================================================
REPLAY ATTACK DEMONSTRATION
============================================================

SCENARIO 1: Message WITHOUT Replay Protection
------------------------------------------------------------
1. Alice sends encrypted message:
   Plaintext: Transfer $1000 to account 12345
   ...
   ❌ Bob executes the command AGAIN!
   ❌ $1000 transferred TWICE!

============================================================
SCENARIO 2: Message WITH Replay Protection
------------------------------------------------------------
...
❌ REPLAY ATTACK DETECTED: Nonce already used!
✅ Replay attack PREVENTED
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 4.3: Terminal output showing both scenarios

---

## TEST SUITE 5: MITM Attack Prevention

### TEST 5.1: Run MITM Attack Demo Script

**Location:** Terminal

**Steps:**
```bash
cd docs/attack-demos
node mitm-attack.js
```

**Expected Output:**
```
============================================================
MITM ATTACK DEMONSTRATION
============================================================

SCENARIO 1: Key Exchange WITHOUT Digital Signatures
------------------------------------------------------------
...
❌ Alice and Bob have DIFFERENT shared secrets!
✅ Mallory can decrypt and read all messages!

============================================================
SCENARIO 2: Key Exchange WITH Digital Signatures (Protected)
------------------------------------------------------------
...
❌ Bob's verification FAILS!
✅ MITM attack PREVENTED by digital signatures
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 5.1: Terminal output showing MITM attack prevented

---

### TEST 5.2: Verify Signature Verification in Code

**Location:** Browser DevTools - Sources Tab

**Steps:**
1. Open DevTools → Sources tab
2. Navigate to `client/src/crypto/keyExchange.js`
3. Find `verifySignature()` function (around line 73-106)
4. Set breakpoint on signature verification line
5. Initiate key exchange
6. Step through code to see verification happen

**Expected Results:**
- ✅ Signature verification executes
- ✅ Returns true for valid signatures
- ✅ Would return false for tampered signatures

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 5.2: Debugger showing signature verification code

---

## TEST SUITE 6: End-to-End File Sharing

### TEST 6.1: Encrypt and Upload File

**Location:** Browser - Alice's window

**Steps:**
1. Prepare a test file (e.g., `test-image.png` or `test-document.pdf`)
2. In chat with Bob (after key exchange), click "📎 Attach File"
3. Select the test file
4. Wait for encryption and upload to complete
5. Observe file message appears in chat

**Expected Results:**
- ✅ File uploaded successfully
- ✅ File message shows "📎 filename" in chat
- ✅ File encrypted client-side before upload

**Network Tab Verification:**
1. Find POST `/api/files/upload` request
2. Check request payload - should be encrypted binary data
3. Check response - returns fileId

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 6.1a: File selection dialog
- ✅ Screenshot 6.1b: File message in chat
- ✅ Screenshot 6.1c: Network request showing file upload
- ✅ Screenshot 6.1d: Upload response with fileId

**Server Verification:**
```bash
# Check uploads/ directory
ls server/uploads/
# Should see encrypted-<timestamp>-<random>.ext file
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 6.1e: Server uploads/ folder showing encrypted file

**MongoDB Verification:**
```bash
db.files.findOne()

# Verify:
# - filename: server filename
# - originalFilename: original name
# - iv, authTag: present
# - chunks: array with encryption metadata
# - uploaderId: Alice's ID
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 6.1f: MongoDB file document

---

### TEST 6.2: Download and Decrypt File

**Location:** Browser - Bob's window

**Steps:**
1. In Bob's window, find the file message from Alice
2. Click on the file message / download link
3. Wait for download and decryption
4. Open downloaded file

**Expected Results:**
- ✅ File downloads
- ✅ File decrypts successfully
- ✅ File opens and is identical to original

**Console Verification:**
1. Check console for decryption logs
2. Look for chunk decryption process

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 6.2a: File downloading
- ✅ Screenshot 6.2b: Decrypted file opened (showing content matches)
- ✅ Screenshot 6.2c: Console showing decryption process

---

### TEST 6.3: Verify File Encryption (Server Storage)

**Location:** Server filesystem

**Steps:**
1. Open server/uploads/ directory
2. Find the uploaded encrypted file
3. Try to open it with appropriate application

**Expected Results:**
- ❌ File cannot be opened (corrupted/encrypted)
- ✅ File is stored in encrypted form only

**Alternative Verification:**
```bash
# Try to view file contents
cat server/uploads/encrypted-*.png
# or
notepad server/uploads/encrypted-*.pdf

# Should see binary garbage, not readable content
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 6.3a: Encrypted file opened showing unreadable content
- ✅ Screenshot 6.3b: Error message when trying to open encrypted file

---

## TEST SUITE 7: Real-Time Messaging (Socket.io)

### TEST 7.1: Real-Time Message Delivery

**Location:** Both Browser Windows (side by side)

**Steps:**
1. Arrange Alice's window and Bob's window side by side
2. From Alice, send message: "Real-time test message"
3. Observe Bob's window

**Expected Results:**
- ✅ Message appears in Bob's window instantly (< 1 second)
- ✅ No page refresh needed
- ✅ Socket.io delivers message in real-time

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 7.1: Both windows side by side showing real-time delivery

**Server Logs:**
```
Message forwarded from <alice_id> to <bob_id>
```

---

### TEST 7.2: Socket Connection Verification

**Location:** Browser DevTools - Network Tab

**Steps:**
1. Refresh Alice's chat page
2. Open Network tab
3. Filter by "WS" (WebSocket)
4. Find socket.io connection

**Expected Results:**
- ✅ WebSocket connection established
- ✅ Connection shows "101 Switching Protocols"
- ✅ Socket.io handshake successful

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 7.2: Network tab showing WebSocket connection

---

## TEST SUITE 8: Security Logging & Auditing

### TEST 8.1: Verify Security Logs

**Location:** Server filesystem

**Steps:**
```bash
cd server/logs
cat security.log | tail -50
```

**Expected Log Entries:**
```json
{"event":"USER_REGISTERED","timestamp":"...","userId":"...","username":"alice_test"}
{"event":"USER_LOGIN","timestamp":"...","userId":"...","username":"alice_test"}
{"event":"KEY_EXCHANGE_INITIATED","timestamp":"...","initiatorId":"...","responderId":"..."}
{"event":"KEY_EXCHANGE_COMPLETED","timestamp":"...","keyExchangeId":"..."}
{"event":"MESSAGE_SENT","timestamp":"...","senderId":"...","recipientId":"..."}
{"event":"FILE_UPLOADED","timestamp":"...","userId":"...","fileId":"..."}
{"event":"REPLAY_ATTACK_DETECTED","timestamp":"...","userId":"...","nonce":"..."}
```

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 8.1: security.log file showing various events

---

### TEST 8.2: Error Logging

**Steps:**
1. Trigger an error (e.g., invalid login)
2. Check error.log

```bash
cat server/logs/error.log
```

**Expected Results:**
- ✅ Errors logged with timestamps
- ✅ Stack traces included

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 8.2: error.log showing logged errors

---

## TEST SUITE 9: Cryptographic Verification

### TEST 9.1: Verify RSA-2048 Key Size

**Location:** Browser DevTools Console

**Steps:**
```javascript
// Get keys from IndexedDB
const db = await indexedDB.open('E2EEKeyStore', 1);
// Check publicKeyJWK.n length (modulus)
// Base64 encoded 2048-bit modulus should be ~344 characters
```

**Expected Results:**
- ✅ Key modulus length indicates 2048-bit key

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 9.1: Console showing key size verification

---

### TEST 9.2: Verify ECDH P-256 Curve

**Location:** Code Inspection

**Steps:**
1. Open `client/src/crypto/keyManager.js` in editor
2. Find `generateECDHKeyPair()` function (line ~70-85)
3. Verify `namedCurve: 'P-256'` parameter

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 9.2: Code showing P-256 curve specification

---

### TEST 9.3: Verify No Plaintext Storage

**Location:** MongoDB

**Steps:**
```bash
# Check all messages
db.messages.find()

# Search for any plaintext field
# Should NOT exist
```

**Expected Results:**
- ✅ No "content" or "plaintext" field in messages
- ✅ Only ciphertext, iv, authTag present

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 9.3: MongoDB messages showing no plaintext field

---

## TEST SUITE 10: Threat Model Validation

### TEST 10.1: Review STRIDE Documentation

**Location:** Documentation

**Steps:**
1. Open `docs/threat-model.md`
2. Review all 6 threat categories
3. Verify countermeasures are implemented

**Checklist:**
- ✅ Spoofing - Passwords hashed, JWT tokens, signatures
- ✅ Tampering - Auth tags, digital signatures
- ✅ Repudiation - Logging, signatures
- ✅ Information Disclosure - E2EE, no plaintext storage
- ✅ Denial of Service - Rate limiting (optional)
- ✅ Elevation of Privilege - JWT validation, role checks

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 10.1: threat-model.md showing STRIDE analysis

---

## TEST SUITE 11: Cross-Browser Testing

### TEST 11.1: Chrome Testing
- ✅ Complete all tests in Chrome (already done above)

### TEST 11.2: Firefox Testing

**Steps:**
1. Open Firefox browser
2. Repeat TEST 1.1 (register new user: charlie_test)
3. Test key exchange with alice_test
4. Send messages
5. Upload file

**Expected Results:**
- ✅ All functionality works in Firefox

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 11.2: Firefox showing working application

### TEST 11.3: Edge Testing
- Repeat tests in Microsoft Edge

---

## TEST SUITE 12: Network Security Testing

### TEST 12.1: Wireshark Packet Capture

**Location:** Wireshark application

**Steps:**
1. Install Wireshark if not installed
2. Start capture on loopback interface (127.0.0.1)
3. Filter: `http && tcp.port == 5000`
4. Send message from Alice to Bob
5. Stop capture
6. Find POST /api/messages packet
7. Right-click → Follow → HTTP Stream

**Expected Results:**
- ✅ Request body shows encrypted ciphertext
- ✅ No plaintext visible in packet data
- ✅ HTTPS would encrypt entire payload

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 12.1a: Wireshark showing captured packets
- ✅ Screenshot 12.1b: HTTP stream showing encrypted payload

---

### TEST 12.2: BurpSuite Interception

**Location:** BurpSuite Community Edition

**Steps:**
1. Install and start BurpSuite
2. Configure browser proxy (127.0.0.1:8080)
3. Enable intercept
4. Send message from Alice to Bob
5. Examine intercepted request

**Expected Results:**
- ✅ Request intercepted
- ✅ POST body contains encrypted data only
- ✅ No plaintext visible

**📸 SCREENSHOTS TO TAKE:**
- ✅ Screenshot 12.2a: BurpSuite intercepting request
- ✅ Screenshot 12.2b: Request body showing encrypted data

---

## SUMMARY OF REQUIRED SCREENSHOTS

### Critical Screenshots (Must Have):

**Authentication & Keys (6 screenshots)**
1. User registration form
2. IndexedDB showing stored private keys
3. MongoDB user document with hashed password
4. Login successful
5. Failed login error
6. JWT token in localStorage

**Key Exchange (5 screenshots)**
7. Key exchange initiation button
8. Encrypted connection indicator
9. Network tab showing key exchange requests
10. MongoDB keyexchange document with signatures
11. Session key in localStorage

**Message Encryption (8 screenshots)**
12. Message sent in chat
13. Network request showing encrypted payload (NO PLAINTEXT)
14. Request payload details (ciphertext, iv, authTag)
15. MongoDB message document (encrypted only)
16. Received message decrypted
17. Multiple messages with sequence numbers
18. Code showing AES-256-GCM algorithm
19. Both windows showing real-time messaging

**Replay Attack Protection (4 screenshots)**
20. MongoDB duplicate nonce error
21. API 400 error for duplicate nonce
22. Server logs showing REPLAY_ATTACK_DETECTED
23. Replay attack demo script output

**MITM Attack Prevention (2 screenshots)**
24. MITM attack demo script output
25. Signature verification code in debugger

**File Sharing (6 screenshots)**
26. File selection and upload
27. File message in chat
28. Network showing file upload
29. MongoDB file document
30. Encrypted file on server (unreadable)
31. Decrypted file opened successfully

**Security Logging (2 screenshots)**
32. security.log showing events
33. Server logs directory

**Network Security (4 screenshots)**
34. Wireshark packet capture
35. Wireshark HTTP stream (encrypted payload)
36. BurpSuite intercepted request
37. BurpSuite request body

**Documentation (2 screenshots)**
38. threat-model.md STRIDE analysis
39. Architecture diagram from docs

**Total: ~39 Critical Screenshots**

---

## TESTING CHECKLIST

### Pre-Submission Checklist:

- [ ] All 12 test suites completed
- [ ] All 39 screenshots captured and organized
- [ ] MongoDB shows encrypted data only (no plaintext)
- [ ] Server logs contain security events
- [ ] Attack demo scripts run successfully
- [ ] Wireshark/BurpSuite captures obtained
- [ ] Network tab shows encrypted payloads
- [ ] IndexedDB contains private keys
- [ ] Real-time messaging works
- [ ] File encryption/decryption works
- [ ] Replay attack prevention verified
- [ ] MITM prevention verified
- [ ] Cross-browser testing completed

---

## SCREENSHOT ORGANIZATION

Create folder structure:
```
screenshots/
├── 01-authentication/
│   ├── 1.1a-registration-form.png
│   ├── 1.1b-registration-success.png
│   ├── 1.1c-indexeddb-keys.png
│   └── ...
├── 02-key-exchange/
│   ├── 2.1a-before-key-exchange.png
│   └── ...
├── 03-message-encryption/
│   ├── 3.1a-message-sent.png
│   └── ...
├── 04-replay-attack/
│   └── ...
├── 05-mitm-prevention/
│   └── ...
├── 06-file-sharing/
│   └── ...
├── 07-security-logs/
│   └── ...
└── 08-network-security/
    └── ...
```

---

## TESTING COMPLETION TIME ESTIMATE

- Test Suite 1: 15 minutes
- Test Suite 2: 10 minutes
- Test Suite 3: 15 minutes
- Test Suite 4: 10 minutes
- Test Suite 5: 5 minutes
- Test Suite 6: 15 minutes
- Test Suite 7: 5 minutes
- Test Suite 8: 5 minutes
- Test Suite 9: 5 minutes
- Test Suite 10: 5 minutes
- Test Suite 11: 15 minutes
- Test Suite 12: 20 minutes

**Total Estimated Time: ~2 hours**

---

## NEXT STEPS AFTER TESTING

Once all tests pass and screenshots are captured:
1. ✅ Organize screenshots into report
2. ✅ Generate PDF report from markdown docs
3. ✅ Record demonstration video (10-15 min)
4. ✅ Prepare project presentation
5. ✅ Final code review and cleanup

---

**END OF TESTING GUIDE**
