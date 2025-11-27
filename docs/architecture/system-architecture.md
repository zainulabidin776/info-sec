# System Architecture

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT (Browser)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   React UI   │  │  Web Crypto  │  │  IndexedDB    │    │
│  │  Components  │  │     API      │  │  Key Storage  │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                 │                 │             │
│         └─────────────────┼─────────────────┘             │
│                           │                               │
│                    ┌──────▼──────┐                       │
│                    │ Crypto Layer │                       │
│                    │ - Key Gen    │                       │
│                    │ - Encryption │                       │
│                    │ - Key Exch.  │                       │
│                    └──────┬───────┘                       │
└───────────────────────────┼───────────────────────────────┘
                            │ HTTPS
                            │ (Encrypted Transport)
┌───────────────────────────▼───────────────────────────────┐
│                      SERVER (Node.js)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Express    │  │   Socket.io  │  │   MongoDB    │   │
│  │   REST API   │  │  Real-time   │  │   Database   │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                 │                 │            │
│         └─────────────────┼─────────────────┘            │
│                           │                               │
│                    ┌──────▼──────┐                       │
│                    │  Business   │                       │
│                    │    Logic    │                       │
│                    │ - Auth      │                       │
│                    │ - Routing   │                       │
│                    │ - Logging   │                       │
│                    └─────────────┘                       │
└───────────────────────────────────────────────────────────┘
```

## Component Architecture

### Client-Side Components

#### 1. React Application Layer
- **Login Component**: User authentication UI
- **Chat Component**: Main messaging interface
- **App Component**: Routing and state management

#### 2. Cryptographic Layer
- **keyManager.js**: 
  - RSA-2048 key pair generation
  - ECDH key pair generation
  - Key import/export (JWK format)
  - IndexedDB storage management

- **keyExchange.js**:
  - ECDH shared secret derivation
  - RSA-PSS signature creation/verification
  - Key exchange protocol implementation
  - HKDF session key derivation

- **encryption.js**:
  - AES-256-GCM encryption/decryption
  - IV generation
  - Nonce generation
  - File encryption with chunking

#### 3. Service Layer
- **api.js**: HTTP API client (Axios)
- **socket.js**: WebSocket client (Socket.io)

#### 4. Storage Layer
- **IndexedDB**: Private key storage
- **localStorage**: Session keys, nonces, sequence numbers

### Server-Side Components

#### 1. API Layer
- **Express.js**: REST API framework
- **Routes**:
  - `/api/auth`: Authentication (register, login)
  - `/api/users`: User management
  - `/api/messages`: Message handling
  - `/api/files`: File upload/download
  - `/api/key-exchange`: Key exchange coordination

#### 2. Real-Time Layer
- **Socket.io**: WebSocket server for real-time messaging
- Event handling for message delivery

#### 3. Data Layer
- **MongoDB**: Metadata storage
  - Users collection
  - Messages collection (ciphertext only)
  - Files collection (metadata only)
  - KeyExchange collection

#### 4. Security Layer
- **Authentication Middleware**: JWT verification
- **Logger**: Security event logging
- **Validation**: Input sanitization

## Data Flow

### Message Sending Flow

```
User Input
    │
    ▼
[Chat Component]
    │
    ▼
[Encrypt Message] (AES-256-GCM)
    │
    ├─► Generate IV
    ├─► Generate Nonce
    ├─► Get Sequence Number
    └─► Encrypt with Session Key
    │
    ▼
[Send to Server] (HTTPS)
    │
    ├─► POST /api/messages
    └─► Socket.io emit
    │
    ▼
[Server]
    │
    ├─► Verify JWT
    ├─► Check Nonce (replay protection)
    ├─► Store in MongoDB (ciphertext only)
    └─► Forward via Socket.io
    │
    ▼
[Recipient Client]
    │
    ├─► Receive via Socket.io
    ├─► Check Nonce
    ├─► Decrypt with Session Key
    └─► Display Message
```

### Key Exchange Flow

```
Initiator                    Server                    Responder
    │                          │                          │
    │──[1] Initiate───────────►│                          │
    │                          │──[2] Store──────────────►│
    │                          │                          │
    │                          │◄──[3] Retrieve───────────│
    │                          │                          │
    │                          │◄──[4] Respond─────────────│
    │                          │                          │
    │◄──[5] Get Response────────│                          │
    │                          │                          │
    │[6] Derive Session Key    │                          │[6] Derive Session Key
    │                          │                          │
```

### File Sharing Flow

```
User Selects File
    │
    ▼
[Encrypt File] (Client-side)
    │
    ├─► Split into Chunks
    ├─► Encrypt Each Chunk (AES-256-GCM)
    └─► Generate IV per Chunk
    │
    ▼
[Upload to Server] (HTTPS)
    │
    ├─► POST /api/files/upload
    └─► Multipart Form Data
    │
    ▼
[Server]
    │
    ├─► Verify JWT
    ├─► Store File (encrypted)
    ├─► Store Metadata in MongoDB
    └─► Return File ID
    │
    ▼
[Send File Message]
    │
    ├─► POST /api/messages (with fileId)
    └─► Recipient notified
    │
    ▼
[Recipient Downloads]
    │
    ├─► GET /api/files/:fileId
    ├─► Download Encrypted File
    ├─► Decrypt Client-side
    └─► Save Decrypted File
```

## Security Architecture

### Encryption Layers

1. **Transport Layer**: HTTPS (TLS 1.2+)
2. **Application Layer**: End-to-End Encryption (AES-256-GCM)
3. **Key Exchange**: ECDH + RSA Signatures

### Key Management

```
Registration
    │
    ├─► Generate RSA-2048 Key Pair
    ├─► Generate ECDH Key Pair (P-256)
    ├─► Store Private Keys in IndexedDB
    └─► Send Public Keys to Server

Key Exchange
    │
    ├─► Generate Ephemeral ECDH Key Pair
    ├─► Sign with RSA Private Key
    ├─► Derive Shared Secret (ECDH)
    └─► Derive Session Key (HKDF)

Session Key Storage
    │
    └─► Store in localStorage (per conversation)
```

### Attack Mitigations

```
MITM Attack
    │
    └─► Digital Signatures (RSA-PSS)
        └─► Verify before accepting keys

Replay Attack
    │
    ├─► Nonces (unique per message)
    ├─► Timestamps (5-minute window)
    └─► Sequence Numbers (ordering)

Data Tampering
    │
    └─► AES-GCM Authentication Tag
        └─► Decryption fails if tampered
```

## Database Schema

### Users Collection
```javascript
{
  _id: ObjectId,
  username: String (unique),
  passwordHash: String (bcrypt),
  publicKey: String,
  publicKeyJWK: Object,
  createdAt: Date,
  lastLogin: Date,
  isActive: Boolean
}
```

### Messages Collection
```javascript
{
  _id: ObjectId,
  senderId: ObjectId (ref: User),
  recipientId: ObjectId (ref: User),
  ciphertext: String,      // Encrypted message
  iv: String,              // Initialization vector
  authTag: String,         // Authentication tag
  nonce: String (unique),  // Replay protection
  sequenceNumber: Number,  // Ordering
  timestamp: Date,
  messageType: String,     // 'text' or 'file'
  fileId: ObjectId (ref: File, optional)
}
```

### Files Collection
```javascript
{
  _id: ObjectId,
  filename: String,        // Server filename
  originalFilename: String, // Original filename
  mimeType: String,
  size: Number,
  filePath: String,        // Path on disk
  iv: String,
  authTag: String,
  chunks: Array,           // Chunk metadata
  uploaderId: ObjectId (ref: User),
  uploadedAt: Date
}
```

### KeyExchange Collection
```javascript
{
  _id: ObjectId,
  initiatorId: ObjectId (ref: User),
  responderId: ObjectId (ref: User),
  initiatorECDHPublicKey: Object (JWK),
  responderECDHPublicKey: Object (JWK),
  initiatorSignature: String,
  responderSignature: String,
  initiatorNonce: String,
  responderNonce: String,
  initiatorTimestamp: Number,
  responderTimestamp: Number,
  salt: String,
  status: String,          // 'initiated', 'completed', 'failed'
  completedAt: Date
}
```

## Deployment Architecture

### Development
```
localhost:3000 (React Dev Server)
    │
    └─► localhost:5000 (Node.js Server)
            │
            └─► localhost:27017 (MongoDB)
```

### Production (Recommended)
```
HTTPS Frontend (CDN/Static Hosting)
    │
    └─► HTTPS Backend (Node.js Server)
            │
            ├─► MongoDB (Cloud/Managed)
            └─► File Storage (S3/Cloud Storage)
```

## Performance Considerations

1. **Key Generation**: Done once per user (registration)
2. **Key Exchange**: Done once per conversation
3. **Message Encryption**: Client-side, minimal overhead
4. **File Encryption**: Chunked for large files
5. **Database**: Indexed for efficient queries
6. **Real-time**: Socket.io for instant delivery

## Scalability

- **Horizontal Scaling**: Stateless server design
- **Database**: MongoDB sharding support
- **File Storage**: Can use cloud storage (S3, etc.)
- **Caching**: Session keys cached client-side
- **Load Balancing**: Multiple server instances supported

