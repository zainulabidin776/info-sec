# Secure End-to-End Encrypted Messaging & File-Sharing System

## Project Overview

This is a complete end-to-end encrypted messaging and file-sharing system developed as a semester project for Information Security course. The system ensures that messages and files are never stored in plaintext and the server cannot decrypt or view any user content.

## Key Features

- **End-to-End Encryption**: All messages and files encrypted client-side using AES-256-GCM
- **Secure Key Exchange**: Custom ECDH-based key exchange protocol with digital signatures
- **Replay Attack Protection**: Nonces, timestamps, and sequence numbers
- **MITM Attack Mitigation**: Digital signatures prevent man-in-the-middle attacks
- **Secure Key Storage**: Private keys stored only on client device using IndexedDB
- **Security Auditing**: Comprehensive logging of security events

## Technology Stack

### Frontend
- React.js
- Web Crypto API (SubtleCrypto)
- IndexedDB for key storage
- Axios for HTTP requests
- Socket.io-client for real-time messaging

### Backend
- Node.js + Express
- MongoDB for metadata storage
- Socket.io for real-time communication
- bcrypt for password hashing

## Project Structure

```
.
├── client/                 # React frontend application
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── crypto/        # Cryptographic functions
│   │   ├── services/      # API services
│   │   ├── utils/         # Utility functions
│   │   └── App.js
│   └── package.json
├── server/                 # Node.js backend
│   ├── models/            # MongoDB models
│   ├── routes/            # API routes
│   ├── middleware/        # Express middleware
│   ├── utils/             # Server utilities
│   └── index.js
└── package.json
```

## Quick Start

See [SETUP.md](SETUP.md) for detailed setup instructions.

### Quick Setup

1. **Install dependencies:**
   ```bash
   npm run install-all
   ```

2. **Configure environment:**
   ```bash
   cd server
   # Create .env file with:
   # MONGODB_URI=mongodb://localhost:27017/e2ee_messaging
   # PORT=5000
   # JWT_SECRET=your-secret-key-here
   # CLIENT_URL=http://localhost:3000
   ```

3. **Start MongoDB:**
   ```bash
   mongod
   ```

4. **Start application:**
   ```bash
   npm run dev
   ```

5. **Access application:**
   - Frontend: http://localhost:3000
   - Backend: http://localhost:5000

## Security Features

### Cryptographic Implementation
- **Asymmetric Encryption**: RSA-2048 for key exchange
- **Symmetric Encryption**: AES-256-GCM for message/file encryption
- **Key Derivation**: HKDF for session key derivation
- **Digital Signatures**: RSA-PSS for authentication

### Attack Mitigations
- **MITM Attacks**: Prevented through digital signatures in key exchange
- **Replay Attacks**: Prevented through nonces, timestamps, and sequence numbers
- **Key Storage**: Private keys encrypted and stored only on client device

## Testing

### Manual Testing
1. Register two users (use incognito window for second user)
2. Initiate key exchange between users
3. Send encrypted messages
4. Upload and download encrypted files
5. Test replay attack protection
6. Test MITM attack scenarios

### Attack Demonstrations

Run the attack demonstration scripts:

```bash
# MITM Attack Demo
cd docs/attack-demos
node mitm-attack.js

# Replay Attack Demo
cd docs/attack-demos
node replay-attack.js
```

These scripts demonstrate:
- How attacks work without protection
- How our defenses prevent attacks
- Security properties of the system

## Documentation

- **Setup Guide**: [SETUP.md](SETUP.md) - Detailed installation and configuration
- **Key Exchange Protocol**: [docs/protocols/key-exchange-protocol.md](docs/protocols/key-exchange-protocol.md) - Protocol specification
- **Threat Model**: [docs/threat-model.md](docs/threat-model.md) - STRIDE threat analysis
- **Attack Demonstrations**: [docs/attack-demos/](docs/attack-demos/) - MITM and replay attack scripts

## Project Structure

```
.
├── client/                 # React frontend
│   ├── src/
│   │   ├── components/     # React components (Login, Chat)
│   │   ├── crypto/         # Cryptographic functions
│   │   │   ├── keyManager.js      # Key generation & storage
│   │   │   ├── keyExchange.js     # Key exchange protocol
│   │   │   └── encryption.js      # AES-GCM encryption
│   │   ├── services/       # API & Socket services
│   │   └── utils/          # Utilities (storage, etc.)
│   └── package.json
├── server/                 # Node.js backend
│   ├── models/            # MongoDB models
│   ├── routes/            # API routes
│   ├── middleware/        # Express middleware
│   ├── utils/             # Server utilities (logger)
│   └── index.js          # Server entry point
├── docs/                  # Documentation
│   ├── protocols/         # Protocol specifications
│   ├── attack-demos/     # Attack demonstration scripts
│   └── threat-model.md   # STRIDE analysis
└── README.md
```

## License

MIT License - Educational Project

## Authors

[Your Group Members]

