# Setup Instructions

## Prerequisites

- Node.js (v16 or higher)
- MongoDB (local installation or cloud instance like MongoDB Atlas)
- npm or yarn package manager

## Installation Steps

### 1. Clone the Repository

```bash
git clone <repository-url>
cd INFO-SEC
```

### 2. Install Dependencies

Install all dependencies for root, server, and client:

```bash
npm run install-all
```

Or manually:

```bash
npm install
cd server && npm install && cd ..
cd client && npm install && cd ..
```

### 3. Configure Environment Variables

Create a `.env` file in the `server` directory:

```bash
cd server
cp .env.example .env
```

Edit `server/.env` with your configuration:

```env
# MongoDB Connection
MONGODB_URI=mongodb://localhost:27017/e2ee_messaging

# Server Configuration
PORT=5000
NODE_ENV=development

# JWT Secret (CHANGE THIS IN PRODUCTION!)
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-min-32-chars

# Client URL (for CORS)
CLIENT_URL=http://localhost:3000

# File Upload Directory
UPLOAD_DIR=./uploads

# Logging
LOG_LEVEL=info
```

**Important**: Change `JWT_SECRET` to a strong random string in production!

### 4. Start MongoDB

If using local MongoDB:

```bash
# On Windows
mongod

# On Linux/Mac
sudo systemctl start mongod
# or
mongod --dbpath /path/to/data
```

If using MongoDB Atlas, ensure your connection string is correct in `.env`.

### 5. Start the Application

From the root directory:

```bash
npm run dev
```

This will start:
- Backend server on `http://localhost:5000`
- Frontend React app on `http://localhost:3000`

Or start them separately:

```bash
# Terminal 1 - Backend
npm run server

# Terminal 2 - Frontend
npm run client
```

### 6. Access the Application

Open your browser and navigate to:
```
http://localhost:3000
```

## First-Time Setup

1. **Register a User**
   - Click "Register" tab
   - Enter username (alphanumeric + underscore, 3-30 chars)
   - Enter password (minimum 8 characters)
   - Keys will be generated automatically and stored locally

2. **Register a Second User** (for testing)
   - Open an incognito/private window
   - Register another user
   - This simulates two different users

3. **Establish Key Exchange**
   - Login as first user
   - Select second user from the list
   - Click "Establish Secure Connection"
   - Wait for key exchange to complete

4. **Send Encrypted Messages**
   - Type a message
   - Click "Send"
   - Message is encrypted client-side before sending

5. **Share Encrypted Files**
   - Click "Attach File"
   - Select a file
   - File is encrypted client-side before upload

## Testing Attack Demonstrations

### MITM Attack Demo

```bash
cd docs/attack-demos
node mitm-attack.js
```

This demonstrates:
- How MITM attacks work without signatures
- How digital signatures prevent MITM attacks

### Replay Attack Demo

```bash
cd docs/attack-demos
node replay-attack.js
```

This demonstrates:
- How replay attacks work without protection
- How nonces, timestamps, and sequence numbers prevent replay attacks

## Troubleshooting

### MongoDB Connection Error

**Error**: `MongoDB connection error`

**Solution**:
- Ensure MongoDB is running
- Check `MONGODB_URI` in `.env` is correct
- For MongoDB Atlas, ensure your IP is whitelisted

### Port Already in Use

**Error**: `Port 5000 already in use`

**Solution**:
- Change `PORT` in `server/.env`
- Or stop the process using port 5000

### CORS Errors

**Error**: `CORS policy blocked`

**Solution**:
- Ensure `CLIENT_URL` in `server/.env` matches your frontend URL
- Check that both server and client are running

### Key Generation Fails

**Error**: `Failed to generate key pair`

**Solution**:
- Ensure you're using a modern browser (Chrome, Firefox, Edge)
- Web Crypto API requires HTTPS in production (HTTP works for localhost)

### File Upload Fails

**Error**: `File upload failed`

**Solution**:
- Check file size (limit is 100MB)
- Ensure `UPLOAD_DIR` exists and is writable
- Check server logs for detailed error

## Development Notes

### Key Storage

- Private keys are stored in browser's IndexedDB
- Keys are **never** sent to the server
- If you clear browser data, keys will be lost
- For production, implement key backup/export feature

### Security Considerations

- This is a **development** setup
- For production:
  - Use HTTPS (required for Web Crypto API)
  - Use strong JWT secret
  - Implement rate limiting
  - Use environment-specific MongoDB
  - Enable MongoDB authentication

### Logging

Security logs are stored in:
- `server/logs/security.log` - Security events
- `server/logs/combined.log` - All logs
- `server/logs/error.log` - Errors only

## Production Deployment

### Backend Deployment

1. Set `NODE_ENV=production` in `.env`
2. Use a production MongoDB instance
3. Set strong `JWT_SECRET`
4. Configure HTTPS
5. Set up reverse proxy (nginx)
6. Enable MongoDB authentication

### Frontend Deployment

1. Build the React app:
   ```bash
   cd client
   npm run build
   ```

2. Serve the `build` directory with a web server
3. Ensure HTTPS is enabled (required for Web Crypto API)
4. Update `REACT_APP_API_URL` to production backend URL

### Environment Variables

Production `.env` should include:
- Strong `JWT_SECRET` (32+ characters, random)
- Production MongoDB URI with authentication
- Production `CLIENT_URL`
- `NODE_ENV=production`

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review server logs in `server/logs/`
3. Check browser console for client-side errors
4. Review documentation in `docs/` directory

