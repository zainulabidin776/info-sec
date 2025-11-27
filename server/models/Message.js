const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  recipientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  // Encrypted content - server never sees plaintext
  ciphertext: {
    type: String,
    required: true
  },
  iv: {
    type: String,
    required: true
  },
  authTag: {
    type: String,
    required: true
  },
  // Metadata for replay protection
  nonce: {
    type: String,
    required: true,
    unique: true
  },
  sequenceNumber: {
    type: Number,
    required: true
  },
  timestamp: {
    type: Date,
    required: true,
    default: Date.now,
    index: true
  },
  messageType: {
    type: String,
    enum: ['text', 'file'],
    default: 'text'
  },
  // For file messages, reference the encrypted file
  fileId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'File',
    default: null
  }
}, {
  timestamps: true
});

// Compound index for efficient message retrieval
messageSchema.index({ senderId: 1, recipientId: 1, timestamp: -1 });
messageSchema.index({ nonce: 1 }, { unique: true });

module.exports = mongoose.model('Message', messageSchema);

