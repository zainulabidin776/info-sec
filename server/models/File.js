const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  filename: {
    type: String,
    required: true
  },
  originalFilename: {
    type: String,
    required: true
  },
  mimeType: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true
  },
  // Encrypted file stored on disk
  filePath: {
    type: String,
    required: true
  },
  // Encryption metadata
  iv: {
    type: String,
    required: true
  },
  authTag: {
    type: String,
    required: true
  },
  // Chunk information if file is chunked
  chunks: [{
    chunkIndex: Number,
    iv: String,
    authTag: String,
    size: Number
  }],
  uploaderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  uploadedAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('File', fileSchema);

