const mongoose = require('mongoose');

const keyExchangeSchema = new mongoose.Schema({
  initiatorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  responderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  // ECDH public key from initiator (JWK format)
  initiatorECDHPublicKey: {
    type: Object,
    required: true
  },
  // ECDH public key from responder (JWK format)
  responderECDHPublicKey: {
    type: Object
  },
  // Digital signature from initiator
  initiatorSignature: {
    type: String,
    required: true
  },
  // Digital signature from responder
  responderSignature: {
    type: String
  },
  // Nonces for replay protection
  initiatorNonce: {
    type: String,
    required: true
  },
  responderNonce: {
    type: String
  },
  // Timestamps
  initiatorTimestamp: {
    type: Number,
    required: true
  },
  responderTimestamp: {
    type: Number
  },
  // Salt for HKDF
  salt: {
    type: String
  },
  // Status: initiated, completed, failed
  status: {
    type: String,
    enum: ['initiated', 'completed', 'failed'],
    default: 'initiated'
  },
  completedAt: {
    type: Date
  }
}, {
  timestamps: true
});

// Compound index for efficient lookups
keyExchangeSchema.index({ initiatorId: 1, responderId: 1, status: 1 });
keyExchangeSchema.index({ initiatorNonce: 1 }, { unique: true });

module.exports = mongoose.model('KeyExchange', keyExchangeSchema);

