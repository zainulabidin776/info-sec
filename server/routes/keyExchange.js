const express = require('express');
const { authenticate } = require('../middleware/auth');
const KeyExchange = require('../models/KeyExchange');
const User = require('../models/User');
const { logSecurityEvent } = require('../utils/logger');

const router = express.Router();

// Initiate key exchange
router.post('/initiate', authenticate, async (req, res) => {
  try {
    const { responderId, ecdhPublicKey, timestamp, nonce, signature } = req.body;

    if (!responderId || !ecdhPublicKey || !timestamp || !nonce || !signature) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if responder exists
    const responder = await User.findById(responderId);
    if (!responder) {
      return res.status(404).json({ error: 'Responder not found' });
    }

    // Store key exchange initiation
    const keyExchange = new KeyExchange({
      initiatorId: req.userId,
      responderId,
      initiatorECDHPublicKey: ecdhPublicKey,
      initiatorNonce: nonce,
      initiatorTimestamp: timestamp,
      initiatorSignature: signature,
      status: 'initiated',
      createdAt: new Date()
    });

    await keyExchange.save();

    logSecurityEvent('KEY_EXCHANGE_INITIATED', {
      initiatorId: req.userId,
      responderId,
      keyExchangeId: keyExchange._id,
      ip: req.ip
    });

    res.status(201).json({
      message: 'Key exchange initiated',
      keyExchangeId: keyExchange._id,
      responderPublicKey: responder.publicKeyJWK
    });
  } catch (error) {
    logSecurityEvent('KEY_EXCHANGE_ERROR', {
      error: error.message,
      userId: req.userId,
      ip: req.ip
    });
    res.status(500).json({ error: 'Failed to initiate key exchange', details: error.message });
  }
});

// Respond to key exchange
router.post('/respond', authenticate, async (req, res) => {
  try {
    const { keyExchangeId, ecdhPublicKey, timestamp, nonce, initNonce, signature, salt } = req.body;

    if (!keyExchangeId || !ecdhPublicKey || !timestamp || !nonce || !signature || !salt) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Find key exchange
    const keyExchange = await KeyExchange.findById(keyExchangeId);
    if (!keyExchange) {
      return res.status(404).json({ error: 'Key exchange not found' });
    }

    // Verify responder
    if (keyExchange.responderId.toString() !== req.userId.toString()) {
      logSecurityEvent('UNAUTHORIZED_KEY_EXCHANGE', {
        userId: req.userId,
        keyExchangeId,
        ip: req.ip
      });
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Update key exchange
    keyExchange.responderECDHPublicKey = ecdhPublicKey;
    keyExchange.responderNonce = nonce;
    keyExchange.responderTimestamp = timestamp;
    keyExchange.responderSignature = signature;
    keyExchange.salt = salt;
    keyExchange.status = 'completed';
    keyExchange.completedAt = new Date();

    await keyExchange.save();

    // Get initiator's public key
    const initiator = await User.findById(keyExchange.initiatorId);

    logSecurityEvent('KEY_EXCHANGE_COMPLETED', {
      keyExchangeId,
      initiatorId: keyExchange.initiatorId,
      responderId: req.userId,
      ip: req.ip
    });

    res.json({
      message: 'Key exchange completed',
      initiatorPublicKey: initiator.publicKeyJWK,
      initiatorECDHPublicKey: keyExchange.initiatorECDHPublicKey,
      salt
    });
  } catch (error) {
    logSecurityEvent('KEY_EXCHANGE_ERROR', {
      error: error.message,
      userId: req.userId,
      ip: req.ip
    });
    res.status(500).json({ error: 'Failed to respond to key exchange', details: error.message });
  }
});

// Get pending key exchanges
router.get('/pending', authenticate, async (req, res) => {
  try {
    const keyExchanges = await KeyExchange.find({
      $or: [
        { initiatorId: req.userId, status: 'initiated' },
        { responderId: req.userId, status: 'initiated' }
      ]
    })
    .populate('initiatorId', 'username publicKeyJWK')
    .populate('responderId', 'username publicKeyJWK')
    .sort({ createdAt: -1 });

    res.json(keyExchanges);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch key exchanges', details: error.message });
  }
});

// Get key exchange by ID
router.get('/:keyExchangeId', authenticate, async (req, res) => {
  try {
    const keyExchange = await KeyExchange.findById(req.params.keyExchangeId)
      .populate('initiatorId', 'username publicKeyJWK')
      .populate('responderId', 'username publicKeyJWK');

    if (!keyExchange) {
      return res.status(404).json({ error: 'Key exchange not found' });
    }

    // Verify user has access
    if (keyExchange.initiatorId._id.toString() !== req.userId.toString() &&
        keyExchange.responderId._id.toString() !== req.userId.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(keyExchange);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch key exchange', details: error.message });
  }
});

module.exports = router;

