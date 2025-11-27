const express = require('express');
const { authenticate } = require('../middleware/auth');
const Message = require('../models/Message');
const { logSecurityEvent } = require('../utils/logger');

const router = express.Router();

// Send encrypted message
router.post('/', authenticate, async (req, res) => {
  try {
    const { recipientId, ciphertext, iv, authTag, nonce, sequenceNumber, messageType, fileId } = req.body;

    if (!recipientId || !ciphertext || !iv || !authTag || !nonce || !sequenceNumber) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check for duplicate nonce (replay attack detection)
    const existingMessage = await Message.findOne({ nonce });
    if (existingMessage) {
      logSecurityEvent('REPLAY_ATTACK_DETECTED', {
        userId: req.userId,
        recipientId,
        nonce,
        ip: req.ip
      });
      return res.status(400).json({ error: 'Duplicate nonce detected - possible replay attack' });
    }

    // Create message
    const message = new Message({
      senderId: req.userId,
      recipientId,
      ciphertext,
      iv,
      authTag,
      nonce,
      sequenceNumber,
      messageType: messageType || 'text',
      fileId: fileId || null,
      timestamp: new Date()
    });

    await message.save();

    logSecurityEvent('MESSAGE_SENT', {
      senderId: req.userId,
      recipientId,
      messageId: message._id,
      nonce
    });

    res.status(201).json({
      message: 'Message sent successfully',
      messageId: message._id,
      timestamp: message.timestamp
    });
  } catch (error) {
    if (error.code === 11000) {
      // Duplicate key error (nonce)
      logSecurityEvent('REPLAY_ATTACK_DETECTED', {
        userId: req.userId,
        nonce: req.body.nonce,
        ip: req.ip
      });
      return res.status(400).json({ error: 'Duplicate nonce detected - possible replay attack' });
    }
    res.status(500).json({ error: 'Failed to send message', details: error.message });
  }
});

// Get messages between current user and another user
router.get('/:otherUserId', authenticate, async (req, res) => {
  try {
    const { otherUserId } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    const before = req.query.before ? new Date(req.query.before) : new Date();

    const messages = await Message.find({
      $or: [
        { senderId: req.userId, recipientId: otherUserId },
        { senderId: otherUserId, recipientId: req.userId }
      ],
      timestamp: { $lt: before }
    })
    .sort({ timestamp: -1 })
    .limit(limit)
    .populate('senderId', 'username')
    .populate('recipientId', 'username')
    .lean();

    // Return in chronological order
    messages.reverse();

    logSecurityEvent('MESSAGES_RETRIEVED', {
      userId: req.userId,
      otherUserId,
      count: messages.length
    });

    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages', details: error.message });
  }
});

// Get message by ID (for verification)
router.get('/message/:messageId', authenticate, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId)
      .populate('senderId', 'username')
      .populate('recipientId', 'username');

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Verify user has access to this message
    if (message.senderId._id.toString() !== req.userId.toString() &&
        message.recipientId._id.toString() !== req.userId.toString()) {
      logSecurityEvent('UNAUTHORIZED_MESSAGE_ACCESS', {
        userId: req.userId,
        messageId: req.params.messageId,
        ip: req.ip
      });
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(message);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch message', details: error.message });
  }
});

module.exports = router;

