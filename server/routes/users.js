const express = require('express');
const { authenticate } = require('../middleware/auth');
const User = require('../models/User');

const router = express.Router();

// Get all users (for selecting chat partners)
router.get('/', authenticate, async (req, res) => {
  try {
    const users = await User.find(
      { _id: { $ne: req.userId }, isActive: true },
      { username: 1, publicKey: 1, publicKeyJWK: 1, createdAt: 1 }
    ).sort({ username: 1 });

    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users', details: error.message });
  }
});

// Get user by ID
router.get('/:id', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.params.id, {
      username: 1,
      publicKey: 1,
      publicKeyJWK: 1,
      createdAt: 1
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user', details: error.message });
  }
});

// Get current user profile
router.get('/profile/me', authenticate, async (req, res) => {
  try {
    res.json({
      id: req.user._id,
      username: req.user.username,
      publicKey: req.user.publicKey,
      createdAt: req.user.createdAt,
      lastLogin: req.user.lastLogin
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile', details: error.message });
  }
});

module.exports = router;

