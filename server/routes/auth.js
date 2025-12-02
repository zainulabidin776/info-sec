const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { logSecurityEvent } = require('../utils/logger');

const router = express.Router();

// Register new user
router.post('/register', [
  body('username').trim().isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/),
  body('password').isLength({ min: 8 }),
  body('publicKey').notEmpty(),
  body('publicKeyJWK').notEmpty(),
  body('signingPublicKeyJWK').optional()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, publicKey, publicKeyJWK, signingPublicKeyJWK } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      logSecurityEvent('REGISTRATION_FAILED', {
        reason: 'Username already exists',
        username,
        ip: req.ip
      });
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create new user
    const user = new User({
      username,
      passwordHash,
      publicKey,
      publicKeyJWK,
      signingPublicKeyJWK
    });

    await user.save();

    logSecurityEvent('USER_REGISTERED', {
      userId: user._id,
      username,
      ip: req.ip
    });

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        publicKey: user.publicKey
      }
    });
  } catch (error) {
    logSecurityEvent('REGISTRATION_ERROR', {
      error: error.message,
      ip: req.ip
    });
    res.status(500).json({ error: 'Registration failed', details: error.message });
  }
});

// Login
router.post('/login', [
  body('username').trim().notEmpty(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      logSecurityEvent('LOGIN_FAILED', {
        reason: 'User not found',
        username,
        ip: req.ip
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      logSecurityEvent('LOGIN_FAILED', {
        reason: 'Invalid password',
        userId: user._id,
        username,
        ip: req.ip
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    logSecurityEvent('LOGIN_SUCCESS', {
      userId: user._id,
      username,
      ip: req.ip
    });

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        publicKey: user.publicKey,
        publicKeyJWK: user.publicKeyJWK,
        signingPublicKeyJWK: user.signingPublicKeyJWK
      }
    });
  } catch (error) {
    logSecurityEvent('LOGIN_ERROR', {
      error: error.message,
      ip: req.ip
    });
    res.status(500).json({ error: 'Login failed', details: error.message });
  }
});

module.exports = router;

