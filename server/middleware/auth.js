const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { logSecurityEvent } = require('../utils/logger');

// Middleware to verify JWT token
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]; // Bearer <token>

    if (!token) {
      logSecurityEvent('AUTH_FAILED', {
        reason: 'No token provided',
        ip: req.ip,
        path: req.path
      });
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user || !user.isActive) {
      logSecurityEvent('AUTH_FAILED', {
        reason: 'Invalid or inactive user',
        userId: decoded.userId,
        ip: req.ip
      });
      return res.status(401).json({ error: 'Invalid or inactive user' });
    }

    req.user = user;
    req.userId = user._id;
    next();
  } catch (error) {
    logSecurityEvent('AUTH_FAILED', {
      reason: 'Token verification failed',
      error: error.message,
      ip: req.ip
    });
    res.status(401).json({ error: 'Invalid token' });
  }
};

module.exports = { authenticate };

