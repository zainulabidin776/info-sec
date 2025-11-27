const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { authenticate } = require('../middleware/auth');
const File = require('../models/File');
const { logSecurityEvent } = require('../utils/logger');

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = process.env.UPLOAD_DIR || './uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate unique filename
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, `encrypted-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB limit
  }
});

// Upload encrypted file
router.post('/upload', authenticate, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { originalFilename, mimeType, iv, authTag, chunks } = req.body;

    if (!iv || !authTag) {
      // Clean up uploaded file if validation fails
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Missing encryption metadata (iv, authTag)' });
    }

    const file = new File({
      filename: req.file.filename,
      originalFilename: originalFilename || req.file.originalname,
      mimeType: mimeType || req.file.mimetype,
      size: req.file.size,
      filePath: req.file.path,
      iv,
      authTag,
      chunks: chunks ? JSON.parse(chunks) : [],
      uploaderId: req.userId
    });

    await file.save();

    logSecurityEvent('FILE_UPLOADED', {
      userId: req.userId,
      fileId: file._id,
      filename: file.originalFilename,
      size: file.size
    });

    res.status(201).json({
      message: 'File uploaded successfully',
      fileId: file._id,
      filename: file.originalFilename,
      size: file.size
    });
  } catch (error) {
    // Clean up file on error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Failed to upload file', details: error.message });
  }
});

// Download encrypted file
router.get('/:fileId', authenticate, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Verify file exists on disk
    if (!fs.existsSync(file.filePath)) {
      logSecurityEvent('FILE_NOT_FOUND_ON_DISK', {
        userId: req.userId,
        fileId: file._id,
        filePath: file.filePath
      });
      return res.status(404).json({ error: 'File not found on server' });
    }

    logSecurityEvent('FILE_DOWNLOADED', {
      userId: req.userId,
      fileId: file._id,
      filename: file.originalFilename
    });

    // Send file with encryption metadata
    res.json({
      fileId: file._id,
      filename: file.originalFilename,
      mimeType: file.mimeType,
      size: file.size,
      iv: file.iv,
      authTag: file.authTag,
      chunks: file.chunks,
      // In production, you might want to stream the file instead
      // For now, we'll return the metadata and client can request the file content separately
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch file', details: error.message });
  }
});

// Get encrypted file content (binary)
router.get('/:fileId/content', authenticate, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    if (!fs.existsSync(file.filePath)) {
      return res.status(404).json({ error: 'File not found on server' });
    }

    // Set headers for file download
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);

    // Stream the encrypted file
    const fileStream = fs.createReadStream(file.filePath);
    fileStream.pipe(res);

    logSecurityEvent('FILE_CONTENT_DOWNLOADED', {
      userId: req.userId,
      fileId: file._id
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to download file', details: error.message });
  }
});

module.exports = router;

