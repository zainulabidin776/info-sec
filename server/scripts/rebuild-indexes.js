const mongoose = require('mongoose');
require('dotenv').config();

// Import models
const Message = require('../models/Message');
const User = require('../models/User');
const KeyExchange = require('../models/KeyExchange');
const File = require('../models/File');

async function rebuildIndexes() {
  try {
    console.log('🔌 Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/e2ee-chat');
    console.log('✅ Connected to MongoDB');

    console.log('\n📊 Checking and rebuilding indexes...\n');

    // Drop and recreate all indexes for each model
    const models = [
      { name: 'Message', model: Message },
      { name: 'User', model: User },
      { name: 'KeyExchange', model: KeyExchange },
      { name: 'File', model: File }
    ];

    for (const { name, model } of models) {
      console.log(`🔧 Processing ${name} collection...`);
      
      try {
        // Drop existing indexes (except _id)
        await model.collection.dropIndexes();
        console.log(`  ✓ Dropped existing indexes`);
      } catch (error) {
        console.log(`  ℹ No indexes to drop or error: ${error.message}`);
      }

      // Recreate indexes based on schema
      await model.syncIndexes();
      console.log(`  ✓ Recreated indexes`);

      // List current indexes
      const indexes = await model.collection.indexes();
      console.log(`  ✓ Current indexes:`, indexes.map(idx => idx.name).join(', '));
      console.log();
    }

    console.log('✅ All indexes rebuilt successfully!');
    
    // Verify the unique nonce index specifically
    console.log('\n🔍 Verifying Message nonce unique constraint...');
    const messageIndexes = await Message.collection.indexes();
    const nonceIndex = messageIndexes.find(idx => idx.key.nonce);
    
    if (nonceIndex && nonceIndex.unique) {
      console.log('✅ Nonce unique index exists:', nonceIndex);
    } else {
      console.log('❌ WARNING: Nonce unique index not found or not unique!');
    }

    // Test duplicate nonce prevention
    console.log('\n🧪 Testing duplicate nonce prevention...');
    const testNonce = 'test_nonce_' + Date.now();
    
    try {
      // Insert first message
      await Message.create({
        senderId: new mongoose.Types.ObjectId(),
        recipientId: new mongoose.Types.ObjectId(),
        ciphertext: 'test1',
        iv: 'test1',
        authTag: 'test1',
        nonce: testNonce,
        sequenceNumber: 1,
        timestamp: new Date()
      });
      console.log('✓ First message with nonce inserted');

      // Try to insert duplicate
      await Message.create({
        senderId: new mongoose.Types.ObjectId(),
        recipientId: new mongoose.Types.ObjectId(),
        ciphertext: 'test2',
        iv: 'test2',
        authTag: 'test2',
        nonce: testNonce, // DUPLICATE!
        sequenceNumber: 2,
        timestamp: new Date()
      });
      
      console.log('❌ ERROR: Duplicate nonce was allowed! Index not working!');
    } catch (error) {
      if (error.code === 11000) {
        console.log('✅ Duplicate nonce correctly rejected! (Error code 11000)');
      } else {
        console.log('❌ Unexpected error:', error.message);
      }
    } finally {
      // Cleanup test data
      await Message.deleteMany({ nonce: testNonce });
    }

    console.log('\n✅ Index rebuild complete!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error rebuilding indexes:', error);
    process.exit(1);
  }
}

rebuildIndexes();
