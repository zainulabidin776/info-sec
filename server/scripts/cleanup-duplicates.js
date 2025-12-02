const mongoose = require('mongoose');
require('dotenv').config();

async function cleanupDuplicates() {
  try {
    console.log('🔌 Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/e2ee-chat');
    console.log('✅ Connected to MongoDB\n');

    const db = mongoose.connection.db;
    const messagesCollection = db.collection('messages');

    console.log('🔍 Finding duplicate nonces...\n');

    // Find all duplicate nonces
    const duplicates = await messagesCollection.aggregate([
      {
        $group: {
          _id: '$nonce',
          count: { $sum: 1 },
          ids: { $push: '$_id' },
          timestamps: { $push: '$timestamp' }
        }
      },
      {
        $match: {
          count: { $gt: 1 }
        }
      }
    ]).toArray();

    if (duplicates.length === 0) {
      console.log('✅ No duplicate nonces found!');
      process.exit(0);
    }

    console.log(`⚠️ Found ${duplicates.length} duplicate nonce(s):\n`);

    for (const dup of duplicates) {
      console.log(`Nonce: ${dup._id}`);
      console.log(`  Count: ${dup.count}`);
      console.log(`  Message IDs: ${dup.ids.join(', ')}`);
      console.log(`  Timestamps: ${dup.timestamps.map(t => t.toISOString()).join(', ')}`);
      console.log();
    }

    console.log('🧹 Cleaning up duplicates (keeping oldest message for each nonce)...\n');

    let totalDeleted = 0;

    for (const dup of duplicates) {
      // Keep the first message (oldest), delete the rest
      const idsToDelete = dup.ids.slice(1);
      
      const result = await messagesCollection.deleteMany({
        _id: { $in: idsToDelete }
      });

      console.log(`✓ Deleted ${result.deletedCount} duplicate(s) for nonce: ${dup._id.substring(0, 16)}...`);
      totalDeleted += result.deletedCount;
    }

    console.log(`\n✅ Cleanup complete! Removed ${totalDeleted} duplicate messages.`);
    console.log('\n📝 Now run: node scripts/rebuild-indexes.js');
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during cleanup:', error);
    process.exit(1);
  }
}

cleanupDuplicates();
