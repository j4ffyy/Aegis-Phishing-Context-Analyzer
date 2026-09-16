/**
 * Automated Test Suite for Aegis Background Communication Bridge & Cache (Milestone 2.3)
 * Specification: Implementation Plan §3.1, §5.1.4, §5.1.5
 */

const assert = require('assert');
const backgroundBridge = require('../background.js');

console.log('Running Aegis Background Bridge & Cache Test Suite...\n');

let testsPassed = 0;
let testsFailed = 0;

async function runAsyncTest(name, fn) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    testsPassed++;
  } catch (err) {
    console.error(`[FAIL] ${name}`);
    console.error('       ', err.message);
    testsFailed++;
  }
}

async function main() {
  const { AegisCache, CONFIG, deriveEmailCacheKey, computeSHA256, storageAdapter } = backgroundBridge;

  // Reset storage adapter before test execution
  await storageAdapter.clear();

  // ---------------------------------------------------------------------------
  // 1. SHA-256 and Key Generation Tests
  // ---------------------------------------------------------------------------
  await runAsyncTest('computeSHA256 produces valid 64-char hex hash', async () => {
    const hash = await computeSHA256('hello world');
    assert.strictEqual(typeof hash, 'string');
    assert.strictEqual(hash.length, 64);
    assert.strictEqual(hash, 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
  });

  await runAsyncTest('deriveEmailCacheKey produces deterministic hash for identical email contexts', async () => {
    const email1 = {
      senderEmail: 'billing@bdo-notice.com',
      subject: 'Urgent Account Suspension Notice',
      attachmentCount: 1,
      links: [{ url: 'http://192.168.1.1/login' }, { url: 'https://bdo.com.ph' }],
      bodyText: 'Please verify your credentials immediately or your account will be closed.'
    };
    const email2 = {
      senderEmail: 'BILLING@bdo-notice.com', // Case insensitivity test
      subject: 'Urgent Account Suspension Notice',
      attachmentCount: 1,
      links: [{ url: 'https://bdo.com.ph' }, { url: 'http://192.168.1.1/login' }], // Sorting test
      bodyText: 'Please verify your credentials immediately or your account will be closed.'
    };

    const key1 = await deriveEmailCacheKey(email1);
    const key2 = await deriveEmailCacheKey(email2);
    assert.strictEqual(key1, key2);
    assert.strictEqual(key1.length, 64);
  });

  // ---------------------------------------------------------------------------
  // 2. Cache Basic Operations (Get / Set / Clear)
  // ---------------------------------------------------------------------------
  await runAsyncTest('AegisCache basic set, get, and miss behavior', async () => {
    await AegisCache.clear();
    const testKey = 'test_key_123';
    const testPayload = { score: 92, riskLevel: 'Critical' };

    const initialMiss = await AegisCache.get(testKey);
    assert.strictEqual(initialMiss, null);

    await AegisCache.set(testKey, testPayload);
    const hit = await AegisCache.get(testKey);
    assert.deepStrictEqual(hit, testPayload);

    const stats = await AegisCache.getStats();
    assert.strictEqual(stats.entryCount, 1);
  });

  // ---------------------------------------------------------------------------
  // 3. TTL Eviction Enforcement (7-day TTL)
  // ---------------------------------------------------------------------------
  await runAsyncTest('AegisCache evicts entries exceeding 7-day TTL', async () => {
    await AegisCache.clear();
    const testKey = 'expired_key_test';
    const testPayload = { score: 10, riskLevel: 'Safe' };

    // Manually inject an entry created 8 days ago
    const eightDaysAgo = Date.now() - (8 * 24 * 60 * 60 * 1000);
    const store = {
      [testKey]: {
        data: testPayload,
        createdAt: eightDaysAgo,
        lastAccessed: eightDaysAgo
      }
    };
    await storageAdapter.set(CONFIG.STORAGE_KEY_CACHE, store);

    // Fetching should trigger TTL eviction and return null
    const result = await AegisCache.get(testKey);
    assert.strictEqual(result, null, 'Expired record should be evicted and return null');

    const stats = await AegisCache.getStats();
    assert.strictEqual(stats.entryCount, 0, 'Expired record should be pruned from storage');
  });

  // ---------------------------------------------------------------------------
  // 4. LRU Eviction Enforcement (100 Max Entries)
  // ---------------------------------------------------------------------------
  await runAsyncTest('AegisCache evicts least-recently accessed entry when exceeding MAX_CACHE_ENTRIES', async () => {
    await AegisCache.clear();

    // Populate exactly 100 entries
    for (let i = 1; i <= 100; i++) {
      const key = `key_${i.toString().padStart(3, '0')}`;
      await AegisCache.set(key, { index: i });
    }

    let stats = await AegisCache.getStats();
    assert.strictEqual(stats.entryCount, 100, 'Cache should have exactly 100 items');

    // Access key_001 so its lastAccessed is updated to the freshest
    const refreshed = await AegisCache.get('key_001');
    assert.ok(refreshed);

    // Insert the 101st entry — key_002 should be the oldest and thus evicted
    await AegisCache.set('key_101', { index: 101 });

    stats = await AegisCache.getStats();
    assert.strictEqual(stats.entryCount, 100, 'Cache count must not exceed MAX_CACHE_ENTRIES (100)');

    const evictedItem = await AegisCache.get('key_002');
    assert.strictEqual(evictedItem, null, 'Oldest unaccessed key_002 should have been evicted');

    const accessedItem = await AegisCache.get('key_001');
    assert.ok(accessedItem, 'Recently accessed key_001 should still exist in cache');

    const newestItem = await AegisCache.get('key_101');
    assert.ok(newestItem, 'Newest entry key_101 should exist in cache');
  });

  // ---------------------------------------------------------------------------
  // 5. Network AbortController Timeout (2.0s Limit)
  // ---------------------------------------------------------------------------
  await runAsyncTest('fetchWithTimeout aborts and rejects when response exceeds timeout', async () => {
    const { fetchWithTimeout } = backgroundBridge;

    // Simulate an HTTP fetch that takes 100ms with a 30ms timeout
    const originalFetch = global.fetch;
    global.fetch = (url, opts) => {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          resolve(new Response(JSON.stringify({ ok: true })));
        }, 150);

        if (opts && opts.signal) {
          opts.signal.addEventListener('abort', () => {
            clearTimeout(timer);
            const abortErr = new Error('The operation was aborted.');
            abortErr.name = 'AbortError';
            reject(abortErr);
          });
        }
      });
    };

    let errorCaught = null;
    try {
      await fetchWithTimeout('http://dummy-test.local', {}, 40);
    } catch (err) {
      errorCaught = err;
    } finally {
      global.fetch = originalFetch;
    }

    assert.ok(errorCaught, 'Expected request to be aborted due to timeout');
    assert.strictEqual(errorCaught.name, 'AbortError');
    assert.strictEqual(errorCaught.isTimeout, true);
  });

  // ---------------------------------------------------------------------------
  // 6. Offline Fallback Routing
  // ---------------------------------------------------------------------------
  await runAsyncTest('dispatchEmailAnalysis delegates to offline fallback when backend is offline/unreachable', async () => {
    const { dispatchEmailAnalysis } = backgroundBridge;

    const emailPayload = {
      senderEmail: 'test@unreachable-backend.local',
      subject: 'Offline Test Verification',
      bodyText: 'This request will hit an unreachable backend server port.'
    };

    const originalFetch = global.fetch;
    global.fetch = () => Promise.reject(new Error('ECONNREFUSED'));

    try {
      const result = await dispatchEmailAnalysis(emailPayload);
      assert.strictEqual(result._fallback, true);
      assert.strictEqual(result._source, 'offline_fallback');
      assert.ok(result._fallbackReason.includes('unreachable') || result._fallbackReason.includes('ECONNREFUSED'));
    } finally {
      global.fetch = originalFetch;
    }
  });

  // ---------------------------------------------------------------------------
  // 7. Summary
  // ---------------------------------------------------------------------------
  console.log('\n========================================');
  console.log(`Test Execution Summary:`);
  console.log(`Passed: ${testsPassed}`);
  console.log(`Failed: ${testsFailed}`);
  console.log('========================================\n');

  if (testsFailed > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
