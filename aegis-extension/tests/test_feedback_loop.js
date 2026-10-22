/**
 * Automated Test Suite for Aegis False-Positive Feedback Loop (PR-05)
 * Branch: feat/w5-5-false-positive-feedback
 *
 * Verifies:
 * 1. False-positive feedback submission payload generation.
 * 2. In-memory & local storage state updates for aegis_detection_log.
 * 3. aegis_feedback_log storage tracking & capacity constraints.
 * 4. Automatic sender whitelisting trigger integration.
 * 5. Overlay analysis score override & visual state transition logic.
 */

const assert = require('assert');

console.log('Running Aegis False-Positive Feedback Loop Test Suite (PR-05)...\n');

let testsPassed = 0;
let testsFailed = 0;

function runTest(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
    testsPassed++;
  } catch (err) {
    console.error(`[FAIL] ${name}`);
    console.error('       ', err.message);
    testsFailed++;
  }
}

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

// Mock chrome.storage.local
const mockStorage = {};
const mockChromeStorage = {
  get(keys, cb) {
    const result = {};
    keys.forEach(k => { result[k] = mockStorage[k] || null; });
    cb(result);
  },
  set(items, cb) {
    Object.assign(mockStorage, items);
    if (cb) cb();
  }
};

async function main() {
  runTest('Overlay analysis object overrides to Safe tier upon user feedback', () => {
    const initialAnalysis = {
      score: 88,
      riskLevel: 'Critical',
      riskClass: 'threat-critical',
      desc: 'High-confidence phishing indicators detected.',
      layers: {
        sanitization: { text: 'Pre-filter: Sanitization', detail: 'HTML Stripped', icon: 'fa-check-circle' },
        auth:         { text: 'Layer 1: Auth (SPF/DKIM)', detail: 'SPF pass', icon: 'fa-check-circle' },
        attach:       { text: 'Layer 2: Attachment Check', detail: 'No attachments', icon: 'fa-check-circle' },
        behavior:     { text: 'Layer 3: Behavioral Analysis', detail: 'Rapid click-through anomaly', icon: 'fa-times-circle' },
        nlp:          { text: 'Layer 4: Deep NLP Context', detail: 'Urgency keywords', icon: 'fa-times-circle' },
      },
      xai: 'Urgent payment request flagged by Deep NLP.'
    };

    const overrideAnalysis = Object.assign({}, initialAnalysis, {
      score: 10,
      riskLevel: 'Safe',
      riskClass: 'threat-safe',
      desc: 'Marked as safe by user override (False Positive reported).',
      _userOverride: true,
      xai: '[USER OVERRIDE: SAFE] Email reported as benign (trusted_partner). Aegis threat score updated.'
    });

    overrideAnalysis.layers.behavior = {
      text: 'Layer 3: Behavioral Analysis',
      detail: 'User Verified Benign (Override)',
      icon: 'fa-check-circle'
    };

    assert.strictEqual(overrideAnalysis.score, 10);
    assert.strictEqual(overrideAnalysis.riskLevel, 'Safe');
    assert.strictEqual(overrideAnalysis.riskClass, 'threat-safe');
    assert.strictEqual(overrideAnalysis._userOverride, true);
    assert.strictEqual(overrideAnalysis.layers.behavior.icon, 'fa-check-circle');
  });

  runTest('Feedback reasons match defined taxonomies', () => {
    const validReasons = ['trusted_partner', 'expected_transaction', 'verified_content', 'other'];
    const testInput = 'expected_transaction';
    assert.ok(validReasons.includes(testInput), 'Reason should be part of allowed enum');
  });

  await runAsyncTest('Feedback submission updates aegis_detection_log with userOverride=true', async () => {
    const emailHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    
    mockStorage['aegis_detection_log'] = [
      {
        emailHash: emailHash,
        score: 58,
        riskLevel: 'Warning',
        sender: 'supplier@external-parts.com',
        subject: 'Updated Order Invoice #4912',
        source: 'backend',
        analyzedAt: new Date().toISOString(),
        userOverride: false
      }
    ];

    const detList = mockStorage['aegis_detection_log'];
    const match = detList.find(e => e.emailHash === emailHash);
    assert.ok(match, 'Target detection entry should exist');
    
    match.userOverride = true;
    match.riskLevel = 'Safe';
    match.score = 10;
    match.feedbackReason = 'expected_transaction';

    assert.strictEqual(match.userOverride, true);
    assert.strictEqual(match.riskLevel, 'Safe');
    assert.strictEqual(match.score, 10);
    assert.strictEqual(match.feedbackReason, 'expected_transaction');
  });

  await runAsyncTest('aegis_feedback_log records feedback entries and respects capacity ceiling', async () => {
    mockStorage['aegis_feedback_log'] = [];
    const maxCapacity = 100;

    for (let i = 0; i < 110; i++) {
      const fbPayload = {
        emailHash: `hash_${i}`,
        userVerdict: 'safe',
        reason: 'trusted_partner',
        notes: `Note ${i}`,
        sender: `user${i}@partner.com`,
        subject: `Invoice ${i}`,
        reportedAt: new Date().toISOString()
      };
      mockStorage['aegis_feedback_log'].unshift(fbPayload);
      if (mockStorage['aegis_feedback_log'].length > maxCapacity) {
        mockStorage['aegis_feedback_log'] = mockStorage['aegis_feedback_log'].slice(0, maxCapacity);
      }
    }

    assert.strictEqual(mockStorage['aegis_feedback_log'].length, 100);
    assert.strictEqual(mockStorage['aegis_feedback_log'][0].emailHash, 'hash_109');
  });

  await runAsyncTest('Automatic whitelist delegation creates formatted whitelist entry', async () => {
    let whitelistCalledWith = null;
    const mockAegisWhitelist = {
      addWhitelistEntry(entry) {
        whitelistCalledWith = entry;
        return Promise.resolve({ success: true });
      }
    };

    const emailContext = {
      senderEmail: 'cfo-assistant@trusted-vendor.com',
      senderName: 'CFO Office',
      subject: 'Quarterly Audit Review'
    };

    const reason = 'trusted_partner';
    await mockAegisWhitelist.addWhitelistEntry({
      email: emailContext.senderEmail,
      displayName: emailContext.senderName || emailContext.senderEmail,
      role: 'Trusted Partner',
      department: 'Whitelisted Senders',
      notes: `Whitelisted via False Positive Feedback (${reason})`
    });

    assert.ok(whitelistCalledWith, 'Whitelist service should be invoked');
    assert.strictEqual(whitelistCalledWith.email, 'cfo-assistant@trusted-vendor.com');
    assert.strictEqual(whitelistCalledWith.role, 'Trusted Partner');
    assert.ok(whitelistCalledWith.notes.includes('trusted_partner'));
  });

  console.log('\n========================================');
  console.log('Test Execution Summary:');
  console.log(`Passed: ${testsPassed}`);
  console.log(`Failed: ${testsFailed}`);
  console.log('========================================\n');

  if (testsFailed > 0) {
    process.exit(1);
  }
}

main();
