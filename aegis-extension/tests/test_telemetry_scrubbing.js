/**
 * Automated Test Suite for Aegis Extension Telemetry Scrubbing & Logging Toggle (Post-Defense Item 3)
 */

const assert = require('assert');

let mockLocalStorage = {};

const dummyElem = {
  id: '',
  className: '',
  innerHTML: '',
  style: {},
  classList: { add: () => {}, remove: () => {}, contains: () => false },
  appendChild: () => {},
  querySelector: () => null,
  querySelectorAll: () => [],
  addEventListener: () => {},
};

global.window = {
  addEventListener: () => {},
  location: { hash: '#inbox' },
  AegisPIIScrubber: {
    scrubText: (text) => {
      let s = (text || '');
      s = s.replace(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g, '[EMAIL]');
      s = s.replace(/\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[PHONE]');
      s = s.replace(/\b\d{7,16}\b/g, '[NUMBER]');
      return { scrubbedText: s };
    }
  }
};

global.document = {
  readyState: 'complete',
  createElement: () => dummyElem,
  getElementById: () => dummyElem,
  addEventListener: () => {},
  body: dummyElem,
};

let sentRuntimeMessages = [];

global.chrome = {
  storage: {
    local: {
      get: (keys, cb) => {
        const res = {};
        const keyList = Array.isArray(keys) ? keys : Object.keys(keys);
        keyList.forEach(k => {
          if (mockLocalStorage[k] !== undefined) {
            res[k] = mockLocalStorage[k];
          } else if (typeof keys === 'object' && !Array.isArray(keys) && keys[k] !== undefined) {
            res[k] = keys[k];
          }
        });
        cb(res);
      },
      set: (data, cb) => {
        Object.assign(mockLocalStorage, data);
        if (cb) cb();
      },
    }
  },
  runtime: {
    id: 'test-extension-id',
    sendMessage: (msg) => {
      sentRuntimeMessages.push(msg);
    }
  }
};

const overlay = require('../overlay/overlay.js');

function runTest(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
  } catch (err) {
    console.error(`[FAIL] ${name}:`, err.message);
    process.exit(1);
  }
}

console.log('Running Aegis Extension Telemetry Scrubbing Test Suite...\n');

runTest('extractSenderDomain extracts pure domain from diverse sender formats', () => {
  assert.strictEqual(overlay.extractSenderDomain('phisher@evil-bank.com'), 'evil-bank.com');
  assert.strictEqual(overlay.extractSenderDomain('Bank Admin <alert@security-dept.ph>'), 'security-dept.ph');
  assert.strictEqual(overlay.extractSenderDomain('raw-domain.com'), 'raw-domain.com');
  assert.strictEqual(overlay.extractSenderDomain(''), '[DOMAIN]');
});

runTest('getScrubbedSubject redacts email addresses and numeric IDs', () => {
  const ctx = {
    subject: 'Urgent notice regarding user@victim.org and TIN 123-456-789-000'
  };
  const scrubbed = overlay.getScrubbedSubject(ctx);
  assert.strictEqual(scrubbed.includes('user@victim.org'), false);
  assert.strictEqual(scrubbed.includes('[EMAIL]'), true);
});

runTest('logDetectionResult stores domain only and scrubbed subject', () => {
  mockLocalStorage = { aegis_logging_enabled: true };
  sentRuntimeMessages = [];

  const emailCtx = {
    senderEmail: 'attacker@fraud-domain.xyz',
    subject: 'Urgent transfer to account 987654321 for alert@target.com',
    emailHash: 'hash_test_1234',
  };
  const analysis = {
    score: 88,
    riskLevel: 'Critical',
    _source: 'remote',
  };

  overlay.logDetectionResult(emailCtx, analysis);

  const logList = mockLocalStorage['aegis_detection_log'];
  assert.ok(Array.isArray(logList));
  assert.strictEqual(logList.length, 1);

  const entry = logList[0];
  assert.strictEqual(entry.sender, 'fraud-domain.xyz');
  assert.strictEqual(entry.sender.includes('attacker@'), false);
  assert.strictEqual(entry.subject.includes('alert@target.com'), false);
  assert.strictEqual(entry.subject.includes('[EMAIL]'), true);
  assert.strictEqual(entry.subject.includes('[NUMBER]'), true);
  assert.strictEqual(entry.riskLevel, 'Critical');
});

runTest('logDetectionResult respects aegis_logging_enabled toggle', () => {
  mockLocalStorage = { aegis_logging_enabled: false, aegis_detection_log: [] };
  sentRuntimeMessages = [];

  const emailCtx = {
    senderEmail: 'legit@service.com',
    subject: 'Monthly statement',
    emailHash: 'hash_disabled_test',
  };
  const analysis = {
    score: 10,
    riskLevel: 'Safe',
    _source: 'remote',
  };

  overlay.logDetectionResult(emailCtx, analysis);

  const logList = mockLocalStorage['aegis_detection_log'];
  assert.strictEqual(logList.length, 0);
  assert.strictEqual(sentRuntimeMessages.length, 0);
});

console.log('\nAll 4 telemetry scrubbing and logging toggle tests passed successfully!');
process.exit(0);

