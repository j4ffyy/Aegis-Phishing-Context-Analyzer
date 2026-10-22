/**
 * Automated Test Suite for Attachment VirusTotal File Hash Integration (PR-09)
 * Specification: Capstone 2 Paper §3.1 & PR-09 Specification
 */

const assert = require('assert');
const backgroundBridge = require('../background.js');
const contentScript = require('../content_script.js');

console.log('Running Aegis Attachment VirusTotal File Hash Test Suite (PR-09)...\n');

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

// Minimal mock node helper
function createMockNode(tag, attrs = {}, text = '', children = []) {
  return {
    tagName: tag.toUpperCase(),
    getAttribute(name) { return attrs[name] !== undefined ? attrs[name] : null; },
    textContent: text,
    innerText: text,
    querySelectorAll(selector) {
      const results = [];
      function traverse(n) {
        for (const child of (n.children || [])) {
          if (matchesSelector(child, selector)) {
            results.push(child);
          }
          traverse(child);
        }
      }
      traverse({ children: children });
      return results;
    },
    querySelector(selector) {
      const all = this.querySelectorAll(selector);
      return all.length > 0 ? all[0] : null;
    },
    children: children
  };
}

function matchesSelector(node, selector) {
  const parts = selector.split(',').map(s => s.trim());
  for (const sel of parts) {
    if (sel.includes('.aZo') && (node.getAttribute('class') || '').includes('aZo')) return true;
    if (sel.includes('.aQy') && (node.getAttribute('class') || '').includes('aQy')) return true;
    if (sel.includes('.att') && (node.getAttribute('class') || '').includes('att')) return true;
    if (sel.includes('span[download_url]') && node.getAttribute('download_url')) return true;
  }
  return false;
}

const EICAR_HASH = '275a021bbfb341410736ae3d319e0666baeb82e9f91ceb857a142eb0ce3779b4';
const CLEAN_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

async function main() {
  // 1. Background Bridge API export check
  runTest('BackgroundBridgeAPI exports checkVTHash function', () => {
    assert.strictEqual(typeof backgroundBridge.checkVTHash, 'function');
  });

  await runAsyncTest('checkVTHash throws error if fileHash is missing', async () => {
    try {
      await backgroundBridge.checkVTHash('');
      assert.fail('Should have thrown error on empty hash');
    } catch (err) {
      assert.match(err.message, /Missing fileHash/i);
    }
  });

  // 2. Content Script Attachment Hash Extraction
  runTest('extractAttachments extracts filename and data-aegis-hash attributes', () => {
    const attachNode1 = createMockNode('div', {
      class: 'aZo',
      'data-aegis-hash': EICAR_HASH
    }, 'malicious_invoice.exe');

    const attachNode2 = createMockNode('div', {
      class: 'aZo',
      'data-sha256': CLEAN_HASH
    }, 'legit_specs.pdf');

    const root = createMockNode('div', {}, '', [attachNode1, attachNode2]);

    const extracted = contentScript.extractAttachments(root);
    assert.strictEqual(extracted.count, 2);
    assert.strictEqual(extracted.names.length, 2);
    assert.strictEqual(extracted.names[0], 'malicious_invoice.exe');
    assert.strictEqual(extracted.names[1], 'legit_specs.pdf');
    assert.strictEqual(extracted.hashes.length, 2);
    assert.strictEqual(extracted.hashes[0], EICAR_HASH);
    assert.strictEqual(extracted.hashes[1], CLEAN_HASH);
  });

  runTest('extractAttachments ignores invalid or non-hex hashes', () => {
    const badAttachNode = createMockNode('div', {
      class: 'aZo',
      'data-aegis-hash': 'short_hash_123'
    }, 'document.pdf');

    const root = createMockNode('div', {}, '', [badAttachNode]);
    const extracted = contentScript.extractAttachments(root);
    assert.strictEqual(extracted.count, 1);
    assert.strictEqual(extracted.hashes.length, 0); // malformed hash skipped
  });

  runTest('extractAttachments reads container-level data-aegis-attachment-hashes attribute', () => {
    const root = createMockNode('div', {
      'data-aegis-attachment-hashes': `${EICAR_HASH}, ${CLEAN_HASH}`
    }, '', []);

    const extracted = contentScript.extractAttachments(root);
    assert.strictEqual(extracted.hashes.length, 2);
    assert.strictEqual(extracted.hashes[0], EICAR_HASH);
    assert.strictEqual(extracted.hashes[1], CLEAN_HASH);
  });

  console.log(`\n========================================`);
  console.log(`Results: ${testsPassed} passed | ${testsFailed} failed`);
  console.log(`========================================\n`);

  if (testsFailed > 0) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Unhandled test failure:', err);
  process.exit(1);
});
