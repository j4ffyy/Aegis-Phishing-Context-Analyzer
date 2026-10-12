/**
 * Automated Test Suite for Aegis Content Script SPF/DKIM Extraction (PR-02)
 * Specification: Implementation Plan §5.1.2 & §4.3 Layer 1 Verification
 */

const assert = require('assert');
const contentScript = require('../content_script.js');

console.log('Running Aegis Content Script Auth Extraction Test Suite (PR-02)...\n');

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

// Minimal mock DOM node for Node.js testing environment
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
    if (sel.startsWith('div[role="alert"]') && node.tagName === 'DIV' && node.getAttribute('role') === 'alert') return true;
    if (sel.includes('.a6E') && (node.getAttribute('class') || '').includes('a6E')) return true;
    if (sel.includes('.msg-header-warning') && (node.getAttribute('class') || '').includes('msg-header-warning')) return true;
    if (sel.includes('.a98') && (node.getAttribute('class') || '').includes('a98')) return true;
    if (sel.startsWith('table') && node.tagName === 'TABLE') return true;
    if (sel === 'tr' && node.tagName === 'TR') return true;
    if (sel === 'th' && node.tagName === 'TH') return true;
    if (sel === 'td' && node.tagName === 'TD') return true;
    if (sel.includes('.gJ') && (node.getAttribute('class') || '').includes('gJ')) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// 1. Gmail Warning Banner Detection
// ---------------------------------------------------------------------------
runTest('Extracts spfPass=false, dkimPass=false from Gmail spoof alert banner', () => {
  const banner = createMockNode('div', { role: 'alert', class: 'a6E' },
    "Be careful with this message. Gmail couldn't verify that this message actually came from paypal.com."
  );
  const root = createMockNode('div', {}, '', [banner]);

  const auth = contentScript.extractAuthStatus(root);
  assert.strictEqual(auth.spfPass, false, 'spfPass must be false on spoof alert');
  assert.strictEqual(auth.dkimPass, false, 'dkimPass must be false on spoof alert');
  assert.strictEqual(auth.source, 'gmail_warning_banner');
  assert.ok(auth.alertText.includes("couldn't verify"));
});

runTest('Extracts spfPass=false, dkimPass=false from unverified sender warning', () => {
  const warning = createMockNode('div', { class: 'msg-header-warning' },
    'This message contains a spoofed or unverified sender address. Failed authentication.'
  );
  const root = createMockNode('div', {}, '', [warning]);

  const auth = contentScript.extractAuthStatus(root);
  assert.strictEqual(auth.spfPass, false);
  assert.strictEqual(auth.dkimPass, false);
  assert.strictEqual(auth.source, 'gmail_warning_banner');
});

// ---------------------------------------------------------------------------
// 2. Gmail Details Table Extraction (mailed-by, signed-by)
// ---------------------------------------------------------------------------
runTest('Extracts spfPass=true, dkimPass=true from Gmail details table', () => {
  const rowSpf = createMockNode('tr', {}, '', [
    createMockNode('th', {}, 'mailed-by:'),
    createMockNode('td', {}, 'bdo.com.ph')
  ]);
  const rowDkim = createMockNode('tr', {}, '', [
    createMockNode('th', {}, 'signed-by:'),
    createMockNode('td', {}, 'bdo.com.ph')
  ]);
  const table = createMockNode('table', { class: 'cf gJ' }, '', [rowSpf, rowDkim]);
  const root = createMockNode('div', {}, '', [table]);

  const auth = contentScript.extractAuthStatus(root);
  assert.strictEqual(auth.spfPass, true, 'spfPass must be true when mailed-by is present');
  assert.strictEqual(auth.dkimPass, true, 'dkimPass must be true when signed-by is present');
  assert.strictEqual(auth.mailedBy, 'bdo.com.ph');
  assert.strictEqual(auth.signedBy, 'bdo.com.ph');
  assert.strictEqual(auth.source, 'gmail_details_table');
});

runTest('Extracts partial auth (spfPass=true, dkimPass=null) when only mailed-by present', () => {
  const rowSpf = createMockNode('tr', {}, '', [
    createMockNode('th', {}, 'mailed-by:'),
    createMockNode('td', {}, 'mail-relay.google.com')
  ]);
  const table = createMockNode('table', { class: 'gJ' }, '', [rowSpf]);
  const root = createMockNode('div', {}, '', [table]);

  const auth = contentScript.extractAuthStatus(root);
  assert.strictEqual(auth.spfPass, true);
  assert.strictEqual(auth.dkimPass, null);
  assert.strictEqual(auth.mailedBy, 'mail-relay.google.com');
  assert.strictEqual(auth.signedBy, null);
});

// ---------------------------------------------------------------------------
// 3. Indeterminate / Collapsed Header State
// ---------------------------------------------------------------------------
runTest('Returns spfPass=null, dkimPass=null when headers collapsed and no warning alert', () => {
  const root = createMockNode('div', {}, 'Ordinary clean email body without warnings or open details');

  const auth = contentScript.extractAuthStatus(root);
  assert.strictEqual(auth.spfPass, null);
  assert.strictEqual(auth.dkimPass, null);
  assert.strictEqual(auth.source, 'indeterminate');
});

// ---------------------------------------------------------------------------
// 4. Test Fixture Overrides (data-aegis-spf / data-aegis-dkim)
// ---------------------------------------------------------------------------
runTest('Respects data-aegis-spf and data-aegis-dkim test fixture attributes', () => {
  const root = createMockNode('div', {
    'data-aegis-spf': 'false',
    'data-aegis-dkim': 'false',
    'data-aegis-mailed-by': 'spoofed-domain.xyz'
  });

  const auth = contentScript.extractAuthStatus(root);
  assert.strictEqual(auth.spfPass, false);
  assert.strictEqual(auth.dkimPass, false);
  assert.strictEqual(auth.source, 'test_fixture');
  assert.strictEqual(auth.mailedBy, 'spoofed-domain.xyz');
});

console.log(`\nContent Script Auth Results: ${testsPassed} passed, ${testsFailed} failed.`);
if (testsFailed > 0) {
  process.exit(1);
}
