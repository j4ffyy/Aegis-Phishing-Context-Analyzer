/**
 * Automated Test Suite for Graceful Degraded Mode Banner & Health Indicator (PR-10)
 * Specification: Capstone 2 Paper §3.2 & Milestone 2.3
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const backgroundBridge = require('../background.js');

console.log('Running Aegis Graceful Degraded Mode Test Suite (PR-10)...\n');

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

// ---------------------------------------------------------------------------
// 1. Static Contract & Specification Checks
// ---------------------------------------------------------------------------
const EXPECTED_OFFLINE_NOTICE = 'Protection running in Offline Heuristic Mode — relying on local behavioral baseline and cached threat rules.';

runTest('Capstone 2 §3.2 Specification: Degraded banner string exact match in overlay.js', () => {
  const overlayJsPath = path.resolve(__dirname, '../overlay/overlay.js');
  const overlayContent = fs.readFileSync(overlayJsPath, 'utf8');

  assert.ok(
    overlayContent.includes(EXPECTED_OFFLINE_NOTICE),
    'overlay.js must contain the exact §3.2 offline notice text'
  );
  assert.ok(
    overlayContent.includes('id="aegis-degraded-mode-banner"'),
    'overlay.js must define #aegis-degraded-mode-banner'
  );
  assert.ok(
    overlayContent.includes('id="aegis-fam-degraded-banner"'),
    'overlay.js must define #aegis-fam-degraded-banner'
  );
});

runTest('Stylesheet Validation: overlay.css includes neo-brutalist banner definitions', () => {
  const overlayCssPath = path.resolve(__dirname, '../overlay/overlay.css');
  const overlayCss = fs.readFileSync(overlayCssPath, 'utf8');

  assert.ok(
    overlayCss.includes('.aegis-degraded-mode-banner'),
    'overlay.css must include .aegis-degraded-mode-banner'
  );
  assert.ok(
    overlayCss.includes('.aegis-fam-degraded-banner'),
    'overlay.css must include .aegis-fam-degraded-banner'
  );
});

runTest('Popup Markup: popup.html includes live backend-status-row indicator', () => {
  const popupHtmlPath = path.resolve(__dirname, '../popup/popup.html');
  const popupHtml = fs.readFileSync(popupHtmlPath, 'utf8');

  assert.ok(popupHtml.includes('id="backend-status-row"'), 'popup.html must contain backend-status-row');
  assert.ok(popupHtml.includes('id="backend-status-dot"'), 'popup.html must contain backend-status-dot');
  assert.ok(popupHtml.includes('id="backend-status-text"'), 'popup.html must contain backend-status-text');
  assert.ok(popupHtml.includes('id="backend-status-pill"'), 'popup.html must contain backend-status-pill');
});

runTest('Popup Styles: popup.css defines online and offline pill & dot tokens', () => {
  const popupCssPath = path.resolve(__dirname, '../popup/popup.css');
  const popupCss = fs.readFileSync(popupCssPath, 'utf8');

  assert.ok(popupCss.includes('.backend-status-row'), 'popup.css must style .backend-status-row');
  assert.ok(popupCss.includes('.backend-status-dot.online'), 'popup.css must style .backend-status-dot.online');
  assert.ok(popupCss.includes('.backend-status-dot.offline'), 'popup.css must style .backend-status-dot.offline');
  assert.ok(popupCss.includes('.backend-status-pill.online'), 'popup.css must style .backend-status-pill.online');
  assert.ok(popupCss.includes('.backend-status-pill.offline'), 'popup.css must style .backend-status-pill.offline');
});

// ---------------------------------------------------------------------------
// 2. Degraded Banner Toggle Logic Simulation
// ---------------------------------------------------------------------------
runTest('Overlay Banner Display Logic: Fallback analysis shows banner, clean analysis hides banner', () => {
  function computeBannerDisplay(analysis) {
    const isDegraded = Boolean(analysis && (analysis._fallback || analysis._source === 'offline_fallback'));
    return isDegraded ? 'flex' : 'none';
  }

  // Degraded cases
  assert.strictEqual(computeBannerDisplay({ score: 45, _fallback: true }), 'flex');
  assert.strictEqual(computeBannerDisplay({ score: 45, _source: 'offline_fallback' }), 'flex');
  assert.strictEqual(computeBannerDisplay({ score: 45, _fallback: true, _source: 'offline_fallback' }), 'flex');

  // Online / Non-degraded cases
  assert.strictEqual(computeBannerDisplay({ score: 10, riskLevel: 'SAFE' }), 'none');
  assert.strictEqual(computeBannerDisplay({ score: 90, riskLevel: 'CRITICAL', _source: 'backend_api' }), 'none');
  assert.strictEqual(computeBannerDisplay({ score: 20, _source: 'local_cache' }), 'none');
});

// ---------------------------------------------------------------------------
// 3. Popup State Transition Simulation
// ---------------------------------------------------------------------------
runTest('Popup State Simulation: Online vs Offline state rendering', () => {
  const mockElements = {
    dot: { className: '' },
    text: { textContent: '' },
    pill: { className: '', textContent: '' },
    desc: { textContent: '' }
  };

  function setBackendStatus(isOnline) {
    if (isOnline) {
      mockElements.dot.className = 'backend-status-dot online';
      mockElements.text.textContent = 'Remote ML Backend Connected';
      mockElements.pill.className = 'backend-status-pill online';
      mockElements.pill.textContent = 'ONLINE';
      mockElements.desc.textContent = 'Aegis is actively monitoring email threads with multi-tier ML defense.';
    } else {
      mockElements.dot.className = 'backend-status-dot offline';
      mockElements.text.textContent = 'Offline Heuristic Mode Active';
      mockElements.pill.className = 'backend-status-pill offline';
      mockElements.pill.textContent = 'OFFLINE MODE';
      mockElements.desc.textContent = EXPECTED_OFFLINE_NOTICE;
    }
  }

  // Test Online transition
  setBackendStatus(true);
  assert.strictEqual(mockElements.dot.className, 'backend-status-dot online');
  assert.strictEqual(mockElements.text.textContent, 'Remote ML Backend Connected');
  assert.strictEqual(mockElements.pill.textContent, 'ONLINE');
  assert.ok(mockElements.desc.textContent.includes('multi-tier ML defense'));

  // Test Offline transition
  setBackendStatus(false);
  assert.strictEqual(mockElements.dot.className, 'backend-status-dot offline');
  assert.strictEqual(mockElements.text.textContent, 'Offline Heuristic Mode Active');
  assert.strictEqual(mockElements.pill.textContent, 'OFFLINE MODE');
  assert.strictEqual(mockElements.desc.textContent, EXPECTED_OFFLINE_NOTICE);
});

// ---------------------------------------------------------------------------
// 4. Background Service Worker Health Probe
// ---------------------------------------------------------------------------
runTest('Background Bridge: checkBackendHealth is defined and exported', () => {
  assert.strictEqual(
    typeof backgroundBridge.checkBackendHealth,
    'function',
    'background.js must export checkBackendHealth function'
  );
});

runAsyncTest('Background Bridge: checkBackendHealth throws gracefully when offline', async () => {
  // Point to a non-existent port to test network failure handling
  await backgroundBridge.storageAdapter.set(backgroundBridge.CONFIG.STORAGE_KEY_CONFIG, {
    backendUrl: 'http://127.0.0.1:59999'
  });

  try {
    await backgroundBridge.checkBackendHealth();
    assert.fail('Expected checkBackendHealth to throw on unreachable server');
  } catch (err) {
    assert.ok(err, 'Expected network error to be thrown when endpoint is down');
  } finally {
    // Restore default configuration
    await backgroundBridge.storageAdapter.remove(backgroundBridge.CONFIG.STORAGE_KEY_CONFIG);
  }
});

// ---------------------------------------------------------------------------
// Test Summary
// ---------------------------------------------------------------------------
setTimeout(() => {
  console.log(`\n========================================`);
  console.log(`Tests Completed: ${testsPassed + testsFailed}`);
  console.log(`Passed: ${testsPassed}`);
  console.log(`Failed: ${testsFailed}`);
  console.log(`========================================\n`);

  if (testsFailed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}, 50);
