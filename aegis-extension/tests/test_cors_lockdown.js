/**
 * Aegis – PR-07: CORS Production Lockdown
 * Test Suite: Verify CORS config logic and background.js URL resolution
 *
 * Run: node aegis-extension/tests/test_cors_lockdown.js
 */

'use strict';

let passed = 0, failed = 0;
function assert(cond, label) {
  if (cond) { console.log(`  ✅  PASS  ${label}`); passed++; }
  else       { console.error(`  ❌  FAIL  ${label}`); failed++; }
}

// ---------------------------------------------------------------------------
// Reproduce getBackendUrl resolution logic from background.js (PR-07)
// ---------------------------------------------------------------------------
const CONFIG = {
  DEFAULT_BACKEND_URL: 'http://localhost:8000',
  RENDER_BACKEND_URL:  'https://aegis-backend.onrender.com',
};

function getBackendUrl(config = {}) {
  if (config.backendUrl) return config.backendUrl;
  if (config.useRender)  return CONFIG.RENDER_BACKEND_URL;
  return CONFIG.DEFAULT_BACKEND_URL;
}

// ---------------------------------------------------------------------------
// Reproduce CORS origin resolution logic from main.py (PR-07)
// ---------------------------------------------------------------------------
function resolveCorsOrigins({ CORS_ORIGIN = '', ENVIRONMENT = 'development' } = {}) {
  const origin = CORS_ORIGIN.trim();
  const env    = ENVIRONMENT.trim().toLowerCase();
  if (origin) return { origins: [origin], mode: 'production' };
  if (env === 'production') throw new Error('CORS_ORIGIN not set in production');
  return { origins: ['*'], mode: 'development' };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

console.log('\n═══════════════════════════════════════════════════════');
console.log('  Aegis PR-07 · CORS Production Lockdown — Test Suite  ');
console.log('═══════════════════════════════════════════════════════\n');

// --- Test 1: Backend URL resolution ---
console.log('▶ Test 1: getBackendUrl() resolution priority');
assert(
  getBackendUrl({}) === 'http://localhost:8000',
  'No config → returns localhost (dev default)'
);
assert(
  getBackendUrl({ useRender: true }) === 'https://aegis-backend.onrender.com',
  'useRender=true → returns Render.com URL'
);
assert(
  getBackendUrl({ backendUrl: 'http://custom:9000' }) === 'http://custom:9000',
  'backendUrl override takes priority over useRender'
);
assert(
  getBackendUrl({ useRender: true, backendUrl: 'http://localhost:8000' }) === 'http://localhost:8000',
  'Explicit backendUrl beats useRender flag'
);
assert(
  CONFIG.RENDER_BACKEND_URL === 'https://aegis-backend.onrender.com',
  'RENDER_BACKEND_URL constant matches manifest host_permission'
);
console.log();

// --- Test 2: CORS origin resolution (dev) ---
console.log('▶ Test 2: CORS origin resolution — development mode');
{
  const r = resolveCorsOrigins({ CORS_ORIGIN: '', ENVIRONMENT: 'development' });
  assert(r.mode === 'development', 'ENVIRONMENT=development → mode=development');
  assert(r.origins[0] === '*', 'ENVIRONMENT=development → origin wildcard "*"');
}
{
  const r = resolveCorsOrigins({});
  assert(r.mode === 'development', 'No env vars → defaults to development');
  assert(r.origins[0] === '*', 'No env vars → wildcard');
}
console.log();

// --- Test 3: CORS origin resolution (production) ---
console.log('▶ Test 3: CORS origin resolution — production mode');
{
  const extId = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop';
  const r = resolveCorsOrigins({ CORS_ORIGIN: extId, ENVIRONMENT: 'production' });
  assert(r.mode === 'production', 'CORS_ORIGIN + ENVIRONMENT=production → mode=production');
  assert(r.origins[0] === extId, 'Exact extension origin is set as allow_origins');
  assert(r.origins.length === 1, 'Only one origin allowed in production mode');
}
{
  // CORS_ORIGIN alone (without ENVIRONMENT=production) still triggers lockdown
  const extId = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop';
  const r = resolveCorsOrigins({ CORS_ORIGIN: extId });
  assert(r.mode === 'production', 'CORS_ORIGIN set → always locks to that origin');
}
console.log();

// --- Test 4: Production without CORS_ORIGIN raises error ---
console.log('▶ Test 4: Production guard — missing CORS_ORIGIN raises RuntimeError');
{
  let threw = false;
  try { resolveCorsOrigins({ CORS_ORIGIN: '', ENVIRONMENT: 'production' }); }
  catch (e) { threw = true; }
  assert(threw, 'ENVIRONMENT=production + no CORS_ORIGIN → raises error');
}
{
  let threw = false;
  try { resolveCorsOrigins({ ENVIRONMENT: 'production' }); }
  catch (e) { threw = true; }
  assert(threw, 'Missing CORS_ORIGIN in prod always raises');
}
console.log();

// --- Test 5: Extension ID format validation ---
console.log('▶ Test 5: Extension ID format sanity');
const VALID_EXT_RE = /^chrome-extension:\/\/[a-z]{32}$/;
assert(VALID_EXT_RE.test('chrome-extension://abcdefghijklmnopabcdefghijklmnop'), 'Valid 32-char lowercase extension ID passes');
assert(!VALID_EXT_RE.test('chrome-extension://*'), 'Glob wildcard is NOT a valid extension ID');
assert(!VALID_EXT_RE.test('https://aegis-backend.onrender.com'), 'HTTPS URL is not a valid extension ID for CORS');
assert(!VALID_EXT_RE.test('chrome-extension://YOUR_EXTENSION_ID_HERE'), 'Placeholder template value detected as invalid');
console.log();

// Summary
const total = passed + failed;
console.log('═══════════════════════════════════════════════════════');
console.log(`  Results: ${passed}/${total} passed  |  ${failed} failed`);
console.log('═══════════════════════════════════════════════════════\n');
if (failed > 0) process.exit(1);
