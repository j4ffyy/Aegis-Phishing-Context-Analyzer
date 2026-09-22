/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Test Suite: Behavioral Baseline (Milestone 3.2)
 * Specification: Implementation Plan §6.4
 *
 * Verifies:
 *  1. circularHourDistance correctness including midnight-boundary elimination
 *  2. First-time sender score (25)
 *  3. Unfamiliar sender score (15, count < 3)
 *  4. Warming-up sender score (5, count 3-4)
 *  5. Established on-schedule score (0, minDist <= 6h)
 *  6. Off-hours anomaly score (20, minDist > 6h)
 *  7. updateBehavioralBaseline persists correctly
 *  8. hoursSeen ring is capped at 50 entries
 *  9. scoreBehavioral handles null/empty sender gracefully
 * 10. clearBehavioralBaseline wipes the store
 */

'use strict';

// ---------------------------------------------------------------------------
// Minimal shim: inline the behavioral baseline module for Node.js testing
// ---------------------------------------------------------------------------

const BEHAVIORAL_STORAGE_KEY = 'aegis_behavioral_baseline';
const BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS = 5;
const BEHAVIORAL_OFF_HOURS_THRESHOLD_H = 6;

// In-memory storage shim (mirrors chrome.storage.local fallback in content_script.js)
let _mem = {};
const behavioralStorage = {
  get() { return Promise.resolve(JSON.parse(JSON.stringify(_mem))); },
  set(store) { _mem = JSON.parse(JSON.stringify(store)); return Promise.resolve(); },
  clear() { _mem = {}; return Promise.resolve(); }
};

function circularHourDistance(h1, h2) {
  const linear = Math.abs(h1 - h2);
  return Math.min(linear, 24 - linear);
}

function updateBehavioralBaseline(senderEmail, hourOfDay) {
  if (!senderEmail) return Promise.resolve();
  const hour = (hourOfDay !== undefined && hourOfDay !== null) ? Math.floor(hourOfDay) % 24 : new Date().getHours();
  return behavioralStorage.get().then(function (store) {
    const key = senderEmail.toLowerCase().trim();
    const rec = store[key] || { interactionCount: 0, hoursSeen: [], lastSeen: 0 };
    rec.interactionCount += 1;
    rec.hoursSeen.push(hour);
    if (rec.hoursSeen.length > 50) rec.hoursSeen = rec.hoursSeen.slice(rec.hoursSeen.length - 50);
    rec.lastSeen = Date.now();
    store[key] = rec;
    return behavioralStorage.set(store);
  });
}

function scoreBehavioral(senderEmail, hourOfDay) {
  const DEFAULT = { score: 15, reason: 'unknown_sender', interactionCount: 0 };
  if (!senderEmail) return Promise.resolve(DEFAULT);
  const hour = (hourOfDay !== undefined && hourOfDay !== null) ? Math.floor(hourOfDay) % 24 : new Date().getHours();
  return behavioralStorage.get().then(function (store) {
    const key = senderEmail.toLowerCase().trim();
    const rec = store[key];
    if (!rec || rec.interactionCount === 0) return { score: 25, reason: 'first_time_sender', interactionCount: 0 };
    const count = rec.interactionCount;
    const hoursSeen = rec.hoursSeen || [];
    if (count < 3) return { score: 15, reason: 'unfamiliar_sender', interactionCount: count };
    if (count < BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS) return { score: 5, reason: 'warming_up', interactionCount: count };
    const dists = hoursSeen.map(function (h) { return circularHourDistance(hour, h); });
    const minDist = dists.length > 0 ? Math.min(...dists) : BEHAVIORAL_OFF_HOURS_THRESHOLD_H + 1;
    if (minDist > BEHAVIORAL_OFF_HOURS_THRESHOLD_H) {
      return { score: 20, reason: 'off_hours_anomaly', interactionCount: count, minCircularDistanceH: Math.round(minDist * 10) / 10 };
    }
    return { score: 0, reason: 'established_on_schedule', interactionCount: count, minCircularDistanceH: Math.round(minDist * 10) / 10 };
  });
}

function clearBehavioralBaseline() { return behavioralStorage.clear(); }

// ---------------------------------------------------------------------------
// Test Runner
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log('[PASS] ' + message);
    passed++;
  } else {
    console.error('[FAIL] ' + message);
    failed++;
  }
}

async function run() {
  console.log('Running Aegis Behavioral Baseline Test Suite (Milestone 3.2)...\n');

  // 1. circularHourDistance — standard cases
  assert(circularHourDistance(9, 14) === 5, 'circularHourDistance(9, 14) = 5h');
  assert(circularHourDistance(14, 9) === 5, 'circularHourDistance(14, 9) = 5h (symmetric)');

  // 2. circularHourDistance — midnight boundary elimination
  assert(circularHourDistance(23, 1) === 2, 'circularHourDistance(23, 1) = 2h (midnight-boundary eliminated, not 22h)');
  assert(circularHourDistance(1, 23) === 2, 'circularHourDistance(1, 23) = 2h (symmetric)');

  // 3. circularHourDistance — maximum distance (noon/midnight)
  assert(circularHourDistance(0, 12) === 12, 'circularHourDistance(0, 12) = 12h (maximum circular distance)');

  // 4. circularHourDistance — same hour
  assert(circularHourDistance(9, 9) === 0, 'circularHourDistance(9, 9) = 0h (identical hours)');

  // 5. First-time sender (no history) → score 25
  await clearBehavioralBaseline();
  const r1 = await scoreBehavioral('new@example.com', 10);
  assert(r1.score === 25, 'First-time sender receives novelty baseline score of 25');
  assert(r1.reason === 'first_time_sender', 'First-time sender reason = first_time_sender');

  // 6. Null sender → returns default gracefully (no throw)
  const rNull = await scoreBehavioral(null, 10);
  assert(rNull.score === 15, 'Null sender returns safe default score of 15 without throwing');

  // 7. Empty string sender → returns default gracefully
  const rEmpty = await scoreBehavioral('', 10);
  assert(rEmpty.score === 15, 'Empty sender returns safe default score of 15 without throwing');

  // 8. Unfamiliar sender (count = 1) → score 15
  await clearBehavioralBaseline();
  await updateBehavioralBaseline('familiar@example.com', 9);
  const r2 = await scoreBehavioral('familiar@example.com', 10);
  assert(r2.score === 15, 'Sender with 1 interaction returns unfamiliarity score of 15');
  assert(r2.reason === 'unfamiliar_sender', 'Reason = unfamiliar_sender for count < 3');

  // 9. Unfamiliar sender (count = 2) → score 15
  await updateBehavioralBaseline('familiar@example.com', 10);
  const r2b = await scoreBehavioral('familiar@example.com', 10);
  assert(r2b.score === 15, 'Sender with 2 interactions still returns unfamiliarity score of 15');

  // 10. Warming-up sender (count = 3) → score 5
  await updateBehavioralBaseline('familiar@example.com', 10);
  const r3 = await scoreBehavioral('familiar@example.com', 10);
  assert(r3.score === 5, 'Sender with 3 interactions returns warming-up score of 5');
  assert(r3.reason === 'warming_up', 'Reason = warming_up for count in [3, 4]');

  // 11. Warming-up sender (count = 4) → score 5
  await updateBehavioralBaseline('familiar@example.com', 10);
  const r4 = await scoreBehavioral('familiar@example.com', 10);
  assert(r4.score === 5, 'Sender with 4 interactions still returns warming-up score of 5');

  // 12. Established on-schedule (count >= 5, email at typical hour) → score 0
  await updateBehavioralBaseline('familiar@example.com', 10); // 5th interaction at hour 10
  // Score at hour 9 — circular distance to hour 10 is 1h (<= 6h threshold)
  const r5 = await scoreBehavioral('familiar@example.com', 9);
  assert(r5.score === 0, 'Established sender at typical hour receives score of 0 (on-schedule)');
  assert(r5.reason === 'established_on_schedule', 'Reason = established_on_schedule');

  // 13. Off-hours anomaly (count >= 5, email far outside pattern) → score 20
  // All 5 interactions at hour 10; score at hour 23 → circular distance = min(13, 11) = 11h > 6h
  await clearBehavioralBaseline();
  for (let i = 0; i < 5; i++) await updateBehavioralBaseline('cfo@company.com', 10);
  const r6 = await scoreBehavioral('cfo@company.com', 23);
  assert(r6.score === 20, 'Established sender at off-hours receives anomaly score of 20');
  assert(r6.reason === 'off_hours_anomaly', 'Reason = off_hours_anomaly');
  assert(r6.minCircularDistanceH > BEHAVIORAL_OFF_HOURS_THRESHOLD_H,
    'minCircularDistanceH (' + r6.minCircularDistanceH + 'h) exceeds 6h threshold');

  // 14. updateBehavioralBaseline persists interactionCount correctly
  await clearBehavioralBaseline();
  await updateBehavioralBaseline('persist@test.com', 8);
  await updateBehavioralBaseline('persist@test.com', 9);
  await updateBehavioralBaseline('persist@test.com', 10);
  const store = await behavioralStorage.get();
  const rec = store['persist@test.com'];
  assert(rec && rec.interactionCount === 3, 'interactionCount persists across 3 calls');
  assert(rec && rec.hoursSeen.length === 3, 'hoursSeen has 3 entries after 3 updates');
  assert(rec && JSON.stringify(rec.hoursSeen) === '[8,9,10]', 'hoursSeen values are [8,9,10]');

  // 15. hoursSeen ring cap at 50 entries
  await clearBehavioralBaseline();
  for (let i = 0; i < 55; i++) await updateBehavioralBaseline('capped@test.com', i % 24);
  const storeCap = await behavioralStorage.get();
  const recCap = storeCap['capped@test.com'];
  assert(recCap && recCap.hoursSeen.length === 50, 'hoursSeen ring is capped at 50 entries (not ' + (recCap ? recCap.hoursSeen.length : 'null') + ')');
  assert(recCap && recCap.interactionCount === 55, 'interactionCount correctly records all 55 interactions despite ring cap');

  // 16. clearBehavioralBaseline wipes the store
  await clearBehavioralBaseline();
  const storeAfterClear = await behavioralStorage.get();
  assert(Object.keys(storeAfterClear).length === 0, 'clearBehavioralBaseline wipes all records from storage');

  // 17. Multiple senders are isolated in the same store
  await clearBehavioralBaseline();
  await updateBehavioralBaseline('alice@corp.com', 9);
  await updateBehavioralBaseline('bob@corp.com', 14);
  const storeIso = await behavioralStorage.get();
  assert(storeIso['alice@corp.com'] && storeIso['alice@corp.com'].interactionCount === 1, 'alice@corp.com has 1 interaction');
  assert(storeIso['bob@corp.com'] && storeIso['bob@corp.com'].interactionCount === 1, 'bob@corp.com has 1 interaction');
  assert(!storeIso['charlie@corp.com'], 'charlie@corp.com has no record (not yet seen)');

  console.log('\n========================================');
  console.log('Behavioral Baseline Results: ' + passed + ' passed, ' + failed + ' failed.');
  console.log('========================================\n');
  if (failed > 0) process.exit(1);
}

run().catch(function (err) {
  console.error('UNHANDLED ERROR:', err);
  process.exit(1);
});