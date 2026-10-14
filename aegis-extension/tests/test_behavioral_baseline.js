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

const SUSPICIOUS_BEHAVIORAL_EXTENSIONS = new Set([
  'zip', 'rar', '7z', 'tar', 'gz', 'iso', 'img',
  'exe', 'scr', 'vbs', 'bat', 'cmd', 'js', 'wsf', 'ps1', 'hta', 'html', 'htm'
]);

function extractExtension(filename) {
  if (!filename || typeof filename !== 'string') return '';
  const parts = filename.toLowerCase().trim().split('.');
  return parts.length > 1 ? parts.pop() : '';
}

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

function updateBehavioralBaseline(senderEmail, hourOfDay, dayOfWeek, attachmentNames) {
  if (!senderEmail) return Promise.resolve();
  const hour = (hourOfDay !== undefined && hourOfDay !== null) ? Math.floor(hourOfDay) % 24 : new Date().getHours();
  const day = (dayOfWeek !== undefined && dayOfWeek !== null) ? Math.floor(dayOfWeek) % 7 : new Date().getDay();
  const attachList = Array.isArray(attachmentNames) ? attachmentNames : [];

  return behavioralStorage.get().then(function (store) {
    const key = senderEmail.toLowerCase().trim();
    const rec = store[key] || {
      interactionCount: 0,
      hoursSeen: [],
      daysSeen: [],
      knownExtensions: [],
      hasSentAttachments: false,
      lastSeen: 0
    };

    rec.interactionCount += 1;
    if (!Array.isArray(rec.hoursSeen)) rec.hoursSeen = [];
    rec.hoursSeen.push(hour);
    if (rec.hoursSeen.length > 50) rec.hoursSeen = rec.hoursSeen.slice(rec.hoursSeen.length - 50);

    if (!Array.isArray(rec.daysSeen)) rec.daysSeen = [];
    rec.daysSeen.push(day);
    if (rec.daysSeen.length > 50) rec.daysSeen = rec.daysSeen.slice(rec.daysSeen.length - 50);

    if (!Array.isArray(rec.knownExtensions)) rec.knownExtensions = [];
    if (attachList.length > 0) {
      rec.hasSentAttachments = true;
      attachList.forEach(function (att) {
        const ext = extractExtension(att);
        if (ext && rec.knownExtensions.indexOf(ext) === -1) {
          rec.knownExtensions.push(ext);
        }
      });
    }

    rec.lastSeen = Date.now();
    store[key] = rec;
    return behavioralStorage.set(store);
  });
}

function scoreBehavioral(senderEmail, hourOfDay, dayOfWeek, attachmentNames) {
  const DEFAULT = {
    score: 15,
    reason: 'unknown_sender',
    reasons: ['unknown_sender'],
    interactionCount: 0,
    minCircularDistanceH: null,
    dayOfWeek: null,
    isWeekend: false,
    hasNovelAttachment: false,
    novelExtensions: []
  };
  if (!senderEmail) return Promise.resolve(DEFAULT);

  const hour = (hourOfDay !== undefined && hourOfDay !== null) ? Math.floor(hourOfDay) % 24 : new Date().getHours();
  const day = (dayOfWeek !== undefined && dayOfWeek !== null) ? Math.floor(dayOfWeek) % 7 : new Date().getDay();
  const isWeekend = (day === 0 || day === 6);
  const attachList = Array.isArray(attachmentNames) ? attachmentNames : [];
  const currentExtensions = attachList.map(extractExtension).filter(Boolean);

  return behavioralStorage.get().then(function (store) {
    const key = senderEmail.toLowerCase().trim();
    const rec = store[key];

    // 1. Novelty Scoring
    if (!rec || rec.interactionCount === 0) {
      return {
        score: 25,
        reason: 'first_time_sender',
        reasons: ['first_time_sender'],
        interactionCount: 0,
        minCircularDistanceH: null,
        dayOfWeek: day,
        isWeekend: isWeekend,
        hasNovelAttachment: false,
        novelExtensions: []
      };
    }

    const count = rec.interactionCount;
    const hoursSeen = Array.isArray(rec.hoursSeen) ? rec.hoursSeen : [];
    const daysSeen = Array.isArray(rec.daysSeen) ? rec.daysSeen : [];
    const knownExts = Array.isArray(rec.knownExtensions) ? rec.knownExtensions : [];

    if (count < 3) {
      return {
        score: 15,
        reason: 'unfamiliar_sender',
        reasons: ['unfamiliar_sender'],
        interactionCount: count,
        minCircularDistanceH: null,
        dayOfWeek: day,
        isWeekend: isWeekend,
        hasNovelAttachment: false,
        novelExtensions: []
      };
    }

    let noveltyBase = 0;
    const reasons = [];

    if (count < BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS) {
      noveltyBase = 5;
      reasons.push('warming_up');
    } else {
      reasons.push('established_sender');
    }

    let penalty = 0;

    // 2. Off-Hours Timing Anomaly (Circular Hour Distance)
    let minDist = null;
    if (count >= BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS && hoursSeen.length > 0) {
      const dists = hoursSeen.map(function (h) { return circularHourDistance(hour, h); });
      minDist = Math.min(...dists);
      if (minDist > BEHAVIORAL_OFF_HOURS_THRESHOLD_H) {
        penalty += 20;
        reasons.push('off_hours_anomaly');
      }
    }

    // 3. Day-of-Week Anomaly (Weekday routine vs Weekend transmission)
    let weekendAnomaly = false;
    if (count >= BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS && isWeekend && daysSeen.length >= 5) {
      const hasPriorWeekend = daysSeen.some(function (d) { return d === 0 || d === 6; });
      if (!hasPriorWeekend) {
        penalty += 10;
        weekendAnomaly = true;
        reasons.push('weekend_anomaly');
      }
    }

    // 4. Attachment Extension Novelty
    const novelExtensions = [];
    if (count >= 3 && currentExtensions.length > 0) {
      currentExtensions.forEach(function (ext) {
        if (SUSPICIOUS_BEHAVIORAL_EXTENSIONS.has(ext) && knownExts.indexOf(ext) === -1) {
          novelExtensions.push(ext);
        }
      });
      if (novelExtensions.length > 0) {
        penalty += 15;
        reasons.push('novel_attachment_anomaly');
      }
    }

    const totalScore = Math.min(100, noveltyBase + penalty);
    let primaryReason = reasons.length > 1 && reasons[0] === 'established_sender' ? reasons[1] : (reasons[0] || 'established_on_schedule');

    if (totalScore === 0 && reasons.indexOf('established_on_schedule') === -1) {
      primaryReason = 'established_on_schedule';
    }

    return {
      score: totalScore,
      reason: primaryReason,
      reasons: reasons,
      interactionCount: count,
      minCircularDistanceH: minDist !== null ? Math.round(minDist * 10) / 10 : null,
      dayOfWeek: day,
      isWeekend: isWeekend,
      hasNovelAttachment: novelExtensions.length > 0,
      novelExtensions: novelExtensions
    };
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

  // 18. PR-03: Weekend anomaly detection for weekday-only sender
  await clearBehavioralBaseline();
  // Simulate 5 weekday interactions (Mon-Fri, days 1 to 5) at 10:00
  for (let d = 1; d <= 5; d++) {
    await updateBehavioralBaseline('weekday.boss@corp.com', 10, d, []);
  }
  // Now evaluate on Sunday (day 0) at 10:00 (on-schedule hour, but weekend anomaly)
  const rWeekend = await scoreBehavioral('weekday.boss@corp.com', 10, 0, []);
  assert(rWeekend.score === 10, 'Established weekday sender communicating on weekend gets penalty score 10');
  assert(rWeekend.reasons.includes('weekend_anomaly'), 'Reasons includes weekend_anomaly');
  assert(rWeekend.isWeekend === true, 'isWeekend is true on Sunday');

  // 19. PR-03: Normal weekday interaction has no weekend penalty
  const rWeekday = await scoreBehavioral('weekday.boss@corp.com', 10, 2, []); // Tuesday
  assert(rWeekday.score === 0, 'Established weekday sender on Tuesday gets score 0');
  assert(rWeekday.reason === 'established_on_schedule', 'Reason is established_on_schedule');

  // 20. PR-03: Novel attachment anomaly (known sender suddenly sending .zip archive)
  await clearBehavioralBaseline();
  // Sender is established (5 interactions) and previously only sent harmless PDFs
  for (let i = 0; i < 5; i++) {
    await updateBehavioralBaseline('vendor@trusted.com', 11, 2, ['invoice.pdf', 'spec.docx']);
  }
  // Now sender sends an unexpected archive
  const rAttach = await scoreBehavioral('vendor@trusted.com', 11, 2, ['urgent_update.zip']);
  assert(rAttach.score === 15, 'Sender with novel archive attachment receives anomaly score 15');
  assert(rAttach.reasons.includes('novel_attachment_anomaly'), 'Reasons includes novel_attachment_anomaly');
  assert(rAttach.hasNovelAttachment === true, 'hasNovelAttachment is true');
  assert(rAttach.novelExtensions.includes('zip'), 'novelExtensions lists zip');

  // 21. PR-03: Routine attachment from established sender gets no attachment penalty
  const rRoutine = await scoreBehavioral('vendor@trusted.com', 11, 2, ['monthly_summary.pdf']);
  assert(rRoutine.score === 0, 'Sender sending previously known .pdf extension gets score 0');
  assert(rRoutine.hasNovelAttachment === false, 'hasNovelAttachment is false');

  // 22. PR-03: Compound anomaly (Off-hours + Weekend + Suspicious Script)
  await clearBehavioralBaseline();
  // Simulate 5 weekday interactions at 10:00 without scripts
  for (let d = 1; d <= 5; d++) {
    await updateBehavioralBaseline('weekday.boss@corp.com', 10, d, ['report.pdf']);
  }
  // Evaluates at 23:00 on Saturday (day 6) with a .vbs script
  const rCompound = await scoreBehavioral('weekday.boss@corp.com', 23, 6, ['payment.vbs']);
  // 20 (off-hours) + 10 (weekend) + 15 (novel script) = 45 points
  assert(rCompound.score === 45, 'Compound off-hours + weekend + novel script accumulates 45 points');
  assert(rCompound.reasons.includes('off_hours_anomaly'), 'Includes off_hours_anomaly');
  assert(rCompound.reasons.includes('weekend_anomaly'), 'Includes weekend_anomaly');
  assert(rCompound.reasons.includes('novel_attachment_anomaly'), 'Includes novel_attachment_anomaly');

  console.log('\n========================================');
  console.log('Behavioral Baseline Results: ' + passed + ' passed, ' + failed + ' failed.');
  console.log('========================================\n');
  if (failed > 0) process.exit(1);
}

run().catch(function (err) {
  console.error('UNHANDLED ERROR:', err);
  process.exit(1);
});