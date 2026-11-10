/**
 * Automated Test Suite for Aegis Sensitivity Preset Tiering & Floor Preservation (Post-Defense Item 4)
 */

const assert = require('assert');

// Mock browser DOM/Chrome environment for overlay module
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
  location: { hash: '#inbox' }
};
global.document = {
  readyState: 'complete',
  createElement: () => dummyElem,
  getElementById: () => dummyElem,
  addEventListener: () => {},
  body: dummyElem,
};
global.chrome = {
  storage: {
    local: {
      get: (keys, cb) => cb({}),
      set: (data, cb) => cb && cb(),
    }
  },
  runtime: {
    sendMessage: () => {}
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

console.log('Running Aegis Preset-Aware Tiering Test Suite...\n');

// Standard presets from dashboard.js
const CONSERVATIVE = { warningThreshold: 35, criticalThreshold: 65 };
const STANDARD     = { warningThreshold: 45, criticalThreshold: 75 };
const AGGRESSIVE   = { warningThreshold: 55, criticalThreshold: 85 };

runTest('Score 70 transitions between Warning (Standard) and Critical (Conservative)', () => {
  const analysis1 = { score: 70, riskLevel: 'Warning', desc: 'Warn', xai: 'Initial' };
  overlay.applyPresetTier(analysis1, STANDARD);
  assert.strictEqual(analysis1.riskLevel, 'Warning');

  const analysis2 = { score: 70, riskLevel: 'Warning', desc: 'Warn', xai: 'Initial' };
  overlay.applyPresetTier(analysis2, CONSERVATIVE);
  assert.strictEqual(analysis2.riskLevel, 'Critical');
  assert.ok(analysis2.xai.includes('CRITICAL ALERT'));
});

runTest('Score 50 transitions between Warning (Standard) and Safe (Aggressive)', () => {
  const analysis1 = { score: 50, riskLevel: 'Warning', desc: 'Warn', xai: 'Initial' };
  overlay.applyPresetTier(analysis1, STANDARD);
  assert.strictEqual(analysis1.riskLevel, 'Warning');

  const analysis2 = { score: 50, riskLevel: 'Warning', desc: 'Warn', xai: 'Initial' };
  overlay.applyPresetTier(analysis2, AGGRESSIVE);
  assert.strictEqual(analysis2.riskLevel, 'Safe');
  assert.ok(analysis2.xai.includes('Safe under current sensitivity preset'));
});

runTest('Backend threat floor: Malicious VirusTotal link remains Critical under Aggressive preset', () => {
  const analysis = {
    score: 60, // Below aggressive crit (85) and standard crit (75)
    riskLevel: 'Critical',
    desc: 'Malicious URL confirmed',
    s_vt: 75,
    flags: [{ title: 'Malicious Hyperlink Detected', severity: 'critical' }],
    xai: 'VT confirmed malicious URL',
  };
  overlay.applyPresetTier(analysis, AGGRESSIVE);
  assert.strictEqual(analysis.riskLevel, 'Critical');
  assert.strictEqual(analysis.riskClass, 'risk-critical');
  assert.ok(analysis.xai.includes('Threat floor enforced'));
});

runTest('Backend threat floor: Malicious attachment hash remains Critical under Aggressive preset', () => {
  const analysis = {
    score: 55,
    riskLevel: 'Critical',
    desc: 'Malicious file signature',
    flags: [{ title: 'Malicious Attachment Hash Detected', severity: 'critical' }],
    xai: 'Attachment hash flagged',
  };
  overlay.applyPresetTier(analysis, AGGRESSIVE);
  assert.strictEqual(analysis.riskLevel, 'Critical');
  assert.strictEqual(analysis.riskClass, 'risk-critical');
  assert.ok(analysis.xai.includes('Threat floor enforced'));
});

runTest('Explanation text accurately reflects the final displayed tier', () => {
  const safeItem = { score: 20, riskLevel: 'Safe', desc: 'Nominal', xai: '' };
  overlay.applyPresetTier(safeItem, STANDARD);
  assert.strictEqual(safeItem.riskLevel, 'Safe');
  assert.ok(safeItem.xai.toLowerCase().includes('safe'));

  const critItem = { score: 80, riskLevel: 'Critical', desc: 'Elevated', xai: '' };
  overlay.applyPresetTier(critItem, STANDARD);
  assert.strictEqual(critItem.riskLevel, 'Critical');
  assert.ok(critItem.xai.toLowerCase().includes('critical'));
});

runTest('Conservative preset flags strictly more than Aggressive preset', () => {
  let flaggedConservative = 0;
  let flaggedAggressive = 0;
  let critConservative = 0;
  let critAggressive = 0;

  for (let s = 0; s <= 100; s++) {
    const itemC = { score: s, riskLevel: s >= 45 ? (s >= 75 ? 'Critical' : 'Warning') : 'Safe' };
    overlay.applyPresetTier(itemC, CONSERVATIVE);
    if (itemC.riskLevel !== 'Safe') flaggedConservative++;
    if (itemC.riskLevel === 'Critical') critConservative++;

    const itemA = { score: s, riskLevel: s >= 45 ? (s >= 75 ? 'Critical' : 'Warning') : 'Safe' };
    overlay.applyPresetTier(itemA, AGGRESSIVE);
    if (itemA.riskLevel !== 'Safe') flaggedAggressive++;
    if (itemA.riskLevel === 'Critical') critAggressive++;
  }

  // Conservative flags scores [35..100] (66 scores), Aggressive flags [55..100] (46 scores)
  assert.ok(flaggedConservative > flaggedAggressive, `Expected Conservative (${flaggedConservative}) > Aggressive (${flaggedAggressive})`);
  // Conservative has critical at [65..100] (36 scores), Aggressive at [85..100] (16 scores)
  assert.ok(critConservative > critAggressive, `Expected Crit Conservative (${critConservative}) > Crit Aggressive (${critAggressive})`);
});

runTest('Backend warning floor: Score 52 (heuristic >= 40) is preserved as Warning under Aggressive preset', () => {
  const analysis = {
    score: 52, // Below Aggressive warn threshold of 55
    riskLevel: 'Warning',
    s_heuristic: 42,
    desc: 'Suspicious email',
    xai: 'Elevated heuristic risk',
  };
  overlay.applyPresetTier(analysis, AGGRESSIVE);
  assert.strictEqual(analysis.riskLevel, 'Warning', 'Floor email must not be downgraded to Safe');
  assert.strictEqual(analysis.riskClass, 'risk-warning');
  assert.ok(analysis.xai.includes('Warning threat floor enforced'));
});

runTest('Backend warning floor: Score 52 (attachment + urgency) is preserved as Warning under Aggressive preset', () => {
  const analysis = {
    score: 52, // Below Aggressive warn threshold of 55
    riskLevel: 'Warning',
    s_heuristic: 25,
    s_nlp: 30,
    flags: [
      { title: 'Compressed Archive Attachment', severity: 'warn' },
      { title: 'Urgency / Coercive Language', severity: 'warn' },
    ],
    desc: 'Multi-threat email',
    xai: 'Multi-indicator detected',
  };
  overlay.applyPresetTier(analysis, AGGRESSIVE);
  assert.strictEqual(analysis.riskLevel, 'Warning', 'Floor email must not be downgraded to Safe');
  assert.strictEqual(analysis.riskClass, 'risk-warning');
  assert.ok(analysis.xai.includes('Warning threat floor enforced'));
});

console.log('\nAll 8 preset tiering, warning/critical floor, and sensitivity comparison tests passed successfully!');
