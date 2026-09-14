/**
 * Automated Test Suite for Aegis Local Heuristics Scoring Engine (Milestone 2.2)
 * Specification: Implementation Plan §6.2 & §5.1
 */

const assert = require('assert');
const heuristics = require('../local_heuristics.js');

console.log('Running Aegis Local Heuristics Test Suite...\n');

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

// ---------------------------------------------------------------------------
// 1. Helper Algorithm Tests
// ---------------------------------------------------------------------------
runTest('Levenshtein distance calculation correctness', () => {
  assert.strictEqual(heuristics.levenshtein('paypal', 'paypal'), 0);
  assert.strictEqual(heuristics.levenshtein('paypa1', 'paypal'), 1);
  assert.strictEqual(heuristics.levenshtein('paypa11', 'paypal'), 2);
  assert.strictEqual(heuristics.levenshtein('bdo', 'bpi'), 2);
});

runTest('IP address host recognition', () => {
  assert.strictEqual(heuristics.isIPAddress('192.168.1.1'), true);
  assert.strictEqual(heuristics.isIPAddress('45.33.32.156'), true);
  assert.strictEqual(heuristics.isIPAddress('google.com'), false);
  assert.strictEqual(heuristics.isIPAddress('192.168.1.com'), false);
});

// ---------------------------------------------------------------------------
// 2. Benign / Legitimate Email Test
// ---------------------------------------------------------------------------
runTest('Benign routine business email evaluates as Safe (score < 45)', () => {
  const benignEmail = {
    subject: 'Project Status Update - Sprint 4',
    senderName: 'Alice Johnson',
    senderEmail: 'alice.johnson@corporate-internal.com',
    bodyText: 'Hi Team,\nPlease find the meeting minutes attached. We will review sprint progress next Tuesday.\nRegards, Alice',
    links: [
      { url: 'https://corporate-internal.com/docs/sprint4', text: 'corporate-internal.com' }
    ],
    attachments: ['minutes.pdf']
  };

  const result = heuristics.evaluate(benignEmail);
  assert.strictEqual(result.riskLevel, 'Safe');
  assert.strictEqual(result.riskClass, 'threat-safe');
  assert.ok(result.score < 45, `Expected score < 45, got ${result.score}`);
  assert.strictEqual(result.flags.length, 0);
  assert.ok(result.xai.includes('passed client-side heuristic inspection'));
});

// ---------------------------------------------------------------------------
// 3. Urgency & Coercive Keywords Test
// ---------------------------------------------------------------------------
runTest('Urgency and coercive keywords scale penalty properly up to 30 pts', () => {
  const email = {
    subject: 'URGENT: Account suspended! Immediate action required',
    senderName: 'Notification Desk',
    senderEmail: 'alert@standard-corp.com',
    bodyText: 'Your account locked due to unauthorized access. Verify your account within 24 hours or access revoked!',
    links: [],
    attachments: []
  };

  const urgency = heuristics.evaluateUrgency(`${email.subject} ${email.bodyText}`);
  assert.ok(urgency.hits.length >= 3, `Expected at least 3 hits, got ${urgency.hits.length}`);
  assert.strictEqual(urgency.points, Math.min(urgency.hits.length * 8, 30));

  const result = heuristics.evaluate(email);
  const flag = result.flags.find(f => f.id === 'RULE_URGENCY');
  assert.ok(flag, 'RULE_URGENCY flag not found');
  assert.ok(result.score >= 24);
});

// ---------------------------------------------------------------------------
// 4. Deceptive Anchor Text Mismatch Test
// ---------------------------------------------------------------------------
runTest('Flags deceptive hyperlinks where visible anchor domain differs from target href', () => {
  const email = {
    subject: 'Account Notice',
    senderName: 'Billing Service',
    senderEmail: 'billing@trusted-vendor.com',
    bodyText: 'Please log in below.',
    links: [
      {
        url: 'http://malicious-harvesting-site.com/login',
        text: 'Click here to sign in at https://paypal.com/signin'
      }
    ],
    attachments: []
  };

  const result = heuristics.evaluate(email);
  const flag = result.flags.find(f => f.id === 'RULE_DECEPTIVE_LINK');
  assert.ok(flag, 'RULE_DECEPTIVE_LINK not triggered');
  assert.strictEqual(flag.points, 35);
  assert.ok(flag.evidence.includes('paypal.com'));
});

// ---------------------------------------------------------------------------
// 5. Direct IP Host Hyperlink Test
// ---------------------------------------------------------------------------
runTest('Flags hyperlinks targeting raw IPv4 addresses with 35 penalty points', () => {
  const email = {
    subject: 'Security Alert',
    senderName: 'Admin',
    senderEmail: 'admin@internal.com',
    bodyText: 'Visit gateway',
    links: [
      {
        url: 'http://192.168.100.55:8080/secure-login',
        text: 'Access Portal'
      }
    ],
    attachments: []
  };

  const result = heuristics.evaluate(email);
  const flag = result.flags.find(f => f.id === 'RULE_IP_URL');
  assert.ok(flag, 'RULE_IP_URL not triggered');
  assert.strictEqual(flag.points, 35);
});

// ---------------------------------------------------------------------------
// 6. Suspicious TLDs in Link and Sender
// ---------------------------------------------------------------------------
runTest('Flags high-abuse TLDs (.top, .xyz) in links and sender domain', () => {
  const email = {
    subject: 'Notice',
    senderName: 'Promotions',
    senderEmail: 'rewards@deals-portal.top',
    bodyText: 'Claim rewards below',
    links: [
      { url: 'https://free-crypto-giveaway.xyz/claim', text: 'Claim' }
    ],
    attachments: []
  };

  const result = heuristics.evaluate(email);
  const senderTldFlag = result.flags.find(f => f.id === 'RULE_SENDER_SUSPICIOUS_TLD');
  const linkTldFlag = result.flags.find(f => f.id === 'RULE_SUSPICIOUS_TLD');

  assert.ok(senderTldFlag, 'RULE_SENDER_SUSPICIOUS_TLD not triggered');
  assert.ok(linkTldFlag, 'RULE_SUSPICIOUS_TLD not triggered');
  assert.ok(result.score >= 45, `Expected score >= 45, got ${result.score}`);
  assert.strictEqual(result.riskLevel, 'Warning');
});

// ---------------------------------------------------------------------------
// 7. Brand Domain Typosquatting (Levenshtein Distance)
// ---------------------------------------------------------------------------
runTest('Detects brand typosquatting on sender domain (e.g., paypa1.com, bdo-alert.com)', () => {
  const email1 = {
    subject: 'Invoice confirmation',
    senderName: 'Customer Support',
    senderEmail: 'service@paypa1.com',
    bodyText: 'Your transaction is complete.',
    links: [],
    attachments: []
  };

  const result1 = heuristics.evaluate(email1);
  const typoFlag1 = result1.flags.find(f => f.id === 'RULE_TYPOSQUATTING');
  assert.ok(typoFlag1, 'RULE_TYPOSQUATTING not triggered for paypa1.com');
  assert.strictEqual(typoFlag1.points, 35);

  const email2 = {
    subject: 'BDO Security Notice',
    senderName: 'BDO Security',
    senderEmail: 'alert@bdo-security.com',
    bodyText: 'Security check required.',
    links: [],
    attachments: []
  };

  const result2 = heuristics.evaluate(email2);
  const typoFlag2 = result2.flags.find(f => f.id === 'RULE_TYPOSQUATTING');
  assert.ok(typoFlag2, 'RULE_TYPOSQUATTING not triggered for hyphenated bdo-security.com');
});

// ---------------------------------------------------------------------------
// 8. Free Email Provider Impersonating Official Organization
// ---------------------------------------------------------------------------
runTest('Flags official brand/department impersonation originating from free webmail (@gmail.com)', () => {
  const email = {
    subject: 'Important Verification',
    senderName: 'BDO Unibank Customer Support Desk',
    senderEmail: 'bdo_support_ph992@gmail.com',
    bodyText: 'Please verify your bank details.',
    links: [],
    attachments: []
  };

  const result = heuristics.evaluate(email);
  const spoofFlag = result.flags.find(f => f.id === 'RULE_FREE_EMAIL_SPOOF');
  assert.ok(spoofFlag, 'RULE_FREE_EMAIL_SPOOF not triggered');
  assert.strictEqual(spoofFlag.points, 30);
});

// ---------------------------------------------------------------------------
// 9. Dangerous / Executable Attachments
// ---------------------------------------------------------------------------
runTest('Flags high-risk executable attachments (.exe, .scr, .vbs)', () => {
  const email = {
    subject: 'Overdue Statement',
    senderName: 'Accounts Payable',
    senderEmail: 'ap@partner-billing.com',
    bodyText: 'See attached invoice.',
    links: [],
    attachments: ['Invoice_Q3.exe']
  };

  const result = heuristics.evaluate(email);
  const attachFlag = result.flags.find(f => f.id === 'RULE_DANGEROUS_ATTACHMENT');
  assert.ok(attachFlag, 'RULE_DANGEROUS_ATTACHMENT not triggered');
  assert.strictEqual(attachFlag.points, 35);
});

// ---------------------------------------------------------------------------
// 10. Compound Threat Reaching Critical Tier (score >= 75)
// ---------------------------------------------------------------------------
runTest('Compound high-severity phishing scenario triggers Critical tier with detailed XAI', () => {
  const phishingEmail = {
    subject: 'URGENT: Unauthorized access detected on your BDO account!',
    senderName: 'BDO Unibank Security Team',
    senderEmail: 'alert@bdo-verification.top', // Typosquat + Suspicious TLD
    bodyText: 'Immediate action required! Your account suspended within 24 hours unless you verify immediately. Visit link below.',
    links: [
      {
        url: 'http://45.33.32.156/bdo-login', // Direct IP
        text: 'https://bdo.com.ph/secure-login' // Deceptive anchor mismatch
      }
    ],
    attachments: ['SecurityPatch.exe'] // Dangerous attachment
  };

  const result = heuristics.evaluate(phishingEmail);
  assert.strictEqual(result.riskLevel, 'Critical');
  assert.strictEqual(result.riskClass, 'threat-critical');
  assert.ok(result.score >= 75, `Expected score >= 75, got ${result.score}`);
  assert.ok(result.flags.length >= 4, `Expected at least 4 flags, got ${result.flags.length}`);
  assert.ok(result.xai.startsWith('CRITICAL RISK ALERT:'));
  assert.ok(result.layers.auth.icon.includes('exclamation') || result.layers.auth.icon.includes('times'));
  assert.strictEqual(result.layers.attach.icon, 'fa-times-circle');
});

// ---------------------------------------------------------------------------
// 11. Robustness: Null & Empty Inputs
// ---------------------------------------------------------------------------
runTest('Gracefully handles null or empty input without throwing', () => {
  const rNull = heuristics.evaluate(null);
  assert.strictEqual(rNull.score, 0);
  assert.strictEqual(rNull.riskLevel, 'Safe');

  const rEmpty = heuristics.evaluate({});
  assert.strictEqual(rEmpty.score, 0);
  assert.strictEqual(rEmpty.riskLevel, 'Safe');
});

console.log(`\nLocal Heuristics Results: ${testsPassed} passed, ${testsFailed} failed.`);
if (testsFailed > 0) {
  process.exit(1);
}
