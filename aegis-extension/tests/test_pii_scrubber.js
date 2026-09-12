/**
 * Automated Test Suite for Aegis Client-Side PII Scrubber (Milestone 2.1)
 * Compliance: Republic Act No. 10173 (Philippine Data Privacy Act of 2012)
 * Specification: Implementation Plan §5.1.3
 */

const assert = require('assert');
const scrubber = require('../pii_scrubber.js');

console.log('Running Aegis PII Scrubber Test Suite...\n');

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

// 1. Email Redaction
runTest('Redacts multiple email addresses into [EMAIL]', () => {
  const input = 'Contact john.doe@example.com or support@bank-security.co.uk immediately.';
  const result = scrubber.scrubText(input);
  assert.strictEqual(
    result.scrubbedText,
    'Contact [EMAIL] or [EMAIL] immediately.'
  );
  assert.strictEqual(result.redactions.email, 2);
});

// 2. Telephone Redaction
runTest('Redacts international E.164, NANP, and local phone numbers into [PHONE]', () => {
  const input = 'Call +63 917 123 4567, 0918-123-4567, (555) 234-5678, or 555-987-6543.';
  const result = scrubber.scrubText(input);
  assert.strictEqual(
    result.scrubbedText,
    'Call [PHONE], [PHONE], [PHONE], or [PHONE].'
  );
  assert.strictEqual(result.redactions.phone, 4);
});

// 3. Payment Card Redaction with Luhn Checksum
runTest('Redacts valid payment card numbers into [CARD_NUMBER] via Luhn algorithm', () => {
  const validVisa = '4532 0150 0000 0049'; // Passes Luhn
  const invalidCard = '4532 0150 0000 0040'; // Fails Luhn check digit
  const input = `Charged card ${validVisa} and fake ${invalidCard}.`;
  const result = scrubber.scrubText(input);
  assert.strictEqual(
    result.scrubbedText,
    `Charged card [CARD_NUMBER] and fake ${invalidCard}.`
  );
  assert.strictEqual(result.redactions.card, 1);
});

// 3b. Luhn boundary tests
runTest('Luhn algorithm rejects 12-digit string (below minimum)', () => {
  assert.strictEqual(scrubber.isValidLuhn('123456789012'), false);
});
runTest('Luhn algorithm rejects 20-digit string (above maximum)', () => {
  assert.strictEqual(scrubber.isValidLuhn('12345678901234567890'), false);
});
runTest('Luhn algorithm accepts valid 13-digit Visa (4111111111119)', () => {
  assert.strictEqual(scrubber.isValidLuhn('4111111111119'), true);
});

// 4. Government IDs (US SSN, Philippine SSS, PhilHealth, TIN)
runTest('Redacts US SSN, PH SSS, PhilHealth, and TIN into [SSN]', () => {
  const input = 'SSN: 123-45-6789, SSS: 02-1234567-9, PhilHealth: 12-345678901-2, TIN: 123-456-789-000.';
  const result = scrubber.scrubText(input);
  assert.strictEqual(
    result.scrubbedText,
    'SSN: [SSN], SSS: [SSN], PhilHealth: [SSN], TIN: [SSN].'
  );
  assert.strictEqual(result.redactions.ssn, 4);
});

// 5. Contextual Names (Salutations & Sign-offs)
runTest('Redacts personal names following standard salutations and sign-offs into [NAME]', () => {
  const input = 'Dear John Doe,\nPlease verify your account.\n\nBest regards,\nMichael Santos';
  const result = scrubber.scrubText(input);
  assert.strictEqual(
    result.scrubbedText,
    'Dear [NAME],\nPlease verify your account.\n\nBest regards,\n[NAME]'
  );
  assert.strictEqual(result.redactions.name, 2);
});

// 6. Non-PII Preservation (Urgent Phishing Signals & Currency & URLs)
runTest('Preserves hyperlinks, urgent phishing signals, and monetary quantities', () => {
  const input = 'URGENT: Your account balance of $1,250.00 is frozen! Visit https://evil-phish.com/login now.';
  const result = scrubber.scrubText(input);
  assert.strictEqual(result.scrubbedText, input);
  assert.strictEqual(result.redactionCount, 0);
});

// 7. Full Email Payload Sanitization
runTest('scrubEmailPayload produces compliant sanitized payload', () => {
  const payload = {
    subject: 'Urgent notice regarding john@corp.com',
    senderName: 'Security Desk',
    senderEmail: 'alert@security.com',
    bodyText: 'Hi Alex,\nCall 555-123-4567 immediately to verify SSN 123-45-6789.',
    links: [{ url: 'https://security.com' }]
  };
  const scrubbed = scrubber.scrubEmailPayload(payload);
  assert.strictEqual(scrubbed.piiSanitized, true);
  assert.strictEqual(scrubbed.senderEmail, 'alert@security.com'); // Preserved for domain reputation
  assert.strictEqual(scrubbed.bodyText, 'Hi [NAME],\nCall [PHONE] immediately to verify SSN [SSN].');
  assert.strictEqual(scrubbed.scrubbedSubject, 'Urgent notice regarding [EMAIL]');
  assert.strictEqual(scrubbed.piiRedactionStats.total, 4);
});

// 8. Edge-case: double call statefulness (regex /g flag safety)
runTest('Calling scrubText twice on the same input yields identical results (statefulness safety)', () => {
  const input = 'Contact john@example.com or call 555-123-4567.';
  const r1 = scrubber.scrubText(input);
  const r2 = scrubber.scrubText(input);
  assert.strictEqual(r1.scrubbedText, r2.scrubbedText);
  assert.strictEqual(r1.redactions.email, r2.redactions.email);
});

// 9. Edge-case: null input robustness
runTest('scrubText handles null input without throwing', () => {
  const r = scrubber.scrubText(null);
  assert.strictEqual(r.scrubbedText, '');
  assert.strictEqual(r.redactionCount, 0);
});

// 10. Date string is NOT redacted as a government ID
runTest('Date string 09-12-2024 is NOT redacted as SSN or TIN', () => {
  const r = scrubber.scrubText('Subscription expires on 09-12-2024.');
  assert.strictEqual(r.redactions.ssn, 0);
  assert.ok(r.scrubbedText.includes('09-12-2024'));
});

// 11. 6-digit OTP is NOT redacted as a phone number
runTest('6-digit OTP code is NOT redacted as a phone number', () => {
  const r = scrubber.scrubText('Your OTP is 482916. Do not share this.');
  assert.strictEqual(r.redactions.phone, 0);
  assert.ok(r.scrubbedText.includes('482916'));
});

console.log(`\nResults: ${testsPassed} passed, ${testsFailed} failed.`);
if (testsFailed > 0) {
  process.exit(1);
}
