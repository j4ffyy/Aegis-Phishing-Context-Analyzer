/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Whitelist & Dual-Trigger Auto-Revocation Test Suite
 * Specification: Implementation Plan §7, §7.1 (Milestone 3.3)
 */

const assert = require('assert');
const AegisWhitelist = require('../whitelist/whitelist.js');

let passedTests = 0;
let failedTests = 0;

function runTest(testName, fn) {
  try {
    const res = fn();
    if (res && typeof res.then === 'function') {
      return res.then(() => {
        console.log(`[PASS] ${testName}`);
        passedTests++;
      }).catch((err) => {
        console.error(`[FAIL] ${testName}: ${err.message}`);
        failedTests++;
      });
    } else {
      console.log(`[PASS] ${testName}`);
      passedTests++;
      return Promise.resolve();
    }
  } catch (err) {
    console.error(`[FAIL] ${testName}: ${err.message}`);
    failedTests++;
    return Promise.resolve();
  }
}

async function runAllTests() {
  console.log('Running Aegis Whitelist & Auto-Revocation Test Suite (Milestone 3.3)...\n');

  // Ensure fresh defaults
  await AegisWhitelist.resetToDefaults();

  // Test 1: Default initial seeds
  await runTest('getWhitelist returns default seed entries when storage initializes', async () => {
    const list = await AegisWhitelist.getWhitelist();
    assert(Array.isArray(list), 'Whitelist must be an array');
    assert(list.length >= 2, 'Default seeds must contain at least 2 entries');
    const exec = list.find(e => e.email === 'executive.director@sme-corp.com');
    assert(exec, 'Default list must contain executive.director@sme-corp.com');
    assert.strictEqual(exec.allowedDomain, 'sme-corp.com');
  });

  // Test 2: Add valid entry
  await runTest('addWhitelistEntry successfully saves normalized entry with generated ID', async () => {
    const entry = await AegisWhitelist.addWhitelistEntry({
      email: 'Finance-Team@Acme-Partners.com',
      displayName: 'Acme Finance Desk',
      role: 'Procurement Partner',
      department: 'Finance'
    });
    assert.strictEqual(entry.email, 'finance-team@acme-partners.com', 'Email must be lowercased');
    assert.strictEqual(entry.allowedDomain, 'acme-partners.com', 'Allowed domain must be derived');
    assert(entry.id.startsWith('wl_'), 'ID must have wl_ prefix');
    assert(entry.addedAt, 'addedAt must be recorded');

    const current = await AegisWhitelist.getWhitelist();
    const found = current.find(e => e.email === 'finance-team@acme-partners.com');
    assert(found, 'Added entry must persist in whitelist directory');
  });

  // Test 3: Update existing entry on same email
  await runTest('addWhitelistEntry updates existing entry when email matches', async () => {
    await AegisWhitelist.addWhitelistEntry({
      email: 'finance-team@acme-partners.com',
      displayName: 'Acme Global Treasury',
      role: 'Senior Partner',
      department: 'Treasury'
    });
    const current = await AegisWhitelist.getWhitelist();
    const matches = current.filter(e => e.email === 'finance-team@acme-partners.com');
    assert.strictEqual(matches.length, 1, 'Duplicate email must update in-place without creating second record');
    assert.strictEqual(matches[0].displayName, 'Acme Global Treasury');
    assert.strictEqual(matches[0].role, 'Senior Partner');
  });

  // Test 4: Reject invalid email
  await runTest('addWhitelistEntry rejects missing or invalid email format', async () => {
    let threw = false;
    try {
      await AegisWhitelist.addWhitelistEntry({ displayName: 'No Email' });
    } catch {
      threw = true;
    }
    assert(threw, 'Should reject entry without email');
  });

  // Test 5: Remove entry by ID or email
  await runTest('removeWhitelistEntry deletes entry by email address', async () => {
    const removed = await AegisWhitelist.removeWhitelistEntry('finance-team@acme-partners.com');
    assert.strictEqual(removed, true, 'Should return true for removed item');
    const current = await AegisWhitelist.getWhitelist();
    const found = current.find(e => e.email === 'finance-team@acme-partners.com');
    assert(!found, 'Entry should no longer exist in directory');
  });

  // Test 6: Remove non-existent entry
  await runTest('removeWhitelistEntry returns false when identifier does not exist', async () => {
    const removed = await AegisWhitelist.removeWhitelistEntry('non-existent-user@nowhere.com');
    assert.strictEqual(removed, false, 'Should return false for non-existent entry');
  });

  // Test 7: Reset to defaults
  await runTest('resetToDefaults restores initial default seeds', async () => {
    await AegisWhitelist.clearWhitelist();
    let empty = await AegisWhitelist.getWhitelist();
    assert.strictEqual(empty.length, 0, 'Directory should be empty after clear');

    const restored = await AegisWhitelist.resetToDefaults();
    assert.strictEqual(restored.length, 2, 'Should restore 2 initial seed records');
  });

  // Test 8: Clean authentic whitelist match
  await runTest('checkWhitelistStatus returns whitelisted=true, score=5 for authentic sender', async () => {
    const res = await AegisWhitelist.checkWhitelistStatus({
      senderEmail: 'payroll@trusted-bank.ph',
      senderName: 'BDO Merchant Services',
      subject: 'Monthly SME Payroll Confirmation'
    }, { spfPass: true, dkimPass: true });

    assert.strictEqual(res.whitelisted, true);
    assert.strictEqual(res.revoked, false);
    assert.strictEqual(res.score, 5);
    assert.strictEqual(res.riskLevel, 'Safe');
    assert(res.matchedIdentity, 'Matched identity should be attached');
  });

  // Test 9: Case-insensitive email match
  await runTest('checkWhitelistStatus handles mixed-case email lookup', async () => {
    const res = await AegisWhitelist.checkWhitelistStatus({
      senderEmail: 'PAYROLL@TRUSTED-BANK.PH',
      senderName: 'BDO Merchant Services'
    });
    assert.strictEqual(res.whitelisted, true);
    assert.strictEqual(res.score, 5);
  });

  // Test 10: Trigger 1 — Display-Name Spoofing (VIP impersonation from free webmail)
  await runTest('Trigger 1: Display-name matches Executive Director but email is external gmail -> Auto-Revoke (95%)', async () => {
    const res = await AegisWhitelist.checkWhitelistStatus({
      senderEmail: 'exec.director.urgent@gmail.com',
      senderName: 'Executive Director',
      subject: 'URGENT: Immediate Wire Transfer Required'
    }, { spfPass: true, dkimPass: true });

    assert.strictEqual(res.whitelisted, false, 'Whitelisted status must be revoked');
    assert.strictEqual(res.revoked, true, 'Revoked flag must be true');
    assert.strictEqual(res.trigger, 'DISPLAY_NAME_SPOOFING');
    assert.strictEqual(res.score, 95, 'Enforced score must be 95');
    assert.strictEqual(res.riskLevel, 'Critical');
    assert(res.reason.includes('impersonates protected identity'), 'Reason must explain impersonation');
  });

  // Test 11: Trigger 1 — Partial/Title Match
  await runTest('Trigger 1: Display-name contains protected title -> Auto-Revoke (95%)', async () => {
    const res = await AegisWhitelist.checkWhitelistStatus({
      senderEmail: 'hacker-relay@phish-domain.xyz',
      senderName: 'Executive Director Office',
      subject: 'Account update'
    });
    assert.strictEqual(res.revoked, true);
    assert.strictEqual(res.trigger, 'DISPLAY_NAME_SPOOFING');
    assert.strictEqual(res.score, 95);
  });

  // Test 12: Legitimate Display-Name match on authorized domain
  await runTest('Legitimate display-name from authorized domain is NOT flagged as spoofing', async () => {
    const res = await AegisWhitelist.checkWhitelistStatus({
      senderEmail: 'executive.director@sme-corp.com',
      senderName: 'Executive Director',
      subject: 'Quarterly Townhall'
    }, { spfPass: true, dkimPass: true });

    assert.strictEqual(res.revoked, false, 'Should not revoke legitimate executive email');
    assert.strictEqual(res.whitelisted, true);
    assert.strictEqual(res.score, 5);
  });

  // Test 13: Trigger 2 — Cryptographic SPF validation failure
  await runTest('Trigger 2: Whitelisted sender fails SPF -> Auto-Revoke (95%)', async () => {
    const res = await AegisWhitelist.checkWhitelistStatus({
      senderEmail: 'payroll@trusted-bank.ph',
      senderName: 'BDO Merchant Services',
      spfPass: false,
      dkimPass: true
    });

    assert.strictEqual(res.whitelisted, false);
    assert.strictEqual(res.revoked, true);
    assert.strictEqual(res.trigger, 'AUTH_FAILURE');
    assert.strictEqual(res.score, 95);
    assert.strictEqual(res.riskLevel, 'Critical');
    assert(res.reason.includes('SPF'), 'Reason must indicate SPF failure');
  });

  // Test 14: Trigger 2 — Cryptographic DKIM validation failure
  await runTest('Trigger 2: Whitelisted sender fails DKIM -> Auto-Revoke (95%)', async () => {
    const res = await AegisWhitelist.checkWhitelistStatus({
      senderEmail: 'executive.director@sme-corp.com',
      senderName: 'Executive Director',
      spfPass: true,
      dkimPass: false
    });

    assert.strictEqual(res.whitelisted, false);
    assert.strictEqual(res.revoked, true);
    assert.strictEqual(res.trigger, 'AUTH_FAILURE');
    assert.strictEqual(res.score, 95);
    assert(res.reason.includes('DKIM'), 'Reason must indicate DKIM failure');
  });

  // Test 15: Trigger 2 — Dual SPF + DKIM failure
  await runTest('Trigger 2: Whitelisted sender fails both SPF and DKIM -> Auto-Revoke (95%)', async () => {
    const res = await AegisWhitelist.checkWhitelistStatus({
      senderEmail: 'executive.director@sme-corp.com',
      senderName: 'Executive Director'
    }, { spfPass: false, dkimPass: false });

    assert.strictEqual(res.revoked, true);
    assert.strictEqual(res.trigger, 'AUTH_FAILURE');
    assert.strictEqual(res.score, 95);
    assert(res.reason.includes('SPF/DKIM'));
  });

  // Test 16: Unrecognized sender
  await runTest('checkWhitelistStatus returns whitelisted=false, score=null for unlisted sender', async () => {
    const res = await AegisWhitelist.checkWhitelistStatus({
      senderEmail: 'unregistered.vendor@external.com',
      senderName: 'Vendor Representative'
    });
    assert.strictEqual(res.whitelisted, false);
    assert.strictEqual(res.revoked, false);
    assert.strictEqual(res.score, null);
  });

  // Test 17: Defensive handling for null context
  await runTest('checkWhitelistStatus gracefully handles null or empty context without throwing', async () => {
    const res1 = await AegisWhitelist.checkWhitelistStatus(null);
    assert.strictEqual(res1.whitelisted, false);
    assert.strictEqual(res1.score, null);

    const res2 = await AegisWhitelist.checkWhitelistStatus({});
    assert.strictEqual(res2.whitelisted, false);
    assert.strictEqual(res2.score, null);
  });

  // Test 18: Empty whitelist directory behavior
  await runTest('checkWhitelistStatus gracefully returns false when whitelist directory is cleared', async () => {
    await AegisWhitelist.clearWhitelist();
    const res = await AegisWhitelist.checkWhitelistStatus({
      senderEmail: 'executive.director@sme-corp.com',
      senderName: 'Executive Director'
    });
    assert.strictEqual(res.whitelisted, false);
    assert.strictEqual(res.score, null);
    await AegisWhitelist.resetToDefaults();
  });

  // Summary
  console.log('\n========================================');
  console.log(`Whitelist Test Results: ${passedTests} passed, ${failedTests} failed.`);
  console.log('========================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runAllTests().catch((err) => {
  console.error('Test suite runner crashed:', err);
  process.exit(1);
});
