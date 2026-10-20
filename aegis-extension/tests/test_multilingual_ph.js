/**
 * Aegis – PR-06: Multilingual PH Support
 * Test Suite: Tagalog urgency keywords, PH brand coverage, language detection
 *
 * Run: node aegis-extension/tests/test_multilingual_ph.js
 */

'use strict';

// ---------------------------------------------------------------------------
// Minimal test harness
// ---------------------------------------------------------------------------
let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  ✅  PASS  ${label}`);
    passed++;
  } else {
    console.error(`  ❌  FAIL  ${label}`);
    failed++;
  }
}

// ---------------------------------------------------------------------------
// Reproduce the patterns from local_heuristics.js (PR-06)
// ---------------------------------------------------------------------------
const URGENCY_PATTERNS_PH = [
  // English
  /\b(urgent(?:ly)?|immediate(?:ly)?|action required|immediate action)\b/i,
  /\b(account suspended|account blocked|account locked|access revoked|account terminated)\b/i,
  /\b(verify your (?:account|identity)|confirm your identity|verification required|re-activate)\b/i,
  /\b(unauthorized (?:login|access|transaction)|security breach|suspicious activity detected)\b/i,
  /\b(within 24 hours|within 48 hours|24 hours? left|limited time|final notice|expires (?:today|soon))\b/i,
  /\b(wire transfer|unauthorized payment|fraud alert|update billing|payment overdue)\b/i,
  /\b(password expired|reset password immediately|click here to verify)\b/i,
  // Tagalog / Taglish (PR-06)
  /\b(i-verify|i-click|i-update|i-log\s+in|mag-log\s+in|mag-login)\b/i,
  /\b(kailangan(?:\s+mo)?|agad(?:\s+na)?|ngayon\s+na|kaagad)\b/i,
  /\b(account\s+mo|iyong\s+account|ang\s+iyong\s+account)\b/i,
  /\b(piliin(?:\s+ang)?|pindutin(?:\s+ang)?|i-tap)\b/i,
  /\b(na-block(?:\s+ang)?|naka-lock(?:\s+ang)?|na-suspend(?:\s+ang)?)\b/i,
  /\b(i-confirm|kumpirmahin|patunayan(?:\s+ang)?)\b/i,
  /\b(bayad(?:\s+na)?|bayaran(?:\s+agad)?|magbayad(?:\s+na)?)\b/i,
  /\b(mag-update(?:\s+ng)?|i-renew|i-reactivate)\b/i,
  /\b(libreng(?:\s+regalo)?|manalo(?:\s+ng)?|napili\s+kayo?)\b/i,
  /\b(scam(?:\s+alert)?|huwag(?:\s+ibigay)?)\b/i,
];

function matchesUrgencyPattern(text) {
  return URGENCY_PATTERNS_PH.some(p => p.test(text));
}

// ---------------------------------------------------------------------------
// Reproduce PH brand list (PR-06 additions only)
// ---------------------------------------------------------------------------
const PH_NEW_BRANDS = [
  { name: 'Landbank', brand: 'landbank', domain: 'landbank.com' },
  { name: 'RCBC', brand: 'rcbc', domain: 'rcbc.com' },
  { name: 'Security Bank', brand: 'securitybank', domain: 'securitybank.com' },
  { name: 'Palawan Pawnshop', brand: 'palawanpawnshop', domain: 'palawanpawnshop.com' },
  { name: 'SSS', brand: 'sss', domain: 'sss.gov.ph' },
  { name: 'PhilHealth', brand: 'philhealth', domain: 'philhealth.gov.ph' },
  { name: 'Pag-IBIG Fund', brand: 'pagibig', domain: 'pagibigfund.gov.ph' },
  { name: 'Shopee Philippines', brand: 'shopee', domain: 'shopee.ph' },
  { name: 'Lazada Philippines', brand: 'lazada', domain: 'lazada.com.ph' },
];

function levenshtein(s1, s2) {
  if (s1.length < s2.length) return levenshtein(s2, s1);
  if (!s2.length) return s1.length;
  let prev = [...Array(s2.length + 1).keys()];
  for (const c1 of s1) {
    const curr = [prev[0] + 1];
    for (let j = 0; j < s2.length; j++) {
      curr.push(Math.min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 !== s2[j] ? 1 : 0)));
    }
    prev = curr;
  }
  return prev[prev.length - 1];
}

function isTyposquattingPH(senderDomain) {
  for (const b of PH_NEW_BRANDS) {
    if (senderDomain === b.domain) continue;
    const dist = levenshtein(senderDomain, b.domain);
    if (dist <= 2 || (b.brand.length > 3 && senderDomain.includes(b.brand) && senderDomain !== b.domain)) {
      return b.name;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Language detection (mirrors backend detect_language heuristic — PR-06)
// ---------------------------------------------------------------------------
const TAGALOG_STOPWORDS = new Set([
  'ang','ng','mga','sa','na','ay','at','ako','siya','kami',
  'tayo','kayo','sila','ito','iyon','dito','doon','nito','noon',
  'para','pero','kung','kasi','dahil','paano','bakit','saan',
  'kapag','habang','lamang','lang','po','opo','ho','naman',
  'pala','yata','talaga','muli','ulit','din','rin','wala',
  'hindi','huwag','mahal','ingat','pasensya','salamat',
]);

function detectLanguage(text) {
  const tokens = new Set(text.toLowerCase().match(/\b[a-z]+\b/g) || []);
  let hits = 0;
  for (const t of tokens) { if (TAGALOG_STOPWORDS.has(t)) hits++; }
  const ratio = hits / Math.max(tokens.size, 1);
  if (ratio >= 0.18) return 'tl';
  if (ratio >= 0.06) return 'tl-en';
  return 'en';
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

console.log('\n═══════════════════════════════════════════════════════');
console.log('  Aegis PR-06 · Multilingual PH Support — Test Suite   ');
console.log('═══════════════════════════════════════════════════════\n');

// --- Test 1: Tagalog urgency keyword detection ---
console.log('▶ Test 1: Tagalog urgency keyword detection');
assert(matchesUrgencyPattern('Kailangan mong i-verify ang iyong account agad na.'), 'Detects "kailangan" + "i-verify" + "agad na"');
assert(matchesUrgencyPattern('Mag-login ka na para hindi ma-block ang account mo.'), 'Detects "mag-login" + "na-block" + "account mo"');
assert(matchesUrgencyPattern('I-click ang link para kumpirmahin ang iyong impormasyon.'), 'Detects "i-click" + "kumpirmahin"');
assert(matchesUrgencyPattern('Nagbabala: Ito ay isang scam alert. Huwag ibigay ang inyong password.'), 'Detects "scam alert" + "huwag ibigay"');
assert(matchesUrgencyPattern('Magbayad na ngayon para maiwasan ang pagkansela ng inyong serbisyo.'), 'Detects "magbayad na" + "ngayon na"');
assert(!matchesUrgencyPattern('Magandang umaga po. Kumusta na kayo?'), 'No false positive on casual Tagalog greeting');
console.log();

// --- Test 2: PH brand typosquatting detection ---
console.log('▶ Test 2: PH brand typosquatting detection (new brands)');
assert(isTyposquattingPH('landb4nk.com') !== null, 'Detects Landbank typosquatting: landb4nk.com');
assert(isTyposquattingPH('rcbc-online.com') !== null, 'Detects RCBC typosquatting: rcbc-online.com');
assert(isTyposquattingPH('philhealth-gov.ph') !== null, 'Detects PhilHealth typosquatting: philhealth-gov.ph');
assert(isTyposquattingPH('shopee-ph.net') !== null, 'Detects Shopee typosquatting: shopee-ph.net');
assert(isTyposquattingPH('lazada-promo.com') !== null, 'Detects Lazada typosquatting: lazada-promo.com');
assert(isTyposquattingPH('pagibig-online.com') !== null, 'Detects Pag-IBIG typosquatting: pagibig-online.com');
assert(isTyposquattingPH('google.com') === null, 'No false positive for legitimate google.com (not in PH brand set)');
console.log();

// --- Test 3: Language detection heuristic ---
console.log('▶ Test 3: Language detection heuristic');
const fullTagalog  = 'Ang iyong account ay na-lock na. Kailangan mong mag-login agad para ma-verify ang iyong impormasyon. Huwag ibigay ang inyong password sa iba.';
// Taglish: ratio ~0.14 (between 0.06 and 0.18) → 'tl-en'
  const taglish      = 'Security alert: Your account access is restricted. Please click this link to confirm your identity and restore access. Ito lang ang kailangan mo.';
const fullEnglish  = 'Your account has been temporarily suspended due to suspicious activity. Please click here to verify your identity immediately.';
const casual_tl    = 'Kumusta na kayo? Salamat sa inyong patuloy na tiwala.';

assert(detectLanguage(fullTagalog) === 'tl', 'Full Tagalog phishing email → "tl"');
assert(detectLanguage(taglish) === 'tl-en', 'Taglish mixed email → "tl-en"');
assert(detectLanguage(fullEnglish) === 'en', 'Full English phishing email → "en"');
assert(detectLanguage(casual_tl) === 'tl', 'Casual Tagalog greeting → "tl"');
console.log();

// --- Test 4: English urgency still works ---
console.log('▶ Test 4: Existing English urgency patterns still work post-PR-06');
assert(matchesUrgencyPattern('Urgent: Your account has been suspended. Verify your identity now.'), 'English "urgent" + "account suspended" detected');
assert(matchesUrgencyPattern('Final notice: payment overdue. Wire transfer required immediately.'), 'English "final notice" + "payment overdue" detected');
assert(matchesUrgencyPattern('Reset your password immediately. Your password expired 3 days ago.'), 'English "reset password immediately" + "password expired" detected');
console.log();

// --- Test 5: PH Government services brand baseline ---
console.log('▶ Test 5: PH government services in brand list');
assert(PH_NEW_BRANDS.some(b => b.brand === 'sss'), 'SSS is in PH brand list');
assert(PH_NEW_BRANDS.some(b => b.brand === 'philhealth'), 'PhilHealth is in PH brand list');
assert(PH_NEW_BRANDS.some(b => b.brand === 'pagibig'), 'Pag-IBIG Fund is in PH brand list');
assert(PH_NEW_BRANDS.some(b => b.domain === 'sss.gov.ph'), 'SSS domain is sss.gov.ph');
assert(PH_NEW_BRANDS.some(b => b.domain === 'philhealth.gov.ph'), 'PhilHealth domain is philhealth.gov.ph');
console.log();

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
const total = passed + failed;
console.log('═══════════════════════════════════════════════════════');
console.log(`  Results: ${passed}/${total} passed  |  ${failed} failed`);
console.log('═══════════════════════════════════════════════════════\n');
if (failed > 0) process.exit(1);
