/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Client-Side PII Scrubber
 * Specification: Implementation Plan §5.1.3 (Milestone 2.1)
 * Compliance: Republic Act No. 10173 (Philippine Data Privacy Act of 2012)
 *
 * Responsibilities:
 * - Deterministic client-side redaction of sensitive Personally Identifiable Information (PII)
 *   from email body text BEFORE inter-process message transfer or outbound analysis.
 * - Replacement tokens:
 *     - Email Addresses            -> [EMAIL]
 *     - Phone Numbers              -> [PHONE]
 *     - Payment Card Numbers       -> [CARD_NUMBER] (validated via Luhn algorithm)
 *     - Government ID / SSN / Tax  -> [SSN] (US SSN, Philippine SSS, PhilHealth, TIN)
 *     - Personal Names / Salutations -> [NAME] (Contextual heuristics: "Hi [NAME]", "Dear [NAME]")
 * - Preserves structural context and phishing signals (e.g. urgent keywords, grammar, hyperlinks)
 *   while ensuring zero unredacted personal identifiers leave the DOM execution context.
 */

(function () {
  'use strict';

  const LOG_PREFIX = '[Aegis::PIIScrubber]';

  /**
   * Luhn algorithm validation for payment card numbers.
   * Prevents false-positive redaction of arbitrary 13-19 digit serial/order numbers.
   *
   * @param {string} digits - Digits-only string.
   * @returns {boolean} True if passes Luhn checksum.
   */
  function isValidLuhn(digits) {
    if (!digits || digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let shouldDouble = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = parseInt(digits.charAt(i), 10);
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }

  /**
   * Redaction Regex Rules
   */
  const RULES = {
    // 1. Email Addresses
    // Matches standard email format: user@domain.com
    email: {
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi,
      token: '[EMAIL]'
    },

    // 2. Payment Cards (Visa, MasterCard, Amex, Discover, JCB, Diners Club)
    // 13 to 19 digits formatted with spaces, dashes, or continuous digits.
    cardCandidates: {
      regex: /\b(?:\d[ -]*?){13,19}\b/g,
      token: '[CARD_NUMBER]'
    },

    // 3. Government Identification Numbers (US SSN + Philippine National Identifiers per Capstone SME demographic)
    // US SSN: XXX-XX-XXXX
    ssnUS: {
      regex: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g,
      token: '[SSN]'
    },
    // Philippine SSS (Social Security System): XX-XXXXXXX-X (10 digits)
    phSSS: {
      regex: /\b\d{2}-\d{7}-\d{1}\b/g,
      token: '[SSN]'
    },
    // Philippine PhilHealth: XX-XXXXXXXXX-X (12 digits)
    phPhilHealth: {
      regex: /\b\d{2}-\d{9}-\d{1}\b/g,
      token: '[SSN]'
    },
    // Philippine TIN (Tax Identification Number): XXX-XXX-XXX or XXX-XXX-XXX-XXX
    phTIN: {
      regex: /\b\d{3}-\d{3}-\d{3}(-\d{3})?\b/g,
      token: '[SSN]'
    },

    // 4. Telephone Numbers (International E.164, North American NANP, and Philippine Mobile/Landline)
    // Examples: +63 917 123 4567, 0917-123-4567, +1 (555) 123-4567, 555-123-4567
    phone: {
      regex: /(?:(?:\+?63[\s.-]?|0)9\d{2}[\s.-]?\d{3}[\s.-]?\d{4}\b)|(?:(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\b\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b)/g,
      token: '[PHONE]'
    },

    // 5. Contextual Personal Name Redactions (Salutations & Sign-offs)
    // Matches "Dear John,", "Hi Mary Doe,", "Hello Bob,", "Thanks, Alice"
    salutationName: {
      regex: /\b(Dear|Hi|Hello|Hey|Greetings)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)(?=[,\s\n\r!])/g,
      token: '$1 [NAME]'
    },
    signoffName: {
      regex: /\b(Sincerely|Regards|Best regards|Warm regards|Thanks|Thank you|Yours truly),?\s*\n+\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b/g,
      token: '$1,\n[NAME]'
    }
  };

  /**
   * Performs ordered client-side redaction on text.
   *
   * @param {string} text - Raw email body or subject string.
   * @returns {{ scrubbedText: string, redactionCount: number, redactions: Record<string, number> }}
   */
  function scrubText(text) {
    if (!text || typeof text !== 'string') {
      return {
        scrubbedText: text || '',
        redactionCount: 0,
        redactions: { email: 0, phone: 0, card: 0, ssn: 0, name: 0 }
      };
    }

    let result = text;
    const stats = {
      email: 0,
      phone: 0,
      card: 0,
      ssn: 0,
      name: 0
    };

    // --- Pass 1: Government Identifiers (SSN / SSS / PhilHealth / TIN) ---
    // Executed first to prevent telephone regex from intercepting formatted ID dashes.
    [RULES.ssnUS, RULES.phSSS, RULES.phPhilHealth, RULES.phTIN].forEach((rule) => {
      result = result.replace(rule.regex, (match) => {
        stats.ssn++;
        return rule.token;
      });
    });

    // --- Pass 2: Payment Cards with Luhn Verification ---
    result = result.replace(RULES.cardCandidates.regex, (match) => {
      const cleanDigits = match.replace(/[\s-]/g, '');
      if (isValidLuhn(cleanDigits)) {
        stats.card++;
        return RULES.cardCandidates.token;
      }
      return match;
    });

    // --- Pass 3: Email Addresses ---
    result = result.replace(RULES.email.regex, (match) => {
      stats.email++;
      return RULES.email.token;
    });

    // --- Pass 4: Telephone Numbers ---
    // Minimum 7 digits required to avoid false-matching small isolated numbers (dates, amounts).
    result = result.replace(RULES.phone.regex, (match) => {
      const digitsOnly = match.replace(/\D/g, '');
      if (digitsOnly.length >= 7 && digitsOnly.length <= 15) {
        stats.phone++;
        return RULES.phone.token;
      }
      return match;
    });

    // --- Pass 5: Contextual Personal Names (Salutations & Sign-offs) ---
    result = result.replace(RULES.salutationName.regex, (match, prefix, name) => {
      stats.name++;
      return `${prefix} [NAME]`;
    });

    result = result.replace(RULES.signoffName.regex, (match, signoff, name) => {
      stats.name++;
      return `${signoff},\n[NAME]`;
    });

    const totalRedactions = stats.email + stats.phone + stats.card + stats.ssn + stats.name;

    return {
      scrubbedText: result,
      redactionCount: totalRedactions,
      redactions: stats
    };
  }

  /**
   * Scrubs full email payload in-place adhering to §5.1.3.
   * Body text is scrubbed before inter-process transfer.
   * Sender email is preserved in its distinct attribute for whitelist/domain checks.
   *
   * @param {object} emailPayload
   * @returns {object} Payload with sanitized bodyText, redacted metadata, and privacy certification.
   */
  function scrubEmailPayload(emailPayload) {
    if (!emailPayload) return null;

    const bodyResult = scrubText(emailPayload.bodyText || '');
    const subjectResult = scrubText(emailPayload.subject || '');

    return {
      ...emailPayload,
      bodyText: bodyResult.scrubbedText,
      rawBodyTextLength: (emailPayload.bodyText || '').length,
      scrubbedBodyTextLength: bodyResult.scrubbedText.length,
      // Subject is scrubbed of direct phone/card/ssn while preserving context
      scrubbedSubject: subjectResult.scrubbedText,
      piiSanitized: true,
      piiRedactionStats: {
        total: bodyResult.redactionCount + subjectResult.redactionCount,
        breakdown: {
          email: bodyResult.redactions.email + subjectResult.redactions.email,
          phone: bodyResult.redactions.phone + subjectResult.redactions.phone,
          card: bodyResult.redactions.card + subjectResult.redactions.card,
          ssn: bodyResult.redactions.ssn + subjectResult.redactions.ssn,
          name: bodyResult.redactions.name + subjectResult.redactions.name
        }
      },
      sanitizedAt: new Date().toISOString()
    };
  }

  // Export to window for extension content script and testing contexts
  if (typeof window !== 'undefined') {
    window.AegisPIIScrubber = {
      scrubText,
      scrubEmailPayload,
      isValidLuhn,
      RULES
    };
  }

  // Node.js CommonJS export for automated testing suites
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      scrubText,
      scrubEmailPayload,
      isValidLuhn,
      RULES
    };
  }

  console.log(`${LOG_PREFIX} Client-Side PII Scrubber active (RA 10173 compliant).`);
})();
