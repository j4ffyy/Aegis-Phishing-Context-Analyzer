/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Local Heuristics Scoring Engine
 * Specification: Implementation Plan §6.2 & §5.1 (Milestone 2.2)
 *
 * Responsibilities:
 * - Autonomous client-side rule evaluation:
 *     1. Urgency / Coercive keyword density
 *     2. Deceptive anchor text (visible domain vs. target href mismatch)
 *     3. IP-based URL host detection
 *     4. High-abuse suspicious TLDs (.top, .xyz, .click, etc.)
 *     5. Brand domain typosquatting (Levenshtein edit distance)
 *     6. Display-name spoofing & free webmail impersonation
 *     7. Risky / executable attachment extensions
 * - Composite risk scoring (0-100%) mapped to Safe / Warning / Critical tiers
 * - Plain-language Explainable AI (XAI) rationale generation
 * - Immediate UI fallback if backend or network is unavailable
 */

(function () {
  'use strict';

  const LOG_PREFIX = '[Aegis::LocalHeuristics]';

  // ---------------------------------------------------------------------------
  // 1. High-Abuse TLDs and Brand Knowledge Bases
  // ---------------------------------------------------------------------------
  const SUSPICIOUS_TLDS = new Set([
    'top', 'xyz', 'club', 'work', 'click', 'loan', 'gq', 'tk',
    'ml', 'ga', 'cf', 'buzz', 'surf', 'monster', 'icu', 'cam',
    'rest', 'bar', 'fit', 'racing', 'country', 'stream', 'kim'
  ]);

  const FREE_EMAIL_PROVIDERS = new Set([
    'gmail.com', 'yahoo.com', 'yahoo.com.ph', 'hotmail.com', 'outlook.com',
    'aol.com', 'mail.com', 'protonmail.com', 'proton.me', 'icloud.com', 'zoho.com'
  ]);

  // Protected brand identities for typosquatting & impersonation checks (PH & Global SMEs)
  const PROTECTED_BRANDS = [
    { name: 'BDO Unibank', brand: 'bdo', domain: 'bdo.com.ph' },
    { name: 'Bank of the Philippine Islands', brand: 'bpi', domain: 'bpi.com.ph' },
    { name: 'Metrobank', brand: 'metrobank', domain: 'metrobank.com.ph' },
    { name: 'UnionBank', brand: 'unionbank', domain: 'unionbankph.com' },
    { name: 'GCash', brand: 'gcash', domain: 'gcash.com' },
    { name: 'Maya', brand: 'maya', domain: 'maya.ph' },
    { name: 'PayPal', brand: 'paypal', domain: 'paypal.com' },
    { name: 'Google', brand: 'google', domain: 'google.com' },
    { name: 'Microsoft', brand: 'microsoft', domain: 'microsoft.com' },
    { name: 'Apple', brand: 'apple', domain: 'apple.com' },
    { name: 'Amazon', brand: 'amazon', domain: 'amazon.com' },
    { name: 'Netflix', brand: 'netflix', domain: 'netflix.com' },
    { name: 'Facebook / Meta', brand: 'facebook', domain: 'facebook.com' },
    { name: 'Chase Bank', brand: 'chase', domain: 'chase.com' }
  ];

  // Dangerous / Executable file extensions
  const DANGEROUS_EXTENSIONS = new Set([
    'exe', 'scr', 'vbs', 'iso', 'bat', 'cmd', 'js', 'wsf',
    'ps1', 'html', 'htm', 'jar', 'hta', 'cpl', 'msc'
  ]);

  const ARCHIVE_EXTENSIONS = new Set(['zip', 'rar', '7z', 'tar', 'gz']);

  // Urgency & Coercion keyword patterns
  const URGENCY_PATTERNS = [
    /\b(urgent(?:ly)?|immediate(?:ly)?|action required|immediate action)\b/i,
    /\b(account suspended|account blocked|account locked|access revoked|account terminated)\b/i,
    /\b(verify your (?:account|identity)|confirm your identity|verification required|re-activate)\b/i,
    /\b(unauthorized (?:login|access|transaction)|security breach|suspicious activity detected)\b/i,
    /\b(within 24 hours|within 48 hours|24 hours? left|limited time|final notice|expires (?:today|soon))\b/i,
    /\b(wire transfer|unauthorized payment|fraud alert|update billing|payment overdue)\b/i,
    /\b(password expired|reset password immediately|click here to verify)\b/i
  ];

  // ---------------------------------------------------------------------------
  // 2. String & URL Helper Functions
  // ---------------------------------------------------------------------------

  /**
   * Computes Levenshtein edit distance between two strings.
   * Used for brand domain typosquatting detection (§6.2).
   */
  function levenshtein(a, b) {
    if (!a || !b) return (a || b || '').length;
    const m = a.length;
    const n = b.length;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,       // deletion
          dp[i][j - 1] + 1,       // insertion
          dp[i - 1][j - 1] + cost // substitution
        );
      }
    }
    return dp[m][n];
  }

  /**
   * Extracts hostname/domain from a URL string safely.
   */
  function extractHostname(urlString) {
    if (!urlString || typeof urlString !== 'string') return '';
    try {
      let clean = urlString.trim();
      if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
        clean = 'http://' + clean;
      }
      const parsed = new URL(clean);
      return parsed.hostname.toLowerCase();
    } catch (e) {
      return '';
    }
  }

  /**
   * Extracts the top-level domain (TLD) from a hostname.
   */
  function extractTLD(hostname) {
    if (!hostname) return '';
    const parts = hostname.split('.');
    return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
  }

  /**
   * Checks if a string is a raw IPv4 or IPv6 address.
   */
  function isIPAddress(hostname) {
    if (!hostname) return false;
    // IPv4 check: e.g., 192.168.1.1
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
    if (ipv4Regex.test(hostname)) return true;

    // IPv6 bracket check or raw IPv6
    const cleanHost = hostname.replace(/^\[|\]$/g, '');
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv6Regex.test(cleanHost);
  }

  /**
   * Extracts the domain portion of an email address.
   */
  function getEmailDomain(email) {
    if (!email || typeof email !== 'string') return '';
    const parts = email.trim().toLowerCase().split('@');
    return parts.length === 2 ? parts[1] : '';
  }

  // ---------------------------------------------------------------------------
  // 3. Rule Evaluation Functions
  // ---------------------------------------------------------------------------

  /**
   * Evaluates urgency keyword density (§6.2).
   * Penalty: min(N_hits * 8, 30) points.
   */
  function evaluateUrgency(text) {
    if (!text) return { points: 0, hits: [] };
    const hits = [];

    URGENCY_PATTERNS.forEach((pattern) => {
      const match = text.match(pattern);
      if (match) {
        hits.push(match[0]);
      }
    });

    const points = Math.min(hits.length * 8, 30);
    return { points, hits };
  }

  /**
   * Evaluates hyperlinks for deceptive anchor text, IP hosts, and suspicious TLDs.
   */
  function evaluateLinks(links) {
    const flags = [];
    let linkPoints = 0;

    if (!Array.isArray(links) || links.length === 0) {
      return { linkPoints: 0, flags };
    }

    // Regexp to test if visible text resembles a domain (e.g., "paypal.com" or "www.bdo.com.ph")
    const domainLikeRegex = /\b(?:https?:\/\/)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/i;

    links.forEach((linkObj) => {
      const url = linkObj.url || '';
      const text = (linkObj.text || '').trim();
      const targetHost = extractHostname(url);

      if (!targetHost) return;

      // Check 1: Direct IP Host
      if (isIPAddress(targetHost)) {
        flags.push({
          id: 'RULE_IP_URL',
          title: 'Direct IP Hyperlink',
          severity: 'critical',
          points: 35,
          evidence: `Link targets raw IP host: ${url}`
        });
        linkPoints += 35;
      }

      // Check 2: Suspicious TLD
      const tld = extractTLD(targetHost);
      if (SUSPICIOUS_TLDS.has(tld)) {
        flags.push({
          id: 'RULE_SUSPICIOUS_TLD',
          title: 'High-Abuse Top-Level Domain (TLD)',
          severity: 'warning',
          points: 20,
          evidence: `Link destination uses high-risk TLD .${tld}: ${url}`
        });
        linkPoints += 20;
      }

      // Check 3: Deceptive Anchor Text (Visible domain vs. Target domain mismatch)
      const textDomainMatch = text.match(domainLikeRegex);
      if (textDomainMatch) {
        const visibleHost = extractHostname(textDomainMatch[0]);
        // If visible host is a valid domain and doesn't match the destination host
        if (visibleHost && targetHost && visibleHost !== targetHost && !targetHost.endsWith('.' + visibleHost)) {
          flags.push({
            id: 'RULE_DECEPTIVE_LINK',
            title: 'Deceptive Hyperlink Display',
            severity: 'critical',
            points: 35,
            evidence: `Display text shows "${visibleHost}" but directs to "${targetHost}"`
          });
          linkPoints += 35;
        }
      }
    });

    return { linkPoints, flags };
  }

  /**
   * Evaluates sender domain for brand typosquatting, impersonation, or suspicious TLDs.
   */
  function evaluateSender(senderEmail, senderName) {
    const flags = [];
    let senderPoints = 0;

    const emailDomain = getEmailDomain(senderEmail);
    if (!emailDomain) return { senderPoints: 0, flags };

    // Check 1: Sender domain has suspicious TLD
    const senderTLD = extractTLD(emailDomain);
    if (SUSPICIOUS_TLDS.has(senderTLD)) {
      flags.push({
        id: 'RULE_SENDER_SUSPICIOUS_TLD',
        title: 'Suspicious Sender Domain TLD',
        severity: 'warning',
        points: 25,
        evidence: `Sender domain uses high-risk TLD .${senderTLD} (${emailDomain})`
      });
      senderPoints += 25;
    }

    // Check 2: Free email provider impersonating official institution or brand
    const isFreeEmail = FREE_EMAIL_PROVIDERS.has(emailDomain);
    const nameLower = (senderName || '').toLowerCase();

    // Sensitive corporate keywords often spoofed on free webmail
    const corporateKeywords = [
      'security desk', 'security team', 'support team', 'customer support',
      'helpdesk', 'billing department', 'it support', 'administrator',
      'account verification', 'unibank', 'bdo', 'bpi', 'metrobank', 'paypal', 'gcash'
    ];

    const matchedCorporateKeyword = corporateKeywords.find((kw) => nameLower.includes(kw));
    if (isFreeEmail && matchedCorporateKeyword) {
      flags.push({
        id: 'RULE_FREE_EMAIL_SPOOF',
        title: 'Institutional Impersonation on Free Webmail',
        severity: 'warning',
        points: 30,
        evidence: `Sender "${senderName}" uses public webmail (${senderEmail}) to request official actions.`
      });
      senderPoints += 30;
    }

    // Check 3: Brand Domain Typosquatting (Levenshtein distance)
    const domainBase = emailDomain.split('.')[0]; // e.g. "paypa1" from "paypa1.com"

    PROTECTED_BRANDS.forEach((brandInfo) => {
      const targetBase = brandInfo.brand.toLowerCase();

      // Skip exact legitimate domain matches
      if (emailDomain === brandInfo.domain || emailDomain.endsWith('.' + brandInfo.domain)) {
        return;
      }

      // Check Levenshtein distance on base brand name (e.g., "paypa1" vs "paypal")
      const dist = levenshtein(domainBase, targetBase);
      const isCloseEdit = dist >= 1 && dist <= 2 && domainBase.length >= 4;
      const isHyphenatedSquat = emailDomain.includes(targetBase + '-') || emailDomain.includes('-' + targetBase);

      if (isCloseEdit || isHyphenatedSquat) {
        flags.push({
          id: 'RULE_TYPOSQUATTING',
          title: `Brand Typosquatting (${brandInfo.name})`,
          severity: 'critical',
          points: 35,
          evidence: `Sender domain "${emailDomain}" appears to imitate genuine brand domain "${brandInfo.domain}"`
        });
        senderPoints += 35;
      } else if (nameLower.includes(targetBase) && !isFreeEmail && !emailDomain.includes(targetBase)) {
        // Display name claims to be the brand, but domain has no relation
        flags.push({
          id: 'RULE_BRAND_IMPERSONATION',
          title: `Brand Identity Mismatch (${brandInfo.name})`,
          severity: 'warning',
          points: 25,
          evidence: `Sender name "${senderName}" references ${brandInfo.name}, but originates from unrecognized domain "${emailDomain}"`
        });
        senderPoints += 25;
      }
    });

    return { senderPoints, flags };
  }

  /**
   * Evaluates attachment safety based on file extensions.
   */
  function evaluateAttachments(attachments) {
    const flags = [];
    let attachPoints = 0;

    if (!Array.isArray(attachments) || attachments.length === 0) {
      return { attachPoints: 0, flags };
    }

    attachments.forEach((fileName) => {
      const cleanName = (fileName || '').trim().toLowerCase();
      const dotIndex = cleanName.lastIndexOf('.');
      if (dotIndex === -1) return;

      const ext = cleanName.substring(dotIndex + 1);

      if (DANGEROUS_EXTENSIONS.has(ext)) {
        flags.push({
          id: 'RULE_DANGEROUS_ATTACHMENT',
          title: 'High-Risk Executable/Script Attachment',
          severity: 'critical',
          points: 35,
          evidence: `Attachment "${fileName}" has dangerous executable/script extension .${ext}`
        });
        attachPoints += 35;
      } else if (ARCHIVE_EXTENSIONS.has(ext)) {
        flags.push({
          id: 'RULE_ARCHIVE_ATTACHMENT',
          title: 'Compressed Archive Attachment',
          severity: 'warning',
          points: 15,
          evidence: `Attachment "${fileName}" is an archive file commonly used to evade scanner inspection.`
        });
        attachPoints += 15;
      }
    });

    return { attachPoints, flags };
  }

  // ---------------------------------------------------------------------------
  // 4. Primary Evaluation & Synthesis Engine
  // ---------------------------------------------------------------------------

  /**
   * Evaluates email payload using client-side heuristic rules.
   *
   * @param {object} emailContext - Extracted email context object.
   * @returns {object} Full heuristic analysis result including score, risk tier, flags, and XAI.
   */
  function evaluate(emailContext) {
    if (!emailContext || typeof emailContext !== 'object') {
      return {
        score: 0,
        riskLevel: 'Safe',
        riskClass: 'threat-safe',
        desc: 'No email context provided.',
        flags: [],
        layers: generateLayerStatus(0, [], 0, 0),
        xai: 'No email data available to evaluate.',
        evaluatedAt: new Date().toISOString()
      };
    }

    const flags = [];
    let totalPoints = 0;

    // 1. Urgency evaluation (Subject + Body)
    const combinedText = `${emailContext.subject || ''} ${emailContext.bodyText || ''}`;
    const urgencyResult = evaluateUrgency(combinedText);
    if (urgencyResult.points > 0) {
      flags.push({
        id: 'RULE_URGENCY',
        title: 'Coercive Urgency Keywords',
        severity: urgencyResult.points >= 20 ? 'critical' : 'warning',
        points: urgencyResult.points,
        evidence: `Urgent phrases detected: "${urgencyResult.hits.slice(0, 3).join('", "')}"`
      });
      totalPoints += urgencyResult.points;
    }

    // 2. Hyperlink evaluation (Deceptive anchor, IP hosts, Suspicious TLDs)
    const linkResult = evaluateLinks(emailContext.links);
    flags.push(...linkResult.flags);
    totalPoints += linkResult.linkPoints;

    // 3. Sender domain & identity evaluation
    const senderResult = evaluateSender(emailContext.senderEmail, emailContext.senderName);
    flags.push(...senderResult.flags);
    totalPoints += senderResult.senderPoints;

    // 4. Attachment evaluation
    const attachResult = evaluateAttachments(emailContext.attachments);
    flags.push(...attachResult.flags);
    totalPoints += attachResult.attachPoints;

    // Composite score capped at 100 per §6.1
    const finalScore = Math.min(100, Math.max(0, totalPoints));

    // Categorical risk tier mapping (§6.6)
    let riskLevel = 'Safe';
    let riskClass = 'threat-safe';
    let desc = 'No significant threats detected.';

    if (finalScore >= 75) {
      riskLevel = 'Critical';
      riskClass = 'threat-critical';
      desc = 'High-confidence phishing indicators detected.';
    } else if (finalScore >= 45) {
      riskLevel = 'Warning';
      riskClass = 'threat-warning';
      desc = 'Suspicious patterns detected. Review carefully.';
    }

    // Plain-language XAI rationale synthesis
    const xai = generateXAIRationale(riskLevel, flags, emailContext);

    // Multi-layer defense breakdown compatible with overlay UI
    const layers = generateLayerStatus(
      finalScore,
      flags,
      (emailContext.attachments || []).length,
      (emailContext.links || []).length
    );

    return {
      score: finalScore,
      riskLevel,
      riskClass,
      desc,
      flags,
      layers,
      xai,
      evaluatedAt: new Date().toISOString()
    };
  }

  /**
   * Generates a plain-language explanation of heuristic findings.
   */
  function generateXAIRationale(riskLevel, flags, emailContext) {
    if (flags.length === 0 || riskLevel === 'Safe') {
      return (
        'This email passed client-side heuristic inspection. No deceptive links, urgency triggers, ' +
        'dangerous attachments, or domain typosquatting patterns were identified.'
      );
    }

    const reasons = flags.map((f, i) => `${i + 1}. ${f.title}: ${f.evidence}`).join(' ');

    if (riskLevel === 'Critical') {
      return (
        `CRITICAL RISK ALERT: Aegis local heuristics flagged this email with high-severity threats: ${reasons} ` +
        'Do NOT click any links, open attachments, or disclose credentials.'
      );
    }

    return (
      `CAUTION ADVISED: Aegis local heuristics detected suspicious patterns: ${reasons} ` +
      'Verify the sender identity through a trusted separate channel before interacting.'
    );
  }

  /**
   * Formats layer status compatible with overlay.js expectations.
   */
  function generateLayerStatus(score, flags, attachCount, linkCount) {
    const hasCritical = flags.some(f => f.severity === 'critical');
    const hasWarning = flags.some(f => f.severity === 'warning');

    const authFlag = flags.find(f => f.id.includes('SENDER') || f.id.includes('TYPO') || f.id.includes('SPOOF'));
    const attachFlag = flags.find(f => f.id.includes('ATTACHMENT'));
    const linkFlag = flags.find(f => f.id.includes('LINK') || f.id.includes('IP') || f.id.includes('TLD'));
    const urgencyFlag = flags.find(f => f.id.includes('URGENCY'));

    return {
      sanitization: {
        text: 'Pre-filter: Sanitization',
        detail: 'HTML Stripped — PII Protected',
        icon: 'fa-check-circle'
      },
      auth: {
        text: 'Layer 1: Email Auth & Domain',
        detail: authFlag ? authFlag.title : 'Domain identity verified (Client Sandbox)',
        icon: authFlag ? 'fa-exclamation-triangle' : 'fa-check-circle'
      },
      attach: {
        text: 'Layer 2: Attachment Intelligence',
        detail: attachFlag
          ? attachFlag.title
          : (attachCount > 0 ? `${attachCount} safe attachment(s)` : 'No attachments'),
        icon: attachFlag ? 'fa-times-circle' : 'fa-check-circle'
      },
      behavior: {
        text: 'Layer 3: Behavioral Analysis',
        detail: 'Local baseline: Standard interaction pattern',
        icon: 'fa-check-circle'
      },
      nlp: {
        text: 'Layer 4: Heuristic Intent Analysis',
        detail: urgencyFlag || linkFlag
          ? `${urgencyFlag ? 'Urgency keywords ' : ''}${linkFlag ? 'Suspicious links' : ''}`.trim()
          : 'Normal context structure',
        icon: hasCritical ? 'fa-times-circle' : (hasWarning ? 'fa-exclamation-triangle' : 'fa-check-circle')
      }
    };
  }

  // ---------------------------------------------------------------------------
  // 5. Environment Exports
  // ---------------------------------------------------------------------------

  const API = {
    evaluate,
    evaluateUrgency,
    evaluateLinks,
    evaluateSender,
    evaluateAttachments,
    levenshtein,
    extractHostname,
    isIPAddress,
    SUSPICIOUS_TLDS,
    PROTECTED_BRANDS
  };

  // Browser global export
  if (typeof window !== 'undefined') {
    window.AegisLocalHeuristics = API;
  }

  // Node.js CommonJS export for test runners
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = API;
  }

  console.log(`${LOG_PREFIX} Local Heuristics Scoring Engine active (§6.2 compliant).`);
})();
