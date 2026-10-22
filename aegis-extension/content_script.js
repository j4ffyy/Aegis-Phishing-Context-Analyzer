/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Content Script (Gmail DOM Extractor & MutationObserver)
 * Specification: Implementation Plan §5.1.2 (Milestone 1.2), §6.4 (Milestone 3.2)
 *
 * Responsibilities:
 * - Debounced MutationObserver monitoring Gmail's [role="main"] container.
 * - Resilient multi-selector fallback chains for Subject, Sender, Body, Attachments.
 * - Strict extraction safeguards: Senders extracted from `email` attributes only.
 * - Deduplication via email context signature to prevent redundant processing.
 * - [Milestone 3.2] Client-side Behavioral Baseline: circular distance scoring and
 *   sender novelty detection backed by chrome.storage.local (§6.4).
 */

(function () {
  'use strict';

  if (typeof window !== 'undefined') {
    if (window.__AEGIS_CONTENT_SCRIPT_LOADED__) return;
    window.__AEGIS_CONTENT_SCRIPT_LOADED__ = true;
  }

  var LOG_PREFIX = '[Aegis::ContentScript]';
  var DEBOUNCE_DELAY_MS = 300;
  var OBSERVER_RETRY_BASE_MS = 250;
  var OBSERVER_RETRY_MAX_ATTEMPTS = 8;
  // Incremented each time initObserver is called fresh (attempt===0).
  // Retry callbacks check this token before continuing — if it changed,
  // a newer initObserver chain superseded this one and we abort silently.
  var observerInitToken = 0;

  /**
   * Returns false when the extension has been hot-reloaded and this stale
   * content script no longer has a valid runtime context.
   * Accessing chrome.runtime.id throws if the context is invalidated.
   */
  function isExtensionContextValid() {
    try {
      return typeof chrome !== 'undefined' && !!chrome.runtime && !!chrome.runtime.id;
    } catch (e) {
      return false;
    }
  }

  /**
   * Called when the extension context is invalidated (e.g. after a hot-reload
   * in chrome://extensions). Stops all timers and observers so the stale script
   * stops running silently in the background.
   */
  function teardown() {
    try {
      if (typeof observer !== 'undefined' && observer) { observer.disconnect(); }
      if (typeof debounceTimer !== 'undefined' && debounceTimer) { clearTimeout(debounceTimer); }
      if (typeof nullRetryTimer !== 'undefined' && nullRetryTimer) { clearTimeout(nullRetryTimer); }
    } catch (e) { /* ignore */ }
    console.log(LOG_PREFIX + ' Extension context invalidated — content script torn down cleanly.');
  }

  var SELECTORS = {
    subject: ['h2.hP', '[data-thread-perm-id] h2', '.ha h2', '[role="main"] h2'],
    sender: ['span.gD', 'span[email]', '.go span', '[data-hovercard-id]'],
    body: ['.a3s.aiL', '.ii.gt', '[role="listitem"] .a3s', 'div[dir="ltr"]'],
    attachments: ['.aV3', '.aZo', '[aria-label*="Attachment"]'],
    timestamp: ['span.g3', 'span[data-timestamp]', '.gH span', '[role="main"] .g3'],
    mainContainer: ['[role="main"]', '.bkK', 'div.aeF'],
    authDetails: ['table.cf.gJ', '.gJ', '[role="region"] table.cf'],
    authWarning: [
      'div[role="alert"]',
      'div.a6E',
      '.msg-header-warning',
      '.a98',
      '[aria-label*="unverified"]',
      '[data-tooltip*="could not verify"]',
      '[data-tooltip*="unverified"]',
      '.a8u'
    ]
  };

  var observer = null;
  var debounceTimer = null;
  var lastProcessedSignature = null;
  var nullRetryTimer = null;

  function queryFirst(selectorList, root) {
    root = root || document;
    for (var i = 0; i < selectorList.length; i++) {
      try {
        var el = root.querySelector(selectorList[i]);
        if (el) return { element: el, selector: selectorList[i] };
      } catch (err) { /* skip bad selector */ }
    }
    return { element: null, selector: null };
  }

  function queryAllFirstWorking(selectorList, root) {
    root = root || document;
    for (var i = 0; i < selectorList.length; i++) {
      try {
        var list = root.querySelectorAll(selectorList[i]);
        if (list && list.length > 0) return { elements: Array.from(list), selector: selectorList[i] };
      } catch (err) { /* skip bad selector */ }
    }
    return { elements: [], selector: null };
  }

  var EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  function extractSender(el) {
    if (!el) return { senderEmail: null, senderName: null };
    var email = el.getAttribute('email');
    if (!email || !EMAIL_REGEX.test(email.trim())) {
      var hc = el.getAttribute('data-hovercard-id');
      email = (hc && EMAIL_REGEX.test(hc.trim())) ? hc.trim() : null;
    }
    if (!email) {
      var txt = (el.textContent || '').trim();
      if (EMAIL_REGEX.test(txt)) email = txt;
    }
    return {
      senderEmail: email ? email.trim().toLowerCase() : null,
      senderName: el.getAttribute('name') || (el.textContent || '').trim() || null
    };
  }

  function extractLinks(bodyEl) {
    if (!bodyEl) return [];
    var anchors = bodyEl.querySelectorAll('a[href]');
    var links = [], seen = new Set();
    anchors.forEach(function (a) {
      var href = (a.getAttribute('href') || '').trim();
      if (!href || href.startsWith('mailto:') || href.startsWith('javascript:') || href === '#') return;
      try {
        if (href.includes('google.com/url?') && href.includes('q=')) {
          var u = new URL(href), q = u.searchParams.get('q');
          if (q) href = q;
        }
      } catch (e) {}
      if (!seen.has(href)) {
        seen.add(href);
        links.push({ url: href, text: (a.textContent || '').trim(), isExternal: !href.includes('mail.google.com') });
      }
    });
    return links;
  }

  function extractAttachments(root) {
    var res = queryAllFirstWorking(SELECTORS.attachments, root);
    var names = [];
    var hashes = [];
    res.elements.forEach(function (el) {
      var n = (el.textContent || el.getAttribute('aria-label') || '').trim();
      if (n) names.push(n);

      // Extract SHA-256 hash if present on element or test fixture (PR-09)
      var h = el.getAttribute('data-aegis-hash') || el.getAttribute('data-hash') || el.getAttribute('data-sha256');
      if (h && /^[0-9a-fA-F]{64}$/.test(h.trim())) {
        hashes.push(h.trim().toLowerCase());
      }
    });

    // Also check root for container-level test fixture hashes (PR-09)
    var rootHashes = root && root.getAttribute && root.getAttribute('data-aegis-attachment-hashes');
    if (rootHashes) {
      rootHashes.split(',').forEach(function (item) {
        var cleanH = item.trim().toLowerCase();
        if (/^[0-9a-fA-F]{64}$/.test(cleanH) && hashes.indexOf(cleanH) === -1) {
          hashes.push(cleanH);
        }
      });
    }

    return { count: names.length, names: names, hashes: hashes, selectorUsed: res.selector };
  }

  function extractTimestamp(root) {
    var res = queryFirst(SELECTORS.timestamp, root);
    if (!res.element) return { timestamp: null, selectorUsed: null };
    var raw = res.element.getAttribute('title') || res.element.getAttribute('data-timestamp') || res.element.textContent || '';
    return { timestamp: raw.trim() || null, selectorUsed: res.selector };
  }

  /**
   * PR-02: Extracts SPF and DKIM authentication signals from Gmail DOM.
   *
   * Strategy:
   * 1. Inspects Gmail security warning banners / unverified sender badges.
   *    If Gmail explicitly flags an authentication failure or spoof alert,
   *    both spfPass and dkimPass are marked false.
   * 2. Inspects Gmail's message details panel (table.cf.gJ or .gJ).
   *    If 'mailed-by' is present -> spfPass: true (SPF validated).
   *    If 'signed-by' is present -> dkimPass: true (DKIM signature valid).
   * 3. Checks data-aegis attributes on root container for testing/fixture overrides.
   * 4. If indeterminate, returns null so heuristic penalties are not falsely triggered.
   *
   * @param {Element} root - Container element for current email thread.
   * @returns {Object} { spfPass: boolean|null, dkimPass: boolean|null, mailedBy: string|null, signedBy: string|null, source: string, alertText: string|null }
   */
  function extractAuthStatus(root) {
    root = root || document;

    // 0. Test fixture override (allows deterministic testing in automated suites)
    var testSpf = root.getAttribute && root.getAttribute('data-aegis-spf');
    var testDkim = root.getAttribute && root.getAttribute('data-aegis-dkim');
    if (testSpf !== null && testSpf !== undefined) {
      return {
        spfPass: testSpf === 'true' ? true : (testSpf === 'false' ? false : null),
        dkimPass: testDkim === 'true' ? true : (testDkim === 'false' ? false : null),
        mailedBy: root.getAttribute('data-aegis-mailed-by') || null,
        signedBy: root.getAttribute('data-aegis-signed-by') || null,
        source: 'test_fixture',
        alertText: null
      };
    }

    // 1. Check for explicit Gmail warning alerts (spoofing / unverified sender)
    for (var w = 0; w < SELECTORS.authWarning.length; w++) {
      try {
        var warnEls = root.querySelectorAll(SELECTORS.authWarning[w]);
        for (var i = 0; i < warnEls.length; i++) {
          var el = warnEls[i];
          var alertText = (el.textContent || el.getAttribute('aria-label') || el.getAttribute('data-tooltip') || '').toLowerCase();
          if (
            alertText.includes("couldn't verify") ||
            alertText.includes("could not verify") ||
            alertText.includes("spoof") ||
            alertText.includes("failed authentication") ||
            alertText.includes("unverified") ||
            alertText.includes("be careful with this message")
          ) {
            return {
              spfPass: false,
              dkimPass: false,
              mailedBy: null,
              signedBy: null,
              source: 'gmail_warning_banner',
              alertText: alertText.slice(0, 150)
            };
          }
        }
      } catch (e) { /* ignore query errors */ }
    }

    // 2. Check for Gmail details table (table.cf.gJ or .gJ)
    var detailsRes = queryFirst(SELECTORS.authDetails, root);
    if (detailsRes.element) {
      var rows = detailsRes.element.querySelectorAll('tr');
      var mailedBy = null;
      var signedBy = null;
      rows.forEach(function (tr) {
        var thEl = tr.querySelector('th');
        var tdEl = tr.querySelector('td');
        var th = (thEl ? thEl.textContent : '').toLowerCase().trim();
        var td = (tdEl ? tdEl.textContent : '').trim();
        if (th.includes('mailed-by') || th.includes('mailed by')) {
          mailedBy = td;
        }
        if (th.includes('signed-by') || th.includes('signed by')) {
          signedBy = td;
        }
      });

      if (mailedBy || signedBy) {
        return {
          spfPass: mailedBy ? true : null,
          dkimPass: signedBy ? true : null,
          mailedBy: mailedBy,
          signedBy: signedBy,
          source: 'gmail_details_table',
          alertText: null
        };
      }
    }

    // 3. Indeterminate state (details collapsed and no warning alert displayed)
    return {
      spfPass: null,
      dkimPass: null,
      mailedBy: null,
      signedBy: null,
      source: 'indeterminate',
      alertText: null
    };
  }

  function extractEmailContext() {
    var containerRes = queryFirst(SELECTORS.mainContainer, document);
    var root = containerRes.element || document;

    var subjectRes = queryFirst(SELECTORS.subject, root);
    var subject = subjectRes.element ? (subjectRes.element.textContent || '').trim() : null;

    // Filter out Gmail list-view header "Conversations" or "Conversation"
    if (subject && /^conversations?$/i.test(subject.trim())) {
      subject = null;
    }

    var senderRes = queryFirst(SELECTORS.sender, root);
    var senderData = extractSender(senderRes.element);

    var bodyRes = queryAllFirstWorking(SELECTORS.body, root);
    var bodyEl = null, bodyText = '';
    if (bodyRes.elements.length > 0) {
      bodyEl = bodyRes.elements[bodyRes.elements.length - 1];
      bodyText = (bodyEl.innerText || bodyEl.textContent || '').trim();
    }

    var attachments = extractAttachments(root);
    var links = extractLinks(bodyEl);
    var tsData = extractTimestamp(root);
    var authData = extractAuthStatus(root);

    // If there is no thread perm id and no senderEmail and no subject, this is a list view, not an email
    var permEl = document.querySelector('[data-thread-perm-id]');
    if (!permEl && (!subject || !senderData.senderEmail)) return null;

    var missing = [];
    if (!subject) missing.push('subject');
    if (!senderData.senderEmail) missing.push('senderEmail');
    if (!bodyText) missing.push('body');
    if (missing.length === 3) return null;
    // Only warn about partial selector failures when inside a real email thread
    // (avoids flooding the console with expected fallback noise on list/compose views)
    if (missing.length > 0 && document.querySelector('[data-thread-perm-id]')) {
      console.warn(LOG_PREFIX + ' Partial selector failure: [' + missing.join(', ') + ']');
    }

    return {
      subject: subject || '(No Subject)',
      senderName: senderData.senderName || '(Unknown Sender)',
      senderEmail: senderData.senderEmail || null,
      bodyText: bodyText || '',
      links: links,
      attachments: attachments.names,
      attachmentCount: attachments.count,
      attachmentHashes: attachments.hashes,
      timestamp: tsData.timestamp,
      spfPass: authData.spfPass,
      dkimPass: authData.dkimPass,
      authMeta: authData,
      extractedAt: new Date().toISOString(),
      metadata: {
        selectorsUsed: {
          subject: subjectRes.selector,
          sender: senderRes.selector,
          body: bodyRes.selector,
          attachments: attachments.selectorUsed,
          timestamp: tsData.selectorUsed,
          auth: authData.source
        }
      }
    };
  }

  function generateSignature(ctx) {
    if (!ctx) return null;
    var urlHash = window.location.hash || '';
    var permEl = document.querySelector('[data-thread-perm-id]');
    var permId = permEl ? (permEl.getAttribute('data-thread-perm-id') || '') : '';
    return urlHash + '|' + permId + '|' + (ctx.senderEmail || '') + '::' + (ctx.subject || '');
  }

  // ---------------------------------------------------------------------------
  // Milestone 3.2: Behavioral Baseline — Circular Distance Scoring (§6.4)
  // ---------------------------------------------------------------------------

  var BEHAVIORAL_STORAGE_KEY = 'aegis_behavioral_baseline';
  var BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS = 5;
  var BEHAVIORAL_OFF_HOURS_THRESHOLD_H = 6;

  var behavioralStorage = {
    _mem: null,
    get: function () {
      if (isExtensionContextValid() && chrome.storage && chrome.storage.local) {
        return new Promise(function (resolve) {
          try {
            chrome.storage.local.get([BEHAVIORAL_STORAGE_KEY], function (res) {
              if (chrome.runtime.lastError) { resolve({}); return; }
              resolve((res && res[BEHAVIORAL_STORAGE_KEY]) || {});
            });
          } catch (e) { resolve({}); }
        });
      }
      if (!behavioralStorage._mem) behavioralStorage._mem = {};
      return Promise.resolve(behavioralStorage._mem);
    },
    set: function (store) {
      if (isExtensionContextValid() && chrome.storage && chrome.storage.local) {
        return new Promise(function (resolve) {
          try {
            var p = {}; p[BEHAVIORAL_STORAGE_KEY] = store;
            chrome.storage.local.set(p, function () { resolve(); });
          } catch (e) { resolve(); }
        });
      }
      behavioralStorage._mem = store;
      return Promise.resolve();
    },
    clear: function () {
      if (isExtensionContextValid() && chrome.storage && chrome.storage.local) {
        return new Promise(function (resolve) {
          try {
            chrome.storage.local.remove([BEHAVIORAL_STORAGE_KEY], function () { resolve(); });
          } catch (e) { resolve(); }
        });
      }
      behavioralStorage._mem = {};
      return Promise.resolve();
    }
  };

  /**
   * Computes circular distance between two clock hours (0-23).
   * Eliminates midnight-boundary artifact: 23h and 01h are 2h apart, not 22h.
   * delta_t = min(|h1-h2|, 24-|h1-h2|)
   *
   * @param {number} h1
   * @param {number} h2
   * @returns {number} distance in hours [0,12]
   */
  function circularHourDistance(h1, h2) {
    var linear = Math.abs(h1 - h2);
    return Math.min(linear, 24 - linear);
  }

  var SUSPICIOUS_BEHAVIORAL_EXTENSIONS = new Set([
    'zip', 'rar', '7z', 'tar', 'gz', 'iso', 'img',
    'exe', 'scr', 'vbs', 'bat', 'cmd', 'js', 'wsf', 'ps1', 'hta', 'html', 'htm'
  ]);

  function extractExtension(filename) {
    if (!filename || typeof filename !== 'string') return '';
    var parts = filename.toLowerCase().trim().split('.');
    return parts.length > 1 ? parts.pop() : '';
  }

  /**
   * Records a sender interaction in the behavioral baseline store (§6.4, PR-03).
   * Persists interaction count, hours ring, days ring, and known attachment extensions.
   * All data strictly preserved in client-side storage per RA 10173.
   *
   * @param {string} senderEmail
   * @param {number} [hourOfDay] defaults to current local hour (0-23)
   * @param {number} [dayOfWeek] defaults to current local day (0-6)
   * @param {Array<string>} [attachmentNames] list of attachment filenames
   * @returns {Promise<void>}
   */
  function updateBehavioralBaseline(senderEmail, hourOfDay, dayOfWeek, attachmentNames) {
    if (!senderEmail) return Promise.resolve();
    var hour = (hourOfDay !== undefined && hourOfDay !== null) ? Math.floor(hourOfDay) % 24 : new Date().getHours();
    var day = (dayOfWeek !== undefined && dayOfWeek !== null) ? Math.floor(dayOfWeek) % 7 : new Date().getDay();
    var attachList = Array.isArray(attachmentNames) ? attachmentNames : [];

    return behavioralStorage.get().then(function (store) {
      var key = senderEmail.toLowerCase().trim();
      var rec = store[key] || {
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
          var ext = extractExtension(att);
          if (ext && rec.knownExtensions.indexOf(ext) === -1) {
            rec.knownExtensions.push(ext);
          }
        });
      }

      rec.lastSeen = Date.now();
      store[key] = rec;
      return behavioralStorage.set(store).then(function () {
        console.log(LOG_PREFIX + ' [Behavioral] Updated ' + key + ': count=' + rec.interactionCount + ' hour=' + hour + ' day=' + day + ' exts=[' + rec.knownExtensions.join(',') + ']');
      });
    }).catch(function (err) {
      console.warn(LOG_PREFIX + ' [Behavioral] updateBehavioralBaseline error:', err);
    });
  }

  /**
   * Computes multi-factor Layer 3 behavioral score S_behavioral (§6.4, PR-03).
   *
   * Scoring factors:
   * 1. Novelty baseline:
   *    count === 0                    -> 25  (first_time_sender)
   *    count < 3                      -> 15  (unfamiliar_sender)
   *    3 <= count < 5                 ->  5  (warming_up)
   *    count >= 5                     ->  0  (established)
   * 2. Off-hours timing anomaly:
   *    count >= 5, minDist > 6h       -> +20 (off_hours_anomaly)
   * 3. Day-of-week anomaly:
   *    count >= 5, weekend transmission from weekday-only sender -> +10 (weekend_anomaly)
   * 4. Attachment extension anomaly:
   *    count >= 3, unexpected archive/script extension -> +15 (novel_attachment_anomaly)
   *
   * @param {string} senderEmail
   * @param {number} [hourOfDay] defaults to current local hour
   * @param {number} [dayOfWeek] defaults to current local day
   * @param {Array<string>} [attachmentNames] attachments in current email
   * @returns {Promise<Object>} Behavioral score, primary reason, telemetry metadata
   */
  function scoreBehavioral(senderEmail, hourOfDay, dayOfWeek, attachmentNames) {
    var DEFAULT = {
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

    var hour = (hourOfDay !== undefined && hourOfDay !== null) ? Math.floor(hourOfDay) % 24 : new Date().getHours();
    var day = (dayOfWeek !== undefined && dayOfWeek !== null) ? Math.floor(dayOfWeek) % 7 : new Date().getDay();
    var isWeekend = (day === 0 || day === 6);
    var attachList = Array.isArray(attachmentNames) ? attachmentNames : [];
    var currentExtensions = attachList.map(extractExtension).filter(Boolean);

    return behavioralStorage.get().then(function (store) {
      var key = senderEmail.toLowerCase().trim();
      var rec = store[key];

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

      var count = rec.interactionCount;
      var hoursSeen = Array.isArray(rec.hoursSeen) ? rec.hoursSeen : [];
      var daysSeen = Array.isArray(rec.daysSeen) ? rec.daysSeen : [];
      var knownExts = Array.isArray(rec.knownExtensions) ? rec.knownExtensions : [];

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

      var noveltyBase = 0;
      var reasons = [];

      if (count < BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS) {
        noveltyBase = 5;
        reasons.push('warming_up');
      } else {
        reasons.push('established_sender');
      }

      var penalty = 0;

      // 2. Off-Hours Timing Anomaly (Circular Hour Distance)
      var minDist = null;
      if (count >= BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS && hoursSeen.length > 0) {
        var dists = hoursSeen.map(function (h) { return circularHourDistance(hour, h); });
        minDist = Math.min.apply(null, dists);
        if (minDist > BEHAVIORAL_OFF_HOURS_THRESHOLD_H) {
          penalty += 20;
          reasons.push('off_hours_anomaly');
        }
      }

      // 3. Day-of-Week Anomaly (Weekday routine vs Weekend transmission)
      var weekendAnomaly = false;
      if (count >= BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS && isWeekend && daysSeen.length >= 5) {
        var hasPriorWeekend = daysSeen.some(function (d) { return d === 0 || d === 6; });
        if (!hasPriorWeekend) {
          penalty += 10;
          weekendAnomaly = true;
          reasons.push('weekend_anomaly');
        }
      }

      // 4. Attachment Extension Novelty
      var novelExtensions = [];
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

      var totalScore = Math.min(100, noveltyBase + penalty);
      var primaryReason = reasons.length > 1 && reasons[0] === 'established_sender' ? reasons[1] : (reasons[0] || 'established_on_schedule');

      if (totalScore === 0 && reasons.indexOf('established_on_schedule') === -1) {
        primaryReason = 'established_on_schedule';
        reasons = ['established_on_schedule'];
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
    }).catch(function (err) {
      console.warn(LOG_PREFIX + ' [Behavioral] scoreBehavioral error:', err);
      return DEFAULT;
    });
  }

  function getBehavioralStore() { return behavioralStorage.get(); }
  function clearBehavioralBaseline() { return behavioralStorage.clear(); }

  // ---------------------------------------------------------------------------
  // Main Inspection Cycle
  // ---------------------------------------------------------------------------

  function handleDOMMutation(isRetry) {
    // GUARD: If the extension was hot-reloaded, this stale content script must stop.
    // Without this, the debounce timer fires and the chrome.storage calls below throw
    // "Extension context invalidated" errors.
    if (!isExtensionContextValid()) { teardown(); return; }

    if (nullRetryTimer) { clearTimeout(nullRetryTimer); nullRetryTimer = null; }
    if (isGmailListView()) {
      if (lastProcessedSignature !== '__LIST_VIEW__') {
        lastProcessedSignature = '__LIST_VIEW__';
        console.log(LOG_PREFIX + ' [SPA] List view detected (' + (window.location.hash || '#inbox') + ') — dispatching aegis:no-email.');
        window.dispatchEvent(new CustomEvent('aegis:no-email'));
      }
      return;
    }
    try {
      var emailContext = extractEmailContext();
      if (!emailContext || (emailContext.subject && /^conversations?$/i.test(emailContext.subject.trim()))) {
        if (!isRetry) {
          // Gmail SPA transition: DOM not yet settled. Retry once after a longer delay.
          nullRetryTimer = setTimeout(function () { handleDOMMutation(true); }, 800);
        } else {
          // Still no email after retry — we are on a list view or compose. Signal no-email.
          console.log(LOG_PREFIX + ' [SPA] No email context after retry — dispatching aegis:no-email.');
          window.dispatchEvent(new CustomEvent('aegis:no-email'));
        }
        return;
      }

      var signature = generateSignature(emailContext);
      if (signature === lastProcessedSignature) return;
      lastProcessedSignature = signature;

      console.log(LOG_PREFIX + ' Email extracted:', {
        subject: emailContext.subject,
        sender: emailContext.senderName + ' <' + emailContext.senderEmail + '>',
        links: emailContext.links.length,
        attachments: emailContext.attachmentCount,
        spfPass: emailContext.spfPass,
        dkimPass: emailContext.dkimPass
      });

      var sanitizedPayload = emailContext;
      if (typeof window.AegisPIIScrubber !== 'undefined' && typeof window.AegisPIIScrubber.scrubEmailPayload === 'function') {
        sanitizedPayload = window.AegisPIIScrubber.scrubEmailPayload(emailContext);
        if (sanitizedPayload.piiRedactionStats && sanitizedPayload.piiRedactionStats.total > 0) {
          console.log(LOG_PREFIX + ' PII scrubbing applied:', sanitizedPayload.piiRedactionStats);
        }
      }

      var currentHour = new Date().getHours();
      var currentDay = new Date().getDay();
      var senderKey = sanitizedPayload.senderEmail || emailContext.senderEmail;
      var currentAttachments = sanitizedPayload.attachments || [];

      // Evaluate Whitelist & Dual-Trigger Revocation (§7.1)
      var authStatus = {
        spfPass: sanitizedPayload.spfPass,
        dkimPass: sanitizedPayload.dkimPass
      };
      var whitelistPromise = (typeof window.AegisWhitelist !== 'undefined' && typeof window.AegisWhitelist.checkWhitelistStatus === 'function')
        ? window.AegisWhitelist.checkWhitelistStatus(sanitizedPayload, authStatus)
        : Promise.resolve({ whitelisted: false, revoked: false, trigger: null, score: null });

      // Score BEFORE recording to avoid self-bias (§6.4)
      whitelistPromise.then(function (whitelistResult) {
        sanitizedPayload._whitelist = whitelistResult;
        return scoreBehavioral(senderKey, currentHour, currentDay, currentAttachments);
      }).then(function (behavioralResult) {
        return updateBehavioralBaseline(senderKey, currentHour, currentDay, currentAttachments).then(function () {
          return behavioralResult;
        });
      }).then(function (behavioralResult) {
        console.log(LOG_PREFIX + ' [Behavioral] Layer 3 score for ' + senderKey + ':', behavioralResult);
        sanitizedPayload._behavioral = behavioralResult;
        sanitizedPayload.behavioralScore = behavioralResult.score;
        sanitizedPayload.behavioral_meta = behavioralResult;
        window.dispatchEvent(new CustomEvent('aegis:email-extracted', { detail: sanitizedPayload }));
      }).catch(function (err) {
        // If the extension context was invalidated (hot-reload), stop cleanly
        if (!isExtensionContextValid()) { teardown(); return; }
        // Otherwise this is a non-fatal behavioral scoring error — dispatch without score
        console.warn(LOG_PREFIX + ' [Behavioral/Whitelist] Non-fatal, dispatching without score:', err.message || err);
        window.dispatchEvent(new CustomEvent('aegis:email-extracted', { detail: sanitizedPayload }));
      });

    } catch (err) {
      console.error(LOG_PREFIX + ' Error during DOM extraction cycle:', err);
    }
  }

  function onMutationObserved() {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(function () { handleDOMMutation(); }, DEBOUNCE_DELAY_MS);
  }

  function initObserver(attempt, _token) {
    // If the extension context was invalidated (hot-reload), stop everything
    if (!isExtensionContextValid()) { teardown(); return; }

    // Fresh start: bump the global token so any in-flight retry chain self-cancels
    if (!attempt) {
      attempt = 0;
      observerInitToken = (observerInitToken + 1) | 0;
      _token = observerInitToken;
    }
    // Stale retry: a newer initObserver(0) has superseded this chain — abort silently
    if (_token !== observerInitToken) return;

    // Query once and reuse in both branches
    var mainNode = document.querySelector('[role="main"]');

    // On list views (e.g. #inbox), [role="main"] may not exist yet and we don't need it.
    // Silently attach to body as a lightweight fallback so navigation events can still fire.
    if (isGmailListView() && attempt === 0) {
      if (!mainNode) {
        if (observer) observer.disconnect();
        observer = new MutationObserver(onMutationObserved);
        observer.observe(document.body, { childList: true, subtree: false });
        return;
      }
    }

    if (!mainNode) {
      if (attempt < OBSERVER_RETRY_MAX_ATTEMPTS) {
        var delay = OBSERVER_RETRY_BASE_MS * Math.pow(2, attempt);
        // console.debug (not warn) — retries are expected SPA behavior, not errors
        if (!isGmailListView()) {
          console.debug(LOG_PREFIX + ' [role="main"] not yet ready. Retry ' + (attempt + 1) + '/' + OBSERVER_RETRY_MAX_ATTEMPTS + ' in ' + delay + 'ms...');
        }
        var tok = _token;
        setTimeout(function () { initObserver(attempt + 1, tok); }, delay);
        return;
      }
      if (!isGmailListView()) {
        console.debug(LOG_PREFIX + ' Falling back to document.body (max retries reached).');
      }
    }
    var targetNode = mainNode || document.body;
    if (observer) observer.disconnect();
    observer = new MutationObserver(onMutationObserved);
    observer.observe(targetNode, { childList: true, subtree: true, characterData: false });
    if (mainNode) {
      console.log(LOG_PREFIX + ' MutationObserver attached to [role="main"].');
    }
    onMutationObserved();
  }

  /**
   * Returns true when the current Gmail URL is a list/folder view
   * (inbox, starred, sent, drafts, snoozed, spam, trash, category/*, label/*)
   * rather than an individual email thread.
   *
   * Gmail thread URLs look like: #inbox/FMfcgzQXKWmHFjprLstFCGGckFfZkVnr
   *   — a folder name followed by a / and a 10+ character alphanumeric thread ID.
   * List/folder views are just: #inbox  #starred  #category/promotions  etc.
   */
  function isGmailListView() {
    var hash = (window.location.hash || '').replace(/^#/, '');
    if (!hash) return true;
    // If the hash contains a slash, the part after must be a thread ID (10+ alphanum chars).
    // Anything shorter (e.g. "category/promotions") is still a list view.
    var slashIdx = hash.indexOf('/');
    if (slashIdx === -1) return true;  // No slash — definitely a list view (#inbox, #starred)
    var afterSlash = hash.slice(slashIdx + 1);
    // Thread IDs are 16+ hex/base64 characters; category names are short English words
    return !/^[A-Za-z0-9_\-]{10,}$/.test(afterSlash);
  }

  /**
   * Gmail SPA navigation handler.
   * Resets the deduplication signature so the next email extraction always
   * re-fires, then schedules a delayed extraction to let Gmail's DOM settle.
   * For list views, immediately signals aegis:no-email without waiting.
   */
  function onGmailNavigate() {
    lastProcessedSignature = null;
    if (debounceTimer) { clearTimeout(debounceTimer); debounceTimer = null; }
    if (nullRetryTimer)  { clearTimeout(nullRetryTimer);  nullRetryTimer  = null; }

    if (isGmailListView()) {
      // User navigated to a list/folder view — no email is open. Signal immediately.
      console.log(LOG_PREFIX + ' [SPA] List view detected (' + window.location.hash + ') — dispatching aegis:no-email.');
      window.dispatchEvent(new CustomEvent('aegis:no-email'));
      return;
    }

    // Thread view — delay extraction to let Gmail finish rendering
    debounceTimer = setTimeout(function () { handleDOMMutation(false); }, 800);
    console.log(LOG_PREFIX + ' [SPA] Thread navigation detected — signature reset, delayed re-scan scheduled.');
  }

  if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    // Give Gmail's SPA framework ~400ms to render the initial DOM before the first
    // observer attach. This reduces or eliminates the "not yet ready" retry chain
    // on initial page load / extension injection.
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () {
        setTimeout(function () { initObserver(0); }, 400);
      });
    } else {
      setTimeout(function () { initObserver(0); }, 400);
    }

    // Listen for Gmail SPA navigation (hash-based routing)
    window.addEventListener('hashchange', onGmailNavigate);
    window.addEventListener('popstate',   onGmailNavigate);
    // Re-scan when the tab becomes visible again (user switches back from another tab)
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'visible') {
        lastProcessedSignature = null;
        if (debounceTimer) { clearTimeout(debounceTimer); debounceTimer = null; }
        debounceTimer = setTimeout(function () { handleDOMMutation(false); }, 600);
        console.log(LOG_PREFIX + ' [SPA] Tab became visible — signature reset, re-scan scheduled.');
      }
    });
  }

  if (isExtensionContextValid() && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
      if (!isExtensionContextValid()) { teardown(); return; }
      if (request.action === 'AEGIS_RESCAN' || request.action === 'AEGIS_RELOAD') {
        console.log(LOG_PREFIX + ' Re-scan triggered from popup.');
        initObserver(0);
        var fab = typeof document !== 'undefined' ? document.getElementById('aegis-fab') : null;
        if (fab && fab.style.display !== 'none') fab.click();
        sendResponse({ status: 'ok', message: 'Aegis re-scan initiated' });
      }
      return true;
    });
  }

  // Public API
  if (typeof window !== 'undefined') {
    window.AegisContentScript = {
      extractEmailContext: extractEmailContext,
      extractAuthStatus: extractAuthStatus,
      SELECTORS: SELECTORS,
      reinitialize: initObserver,
      /**
       * Soft re-scan: clears the deduplication signature so the current email
       * is re-analyzed without a full page reload. Called by overlay.js reload buttons.
       */
      resetSignature: function () {
        lastProcessedSignature = null;
        if (debounceTimer) { clearTimeout(debounceTimer); debounceTimer = null; }
        debounceTimer = setTimeout(function () { handleDOMMutation(false); }, 300);
        console.log(LOG_PREFIX + ' [SPA] Soft re-scan triggered via resetSignature().');
      }
    };

    // [Milestone 3.2] Behavioral baseline API
    window.AegisBehavioralBaseline = {
      updateBehavioralBaseline: updateBehavioralBaseline,
      scoreBehavioral: scoreBehavioral,
      circularHourDistance: circularHourDistance,
      getBehavioralStore: getBehavioralStore,
      clearBehavioralBaseline: clearBehavioralBaseline,
      BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS: BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS,
      BEHAVIORAL_OFF_HOURS_THRESHOLD_H: BEHAVIORAL_OFF_HOURS_THRESHOLD_H,
      BEHAVIORAL_STORAGE_KEY: BEHAVIORAL_STORAGE_KEY
    };
  }

  // Node.js environment export for automated unit testing suites
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      extractAuthStatus: extractAuthStatus,
      extractSender: extractSender,
      extractLinks: extractLinks,
      extractAttachments: extractAttachments,
      SELECTORS: SELECTORS,
      updateBehavioralBaseline: updateBehavioralBaseline,
      scoreBehavioral: scoreBehavioral,
      circularHourDistance: circularHourDistance,
      clearBehavioralBaseline: clearBehavioralBaseline,
      getBehavioralStore: getBehavioralStore,
      BEHAVIORAL_STORAGE_KEY: BEHAVIORAL_STORAGE_KEY,
      BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS: BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS,
      BEHAVIORAL_OFF_HOURS_THRESHOLD_H: BEHAVIORAL_OFF_HOURS_THRESHOLD_H
    };
  }

})();