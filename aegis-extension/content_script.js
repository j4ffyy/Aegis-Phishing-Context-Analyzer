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

  if (window.__AEGIS_CONTENT_SCRIPT_LOADED__) return;
  window.__AEGIS_CONTENT_SCRIPT_LOADED__ = true;

  var LOG_PREFIX = '[Aegis::ContentScript]';
  var DEBOUNCE_DELAY_MS = 300;
  var OBSERVER_RETRY_BASE_MS = 250;
  var OBSERVER_RETRY_MAX_ATTEMPTS = 8;

  var SELECTORS = {
    subject: ['h2.hP', '[data-thread-perm-id] h2', '.ha h2', '[role="main"] h2'],
    sender: ['span.gD', 'span[email]', '.go span', '[data-hovercard-id]'],
    body: ['.a3s.aiL', '.ii.gt', '[role="listitem"] .a3s', 'div[dir="ltr"]'],
    attachments: ['.aV3', '.aZo', '[aria-label*="Attachment"]'],
    timestamp: ['span.g3', 'span[data-timestamp]', '.gH span', '[role="main"] .g3'],
    mainContainer: ['[role="main"]', '.bkK', 'div.aeF']
  };

  var observer = null;
  var debounceTimer = null;
  var lastProcessedSignature = null;

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
    res.elements.forEach(function (el) {
      var n = (el.textContent || el.getAttribute('aria-label') || '').trim();
      if (n) names.push(n);
    });
    return { count: names.length, names: names, selectorUsed: res.selector };
  }

  function extractTimestamp(root) {
    var res = queryFirst(SELECTORS.timestamp, root);
    if (!res.element) return { timestamp: null, selectorUsed: null };
    var raw = res.element.getAttribute('title') || res.element.getAttribute('data-timestamp') || res.element.textContent || '';
    return { timestamp: raw.trim() || null, selectorUsed: res.selector };
  }

  function extractEmailContext() {
    var containerRes = queryFirst(SELECTORS.mainContainer, document);
    var root = containerRes.element || document;

    var subjectRes = queryFirst(SELECTORS.subject, root);
    var subject = subjectRes.element ? (subjectRes.element.textContent || '').trim() : null;

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

    var missing = [];
    if (!subject) missing.push('subject');
    if (!senderData.senderEmail) missing.push('senderEmail');
    if (!bodyText) missing.push('body');
    if (missing.length === 3) return null;
    if (missing.length > 0) console.warn(LOG_PREFIX + ' Partial selector failure: [' + missing.join(', ') + ']');

    return {
      subject: subject || '(No Subject)',
      senderName: senderData.senderName || '(Unknown Sender)',
      senderEmail: senderData.senderEmail || null,
      bodyText: bodyText || '',
      links: links,
      attachments: attachments.names,
      attachmentCount: attachments.count,
      timestamp: tsData.timestamp,
      extractedAt: new Date().toISOString(),
      metadata: { selectorsUsed: { subject: subjectRes.selector, sender: senderRes.selector, body: bodyRes.selector, attachments: attachments.selectorUsed, timestamp: tsData.selectorUsed } }
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
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise(function (resolve) {
          chrome.storage.local.get([BEHAVIORAL_STORAGE_KEY], function (res) {
            resolve((res && res[BEHAVIORAL_STORAGE_KEY]) || {});
          });
        });
      }
      if (!behavioralStorage._mem) behavioralStorage._mem = {};
      return Promise.resolve(behavioralStorage._mem);
    },
    set: function (store) {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise(function (resolve) {
          var p = {}; p[BEHAVIORAL_STORAGE_KEY] = store;
          chrome.storage.local.set(p, function () { resolve(); });
        });
      }
      behavioralStorage._mem = store;
      return Promise.resolve();
    },
    clear: function () {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise(function (resolve) {
          chrome.storage.local.remove([BEHAVIORAL_STORAGE_KEY], function () { resolve(); });
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

  /**
   * Records a sender interaction in the behavioral baseline store.
   * Appends current hour to hoursSeen ring (capped at 50 entries).
   *
   * @param {string} senderEmail
   * @param {number} [hourOfDay] defaults to current local hour
   * @returns {Promise<void>}
   */
  function updateBehavioralBaseline(senderEmail, hourOfDay) {
    if (!senderEmail) return Promise.resolve();
    var hour = (hourOfDay !== undefined && hourOfDay !== null) ? Math.floor(hourOfDay) % 24 : new Date().getHours();
    return behavioralStorage.get().then(function (store) {
      var key = senderEmail.toLowerCase().trim();
      var rec = store[key] || { interactionCount: 0, hoursSeen: [], lastSeen: 0 };
      rec.interactionCount += 1;
      rec.hoursSeen.push(hour);
      if (rec.hoursSeen.length > 50) rec.hoursSeen = rec.hoursSeen.slice(rec.hoursSeen.length - 50);
      rec.lastSeen = Date.now();
      store[key] = rec;
      return behavioralStorage.set(store).then(function () {
        console.log(LOG_PREFIX + ' [Behavioral] Updated ' + key + ': count=' + rec.interactionCount + ' hour=' + hour);
      });
    }).catch(function (err) {
      console.warn(LOG_PREFIX + ' [Behavioral] updateBehavioralBaseline error:', err);
    });
  }

  /**
   * Computes S_behavioral per §6.4 scoring table.
   *
   * count === 0                    -> 25  (first_time_sender)
   * count < 3                      -> 15  (unfamiliar_sender)
   * 3 <= count < 5                 ->  5  (warming_up)
   * count >= 5, minDist > 6h       -> 20  (off_hours_anomaly)
   * count >= 5, minDist <= 6h      ->  0  (established_on_schedule)
   *
   * @param {string} senderEmail
   * @param {number} [hourOfDay] defaults to current local hour
   * @returns {Promise<{score:number, reason:string, interactionCount:number, minCircularDistanceH?:number}>}
   */
  function scoreBehavioral(senderEmail, hourOfDay) {
    var DEFAULT = { score: 15, reason: 'unknown_sender', interactionCount: 0 };
    if (!senderEmail) return Promise.resolve(DEFAULT);
    var hour = (hourOfDay !== undefined && hourOfDay !== null) ? Math.floor(hourOfDay) % 24 : new Date().getHours();
    return behavioralStorage.get().then(function (store) {
      var key = senderEmail.toLowerCase().trim();
      var rec = store[key];
      if (!rec || rec.interactionCount === 0) return { score: 25, reason: 'first_time_sender', interactionCount: 0 };
      var count = rec.interactionCount;
      var hoursSeen = rec.hoursSeen || [];
      if (count < 3) return { score: 15, reason: 'unfamiliar_sender', interactionCount: count };
      if (count < BEHAVIORAL_MIN_INTERACTIONS_FOR_OFFHOURS) return { score: 5, reason: 'warming_up', interactionCount: count };
      var dists = hoursSeen.map(function (h) { return circularHourDistance(hour, h); });
      var minDist = dists.length > 0 ? Math.min.apply(null, dists) : BEHAVIORAL_OFF_HOURS_THRESHOLD_H + 1;
      if (minDist > BEHAVIORAL_OFF_HOURS_THRESHOLD_H) {
        return { score: 20, reason: 'off_hours_anomaly', interactionCount: count, minCircularDistanceH: Math.round(minDist * 10) / 10 };
      }
      return { score: 0, reason: 'established_on_schedule', interactionCount: count, minCircularDistanceH: Math.round(minDist * 10) / 10 };
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

  function handleDOMMutation() {
    try {
      var emailContext = extractEmailContext();
      if (!emailContext) return;

      var signature = generateSignature(emailContext);
      if (signature === lastProcessedSignature) return;
      lastProcessedSignature = signature;

      console.log(LOG_PREFIX + ' Email extracted:', {
        subject: emailContext.subject,
        sender: emailContext.senderName + ' <' + emailContext.senderEmail + '>',
        links: emailContext.links.length,
        attachments: emailContext.attachmentCount
      });

      var sanitizedPayload = emailContext;
      if (typeof window.AegisPIIScrubber !== 'undefined' && typeof window.AegisPIIScrubber.scrubEmailPayload === 'function') {
        sanitizedPayload = window.AegisPIIScrubber.scrubEmailPayload(emailContext);
        if (sanitizedPayload.piiRedactionStats && sanitizedPayload.piiRedactionStats.total > 0) {
          console.log(LOG_PREFIX + ' PII scrubbing applied:', sanitizedPayload.piiRedactionStats);
        }
      }

      var currentHour = new Date().getHours();
      var senderKey = sanitizedPayload.senderEmail || emailContext.senderEmail;

      // Score BEFORE recording to avoid self-bias (§6.4)
      scoreBehavioral(senderKey, currentHour).then(function (behavioralResult) {
        return updateBehavioralBaseline(senderKey, currentHour).then(function () {
          return behavioralResult;
        });
      }).then(function (behavioralResult) {
        console.log(LOG_PREFIX + ' [Behavioral] Layer 3 score for ' + senderKey + ':', behavioralResult);
        sanitizedPayload._behavioral = behavioralResult;
        window.dispatchEvent(new CustomEvent('aegis:email-extracted', { detail: sanitizedPayload }));
      }).catch(function (err) {
        console.warn(LOG_PREFIX + ' [Behavioral] Non-fatal, dispatching without score:', err);
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

  function initObserver(attempt) {
    attempt = attempt || 0;
    var mainNode = document.querySelector('[role="main"]');
    if (!mainNode) {
      if (attempt < OBSERVER_RETRY_MAX_ATTEMPTS) {
        var delay = OBSERVER_RETRY_BASE_MS * Math.pow(2, attempt);
        console.warn(LOG_PREFIX + ' [role="main"] not found. Retry in ' + delay + 'ms...');
        setTimeout(function () { initObserver(attempt + 1); }, delay);
        return;
      }
      console.warn(LOG_PREFIX + ' Falling back to document.body.');
    }
    var targetNode = mainNode || document.body;
    if (observer) observer.disconnect();
    observer = new MutationObserver(onMutationObserved);
    observer.observe(targetNode, { childList: true, subtree: true, characterData: false });
    console.log(LOG_PREFIX + ' MutationObserver attached to', mainNode ? '[role="main"]' : 'document.body (fallback)');
    onMutationObserved();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { initObserver(0); });
  } else {
    initObserver(0);
  }

  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
      if (request.action === 'AEGIS_RESCAN' || request.action === 'AEGIS_RELOAD') {
        console.log(LOG_PREFIX + ' Re-scan triggered from popup.');
        initObserver(0);
        var fab = document.getElementById('aegis-fab');
        if (fab && fab.style.display !== 'none') fab.click();
        sendResponse({ status: 'ok', message: 'Aegis re-scan initiated' });
      }
      return true;
    });
  }

  // Public API
  window.AegisContentScript = {
    extractEmailContext: extractEmailContext,
    SELECTORS: SELECTORS,
    reinitialize: initObserver
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

})();