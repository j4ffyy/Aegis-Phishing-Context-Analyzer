/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Content Script (Gmail DOM Extractor & MutationObserver)
 * Specification: Implementation Plan §5.1.2 (Milestone 1.2)
 *
 * Responsibilities:
 * - Debounced MutationObserver monitoring Gmail's [role="main"] container.
 * - Resilient multi-selector fallback chains for Subject, Sender, Body, and Attachments.
 * - Strict extraction safeguards: Senders extracted strictly from `email` attributes to prevent spoofing.
 * - Extraction of hyperlinks, timestamps, and attachment metadata.
 * - Deduplication via email context signature to prevent redundant processing.
 * - Non-blocking diagnostic logging on selector misses.
 */

(function () {
  'use strict';

  // Prevent double injection on Gmail SPA navigations
  if (window.__AEGIS_CONTENT_SCRIPT_LOADED__) {
    return;
  }
  window.__AEGIS_CONTENT_SCRIPT_LOADED__ = true;

  const LOG_PREFIX = '[Aegis::ContentScript]';
  const DEBOUNCE_DELAY_MS = 300;

  /**
   * Observer initialization retry configuration.
   * Gmail's SPA may not have rendered [role="main"] immediately on injection.
   * We poll with exponential backoff before falling back to document.body.
   */
  const OBSERVER_RETRY_BASE_MS = 250;
  const OBSERVER_RETRY_MAX_ATTEMPTS = 8;

  /**
   * Resilient DOM selector chains per Implementation Plan §5.1.2
   */
  const SELECTORS = {
    subject: [
      'h2.hP',
      '[data-thread-perm-id] h2',
      '.ha h2',
      '[role="main"] h2'
    ],
    sender: [
      'span.gD',
      'span[email]',
      '.go span',
      '[data-hovercard-id]'
    ],
    body: [
      '.a3s.aiL',
      '.ii.gt',
      '[role="listitem"] .a3s',
      'div[dir="ltr"]'
    ],
    attachments: [
      '.aV3',
      '.aZo',
      '[aria-label*="Attachment"]'
    ],
    timestamp: [
      'span.g3',
      'span[data-timestamp]',
      '.gH span',
      '[role="main"] .g3'
    ],
    mainContainer: [
      '[role="main"]',
      '.bkK',
      'div.aeF'
    ]
  };

  /**
   * State management
   */
  let observer = null;
  let debounceTimer = null;
  let lastProcessedSignature = null;

  /**
   * Resolves the first matching element from a prioritized selector list.
   * @param {string[]} selectorList - Array of CSS selectors in order of priority.
   * @param {Element|Document} root - Context root for querySelector.
   * @returns {{ element: Element|null, selector: string|null }}
   */
  function queryFirst(selectorList, root = document) {
    for (const selector of selectorList) {
      try {
        const el = root.querySelector(selector);
        if (el) {
          return { element: el, selector };
        }
      } catch (err) {
        console.warn(`${LOG_PREFIX} Invalid selector query "${selector}":`, err);
      }
    }
    return { element: null, selector: null };
  }

  /**
   * Resolves all matching elements from the first working selector in a prioritized list.
   * @param {string[]} selectorList - Array of CSS selectors in order of priority.
   * @param {Element|Document} root - Context root for querySelectorAll.
   * @returns {{ elements: Element[], selector: string|null }}
   */
  function queryAllFirstWorking(selectorList, root = document) {
    for (const selector of selectorList) {
      try {
        const list = root.querySelectorAll(selector);
        if (list && list.length > 0) {
          return { elements: Array.from(list), selector };
        }
      } catch (err) {
        console.warn(`${LOG_PREFIX} Invalid selector queryAll "${selector}":`, err);
      }
    }
    return { elements: [], selector: null };
  }

  /**
   * Strict email regex validation helper.
   */
  const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  /**
   * Extracts clean sender information adhering to §5.1.2 Integrity Safeguards.
   *
   * Extraction priority order:
   *  1. `email` attribute (Gmail's canonical machine-readable sender address)
   *  2. `data-hovercard-id` attribute (used by newer Gmail layouts)
   *  3. `textContent` — only accepted if it passes strict email regex validation
   *
   * The `name` attribute is captured separately as `senderName` for heuristic
   * display-name spoofing comparison but is NEVER used for identity or routing.
   *
   * Return shape is always { senderEmail: string|null, senderName: string|null }.
   * Callers record `senderRes.selector` independently from `queryFirst()`.
   *
   * @param {Element|null} senderElement
   * @returns {{ senderEmail: string|null, senderName: string|null }}
   */
  function extractSender(senderElement) {
    if (!senderElement) {
      return { senderEmail: null, senderName: null };
    }

    let email = senderElement.getAttribute('email');

    // Fallback 1: check hovercard ID if email attribute is absent or malformed
    if (!email || !EMAIL_REGEX.test(email.trim())) {
      const hovercard = senderElement.getAttribute('data-hovercard-id');
      if (hovercard && EMAIL_REGEX.test(hovercard.trim())) {
        email = hovercard.trim();
      } else {
        email = null;
      }
    }

    // Fallback 2: textContent — only if strictly valid email (prevents display-name contamination)
    if (!email) {
      const textContent = (senderElement.textContent || '').trim();
      if (EMAIL_REGEX.test(textContent)) {
        email = textContent;
      }
    }

    // Display name captured for heuristic comparison only — NOT used for identity
    const displayName =
      senderElement.getAttribute('name') ||
      (senderElement.textContent || '').trim() ||
      null;

    return {
      senderEmail: email ? email.trim().toLowerCase() : null,
      senderName: displayName
    };
  }

  /**
   * Extracts hyperlink targets and labels from the email body.
   */
  function extractLinks(bodyElement) {
    if (!bodyElement) return [];

    const anchors = bodyElement.querySelectorAll('a[href]');
    const links = [];
    const seenUrls = new Set();

    anchors.forEach((a) => {
      let href = (a.getAttribute('href') || '').trim();

      // Filter out non-actionable links
      if (!href || href.startsWith('mailto:') || href.startsWith('javascript:') || href === '#') {
        return;
      }

      // Handle Google redirect wrappers (e.g., https://www.google.com/url?q=...)
      try {
        if (href.includes('google.com/url?') && href.includes('q=')) {
          const parsed = new URL(href);
          const realTarget = parsed.searchParams.get('q');
          if (realTarget) {
            href = realTarget;
          }
        }
      } catch (e) {
        // Fall back to original href if parsing fails
      }

      if (!seenUrls.has(href)) {
        seenUrls.add(href);
        links.push({
          url: href,
          text: (a.textContent || '').trim(),
          isExternal: !href.includes('mail.google.com')
        });
      }
    });

    return links;
  }

  /**
   * Extracts attachment file names and count.
   */
  function extractAttachments(rootElement) {
    const { elements, selector } = queryAllFirstWorking(SELECTORS.attachments, rootElement);
    const attachmentNames = [];

    elements.forEach((el) => {
      const name = (el.textContent || el.getAttribute('aria-label') || '').trim();
      if (name) {
        attachmentNames.push(name);
      }
    });

    return {
      count: attachmentNames.length,
      names: attachmentNames,
      selectorUsed: selector
    };
  }

  /**
   * Extracts timestamp text from the thread.
   */
  function extractTimestamp(rootElement) {
    const { element, selector } = queryFirst(SELECTORS.timestamp, rootElement);
    if (!element) return { timestamp: null, selectorUsed: null };

    const raw = element.getAttribute('title') ||
                element.getAttribute('data-timestamp') ||
                element.textContent || '';

    return {
      timestamp: raw.trim() || null,
      selectorUsed: selector
    };
  }

  /**
   * Primary extraction engine.
   * Walks the multi-selector fallback chains to extract the full email context.
   */
  function extractEmailContext() {
    const mainContainerRes = queryFirst(SELECTORS.mainContainer, document);
    const contextRoot = mainContainerRes.element || document;

    // 1. Subject extraction
    const subjectRes = queryFirst(SELECTORS.subject, contextRoot);
    const subject = subjectRes.element ? (subjectRes.element.textContent || '').trim() : null;

    // 2. Sender extraction
    const senderRes = queryFirst(SELECTORS.sender, contextRoot);
    const { senderEmail, senderName } = extractSender(senderRes.element);

    // 3. Body extraction (select the most recent expanded message body if multiple are present)
    const bodyElementsRes = queryAllFirstWorking(SELECTORS.body, contextRoot);
    let bodyElement = null;
    let bodyText = '';
    // NOTE: bodyHtml is intentionally NOT extracted into the dispatched payload.
    // Raw innerHTML contains unscrubbed PII (names, emails, phone numbers in attributes
    // and text nodes). Per §5.1.3 and RA 10173, only plain text is exported from this
    // context. PII scrubbing (pii_scrubber.js, Milestone 2.1) operates on bodyText.

    if (bodyElementsRes.elements.length > 0) {
      // In Gmail threads, the last expanded element contains the most recently received message.
      // Earlier entries are prior replies (collapsed or quoted) and are intentionally excluded
      // to prevent signature/disclaimer blocks from inflating body length.
      bodyElement = bodyElementsRes.elements[bodyElementsRes.elements.length - 1];
      bodyText = (bodyElement.innerText || bodyElement.textContent || '').trim();
    }

    // 4. Attachments
    const attachments = extractAttachments(contextRoot);

    // 5. Links
    const links = extractLinks(bodyElement);

    // 6. Timestamp
    const timestampData = extractTimestamp(contextRoot);

    // Diagnostic validation: Check for selector misses
    const missing = [];
    if (!subject) missing.push('subject');
    if (!senderEmail) missing.push('senderEmail');
    if (!bodyText) missing.push('body');

    if (missing.length > 0) {
      // If none of the primary fields exist, we are likely on an inbox list view, not an email thread
      if (missing.length === 3) {
        return null;
      }
      console.warn(`${LOG_PREFIX} Partial selector failure. Missing fields: [${missing.join(', ')}].`, {
        subjectSelector: subjectRes.selector,
        senderSelector: senderRes.selector,
        bodySelector: bodyElementsRes.selector
      });
    }

    const emailPayload = {
      subject: subject || '(No Subject)',
      senderName: senderName || '(Unknown Sender)',
      senderEmail: senderEmail || null,
      bodyText: bodyText || '',
      // bodyHtml deliberately omitted — see §5.1.3 PII compliance note above.
      links: links,
      attachments: attachments.names,
      attachmentCount: attachments.count,
      timestamp: timestampData.timestamp,
      extractedAt: new Date().toISOString(),
      metadata: {
        selectorsUsed: {
          subject: subjectRes.selector,
          sender: senderRes.selector,
          body: bodyElementsRes.selector,
          attachments: attachments.selectorUsed,
          timestamp: timestampData.selectorUsed
        }
      }
    };

    return emailPayload;
  }

  /**
   * Generates a collision-resistant deduplication signature for the current email view.
   *
   * Design rationale:
   *  - Gmail encodes the active thread ID in the URL hash (e.g., /#inbox/FMfcgzQXKhpJRmBq).
   *    This is the most reliable stable identifier — it changes on every thread navigation.
   *  - We also capture the DOM-level thread permalink attribute as a secondary anchor.
   *  - Falling back to sender+subject+body prefix alone is deliberately avoided because
   *    it causes false deduplication in multi-reply threads where sender and subject are
   *    the same across all replies (e.g., "Re: Invoice").
   *
   * @param {object} context - Extracted email payload.
   * @returns {string|null}
   */
  function generateSignature(context) {
    if (!context) return null;

    // Primary: Gmail thread URL hash (changes on every distinct thread open)
    const urlHash = window.location.hash || '';

    // Secondary: DOM thread permalink attribute if present (set by Gmail on thread containers)
    const threadPermId =
      (document.querySelector('[data-thread-perm-id]') || {})
        .getAttribute?.('data-thread-perm-id') || '';

    // Tertiary: sender + subject as a human-readable discriminator for logging
    const humanKey = `${context.senderEmail || ''}::${context.subject || ''}`;

    return `${urlHash}|${threadPermId}|${humanKey}`;
  }

  /**
   * Main inspection cycle triggered on debounced DOM mutations.
   */
  function handleDOMMutation() {
    try {
      const emailContext = extractEmailContext();

      if (!emailContext) {
        // User is browsing folder/list view, or email has not rendered yet
        return;
      }

      const signature = generateSignature(emailContext);
      if (signature === lastProcessedSignature) {
        // Already processed this email view
        return;
      }

      lastProcessedSignature = signature;

      console.log(`${LOG_PREFIX} Email thread detected and extracted:`, {
        subject: emailContext.subject,
        sender: `${emailContext.senderName} <${emailContext.senderEmail}>`,
        linksCount: emailContext.links.length,
        attachmentsCount: emailContext.attachmentCount,
        selectors: emailContext.metadata.selectorsUsed
      });

      // Dispatch internal event for downstream components (PII Scrubber, Heuristics, UI Overlay)
      window.dispatchEvent(
        new CustomEvent('aegis:email-extracted', {
          detail: emailContext
        })
      );
    } catch (err) {
      console.error(`${LOG_PREFIX} Error during DOM extraction cycle:`, err);
    }
  }

  /**
   * Debounced mutation callback per §5.1.2 & §3.1 (300ms window).
   */
  function onMutationObserved() {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(() => {
      handleDOMMutation();
    }, DEBOUNCE_DELAY_MS);
  }

  /**
   * Initializes the MutationObserver targeting Gmail's [role="main"].
   *
   * Gmail is a complex SPA. When the content script is injected, [role="main"] may not
   * yet exist in the DOM because Gmail's thread view renders asynchronously after
   * navigation. This function uses exponential backoff polling to wait for the element
   * before attaching the observer.
   *
   * Retry schedule (OBSERVER_RETRY_BASE_MS = 250ms, max 8 attempts):
   *   Attempt 1: 250ms, 2: 500ms, 3: 1000ms, 4: 2000ms ... up to ~32s total.
   * After exhausting retries, falls back to document.body to ensure the observer
   * is always active, even if Gmail's DOM structure has changed significantly.
   *
   * @param {number} [attempt=0] - Current retry attempt index.
   */
  function initObserver(attempt = 0) {
    const mainNode = document.querySelector('[role="main"]');

    if (!mainNode) {
      if (attempt < OBSERVER_RETRY_MAX_ATTEMPTS) {
        // Exponential backoff: 250ms, 500ms, 1000ms, 2000ms ...
        const delay = OBSERVER_RETRY_BASE_MS * Math.pow(2, attempt);
        console.warn(
          `${LOG_PREFIX} [role="main"] not found. Retrying in ${delay}ms (attempt ${attempt + 1}/${OBSERVER_RETRY_MAX_ATTEMPTS})...`
        );
        setTimeout(() => initObserver(attempt + 1), delay);
        return;
      }

      // All retries exhausted — attach to document.body as last resort
      console.warn(
        `${LOG_PREFIX} [role="main"] not found after ${OBSERVER_RETRY_MAX_ATTEMPTS} attempts. Falling back to document.body.`
      );
    }

    const targetNode = mainNode || document.body;

    if (observer) {
      observer.disconnect();
    }

    observer = new MutationObserver(onMutationObserved);

    observer.observe(targetNode, {
      childList: true,
      subtree: true,
      characterData: false
    });

    console.log(
      `${LOG_PREFIX} MutationObserver attached to`,
      mainNode ? '[role="main"]' : 'document.body (fallback after retry exhaustion)'
    );

    // Trigger an immediate extraction pass in case an email thread is
    // already open when the observer attaches (e.g., direct URL navigation).
    onMutationObserved();
  }

  // Initialize observer when document is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initObserver);
  } else {
    initObserver();
  }

  // Expose API for testing and extension communication
  window.AegisContentScript = {
    extractEmailContext,
    SELECTORS,
    reinitialize: initObserver
  };
})();
