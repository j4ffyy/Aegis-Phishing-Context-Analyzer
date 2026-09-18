/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Background Service Worker & Communication Bridge
 * Specification: Implementation Plan §3.1, §5.1.4, §5.1.5 (Milestone 2.3)
 *
 * Responsibilities:
 * - Asynchronous inter-process message bridge between Content Script / UI and Backend.
 * - Enforces strict 2.0-second network abort timeout via AbortController.
 * - Autonomous offline fallback indicator delegation if backend or network is unavailable.
 * - LRU & TTL cache manager backed by chrome.storage.local (100 entries max, 7-day TTL).
 * - Backend service health probe and configuration management.
 */

// ---------------------------------------------------------------------------
// 1. Constants & Configuration (§5.1.4, §5.1.5)
// ---------------------------------------------------------------------------
const LOG_PREFIX = '[Aegis::Background]';

const CONFIG = {
  DEFAULT_BACKEND_URL: 'http://localhost:8000',
  NETWORK_TIMEOUT_MS: 2000,          // 2.0-second network abort timeout per §5.1.4 & §3.1
  MAX_CACHE_ENTRIES: 100,            // LRU capacity ceiling per §5.1.5
  CACHE_TTL_MS: 7 * 24 * 60 * 60 * 1000, // 7-day TTL in milliseconds per §5.1.5
  STORAGE_KEY_CACHE: 'aegis_analysis_cache',
  STORAGE_KEY_CONFIG: 'aegis_config',
};

// ---------------------------------------------------------------------------
// 2. Cryptographic Hashing & Key Generation
// ---------------------------------------------------------------------------

/**
 * Computes a SHA-256 hexadecimal hash string for a given text payload.
 * Supports Web Crypto API in browser/service worker and fallback for Node testing.
 * @param {string} text 
 * @returns {Promise<string>}
 */
async function computeSHA256(text) {
  if (typeof crypto !== 'undefined' && crypto.subtle && typeof crypto.subtle.digest === 'function') {
    const encoder = new TextEncoder();
    const data = encoder.encode(text || '');
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  // Node.js environment fallback for automated testing
  if (typeof require !== 'undefined') {
    try {
      const nodeCrypto = require('crypto');
      return nodeCrypto.createHash('sha256').update(text || '').digest('hex');
    } catch (e) {
      // ignore
    }
  }

  // Pure JS fallback FNV-1a hash formatted as 64-char string if crypto is absent
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  const str = String(text || '');
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = ((h1 ^ (h1 >>> 16)) >>> 0).toString(16).padStart(8, '0');
  h2 = ((h2 ^ (h2 >>> 16)) >>> 0).toString(16).padStart(8, '0');
  return (h1 + h2).repeat(4).slice(0, 64);
}

/**
 * Derives a deterministic cache key from sanitized email context.
 * Uses Sender + Subject + Normalized Links + Attachment Count + Body preview.
 * @param {object} emailContext
 * @returns {Promise<string>}
 */
async function deriveEmailCacheKey(emailContext) {
  if (!emailContext) return computeSHA256('empty');
  
  const sender = (emailContext.senderEmail || '').toLowerCase().trim();
  const subject = (emailContext.subject || '').trim();
  const bodySample = (emailContext.bodyText || '').slice(0, 300).trim();
  const links = Array.isArray(emailContext.links)
    ? emailContext.links.map(l => (typeof l === 'string' ? l : l.url || '')).sort().join(',')
    : '';
  const attachCount = emailContext.attachmentCount || 0;

  const rawKey = `${sender}|${subject}|${attachCount}|${links}|${bodySample}`;
  return computeSHA256(rawKey);
}

// ---------------------------------------------------------------------------
// 3. Storage Adapter (chrome.storage.local with in-memory fallback)
// ---------------------------------------------------------------------------

const storageAdapter = {
  async get(key) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return new Promise((resolve) => {
        chrome.storage.local.get([key], (res) => resolve(res ? res[key] : null));
      });
    }
    // In-memory fallback
    if (!this._memoryStore) this._memoryStore = {};
    return this._memoryStore[key] || null;
  },

  async set(key, value) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return new Promise((resolve) => {
        chrome.storage.local.set({ [key]: value }, () => resolve());
      });
    }
    if (!this._memoryStore) this._memoryStore = {};
    this._memoryStore[key] = value;
  },

  async remove(key) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return new Promise((resolve) => {
        chrome.storage.local.remove([key], () => resolve());
      });
    }
    if (!this._memoryStore) this._memoryStore = {};
    delete this._memoryStore[key];
  },

  async clear() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return new Promise((resolve) => {
        chrome.storage.local.clear(() => resolve());
      });
    }
    this._memoryStore = {};
  }
};

// ---------------------------------------------------------------------------
// 4. LRU & TTL Cache Manager (§5.1.5)
// ---------------------------------------------------------------------------

const AegisCache = {
  /**
   * Retrieves an item from the cache.
   * Checks TTL: if expired, deletes entry and returns null.
   * Updates lastAccessed timestamp to enforce LRU policy.
   * @param {string} key
   * @returns {Promise<object|null>}
   */
  async get(key) {
    try {
      const cacheStore = (await storageAdapter.get(CONFIG.STORAGE_KEY_CACHE)) || {};
      const entry = cacheStore[key];

      if (!entry) {
        return null;
      }

      const now = Date.now();
      // TTL Check (7 days = 604,800,000 ms)
      if (now - entry.createdAt > CONFIG.CACHE_TTL_MS) {
        console.log(`${LOG_PREFIX} Cache entry expired for key ${key.slice(0, 8)}... Evicting.`);
        delete cacheStore[key];
        await storageAdapter.set(CONFIG.STORAGE_KEY_CACHE, cacheStore);
        return null;
      }

      // Update LRU access timestamp
      entry.lastAccessed = now;
      cacheStore[key] = entry;
      await storageAdapter.set(CONFIG.STORAGE_KEY_CACHE, cacheStore);

      return entry.data;
    } catch (err) {
      console.warn(`${LOG_PREFIX} Cache read error:`, err);
      return null;
    }
  },

  /**
   * Saves an item to the cache with LRU & TTL eviction enforcement.
   * If cache exceeds MAX_CACHE_ENTRIES (100), removes the least-recently accessed entry.
   * @param {string} key
   * @param {object} data
   * @returns {Promise<void>}
   */
  async set(key, data) {
    try {
      const cacheStore = (await storageAdapter.get(CONFIG.STORAGE_KEY_CACHE)) || {};
      const now = Date.now();

      // 1. Prune all expired entries first
      for (const [k, item] of Object.entries(cacheStore)) {
        if (now - item.createdAt > CONFIG.CACHE_TTL_MS) {
          delete cacheStore[k];
        }
      }

      // 2. Enforce LRU capacity limit if still at or above ceiling
      const keys = Object.keys(cacheStore);
      if (!cacheStore[key] && keys.length >= CONFIG.MAX_CACHE_ENTRIES) {
        // Find entry with oldest lastAccessed timestamp
        let oldestKey = null;
        let oldestTime = Infinity;

        for (const k of keys) {
          const itemTime = cacheStore[k].lastAccessed || cacheStore[k].createdAt || 0;
          if (itemTime < oldestTime) {
            oldestTime = itemTime;
            oldestKey = k;
          }
        }

        if (oldestKey) {
          console.log(`${LOG_PREFIX} Cache capacity (${CONFIG.MAX_CACHE_ENTRIES}) reached. Evicting LRU item ${oldestKey.slice(0, 8)}...`);
          delete cacheStore[oldestKey];
        }
      }

      // 3. Store new/updated entry
      cacheStore[key] = {
        data,
        createdAt: now,
        lastAccessed: now
      };

      await storageAdapter.set(CONFIG.STORAGE_KEY_CACHE, cacheStore);
    } catch (err) {
      console.warn(`${LOG_PREFIX} Cache write error:`, err);
    }
  },

  /**
   * Clears all entries in the analysis cache.
   */
  async clear() {
    await storageAdapter.remove(CONFIG.STORAGE_KEY_CACHE);
  },

  /**
   * Returns cache statistics (entry count and oldest timestamp).
   */
  async getStats() {
    const cacheStore = (await storageAdapter.get(CONFIG.STORAGE_KEY_CACHE)) || {};
    const keys = Object.keys(cacheStore);
    return {
      entryCount: keys.length,
      maxCapacity: CONFIG.MAX_CACHE_ENTRIES,
      ttlMs: CONFIG.CACHE_TTL_MS
    };
  }
};

// ---------------------------------------------------------------------------
// 5. Network Request Handler with 2.0s Abort Timeout (§5.1.4, §3.1)
// ---------------------------------------------------------------------------

/**
 * Executes a fetch request with an AbortController timeout.
 * @param {string} url
 * @param {object} options
 * @param {number} timeoutMs
 * @returns {Promise<Response>}
 */
async function fetchWithTimeout(url, options = {}, timeoutMs = CONFIG.NETWORK_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    return response;
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      const abortError = new Error(`Network request aborted: Exceeded ${timeoutMs}ms timeout limit`);
      abortError.name = 'AbortError';
      abortError.isTimeout = true;
      throw abortError;
    }
    throw err;
  }
}

/**
 * Retrieves the currently configured backend endpoint URL.
 */
async function getBackendUrl() {
  try {
    const config = (await storageAdapter.get(CONFIG.STORAGE_KEY_CONFIG)) || {};
    return config.backendUrl || CONFIG.DEFAULT_BACKEND_URL;
  } catch {
    return CONFIG.DEFAULT_BACKEND_URL;
  }
}

// ---------------------------------------------------------------------------
// 6. Analysis Dispatch & Offline Fallback Router
// ---------------------------------------------------------------------------

/**
 * Primary dispatch function for email risk analysis.
 * Checks cache -> Calls Backend (/api/v1/analyze) with 2.0s abort -> Emits fallback signal on failure.
 *
 * @param {object} emailPayload - Sanitized email context from content script
 * @returns {Promise<object>} Analysis result structure
 */
async function dispatchEmailAnalysis(emailPayload) {
  const startTime = Date.now();
  const cacheKey = await deriveEmailCacheKey(emailPayload);

  // 1. Local Cache Check (§3.1 step 70-71)
  const cachedResult = await AegisCache.get(cacheKey);
  if (cachedResult) {
    console.log(`${LOG_PREFIX} Cache HIT (0ms): Returned analysis for key ${cacheKey.slice(0, 8)}`);
    return {
      ...cachedResult,
      _source: 'local_cache',
      _cacheHit: true,
      _executionTimeMs: Date.now() - startTime
    };
  }

  console.log(`${LOG_PREFIX} Cache MISS: Dispatching to backend API with ${CONFIG.NETWORK_TIMEOUT_MS}ms abort timeout...`);

  const backendBaseUrl = await getBackendUrl();
  const targetUrl = `${backendBaseUrl.replace(/\/+$/, '')}/api/v1/analyze`;

  try {
    const response = await fetchWithTimeout(
      targetUrl,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(emailPayload)
      },
      CONFIG.NETWORK_TIMEOUT_MS
    );

    if (!response.ok) {
      throw new Error(`HTTP Error ${response.status}: ${response.statusText}`);
    }

    const result = await response.json();
    const executionTimeMs = Date.now() - startTime;

    // Cache the verified successful result
    await AegisCache.set(cacheKey, result);

    return {
      ...result,
      _source: 'remote_backend',
      _cacheHit: false,
      _executionTimeMs: executionTimeMs
    };
  } catch (err) {
    const isTimeout = err.isTimeout || err.name === 'AbortError';
    const reason = isTimeout
      ? `Backend request timed out after ${CONFIG.NETWORK_TIMEOUT_MS}ms`
      : `Backend unreachable: ${err.message}`;

    console.warn(`${LOG_PREFIX} ${reason}. Initiating autonomous offline fallback mode.`);

    // Return an explicit fallback directive. The content script / overlay will
    // seamlessly evaluate via AegisLocalHeuristics with fallback annotations.
    return {
      _source: 'offline_fallback',
      _fallback: true,
      _fallbackReason: reason,
      _isTimeout: isTimeout,
      _executionTimeMs: Date.now() - startTime,
      status: 'offline_fallback'
    };
  }
}

/**
 * Probes the backend health endpoint.
 * @returns {Promise<object>}
 */
async function checkBackendHealth() {
  const backendBaseUrl = await getBackendUrl();
  const targetUrl = `${backendBaseUrl.replace(/\/+$/, '')}/api/v1/health`;

  try {
    const response = await fetchWithTimeout(targetUrl, { method: 'GET' }, 2000);
    if (!response.ok) {
      return { online: false, status: response.status, error: response.statusText };
    }
    const data = await response.json();
    return { online: true, ...data };
  } catch (err) {
    return {
      online: false,
      error: err.name === 'AbortError' ? 'Probe timed out (2.0s)' : err.message
    };
  }
}

/**
 * Polls backend for VirusTotal background scan status (§3.1 step 85-88).
 * @param {string} emailHash
 * @returns {Promise<object>}
 */
async function checkVTStatus(emailHash) {
  if (!emailHash) {
    throw new Error('Missing emailHash for VT status check');
  }

  const backendBaseUrl = await getBackendUrl();
  const targetUrl = `${backendBaseUrl.replace(/\/+$/, '')}/api/v1/vt-status/${encodeURIComponent(emailHash)}`;

  const response = await fetchWithTimeout(targetUrl, { method: 'GET' }, CONFIG.NETWORK_TIMEOUT_MS);
  if (!response.ok) {
    if (response.status === 404) {
      return { status: 'not_found', email_hash: emailHash };
    }
    throw new Error(`HTTP Error ${response.status}: ${response.statusText}`);
  }

  return response.json();
}

// ---------------------------------------------------------------------------
// 7. Chrome Runtime Message Listener (MV3 Asynchronous Bridge)
// ---------------------------------------------------------------------------

if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || !message.action) {
      return false;
    }

    const { action, payload } = message;

    // Dispatch async actions and return true synchronously (§5.1.4)
    if (action === 'AEGIS_ANALYZE_EMAIL') {
      dispatchEmailAnalysis(payload)
        .then((result) => sendResponse({ success: true, data: result }))
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true; // Crucial: Keeps inter-process communication port open
    }

    if (action === 'AEGIS_CHECK_VT_STATUS') {
      const emailHash = typeof payload === 'string' ? payload : payload?.emailHash;
      checkVTStatus(emailHash)
        .then((result) => sendResponse({ success: true, data: result }))
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;
    }

    if (action === 'AEGIS_UPDATE_CACHE') {
      const { cacheKey, analysis } = payload || {};
      if (cacheKey && analysis) {
        AegisCache.set(cacheKey, analysis)
          .then(() => sendResponse({ success: true }))
          .catch((err) => sendResponse({ success: false, error: err.message }));
        return true;
      }
      sendResponse({ success: false, error: 'Missing cacheKey or analysis' });
      return false;
    }

    if (action === 'AEGIS_CHECK_HEALTH') {
      checkBackendHealth()
        .then((result) => sendResponse({ success: true, data: result }))
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;
    }

    if (action === 'AEGIS_GET_CACHE_STATS') {
      AegisCache.getStats()
        .then((stats) => sendResponse({ success: true, data: stats }))
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;
    }

    if (action === 'AEGIS_CLEAR_CACHE') {
      AegisCache.clear()
        .then(() => sendResponse({ success: true, message: 'Cache cleared successfully' }))
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;
    }

    return false;
  });

  chrome.runtime.onInstalled?.addListener((details) => {
    console.log(`${LOG_PREFIX} Service Worker initialized (${details.reason || 'runtime'}).`);
  });
}

// ---------------------------------------------------------------------------
// 8. Module Exports (for Unit Test Environment)
// ---------------------------------------------------------------------------

const BackgroundBridgeAPI = {
  CONFIG,
  computeSHA256,
  deriveEmailCacheKey,
  storageAdapter,
  AegisCache,
  fetchWithTimeout,
  dispatchEmailAnalysis,
  checkBackendHealth,
  checkVTStatus
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = BackgroundBridgeAPI;
}
