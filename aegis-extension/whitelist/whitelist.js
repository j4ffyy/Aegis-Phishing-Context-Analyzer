/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Whitelist Management & Dual-Trigger Auto-Revocation Engine
 * Specification: Implementation Plan §7, §7.1 (Milestone 3.3)
 */

(function () {
  'use strict';

  var LOG_PREFIX = '[Aegis::Whitelist]';
  var STORAGE_KEY_WHITELIST = 'aegis_whitelist';

  // Default seed identities for demonstration and first-launch SME context
  var DEFAULT_WHITELIST = [
    {
      id: 'wl_seed_001',
      email: 'executive.director@sme-corp.com',
      displayName: 'Executive Director',
      role: 'Executive Director',
      department: 'Executive Management',
      allowedDomain: 'sme-corp.com',
      addedAt: '2026-09-01T08:00:00.000Z',
      notes: 'Protected executive identity — monitored for VIP display-name spoofing'
    },
    {
      id: 'wl_seed_002',
      email: 'payroll@trusted-bank.ph',
      displayName: 'BDO Merchant Services',
      role: 'Banking Partner',
      department: 'Treasury & Finance',
      allowedDomain: 'trusted-bank.ph',
      addedAt: '2026-09-05T09:30:00.000Z',
      notes: 'Authorized financial partner for SME payroll disbursement'
    }
  ];

  // ---------------------------------------------------------------------------
  // Storage Adapter: chrome.storage.local with In-Memory Fallback
  // ---------------------------------------------------------------------------

  var whitelistStorage = {
    _mem: null,

    get: function () {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise(function (resolve) {
          chrome.storage.local.get([STORAGE_KEY_WHITELIST], function (res) {
            var data = res && res[STORAGE_KEY_WHITELIST];
            if (!Array.isArray(data)) {
              // Initialize with defaults if empty
              var initial = DEFAULT_WHITELIST.slice();
              var payload = {};
              payload[STORAGE_KEY_WHITELIST] = initial;
              chrome.storage.local.set(payload, function () {
                resolve(initial);
              });
            } else {
              resolve(data);
            }
          });
        });
      }

      // In-memory fallback (Node.js unit tests and headless environments)
      if (whitelistStorage._mem === null) {
        whitelistStorage._mem = DEFAULT_WHITELIST.slice();
      }
      return Promise.resolve(whitelistStorage._mem.slice());
    },

    set: function (entries) {
      if (!Array.isArray(entries)) entries = [];
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise(function (resolve) {
          var payload = {};
          payload[STORAGE_KEY_WHITELIST] = entries;
          chrome.storage.local.set(payload, function () {
            resolve();
          });
        });
      }

      whitelistStorage._mem = entries.slice();
      return Promise.resolve();
    },

    clear: function () {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise(function (resolve) {
          chrome.storage.local.remove([STORAGE_KEY_WHITELIST], function () {
            resolve();
          });
        });
      }
      whitelistStorage._mem = [];
      return Promise.resolve();
    }
  };

  // ---------------------------------------------------------------------------
  // Helper Utility Functions
  // ---------------------------------------------------------------------------

  function normalizeEmail(email) {
    return (email || '').toLowerCase().trim();
  }

  function extractDomain(email) {
    var norm = normalizeEmail(email);
    if (!norm || !norm.includes('@')) return '';
    return norm.split('@')[1].trim();
  }

  function generateId() {
    return 'wl_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
  }

  // ---------------------------------------------------------------------------
  // Whitelist CRUD Operations
  // ---------------------------------------------------------------------------

  /**
   * Retrieves all whitelisted sender records.
   * @returns {Promise<Array<Object>>}
   */
  function getWhitelist() {
    return whitelistStorage.get();
  }

  /**
   * Adds or updates a trusted identity in the whitelist directory.
   *
   * @param {Object} entry
   * @param {string} entry.email - Sender email address (required)
   * @param {string} [entry.displayName] - Display name / contact title
   * @param {string} [entry.role] - Organizational role (e.g., CFO, Partner)
   * @param {string} [entry.department] - Department (e.g., Finance, HR)
   * @param {string} [entry.allowedDomain] - Allowed domain lock (defaults to email domain)
   * @param {string} [entry.notes] - Administrative notes
   * @returns {Promise<Object>} Added/Updated entry
   */
  function addWhitelistEntry(entry) {
    if (!entry || typeof entry !== 'object') {
      return Promise.reject(new Error('Invalid entry payload'));
    }

    var email = normalizeEmail(entry.email);
    if (!email || !email.includes('@')) {
      return Promise.reject(new Error('Valid email address is required'));
    }

    var domain = (entry.allowedDomain || extractDomain(email)).toLowerCase().trim();
    var displayName = (entry.displayName || '').trim() || email;
    var role = (entry.role || '').trim() || 'Trusted Contact';
    var department = (entry.department || '').trim() || 'General';
    var notes = (entry.notes || '').trim();

    return whitelistStorage.get().then(function (list) {
      var existingIndex = list.findIndex(function (e) {
        return normalizeEmail(e.email) === email;
      });

      var record = {
        id: existingIndex >= 0 ? list[existingIndex].id : generateId(),
        email: email,
        displayName: displayName,
        role: role,
        department: department,
        allowedDomain: domain,
        addedAt: existingIndex >= 0 ? list[existingIndex].addedAt : new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        notes: notes
      };

      if (existingIndex >= 0) {
        list[existingIndex] = record;
      } else {
        list.push(record);
      }

      return whitelistStorage.set(list).then(function () {
        console.log(LOG_PREFIX + ' Whitelist record saved for: ' + email);
        return record;
      });
    });
  }

  /**
   * Removes a whitelist entry by unique ID or email address.
   * @param {string} identifier - Record ID or email
   * @returns {Promise<boolean>} True if removed, false otherwise
   */
  function removeWhitelistEntry(identifier) {
    if (!identifier) return Promise.resolve(false);
    var target = identifier.toLowerCase().trim();

    return whitelistStorage.get().then(function (list) {
      var initialLen = list.length;
      var filtered = list.filter(function (e) {
        return e.id.toLowerCase() !== target && normalizeEmail(e.email) !== target;
      });

      if (filtered.length === initialLen) {
        return false;
      }

      return whitelistStorage.set(filtered).then(function () {
        console.log(LOG_PREFIX + ' Removed whitelist entry: ' + identifier);
        return true;
      });
    });
  }

  /**
   * Resets whitelist directory to default initial seeds.
   * @returns {Promise<Array<Object>>}
   */
  function resetToDefaults() {
    var fresh = DEFAULT_WHITELIST.slice();
    return whitelistStorage.set(fresh).then(function () {
      return fresh;
    });
  }

  /**
   * Clears all whitelist records.
   * @returns {Promise<void>}
   */
  function clearWhitelist() {
    return whitelistStorage.clear();
  }

  // ---------------------------------------------------------------------------
  // Dual-Trigger Auto-Revocation Engine (§7.1)
  // ---------------------------------------------------------------------------

  /**
   * Evaluates an email context against the whitelist and auto-revocation rules.
   *
   * Trigger 1: Display-Name Spoofing Detection (DOM Integration):
   *   If incoming display name matches a protected whitelisted identity (e.g. "Executive Director"),
   *   but extracted email address does not match the registered domain -> override whitelist,
   *   issue critical alert, enforce risk score 95%.
   *
   * Trigger 2: Cryptographic Authentication Failure (Synthetic Verification):
   *   If email originating from whitelisted address explicitly fails SPF or DKIM validation
   *   (spfPass === false or dkimPass === false) -> revoke whitelist, enforce score 95%.
   *
   * Clean Whitelisted Match:
   *   Sender matches whitelisted address, display name matches, auth passed/unfailed -> score 5 (Safe).
   *
   * @param {Object} emailContext - Email metadata { senderEmail, senderName, subject, ... }
   * @param {Object} [authStatus] - Optional { spfPass: boolean, dkimPass: boolean }
   * @returns {Promise<Object>} Whitelist evaluation result
   */
  function checkWhitelistStatus(emailContext, authStatus) {
    if (!emailContext || typeof emailContext !== 'object') {
      return Promise.resolve({
        whitelisted: false,
        revoked: false,
        trigger: null,
        score: null,
        reason: 'No email context provided'
      });
    }

    var senderEmail = normalizeEmail(emailContext.senderEmail);
    var senderName = (emailContext.senderName || '').trim();
    var senderDomain = extractDomain(senderEmail);

    var spfPass = authStatus && authStatus.spfPass !== undefined ? authStatus.spfPass : emailContext.spfPass;
    var dkimPass = authStatus && authStatus.dkimPass !== undefined ? authStatus.dkimPass : emailContext.dkimPass;

    return whitelistStorage.get().then(function (whitelist) {
      if (!Array.isArray(whitelist) || whitelist.length === 0) {
        return {
          whitelisted: false,
          revoked: false,
          trigger: null,
          score: null,
          reason: 'Whitelist directory is empty'
        };
      }

      // -----------------------------------------------------------------------
      // TRIGGER 1: Display-Name Spoofing Detection
      // -----------------------------------------------------------------------
      if (senderName) {
        var senderNameLower = senderName.toLowerCase();

        for (var i = 0; i < whitelist.length; i++) {
          var entry = whitelist[i];
          var targetName = (entry.displayName || '').toLowerCase().trim();
          var targetRole = (entry.role || '').toLowerCase().trim();
          var allowedDomain = (entry.allowedDomain || extractDomain(entry.email)).toLowerCase().trim();

          // Check if display name strongly matches a protected identity
          var isNameMatch = targetName && (
            senderNameLower === targetName ||
            senderNameLower.startsWith(targetName + ' ') ||
            senderNameLower.includes(targetName)
          );
          var isRoleMatch = targetRole && targetRole !== 'trusted contact' && (
            senderNameLower === targetRole ||
            senderNameLower.includes(targetRole)
          );

          if (isNameMatch || isRoleMatch) {
            // Identity claimed! Verify if sender email matches authorized domain/email
            var isDomainAuthorized = senderDomain && (
              senderDomain === allowedDomain ||
              senderDomain.endsWith('.' + allowedDomain)
            );
            var isEmailIdentical = senderEmail === normalizeEmail(entry.email);

            if (!isDomainAuthorized && !isEmailIdentical) {
              // TRIGGER 1 ACTIVATED: Display-name spoofing attack detected
              console.warn(
                LOG_PREFIX + ' [AUTO-REVOKE TRIGGER 1] Display-name spoofing detected! ' +
                'Claimed: "' + senderName + '" but actual address is: ' + senderEmail
              );

              return {
                whitelisted: false,
                revoked: true,
                trigger: 'DISPLAY_NAME_SPOOFING',
                score: 95,
                riskLevel: 'Critical',
                riskClass: 'threat-critical',
                flag: 'CRITICAL: Targeted Display-Name Spoofing Detected',
                reason: 'The display name "' + senderName + '" impersonates protected identity "' +
                        entry.displayName + '" (' + (entry.role || 'Executive') + '), but the email originates ' +
                        'from an unauthorized domain (' + (senderDomain || 'unknown') + ' != ' + allowedDomain + ').',
                matchedIdentity: entry
              };
            }
          }
        }
      }

      // -----------------------------------------------------------------------
      // DIRECT MATCH & TRIGGER 2: Cryptographic Auth Failure
      // -----------------------------------------------------------------------
      var directEntry = whitelist.find(function (e) {
        return normalizeEmail(e.email) === senderEmail;
      });

      if (directEntry) {
        // Check Trigger 2: SPF or DKIM explicitly failed
        var authFailed = (spfPass === false) || (dkimPass === false);

        if (authFailed) {
          var failedProtocols = [];
          if (spfPass === false) failedProtocols.push('SPF');
          if (dkimPass === false) failedProtocols.push('DKIM');

          console.warn(
            LOG_PREFIX + ' [AUTO-REVOKE TRIGGER 2] Cryptographic auth failed for whitelisted sender: ' +
            senderEmail + ' (Failed: ' + failedProtocols.join(', ') + ')'
          );

          return {
            whitelisted: false,
            revoked: true,
            trigger: 'AUTH_FAILURE',
            score: 95,
            riskLevel: 'Critical',
            riskClass: 'threat-critical',
            flag: 'CRITICAL: Whitelisted Identity Failed Domain Auth (' + failedProtocols.join('/') + ')',
            reason: 'Sender "' + senderEmail + '" is registered on the Whitelist, but failed cryptographic ' +
                    'authentication (' + failedProtocols.join('/') + '). The email may have been spoofed via an unauthorized relay.',
            matchedIdentity: directEntry
          };
        }

        // Clean whitelist hit
        return {
          whitelisted: true,
          revoked: false,
          trigger: null,
          score: 5,
          riskLevel: 'Safe',
          riskClass: 'threat-safe',
          flag: 'VERIFIED: Sender Identity Whitelisted',
          reason: 'Sender "' + senderEmail + '" is verified on the SME Whitelist (' +
                  (directEntry.role || directEntry.department || 'Trusted Identity') + '). Domain authentication verified.',
          matchedIdentity: directEntry
        };
      }

      // Sender not found in whitelist
      return {
        whitelisted: false,
        revoked: false,
        trigger: null,
        score: null,
        reason: 'Sender is not registered in the whitelist directory'
      };
    });
  }

  // ---------------------------------------------------------------------------
  // Public API Export
  // ---------------------------------------------------------------------------

  var AegisWhitelist = {
    getWhitelist: getWhitelist,
    addWhitelistEntry: addWhitelistEntry,
    removeWhitelistEntry: removeWhitelistEntry,
    clearWhitelist: clearWhitelist,
    resetToDefaults: resetToDefaults,
    checkWhitelistStatus: checkWhitelistStatus,
    normalizeEmail: normalizeEmail,
    extractDomain: extractDomain,
    DEFAULT_WHITELIST: DEFAULT_WHITELIST,
    STORAGE_KEY_WHITELIST: STORAGE_KEY_WHITELIST
  };

  if (typeof window !== 'undefined') {
    window.AegisWhitelist = AegisWhitelist;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = AegisWhitelist;
  }

  console.log(LOG_PREFIX + ' Whitelist & Auto-Revocation Engine initialized (§7.1 compliant).');

})();
