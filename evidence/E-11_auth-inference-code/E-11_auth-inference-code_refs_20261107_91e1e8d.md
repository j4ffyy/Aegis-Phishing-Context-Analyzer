# Code Reference: SPF/DKIM Inference & Absence of DMARC Handling (E-11)

- **Evidence ID:** `E-11`
- **Canonical Slug:** `auth-inference-code`
- **Revision Matrix Rows Addressed:** 
  - Row 11 (Sir John Ray Hernani, Panel Chair — Scoring weights & auth cues)
  - Row 16 (Sir Renz Canlas, Panel Member — Gmail scope overstated: DOM overlay only, no raw header access or API quarantine)
- **Repository Commit:** `91e1e8d` (eval-freeze)
- **Date (UTC):** 2026-11-07
- **Verification Status:** Verified against `aegis-extension/content_script.js`, `aegis-backend/routes/analyze.py`, and grep audit `E-36`.

---

## 1. Executive Summary & Defense Response

During defense evaluation, the panel noted:
> *"Gmail scope overstated (V6): paper claims 'Gmail integration'; system is a DOM overlay only — cannot quarantine, delete, or move emails... E-11 shows content_script.js infers SPF/DKIM from the Gmail UI via extractAuthStatus(), not read from raw email headers. DMARC is not handled."*

This document provides exact source code citations confirming:
1. **DOM-Only Auth Inference:** Aegis does not access RFC 5322 raw email MIME headers via IMAP/POP3 or the Google Workspace API. Authentication indicators are inferred strictly from Gmail's DOM presentation layer via `extractAuthStatus()`.
2. **Complete Absence of DMARC:** DMARC is entirely unhandled in client-side extraction, backend heuristics, ML ensemble classifiers, and scoring logic (zero occurrences across source code, verified in `E-36`).
3. **Tri-State Classification (Post-Defense Fix I-01):**
   - **Fail:** Inferred from Gmail warning alert banners (`.msg-header-warning`, "couldn't verify").
   - **Pass:** Inferred from Gmail sender details dropdown (`.cf.gJ`, `mailed-by`, `signed-by`).
   - **Not verified:** Returned when headers are collapsed or absent (`spfPass=null`, `dkimPass=null`), displaying a neutral "Not verified" badge in both overlay and Advanced FAM drawer without scoring penalty.

---

## 2. Client-Side DOM Extraction Citations

### 2.1 `extractAuthStatus()` Implementation
- **File:** `aegis-extension/content_script.js`
- **Lines 198–285:**
```javascript
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
            alertText: alertText.slice(0, 120)
          };
        }
      }
    } catch (e) {}
  }

  // 2. Check open message details dropdown (mailed-by / signed-by rows)
  for (var d = 0; d < SELECTORS.authDetails.length; d++) {
    try {
      var detailsEl = root.querySelector(SELECTORS.authDetails[d]);
      if (detailsEl) {
        var text = detailsEl.textContent || '';
        var hasMailedBy = /mailed-by/i.test(text);
        var hasSignedBy = /signed-by/i.test(text);

        if (hasMailedBy || hasSignedBy) {
          var mailedMatch = text.match(/mailed-by:\s*([^\s<]+)/i);
          var signedMatch = text.match(/signed-by:\s*([^\s<]+)/i);

          return {
            spfPass: hasMailedBy ? true : null,
            dkimPass: hasSignedBy ? true : null,
            mailedBy: mailedMatch ? mailedMatch[1].trim() : null,
            signedBy: signedMatch ? signedMatch[1].trim() : null,
            source: 'gmail_details_table',
            alertText: null
          };
        }
      }
    } catch (e) {}
  }

  // 3. Fallback: Indeterminate / collapsed headers
  return {
    spfPass: null,
    dkimPass: null,
    mailedBy: null,
    signedBy: null,
    source: 'indeterminate',
    alertText: null
  };
}
```

---

## 3. Absence of DMARC Handling

1. **DOM Scrapers:** `content_script.js` extracts only `mailed-by` (SPF proxy) and `signed-by` (DKIM proxy). It contains no selectors, regex patterns, or parsing routines for DMARC policies (`p=none`, `p=quarantine`, `p=reject`).
2. **Payload Schema:** `routes/analyze.py` (`EmailPayload`) defines only `spfPass: Optional[bool]` and `dkimPass: Optional[bool]`. No `dmarcPass` field exists.
3. **ML Ensemble Features:** `modules/ensemble_classifier.py` defines 12 tabular features for Random Forest and XGBoost. Feature 8 is `spf_fail` ($1$ if SPF fails, $0$ otherwise). No DMARC feature exists.
4. **Codebase Grep Audit (`E-36`):** Automated grep across 57 extension and backend source files produced **zero** occurrences of DMARC in runtime execution paths (commit `74f3086` removed the remaining descriptive UI label).

---

## 4. Architectural Boundaries: DOM Overlay vs. Native Mail API

| Capability | Native Email API (e.g. Google Workspace API) | Aegis Implementation (Manifest V3 DOM Overlay) |
| :--- | :--- | :--- |
| **Header Access** | Full raw RFC 5322 MIME headers (`Authentication-Results`, `Received-SPF`, `DKIM-Signature`, `DMARC-Filter`) | Inferred from Gmail DOM visual elements only (`extractAuthStatus()`). |
| **Quarantine / Move** | Server-side routing: move to Spam, quarantine, reject delivery | Client-side visual DOM injection only; cannot move or quarantine. |
| **Shared Inbox Protection** | Universal policy applied at mail server before delivery | Local browser session only; visual badge displayed only to the active user. |
| **Privacy / Zero-Storage** | Requires full mailbox access permissions (OAuth `gmail.modify`) | Content script reads active DOM node; zero mailbox permissions required. |

---

## 5. Conclusion
Aegis functions strictly as an **ephemeral DOM context analyzer**. Claims of native "Gmail Integration" or "DMARC enforcement" are formally disavowed and corrected across manuscript Chapters 1, 3, and 5.
