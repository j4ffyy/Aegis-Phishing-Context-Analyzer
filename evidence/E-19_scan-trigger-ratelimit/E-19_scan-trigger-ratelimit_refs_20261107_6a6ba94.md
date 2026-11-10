# Code Reference Audit: Scan Trigger & Rate Limit Mechanism (E-19 / I-10)

Audit conducted at commit `6a6ba94`.

## 1. Gmail DOM MutationObserver & Debounce
- `aegis-extension/content_script.js:L24 @ 6a6ba94`: Sets debounce timer constant to 300 milliseconds.
```javascript
var DEBOUNCE_DELAY_MS = 300;
```
- `aegis-extension/content_script.js:L787-L798 @ 6a6ba94`: Attaches `MutationObserver` to Gmail's primary viewport `[role="main"]` monitoring subtree modifications.
```javascript
observer = new MutationObserver(function () {
  onMutationObserved();
});
observer.observe(targetNode, {
  childList: true,
  subtree: true
});
```

## 2. Extraction Deduplication
- `aegis-extension/content_script.js:L642-L652 @ 6a6ba94`: Generates a composite signature consisting of sender, subject, attachment count, link count, and body snippet.
```javascript
function generateSignature(email) {
  if (!email) return '';
  return [
    email.senderEmail || '',
    email.subject || '',
    email.attachmentCount || 0,
    (email.links || []).length,
    (email.bodyText || '').slice(0, 100)
  ].join(':::');
}
```
- `aegis-extension/content_script.js:L683-L685 @ 6a6ba94`: Compares signature to `lastProcessedSignature` to halt redundant extractions while the user is reading an open thread.
```javascript
var signature = generateSignature(emailContext);
if (signature === lastProcessedSignature) return;
lastProcessedSignature = signature;
```

## 3. Scan Triggering Behavior & User Interaction
- `aegis-extension/overlay/overlay.js:L1405-L1416 @ 6a6ba94`: When the user is in Gmail list views (`#inbox`, `#starred`, etc.), the scan trigger is suppressed and the button is hidden (`el.fab.style.display = 'none'`).
- `aegis-extension/overlay/overlay.js:L1438-L1451 @ 6a6ba94`: 
  - **Closed Panel:** When an email thread is detected and the overlay is closed, scanning is **not auto-dispatched**. Instead, the Floating Action Button (FAB) is presented (`el.fab.style.display = 'flex'`) for explicit user-initiated analysis.
  - **Open Panel:** If the user already opened the overlay panel and navigates between emails, the controller automatically triggers a re-scan.

## 4. VirusTotal Rate Pacing & In-Memory Caching
- `aegis-backend/modules/link_scanner.py:L7-L14 @ 6a6ba94`: Implements temporal rate-limiting enforcing $\ge 15.0\text{ s}$ intervals between outbound queries to adhere to the free-tier quota (4 requests/minute).
```python
VT_API_MIN_INTERVAL_SECONDS: float = 15.0
VT_MAX_URLS_PER_EMAIL: int = 2
```
- `aegis-backend/modules/link_scanner.py:L56-L63 @ 6a6ba94`: Triple cache structure preventing redundant network round-trips:
  - `_vt_url_cache`: URL string $\to$ reputation record.
  - `_vt_analysis_cache`: email SHA-256 hash $\to$ composite analysis verdict.
  - `_vt_file_cache`: attachment SHA-256 hash $\to$ file threat record.
- `aegis-backend/modules/link_scanner.py:L45-L50 @ 6a6ba94`: Startup seed caches (`data/vt_seed_cache.json` and `data/vt_file_seed_cache.json`) pre-warm known URLs and hashes, ensuring 0 ms offline evaluation without outbound API consumption.

## 5. Audit Conclusion
Scanning is **strictly debounced (300 ms)** and **deduplicated by composite signature**. It does **not** spam network requests on DOM changes. Outbound VirusTotal checks are bounded by a maximum of 2 URLs per email, protected by a 15-second `asyncio.Lock` temporal spacer, and checked against local pre-warmed seed caches.
