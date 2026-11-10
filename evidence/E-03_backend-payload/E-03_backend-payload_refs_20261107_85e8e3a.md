# Code Reference Audit: Backend Payload Structure & PII Scrubbing (E-03 / I-09)

Audit conducted at commit `85e8e3a`.

## 1. Extension Extraction & Payload Assembly
- `aegis-extension/content_script.js:L696-L702 @ 85e8e3a`: Content script passes extracted DOM context through `AegisPIIScrubber.scrubEmailPayload` prior to processing.
```javascript
var sanitizedPayload = emailContext;
if (typeof window.AegisPIIScrubber !== 'undefined' && typeof window.AegisPIIScrubber.scrubEmailPayload === 'function') {
  sanitizedPayload = window.AegisPIIScrubber.scrubEmailPayload(emailContext);
  if (sanitizedPayload.piiRedactionStats && sanitizedPayload.piiRedactionStats.total > 0) {
    console.log(LOG_PREFIX + ' PII scrubbing applied:', sanitizedPayload.piiRedactionStats);
  }
}
```
- `aegis-extension/content_script.js:L728-L731 @ 85e8e3a`: Attaches client-computed Layer 3 behavioral baseline score and dispatches event.
```javascript
sanitizedPayload._behavioral = behavioralResult;
sanitizedPayload.behavioralScore = behavioralResult.score;
sanitizedPayload.behavioral_meta = behavioralResult;
window.dispatchEvent(new CustomEvent('aegis:email-extracted', { detail: sanitizedPayload }));
```

## 2. PII Sanitization Engine
- `aegis-extension/pii_scrubber.js:L195-L221 @ 85e8e3a`: Replaces sensitive tokens with placeholders (`[EMAIL]`, `[PHONE]`, `[CARD_NUMBER]`, `[SSN]`, `[NAME]`) while preserving `senderEmail` for SPF/DKIM verification.
```javascript
function scrubEmailPayload(emailPayload) {
  if (!emailPayload) return null;
  const bodyResult = scrubText(emailPayload.bodyText || '');
  const subjectResult = scrubText(emailPayload.subject || '');
  return {
    ...emailPayload,
    bodyText: bodyResult.scrubbedText,
    rawBodyTextLength: (emailPayload.bodyText || '').length,
    scrubbedBodyTextLength: bodyResult.scrubbedText.length,
    scrubbedSubject: subjectResult.scrubbedText,
    piiSanitized: true,
    piiRedactionStats: { ... },
    sanitizedAt: new Date().toISOString()
  };
}
```

## 3. Network Transmission to Backend
- `aegis-extension/background.js:L346-L357 @ 85e8e3a`: Background service worker dispatches JSON-serialized payload to `/api/v1/analyze` with a 2000 ms timeout.
```javascript
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
```

## 4. Backend Request Ingestion Schema
- `aegis-backend/routes/analyze.py:L68-L88 @ 85e8e3a`: Declares Pydantic model `EmailPayload` accepting full scrubbed text.
```python
class EmailPayload(BaseModel):
    senderEmail: str = Field(default="", description="Sender email address")
    senderName: Optional[str] = Field(default="", description="Sender display name")
    subject: Optional[str] = Field(default="", description="Email subject line")
    bodyText: Optional[str] = Field(default="", description="Sanitized plain text body")
    links: Optional[List[Any]] = Field(default_factory=list, description="Extracted hyperlinks")
    hasAttachment: Optional[bool] = Field(default=False, description="Whether attachments are present")
    attachments: Optional[List[str]] = Field(default_factory=list, description="Attachment filenames")
    attachmentCount: Optional[int] = Field(default=0, description="Total attachment count")
    attachmentHashes: Optional[List[str]] = Field(default_factory=list, description="Cryptographic SHA-256 hashes of email attachments (PR-09)")
    timestamp: Optional[str] = Field(default="", description="Email received timestamp")
    spfPass: Optional[bool] = Field(default=None, description="SPF authentication status")
    dkimPass: Optional[bool] = Field(default=None, description="DKIM authentication status")
    emailHash: Optional[str] = Field(default=None, description="Client-derived SHA-256 hash")
    behavioralScore: Optional[int] = Field(default=None, description="Client-side behavioral anomaly score (0-100)")
    behavioral_meta: Optional[Dict[str, Any]] = Field(default=None, alias="_behavioral", description="Client-side behavioral context details")
    detectedLanguage: Optional[str] = Field(default=None, description="Heuristic detected language code: 'en', 'tl', or 'tl-en' (Taglish). PR-06.")
```

## 5. Audit Conclusion
The extension transmits the **full email body as scrubbed plain text**, not as pre-computed feature vectors or token embeddings. PII redaction is executed client-side in the browser prior to serialization over the network.
