# Code Reference Audit: Request-Body Logging Verification (E-04 / I-09)

Audit conducted at commit `85e8e3a`.

## 1. Application Middleware & Lifecycle Logging
- `aegis-backend/main.py:L95-L99 @ 85e8e3a`: Startup lifespan logs environment configuration and cache priming without inspecting request streams.
```python
logger.info("[Aegis] CORS mode: %s", _CORS_MODE)
logger.info("[Aegis] Render backend: %s", RENDER_BACKEND_URL)
warm_up_nlp()
load_vt_seed_cache()
load_vt_file_seed_cache()
```
- `aegis-backend/main.py:L117-L122 @ 85e8e3a`: Middleware configuration includes only standard `CORSMiddleware`. There is no request-logging middleware capturing bodies.
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
```

## 2. Analysis Route Logging
- `aegis-backend/routes/analyze.py:L647-L652 @ 85e8e3a`: Cache hit log records only an 8-character prefix of the email SHA-256 hash.
```python
if email_hash in _analysis_store:
    logger.info("[Aegis Analysis] Analysis store HIT for email_hash=%s", email_hash[:8])
    cached_result = dict(_analysis_store[email_hash])
    cached_result["_cacheHit"] = True
    return cached_result
```
- `aegis-backend/routes/analyze.py:L881-L884 @ 85e8e3a`: Telemetry logging truncates hash to 12 characters and logs numeric score and tier only.
```python
logger.info(
    "Detection logged | hash=%s score=%d tier=%s",
    payload.emailHash[:12], payload.score, payload.riskLevel,
)
```

## 3. Audit Conclusion
The backend service **does not log request bodies** or raw email content. Logging is strictly limited to lifecycle events, error exceptions, and anonymized hash identifiers.
