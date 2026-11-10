# Code Reference Audit: In-Memory Data Structures & Persistence Verification (E-28 / I-09)

Audit conducted at commit `85e8e3a`.

## 1. Active In-Memory Structures
- `aegis-backend/routes/analyze.py:L58 @ 85e8e3a`: In-flight task registry mapping email SHA-256 hash to background VT scan metadata.
```python
# In-flight task tracking: email_hash -> metadata
_in_flight_scans: Dict[str, Dict[str, Any]] = {}
```
- `aegis-backend/routes/analyze.py:L61 @ 85e8e3a`: Analysis cache store mapping email SHA-256 hash to synthesized response dictionary.
```python
# Completed full analysis store: email_hash -> full analysis response dict
_analysis_store: Dict[str, Dict[str, Any]] = {}
```
- `aegis-backend/routes/analyze.py:L865-L879 @ 85e8e3a`: Detection log holding recent scan summary telemetry for `/stats` dashboard.
```python
entry: Dict[str, Any] = {
    "emailHash": payload.emailHash,
    "score":     payload.score,
    "riskLevel": payload.riskLevel,
    "sender":    payload.sender,
    "subject":   payload.subject,
    "source":    payload.source,
    "analyzedAt": payload.analyzedAt or _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z"),
}
_detection_log.insert(0, entry)
```
- `aegis-backend/routes/analyze.py:L943-L952 @ 85e8e3a`: Feedback log storing user false positive / negative reports.
```python
record: Dict[str, Any] = {
    "emailHash":   payload.emailHash,
    "userVerdict": payload.userVerdict,
    "reason":      payload.reason,
    "notes":       payload.notes,
    "sender":      payload.sender,
    "subject":     payload.subject,
    "reportedAt":  payload.reportedAt or _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z"),
}
_feedback_log.append(record)
```

## 2. Persistence Analysis
1. **Volatile Process Memory:** All four stores are native Python heap objects (`dict` and `list`).
2. **No Secondary Storage:** No disk files, SQLite databases, or external key-value stores (such as Redis) are connected.
3. **Lifecycle Reset:** When the backend process terminates or restarts (e.g. Render free-tier container spin-down after 15 minutes of inactivity), all state in `_in_flight_scans`, `_analysis_store`, `_detection_log`, and `_feedback_log` is completely wiped.
