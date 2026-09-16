"""
Aegis: AI-Powered Phishing Context Analyzer
Module: VirusTotal Link Scanner (Layer 4 Threat Intelligence Gateway)

Specification: Implementation Plan §5.2.2 & §6.5, Milestone 2.4

This module executes rate-paced URL reputation queries against the
VirusTotal v3 API, enforcing a 15.0-second minimum interval between
outbound requests to stay within the free-tier 4 req/min limit.

Architectural guarantees:
    1. Request Capping: Scans at most 2 hyperlinks per email context.
    2. Temporal Pacing: An asyncio.Lock enforces >= 15.0s delta between
       consecutive outbound network queries.
    3. Dual Cache Partitioning:
       - _vt_url_cache: URL String -> Individual URL reputation verdict.
       - _vt_analysis_cache: email_hash -> Composite link scan result.
    4. Pre-Warmed Seed Cache: Pre-loads known test/benchmark URLs from
       data/vt_seed_cache.json on startup for 0ms deterministic responses.
    5. Graceful Degradation: Missing/placeholder API keys or HTTP 429
       rate limits gracefully fall back to safe/unrated status without
       crashing the pipeline.
"""

import asyncio
import base64
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# Operational Constraints (Implementation Plan §5.2.2)
MAX_LINKS_PER_EMAIL: int = 2
DEFAULT_MIN_REQUEST_INTERVAL: float = 15.0
VT_API_BASE_URL: str = "https://www.virustotal.com/api/v3"
VT_REQUEST_TIMEOUT: float = 10.0

VT_SEED_CACHE_PATH: Path = (
    Path(__file__).parent.parent / "data" / "vt_seed_cache.json"
)

# ---------------------------------------------------------------------------
# Dual Cache Structures & Concurrency Controls
# ---------------------------------------------------------------------------

# Cache 1: URL String -> Raw / Processed Reputation Record
_vt_url_cache: Dict[str, Dict[str, Any]] = {}

# Cache 2: Email SHA-256 Hash -> Composite Email Analysis Result
_vt_analysis_cache: Dict[str, Dict[str, Any]] = {}

# Concurrency & Pacing Controls
_pacing_lock: asyncio.Lock = asyncio.Lock()
_last_request_timestamp: float = 0.0
_min_request_interval: float = DEFAULT_MIN_REQUEST_INTERVAL


def get_vt_api_key() -> str:
    """Retrieves the VirusTotal API key from the environment."""
    key = os.getenv("VT_API_KEY", "").strip()
    if not key or key == "your_virustotal_api_key_here":
        return ""
    return key


def normalize_url(url: str) -> str:
    """
    Normalizes a URL string for consistent cache keying.
    Strips whitespace and normalizes scheme and hostname casing.
    """
    url = url.strip()
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower() or "http"
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return url.strip()


def url_to_vt_id(url: str) -> str:
    """
    Generates a VirusTotal v3 URL identifier:
    Base64-encoded URL string without '=' padding.
    """
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


# ---------------------------------------------------------------------------
# Cache Management & Pre-Warming
# ---------------------------------------------------------------------------

def load_vt_seed_cache(custom_path: Optional[Path] = None) -> None:
    """
    Load pre-warmed VirusTotal URL scan results from the seed cache file.
    Provides instant lookup responses for known test scenario URLs.
    """
    global _vt_url_cache
    target_path = custom_path or VT_SEED_CACHE_PATH
    if target_path.exists():
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    _vt_url_cache.update(loaded)
                    logger.info(
                        "[Aegis] VT seed cache loaded: %d entries from %s",
                        len(_vt_url_cache),
                        target_path.name,
                    )
                else:
                    logger.warning("[Aegis] Seed cache root is not a dictionary")
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("[Aegis] Failed to load VT seed cache: %s", exc)
    else:
        logger.info("[Aegis] VT seed cache file not found at %s", target_path)


def save_vt_seed_cache(custom_path: Optional[Path] = None) -> bool:
    """Persists current URL cache entries to the seed cache JSON file."""
    target_path = custom_path or VT_SEED_CACHE_PATH
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(_vt_url_cache, f, indent=2)
        return True
    except OSError as exc:
        logger.error("[Aegis] Failed to save VT seed cache: %s", exc)
        return False


def get_vt_cache_size() -> int:
    """Returns the number of entries currently in the VT URL cache."""
    return len(_vt_url_cache)


def get_vt_analysis_cache_size() -> int:
    """Returns the number of entries currently in the VT email analysis cache."""
    return len(_vt_analysis_cache)


def clear_vt_cache() -> None:
    """Clears both in-memory caches and resets pacing timers (for testing)."""
    global _vt_url_cache, _vt_analysis_cache, _last_request_timestamp
    _vt_url_cache.clear()
    _vt_analysis_cache.clear()
    _last_request_timestamp = 0.0


def set_pacing_interval(seconds: float) -> None:
    """Modifies the pacing interval (used by test suites to avoid 15s delays)."""
    global _min_request_interval
    _min_request_interval = max(0.0, seconds)


# ---------------------------------------------------------------------------
# Outbound Rate Pacing Engine
# ---------------------------------------------------------------------------

async def _pace_request() -> None:
    """
    Enforces a minimum interval of _min_request_interval seconds
    between consecutive outbound network requests to VirusTotal.
    """
    global _last_request_timestamp
    now = time.monotonic()
    time_since_last = now - _last_request_timestamp
    if _last_request_timestamp > 0.0 and time_since_last < _min_request_interval:
        wait_seconds = _min_request_interval - time_since_last
        logger.info(
            "[Aegis LinkScanner] Rate pacing: sleeping %.2fs to respect VT rate limit",
            wait_seconds,
        )
        await asyncio.sleep(wait_seconds)
    _last_request_timestamp = time.monotonic()


# ---------------------------------------------------------------------------
# URL Reputation Querying
# ---------------------------------------------------------------------------

async def scan_single_url(
    url: str,
    client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    """
    Scans a single URL against VirusTotal v3 with caching and rate pacing.

    Returns:
        Dict with keys: url, malicious, positives, total, status, cached.
    """
    normalized = normalize_url(url)
    if not normalized:
        return {
            "url": url,
            "malicious": False,
            "positives": 0,
            "total": 0,
            "status": "invalid_url",
            "cached": False,
        }

    # 1. Check in-memory URL Cache (0ms response)
    if normalized in _vt_url_cache:
        cached_record = _vt_url_cache[normalized]
        if isinstance(cached_record, dict):
            is_mal = bool(cached_record.get("malicious", False))
            positives = int(cached_record.get("positives", 1 if is_mal else 0))
            total = int(cached_record.get("total", 70))
            status = str(cached_record.get("status", "malicious" if is_mal else "clean"))
        else:
            is_mal = bool(cached_record)
            positives = 1 if is_mal else 0
            total = 70
            status = "malicious" if is_mal else "clean"

        return {
            "url": normalized,
            "malicious": is_mal,
            "positives": positives,
            "total": total,
            "status": status,
            "cached": True,
        }

    # 2. Check API Key presence; if absent, operate in safe fallback mode
    api_key = get_vt_api_key()
    if not api_key:
        logger.debug(
            "[Aegis LinkScanner] VT_API_KEY unconfigured; operating in safe mode for %s",
            normalized,
        )
        return {
            "url": normalized,
            "malicious": False,
            "positives": 0,
            "total": 0,
            "status": "safe_mode_unconfigured",
            "cached": False,
        }

    # 3. Enforce 15.0-second rate pacing lock before outbound network query
    async with _pacing_lock:
        # Re-check cache in case another task populated it while waiting for the lock
        if normalized in _vt_url_cache:
            res = await scan_single_url(normalized, client=client)
            return res

        await _pace_request()

        url_id = url_to_vt_id(normalized)
        target_url = f"{VT_API_BASE_URL}/urls/{url_id}"
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
        }

        should_close_client = False
        http_client = client
        if http_client is None:
            http_client = httpx.AsyncClient(timeout=VT_REQUEST_TIMEOUT)
            should_close_client = True

        try:
            response = await http_client.get(target_url, headers=headers)
            status_code = response.status_code

            if status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                malicious_hits = int(stats.get("malicious", 0))
                suspicious_hits = int(stats.get("suspicious", 0))
                harmless_hits = int(stats.get("harmless", 0))
                undetected_hits = int(stats.get("undetected", 0))
                total_engines = (
                    malicious_hits
                    + suspicious_hits
                    + harmless_hits
                    + undetected_hits
                ) or 1

                # Phishing criteria: >= 1 malicious engine or >= 2 suspicious
                is_malicious = (malicious_hits > 0) or (suspicious_hits >= 2)
                verdict_status = "malicious" if is_malicious else "clean"

                record = {
                    "url": normalized,
                    "malicious": is_malicious,
                    "positives": malicious_hits,
                    "total": total_engines,
                    "status": verdict_status,
                }
                # Store in URL cache
                _vt_url_cache[normalized] = record

                return {
                    **record,
                    "cached": False,
                }

            elif status_code == 404:
                # URL not previously scanned in VirusTotal database
                logger.info(
                    "[Aegis LinkScanner] URL not found in VT database (404): %s",
                    normalized,
                )
                record = {
                    "url": normalized,
                    "malicious": False,
                    "positives": 0,
                    "total": 0,
                    "status": "unrated",
                }
                _vt_url_cache[normalized] = record
                return {**record, "cached": False}

            elif status_code == 429:
                # Operational quota exhausted (4 req/min exceeded)
                logger.warning(
                    "[Aegis LinkScanner] VirusTotal API quota exceeded (HTTP 429)"
                )
                return {
                    "url": normalized,
                    "malicious": False,
                    "positives": 0,
                    "total": 0,
                    "status": "quota_exceeded",
                    "cached": False,
                }

            elif status_code in (401, 403):
                logger.warning(
                    "[Aegis LinkScanner] VirusTotal API authorization failed (HTTP %d)",
                    status_code,
                )
                return {
                    "url": normalized,
                    "malicious": False,
                    "positives": 0,
                    "total": 0,
                    "status": "unauthorized",
                    "cached": False,
                }

            else:
                logger.warning(
                    "[Aegis LinkScanner] VirusTotal returned unexpected HTTP %d for %s",
                    status_code,
                    normalized,
                )
                return {
                    "url": normalized,
                    "malicious": False,
                    "positives": 0,
                    "total": 0,
                    "status": f"http_error_{status_code}",
                    "cached": False,
                }

        except (httpx.TimeoutException, httpx.RequestError) as exc:
            logger.warning(
                "[Aegis LinkScanner] Network error querying VirusTotal for %s: %s",
                normalized,
                exc,
            )
            return {
                "url": normalized,
                "malicious": False,
                "positives": 0,
                "total": 0,
                "status": "network_error",
                "cached": False,
            }
        finally:
            if should_close_client and http_client is not None:
                await http_client.aclose()


# ---------------------------------------------------------------------------
# Composite Email Link Analysis (Layer 4 Risk Formulation)
# ---------------------------------------------------------------------------

async def scan_email_links(
    urls: List[str],
    email_hash: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    """
    Analyzes hyperlinks extracted from an email context.

    Enforces:
    - 2-link maximum scan cap.
    - Check and update of _vt_analysis_cache using email_hash.
    - Mathematical formulation of Layer 4 score (Implementation Plan §6.5):
      S_vt = min(100, N_malicious_links * 50)
    """
    # 1. Check composite analysis cache by email_hash
    if email_hash and email_hash in _vt_analysis_cache:
        cached_composite = dict(_vt_analysis_cache[email_hash])
        cached_composite["cached"] = True
        return cached_composite

    # 2. Handle empty URL list
    if not urls:
        res = {
            "status": "no_links",
            "vt_score": 0,
            "malicious_count": 0,
            "scanned_count": 0,
            "total_links": 0,
            "capped": False,
            "links": [],
            "cached": False,
        }
        if email_hash:
            _vt_analysis_cache[email_hash] = res
        return res

    # 3. Deduplicate while preserving order (normalize first to prevent
    #    case-variant duplicates from consuming the 2-link cap separately)
    seen: set = set()
    unique_urls: List[str] = []
    for u in urls:
        norm = normalize_url(u)
        if norm and norm not in seen:
            seen.add(norm)
            unique_urls.append(norm)

    # 4. Enforce 2-Link Scan Cap (Implementation Plan §5.2.2)
    scanned_targets = unique_urls[:MAX_LINKS_PER_EMAIL]
    capped = len(unique_urls) > MAX_LINKS_PER_EMAIL

    # 5. Scan targets sequentially
    scanned_results: List[Dict[str, Any]] = []
    for target in scanned_targets:
        result = await scan_single_url(target, client=client)
        scanned_results.append(result)

    # 6. Synthesize Layer 4 Risk Score: S_vt = min(100, N_malicious * 50)
    malicious_count = sum(1 for item in scanned_results if item.get("malicious"))
    vt_score = min(100, malicious_count * 50)

    composite_result = {
        "status": "completed",
        "vt_score": vt_score,
        "malicious_count": malicious_count,
        "scanned_count": len(scanned_results),
        "total_links": len(unique_urls),
        "capped": capped,
        "links": scanned_results,
        "cached": False,
    }

    # 7. Store in composite analysis cache
    if email_hash:
        _vt_analysis_cache[email_hash] = composite_result

    return composite_result
