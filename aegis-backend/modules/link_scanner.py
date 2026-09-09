"""
Aegis: AI-Powered Phishing Context Analyzer
Module: VirusTotal Link Scanner

Specification: Implementation Plan §5.2.2, Milestone 2.4

This module will execute rate-paced URL reputation queries against the
VirusTotal v3 API, enforcing a 15.0-second minimum interval between
requests to stay within the free-tier 4 req/min limit.

Rate control parameters:
    - Max links scanned per email: 2
    - Min interval between requests: 15.0 seconds
    - URL result cache: vt_url_cache (URL → {malicious: bool})
    - Analysis result cache: vt_analysis_cache (email_hash → result)

Current state: Milestone 1.4 skeleton stub.
Full implementation: TODO(Milestone 2.4)
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

VT_SEED_CACHE_PATH = Path(__file__).parent.parent / "data" / "vt_seed_cache.json"

# In-memory URL reputation cache. Populated from vt_seed_cache.json on
# startup and updated with live VirusTotal results during runtime.
# Key: URL string  Value: {"malicious": bool}
_vt_url_cache: dict = {}


def load_vt_seed_cache() -> None:
    """
    Load pre-warmed VirusTotal URL scan results from the seed cache file.

    Called once during FastAPI application startup via the lifespan
    context manager in main.py. Provides instant lookup responses for
    known test scenario URLs during usability trials and demo sessions,
    eliminating live VirusTotal API calls for pre-registered URLs.

    Seed cache file: data/vt_seed_cache.json
    Format: {"https://example.com/phish": {"malicious": true}, ...}

    TODO(Milestone 2.4): Replace placeholder with full implementation:
        - asyncio.Lock() for 15.0-second request pacing
        - httpx.AsyncClient for VirusTotal v3 API calls
        - Dual cache partitioning (vt_url_cache + vt_analysis_cache)
        - prewarm_vt_cache.py script for populating vt_seed_cache.json
    """
    global _vt_url_cache
    if VT_SEED_CACHE_PATH.exists():
        try:
            with open(VT_SEED_CACHE_PATH, "r", encoding="utf-8") as f:
                _vt_url_cache = json.load(f)
            logger.info(
                "[Aegis] VT seed cache loaded: %d entries", len(_vt_url_cache)
            )
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("[Aegis] Failed to load VT seed cache: %s", exc)
            _vt_url_cache = {}
    else:
        logger.info("[Aegis] VT seed cache loaded: 0 entries (file not found)")
        _vt_url_cache = {}


def get_vt_cache_size() -> int:
    """Returns the number of entries currently in the VT URL cache."""
    return len(_vt_url_cache)
