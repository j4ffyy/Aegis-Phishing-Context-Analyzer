"""
Aegis: AI-Powered Phishing Context Analyzer
Script: Pre-Warm VirusTotal Seed Cache Utility

Specification: Implementation Plan §5.2.2 & Milestone 2.4

Pre-populates data/vt_seed_cache.json with known evaluation, benchmark,
and test-scenario URLs. This ensures instant (0ms) lookup responses during
usability trials, evaluation benchmarks, and integration tests, eliminating
quota exhaustion on the VirusTotal public free tier.

Usage:
    # Populate default offline ground-truth benchmark seed cache:
    python scripts/prewarm_vt_cache.py

    # Query live VirusTotal API for URLs with 15.0s pacing (requires VT_API_KEY):
    python scripts/prewarm_vt_cache.py --live
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

# Add aegis-backend root to sys.path to allow module imports
BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from modules.link_scanner import (
    VT_SEED_CACHE_PATH,
    clear_vt_cache,
    get_vt_api_key,
    load_vt_seed_cache,
    normalize_url,
    save_vt_seed_cache,
    scan_single_url,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("prewarm_vt_cache")

# Benchmark & Evaluation Dataset Ground Truth
BENCHMARK_SEED_ENTRIES = {
    # Known Phishing / Spoofed Simulation URLs
    "http://paypal-verification-account-sec.com/login": {
        "url": "http://paypal-verification-account-sec.com/login",
        "malicious": True,
        "positives": 18,
        "total": 75,
        "status": "malicious",
        "category": "phishing_credential_harvesting",
    },
    "https://secure-wellsfargo-update.net/auth": {
        "url": "https://secure-wellsfargo-update.net/auth",
        "malicious": True,
        "positives": 14,
        "total": 74,
        "status": "malicious",
        "category": "phishing_banking_impersonation",
    },
    "http://appleid-support-security-alert.xyz/verify": {
        "url": "http://appleid-support-security-alert.xyz/verify",
        "malicious": True,
        "positives": 22,
        "total": 75,
        "status": "malicious",
        "category": "phishing_account_takeover",
    },
    "https://dhl-express-tracking-delivery.info/track": {
        "url": "https://dhl-express-tracking-delivery.info/track",
        "malicious": True,
        "positives": 9,
        "total": 72,
        "status": "malicious",
        "category": "phishing_delivery_fraud",
    },
    "http://office365-password-reset-portal.co/login": {
        "url": "http://office365-password-reset-portal.co/login",
        "malicious": True,
        "positives": 26,
        "total": 75,
        "status": "malicious",
        "category": "phishing_bec_credential_harvesting",
    },
    # Known Legitimate / Safe Domains
    "https://www.google.com/": {
        "url": "https://www.google.com/",
        "malicious": False,
        "positives": 0,
        "total": 75,
        "status": "clean",
        "category": "legitimate_search_engine",
    },
    "https://github.com/": {
        "url": "https://github.com/",
        "malicious": False,
        "positives": 0,
        "total": 75,
        "status": "clean",
        "category": "legitimate_developer_platform",
    },
    "https://www.microsoft.com/": {
        "url": "https://www.microsoft.com/",
        "malicious": False,
        "positives": 0,
        "total": 75,
        "status": "clean",
        "category": "legitimate_enterprise_software",
    },
    "https://www.paypal.com/": {
        "url": "https://www.paypal.com/",
        "malicious": False,
        "positives": 0,
        "total": 75,
        "status": "clean",
        "category": "legitimate_financial_service",
    },
    "https://appleid.apple.com/": {
        "url": "https://appleid.apple.com/",
        "malicious": False,
        "positives": 0,
        "total": 75,
        "status": "clean",
        "category": "legitimate_identity_portal",
    },
}


async def run_live_prewarm(output_path: Path) -> None:
    """Queries live VirusTotal API with 15.0s rate pacing and persists results."""
    api_key = get_vt_api_key()
    if not api_key:
        logger.error(
            "VT_API_KEY environment variable is not set. Cannot run live pre-warm."
        )
        sys.exit(1)

    logger.info("Starting live VirusTotal seed cache pre-warm with 15s pacing...")
    load_vt_seed_cache(output_path)

    for raw_url in BENCHMARK_SEED_ENTRIES.keys():
        norm = normalize_url(raw_url)
        logger.info("Scanning URL: %s", norm)
        result = await scan_single_url(norm)
        logger.info(
            "Result for %s -> malicious: %s (positives: %d/%d, cached: %s)",
            norm,
            result.get("malicious"),
            result.get("positives", 0),
            result.get("total", 0),
            result.get("cached"),
        )

    save_vt_seed_cache(output_path)
    logger.info("Live pre-warm complete. Seed cache saved to: %s", output_path)


def run_offline_prewarm(output_path: Path) -> None:
    """Populates seed cache from built-in ground-truth dataset without network requests."""
    logger.info(
        "Populating offline benchmark seed cache with %d entries...",
        len(BENCHMARK_SEED_ENTRIES),
    )
    existing_cache = {}
    if output_path.exists():
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                existing_cache = json.load(f)
        except Exception:
            existing_cache = {}

    # Merge benchmark entries (normalizing URLs as keys)
    for raw_url, record in BENCHMARK_SEED_ENTRIES.items():
        norm_key = normalize_url(raw_url)
        existing_cache[norm_key] = record

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(existing_cache, f, indent=2)

    logger.info(
        "Successfully wrote %d seed entries to %s",
        len(existing_cache),
        output_path,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Aegis VirusTotal Seed Cache Pre-Warming Utility"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Query live VirusTotal API (requires VT_API_KEY in .env)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=VT_SEED_CACHE_PATH,
        help="Output path for the vt_seed_cache.json file",
    )
    args = parser.parse_args()

    if args.live:
        asyncio.run(run_live_prewarm(args.output))
    else:
        run_offline_prewarm(args.output)


if __name__ == "__main__":
    main()
