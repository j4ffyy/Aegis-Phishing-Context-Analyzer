"""
Aegis Backend Test Suite: Rate-Paced VirusTotal Link Scanner
Specification: Implementation Plan §5.2.2 & §6.5, Milestone 2.4

Validates:
1. URL normalization and VirusTotal v3 Base64 URL ID generation.
2. Pre-warmed seed cache loading and 0ms cache hits.
3. 2-link scan capping per email payload.
4. Temporal pacing lock enforcing request intervals.
5. Dual cache partitioning (_vt_url_cache vs _vt_analysis_cache).
6. VirusTotal v3 API response parsing (malicious, clean, 404 unrated).
7. Mathematical risk formulation: S_vt = min(100, N_malicious * 50).
8. Graceful error handling (429 quota exhaustion, 401 unauthorized, safe mode).
"""

import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure aegis-backend root is on sys.path
BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import httpx

from modules.link_scanner import (
    DEFAULT_MIN_REQUEST_INTERVAL,
    MAX_LINKS_PER_EMAIL,
    clear_vt_cache,
    get_vt_analysis_cache_size,
    get_vt_cache_size,
    load_vt_seed_cache,
    normalize_url,
    save_vt_seed_cache,
    scan_email_links,
    scan_single_url,
    set_pacing_interval,
    url_to_vt_id,
)


class TestLinkScanner(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        clear_vt_cache()
        set_pacing_interval(0.02)  # Fast pacing interval for testing

    def tearDown(self):
        clear_vt_cache()
        set_pacing_interval(DEFAULT_MIN_REQUEST_INTERVAL)

    def test_normalize_url(self):
        """Validates whitespace removal and domain normalization."""
        self.assertEqual(
            normalize_url("  https://EXAMPLE.COM/login?user=1  "),
            "https://example.com/login?user=1",
        )
        self.assertEqual(
            normalize_url("http://bank.test/"),
            "http://bank.test/",
        )
        self.assertEqual(normalize_url(""), "")

    def test_url_to_vt_id(self):
        """Validates base64url encoding without padding (=) per VT v3 specs."""
        url = "http://example.com/phish"
        vt_id = url_to_vt_id(url)
        self.assertNotIn("=", vt_id)
        # Verify decoding recovers the original URL
        padded = vt_id + "=" * ((4 - len(vt_id) % 4) % 4)
        import base64
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
        self.assertEqual(decoded, url)

    def test_load_and_save_seed_cache(self):
        """Tests reading and writing seed cache from a temporary file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_path = Path(tmp_dir) / "test_seed.json"
            sample_data = {
                "http://phish.test/": {"malicious": True, "positives": 15, "total": 70},
                "https://safe.test/": {"malicious": False, "positives": 0, "total": 70},
            }
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(sample_data, f)

            load_vt_seed_cache(temp_path)
            self.assertEqual(get_vt_cache_size(), 2)

            # Modify and save
            output_path = Path(tmp_dir) / "saved_seed.json"
            saved = save_vt_seed_cache(output_path)
            self.assertTrue(saved)
            self.assertTrue(output_path.exists())

    async def test_seed_cache_instant_lookup(self):
        """Pre-warmed seed cache entries return immediately without network calls."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_path = Path(tmp_dir) / "test_seed.json"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "https://paypal.com/": {
                            "malicious": False,
                            "positives": 0,
                            "total": 75,
                            "status": "clean",
                        }
                    },
                    f,
                )
            load_vt_seed_cache(temp_path)

            # Even with no API key, cached entry resolves
            res = await scan_single_url("https://paypal.com/")
            self.assertTrue(res["cached"])
            self.assertFalse(res["malicious"])
            self.assertEqual(res["status"], "clean")

    async def test_two_link_scan_cap(self):
        """Validates that emails with >2 URLs scan only the first 2 (Cap constraint)."""
        urls = [
            "https://test1.org/a",
            "https://test2.org/b",
            "https://test3.org/c",
            "https://test4.org/d",
        ]
        # In safe unconfigured mode, scan_single_url will return safe records
        res = await scan_email_links(urls, email_hash="hash_123")
        self.assertTrue(res["capped"])
        self.assertEqual(res["total_links"], 4)
        self.assertEqual(res["scanned_count"], 2)
        self.assertEqual(len(res["links"]), 2)
        self.assertEqual(res["links"][0]["url"], "https://test1.org/a")
        self.assertEqual(res["links"][1]["url"], "https://test2.org/b")

    async def test_temporal_pacing_lock(self):
        """Validates that consecutive outbound requests respect the pacing interval."""
        test_interval = 0.08  # 80ms
        set_pacing_interval(test_interval)

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 0,
                                "suspicious": 0,
                                "harmless": 70,
                                "undetected": 0,
                            }
                        }
                    }
                },
            )

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as mock_client:
            with patch("modules.link_scanner.get_vt_api_key", return_value="fake_api_key"):
                t0 = time.monotonic()
                await scan_single_url("https://uncached1.org/", client=mock_client)
                await scan_single_url("https://uncached2.org/", client=mock_client)
                elapsed = time.monotonic() - t0

                # Must be at least test_interval between the 2 requests
                self.assertGreaterEqual(elapsed, test_interval * 0.9)

    async def test_dual_cache_partitioning(self):
        """
        Verifies dual cache architecture:
        - URL records are indexed in _vt_url_cache
        - Composite email summaries are indexed in _vt_analysis_cache by email_hash
        """
        email_hash = "abcde1234567890"
        urls = ["https://site1.org/"]

        with patch("modules.link_scanner.get_vt_api_key", return_value=""):
            # First call populates _vt_analysis_cache
            res1 = await scan_email_links(urls, email_hash=email_hash)
            self.assertFalse(res1["cached"])
            self.assertEqual(get_vt_analysis_cache_size(), 1)

            # Second call retrieves directly from _vt_analysis_cache
            res2 = await scan_email_links(urls, email_hash=email_hash)
            self.assertTrue(res2["cached"])

    async def test_layer_4_scoring_formula(self):
        """
        Verifies mathematical formulation of S_vt:
        S_vt = min(100, N_malicious * 50)
        """
        # Populate URL cache directly with 1 malicious and 1 clean link
        from modules.link_scanner import _vt_url_cache
        _vt_url_cache["https://clean.test/"] = {"malicious": False, "positives": 0, "total": 70}
        _vt_url_cache["https://phish1.test/"] = {"malicious": True, "positives": 10, "total": 70}
        _vt_url_cache["https://phish2.test/"] = {"malicious": True, "positives": 25, "total": 70}

        # 0 malicious links -> score 0
        res_clean = await scan_email_links(["https://clean.test/"])
        self.assertEqual(res_clean["vt_score"], 0)
        self.assertEqual(res_clean["malicious_count"], 0)

        # 1 malicious link -> score 50
        res_1phish = await scan_email_links(["https://phish1.test/"])
        self.assertEqual(res_1phish["vt_score"], 50)
        self.assertEqual(res_1phish["malicious_count"], 1)

        # 2 malicious links -> score 100 (capped at 100)
        res_2phish = await scan_email_links(["https://phish1.test/", "https://phish2.test/"])
        self.assertEqual(res_2phish["vt_score"], 100)
        self.assertEqual(res_2phish["malicious_count"], 2)

    async def test_virustotal_api_parsing_and_error_handling(self):
        """Tests parsing of 200 malicious, 200 clean, 404 unrated, 429 quota, and 401 unauthorized."""
        responses = {
            "malicious": {
                "status": 200,
                "data": {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 8,
                                "suspicious": 1,
                                "harmless": 50,
                                "undetected": 10,
                            }
                        }
                    }
                },
            },
            "clean": {
                "status": 200,
                "data": {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 0,
                                "suspicious": 0,
                                "harmless": 70,
                                "undetected": 0,
                            }
                        }
                    }
                },
            },
        }

        def mock_handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            url_id = path.split("/")[-1]
            try:
                import base64
                padded = url_id + "=" * ((4 - len(url_id) % 4) % 4)
                decoded_target = base64.urlsafe_b64decode(padded).decode("utf-8")
            except Exception:
                decoded_target = path

            if "malicious_target" in decoded_target:
                return httpx.Response(200, json=responses["malicious"]["data"])
            elif "clean_target" in decoded_target:
                return httpx.Response(200, json=responses["clean"]["data"])
            elif "not_found" in decoded_target:
                return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
            elif "rate_limit" in decoded_target:
                return httpx.Response(429, json={"error": {"code": "QuotaExceededError"}})
            elif "auth_err" in decoded_target:
                return httpx.Response(401, json={"error": {"code": "UnauthorizedError"}})
            return httpx.Response(500, json={})

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as mock_client:
            with patch("modules.link_scanner.get_vt_api_key", return_value="test_vt_api_key"):
                # 1. Malicious response
                res_mal = await scan_single_url("https://malicious_target.com/", client=mock_client)
                self.assertTrue(res_mal["malicious"])
                self.assertEqual(res_mal["positives"], 8)
                self.assertEqual(res_mal["status"], "malicious")

                # 2. Clean response
                res_clean = await scan_single_url("https://clean_target.com/", client=mock_client)
                self.assertFalse(res_clean["malicious"])
                self.assertEqual(res_clean["status"], "clean")

                # 3. 404 Unrated response
                res_404 = await scan_single_url("https://not_found.com/", client=mock_client)
                self.assertFalse(res_404["malicious"])
                self.assertEqual(res_404["status"], "unrated")

                # 4. 429 Quota Exceeded
                res_429 = await scan_single_url("https://rate_limit.com/", client=mock_client)
                self.assertFalse(res_429["malicious"])
                self.assertEqual(res_429["status"], "quota_exceeded")

                # 5. 401 Unauthorized
                res_401 = await scan_single_url("https://auth_err.com/", client=mock_client)
                self.assertFalse(res_401["malicious"])
                self.assertEqual(res_401["status"], "unauthorized")


if __name__ == "__main__":
    unittest.main()
