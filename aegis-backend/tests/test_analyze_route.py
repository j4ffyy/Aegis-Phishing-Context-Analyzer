"""
Unit and Integration Tests for Aegis Analysis Routes & Background Task Dispatch
Specification: Implementation Plan §3.1, §5.2, §6.1-§6.6 (Milestone 2.5)
"""

import asyncio
import sys
import unittest
from pathlib import Path
from typing import Any, Dict

# Ensure aegis-backend root is on sys.path
BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import httpx

from main import app
from modules.link_scanner import (
    _vt_url_cache,
    clear_vt_cache,
    load_vt_seed_cache,
    set_pacing_interval,
)
from routes.analyze import (
    clear_analysis_store,
    compute_email_hash,
    synthesize_composite_score,
)


class TestAnalyzeRoute(unittest.IsolatedAsyncioTestCase):
    """Test suite for /api/v1/analyze and /api/v1/vt-status/{email_hash}."""

    async def asyncSetUp(self):
        """Prepare clean cache and test client before each test."""
        clear_vt_cache()
        clear_analysis_store()
        load_vt_seed_cache()
        set_pacing_interval(0.0)  # zero pacing for instant tests

    async def asyncTearDown(self):
        """Clean up state."""
        clear_vt_cache()
        clear_analysis_store()

    async def test_analyze_no_links_immediate_completion(self):
        """Emails without hyperlinks should immediately return vt_status='completed'."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            payload = {
                "senderEmail": "hr-announcement@company.com",
                "senderName": "Internal HR",
                "subject": "Scheduled Maintenance Window",
                "bodyText": "Servers will undergo standard scheduled maintenance this weekend.",
                "links": [],
                "hasAttachment": False,
            }

            resp = await client.post("/api/v1/analyze", json=payload)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()

            self.assertEqual(data["vt_status"], "completed")
            self.assertEqual(data["riskLevel"], "Safe")
            self.assertIn("score", data)
            self.assertEqual(data["layers"]["nlp"]["detail"], "Intent pattern nominal")

    async def test_analyze_cached_links_immediate_completion(self):
        """Emails with pre-warmed seed cache links should resolve synchronously in 0ms."""
        # 'http://paypal-verification-account-sec.com/login' is in vt_seed_cache.json as malicious
        test_url = "http://paypal-verification-account-sec.com/login"
        self.assertIn(test_url, _vt_url_cache)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            payload = {
                "senderEmail": "service@paypal-verification-account-sec.com",
                "senderName": "Security Notice",
                "subject": "Urgent account verification required",
                "bodyText": "Please verify your account immediately at http://paypal-verification-account-sec.com/login",
                "links": [{"url": test_url}],
            }

            resp = await client.post("/api/v1/analyze", json=payload)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()

            self.assertEqual(data["vt_status"], "completed")
            self.assertGreater(data["s_vt"], 0)
            self.assertIn(data["riskLevel"], ("Warning", "Critical"))
            # Confirm malicious link flag was attached
            flag_titles = [f["title"] for f in data["flags"]]
            self.assertIn("Malicious Hyperlink Detected", flag_titles)

    async def test_analyze_typosquatting_and_auth_failures(self):
        """Heuristic layer should catch brand typosquatting and SPF/DKIM failures."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            payload = {
                "senderEmail": "billing@bdo-verify-portal.com",
                "senderName": "BDO Online Helpdesk",
                "subject": "Action Required: Account Suspended",
                "bodyText": "Your account has been locked due to suspicious activity. Verify now.",
                "spfPass": False,
                "dkimPass": False,
                "links": [],
            }

            resp = await client.post("/api/v1/analyze", json=payload)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()

            flag_titles = [f["title"] for f in data["flags"]]
            self.assertIn("Domain Typosquatting Detected", flag_titles)
            self.assertIn("SPF Authentication Failure", flag_titles)
            self.assertIn("DKIM Signature Invalid", flag_titles)
            self.assertGreaterEqual(data["score"], 45)

    async def test_analyze_uncached_links_dispatches_background_task(self):
        """Uncached URLs should return vt_status='pending' and resolve via /vt-status polling."""
        uncached_url = "https://unseen-test-domain-xyz.com/promo"
        # Ensure it's not in cache
        _vt_url_cache.pop(uncached_url, None)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            payload = {
                "senderEmail": "newsletter@unseen-test-domain-xyz.com",
                "subject": "Check our monthly offers",
                "bodyText": "Click here to see our latest deals: https://unseen-test-domain-xyz.com/promo",
                "links": [uncached_url],
            }

            # 1. POST /analyze returns pending
            resp = await client.post("/api/v1/analyze", json=payload)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            email_hash = data["emailHash"]

            self.assertEqual(data["vt_status"], "pending")
            self.assertEqual(data["layers"]["nlp"]["icon"], "fa-spinner")

            # 2. Allow event loop a brief tick for background task to execute
            await asyncio.sleep(0.1)

            # 3. GET /vt-status/{email_hash}
            status_resp = await client.get(f"/api/v1/vt-status/{email_hash}")
            self.assertEqual(status_resp.status_code, 200)
            status_data = status_resp.json()

            self.assertIn(status_data["status"], ("pending", "completed"))
            if status_data["status"] == "completed":
                self.assertIn("data", status_data)
                self.assertEqual(status_data["data"]["vt_status"], "completed")

    async def test_vt_status_not_found(self):
        """Querying an unknown email hash should return 404 Not Found."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            resp = await client.get("/api/v1/vt-status/nonexistent_hash_12345")
            self.assertEqual(resp.status_code, 404)

    def test_composite_score_weighting_formula(self):
        """Verifies mathematical formulation: R_final = min(100, round(0.25*Sh + 0.45*Snlp + 0.15*Sb + 0.15*Svt))."""
        # Case 1: All zero
        score_zero = synthesize_composite_score(0, 0, 0, 0)
        self.assertEqual(score_zero, 0)

        # Case 2: All max (100)
        score_max = synthesize_composite_score(100, 100, 100, 100)
        self.assertEqual(score_max, 100)

        # Case 3: Specific layer weights
        # Sh=40 (40*0.25=10), Snlp=60 (60*0.45=27), Sb=20 (20*0.15=3), Svt=50 (50*0.15=7.5) -> sum = 47.5 -> round = 48
        score_mixed = synthesize_composite_score(40, 60, 20, 50)
        self.assertEqual(score_mixed, 48)

        # Case 4: Pending VT scaling (active weights = 0.85)
        # (10 + 27 + 3) / 0.85 = 40 / 0.85 = 47.058 -> round = 47
        score_pending = synthesize_composite_score(40, 60, 20, 0, vt_pending=True)
        self.assertEqual(score_pending, 47)


if __name__ == "__main__":
    unittest.main()
