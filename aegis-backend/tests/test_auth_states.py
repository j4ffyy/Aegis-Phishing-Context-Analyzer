"""
Aegis Phishing Analyzer - Unit Test Suite: SPF/DKIM Auth-State Tri-State Display (I-01)
Verifies:
  1. Fail state: spfPass=False or dkimPass=False -> fa-times-circle ("Failed: ...")
  2. Pass state: spfPass=True or dkimPass=True -> fa-check-circle ("Pass: Domain & identity verified")
  3. Null state: spfPass=None and dkimPass=None -> fa-minus-circle ("Not verified: Authentication headers missing")
Ensures no score changes occur while fixing the unverified auth display bug.
"""

import sys
import unittest
from pathlib import Path

# Ensure aegis-backend is on path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import httpx
from main import app
from modules.meta_classifier import build_layers_status, synthesize_assessment
from routes.analyze import clear_analysis_store


class TestAuthStates(unittest.TestCase):
    """Unit tests for Layer 1 Auth state logic in meta_classifier."""

    def test_auth_state_null_unverified(self):
        """When SPF and DKIM are both None, auth must show 'Not verified' (fa-minus-circle)."""
        layers = build_layers_status(
            s_heuristic=0,
            s_nlp=0,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            flags=[],
            urls=[],
            spf_pass=None,
            dkim_pass=None,
        )
        auth = layers["auth"]
        self.assertEqual(auth["icon"], "fa-minus-circle")
        self.assertEqual(auth["detail"], "Not verified: Authentication headers missing")
        self.assertEqual(auth["text"], "Layer 1: Email Auth & Domain Spoofing")

    def test_auth_state_pass_both(self):
        """When both SPF and DKIM pass, auth must show 'Pass' (fa-check-circle)."""
        layers = build_layers_status(
            s_heuristic=0,
            s_nlp=0,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            flags=[],
            urls=[],
            spf_pass=True,
            dkim_pass=True,
        )
        auth = layers["auth"]
        self.assertEqual(auth["icon"], "fa-check-circle")
        self.assertEqual(auth["detail"], "Pass: Domain & identity verified")

    def test_auth_state_pass_partial_spf_only(self):
        """When only SPF passes (DKIM is None), auth shows 'Pass'."""
        layers = build_layers_status(
            s_heuristic=0,
            s_nlp=0,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            flags=[],
            urls=[],
            spf_pass=True,
            dkim_pass=None,
        )
        auth = layers["auth"]
        self.assertEqual(auth["icon"], "fa-check-circle")
        self.assertEqual(auth["detail"], "Pass: Domain & identity verified")

    def test_auth_state_pass_partial_dkim_only(self):
        """When only DKIM passes (SPF is None), auth shows 'Pass'."""
        layers = build_layers_status(
            s_heuristic=0,
            s_nlp=0,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            flags=[],
            urls=[],
            spf_pass=None,
            dkim_pass=True,
        )
        auth = layers["auth"]
        self.assertEqual(auth["icon"], "fa-check-circle")
        self.assertEqual(auth["detail"], "Pass: Domain & identity verified")

    def test_auth_state_fail_flags(self):
        """When SPF or DKIM fail flags exist, auth must show 'Failed' (fa-times-circle)."""
        flags = [
            {"title": "SPF Authentication Failure", "evidence": "Sender SPF validation failed", "severity": "critical"}
        ]
        layers = build_layers_status(
            s_heuristic=25,
            s_nlp=0,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            flags=flags,
            urls=[],
            spf_pass=False,
            dkim_pass=None,
        )
        auth = layers["auth"]
        self.assertEqual(auth["icon"], "fa-times-circle")
        self.assertIn("Failed", auth["detail"])
        self.assertIn("Sender SPF validation failed", auth["detail"])

    def test_auth_state_fail_direct_boolean(self):
        """When spf_pass=False or dkim_pass=False without flags, auth must show 'Failed'."""
        layers = build_layers_status(
            s_heuristic=0,
            s_nlp=0,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            flags=[],
            urls=[],
            spf_pass=False,
            dkim_pass=False,
        )
        auth = layers["auth"]
        self.assertEqual(auth["icon"], "fa-times-circle")
        self.assertIn("Failed", auth["detail"])

    def test_auth_state_spoofing_flag_overrides(self):
        """Domain spoofing flag takes precedence as a failure even if spf_pass was True."""
        flags = [
            {"title": "Domain Spoofing / Impersonation", "evidence": "Executive name mismatch", "severity": "critical"}
        ]
        layers = build_layers_status(
            s_heuristic=35,
            s_nlp=0,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            flags=flags,
            urls=[],
            spf_pass=True,
            dkim_pass=True,
        )
        auth = layers["auth"]
        self.assertEqual(auth["icon"], "fa-times-circle")
        self.assertIn("Flagged", auth["detail"])


class TestSynthesizeAssessmentAuthIntegration(unittest.TestCase):
    """Tests synthesize_assessment forwarding spf_pass and dkim_pass into layers."""

    def test_synthesize_assessment_null_auth(self):
        res = synthesize_assessment(
            email_hash="hash_null",
            s_heuristic=0,
            s_nlp=0,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            flags=[],
            urls=[],
            spf_pass=None,
            dkim_pass=None,
        )
        self.assertEqual(res["layers"]["auth"]["icon"], "fa-minus-circle")
        self.assertEqual(res["layers"]["auth"]["detail"], "Not verified: Authentication headers missing")

    def test_synthesize_assessment_pass_auth(self):
        res = synthesize_assessment(
            email_hash="hash_pass",
            s_heuristic=0,
            s_nlp=0,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            flags=[],
            urls=[],
            spf_pass=True,
            dkim_pass=True,
        )
        self.assertEqual(res["layers"]["auth"]["icon"], "fa-check-circle")
        self.assertEqual(res["layers"]["auth"]["detail"], "Pass: Domain & identity verified")

    def test_synthesize_assessment_fail_auth(self):
        flags = [{"title": "SPF Authentication Failure", "evidence": "SPF HardFail", "severity": "critical"}]
        res = synthesize_assessment(
            email_hash="hash_fail",
            s_heuristic=25,
            s_nlp=0,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            flags=flags,
            urls=[],
            spf_pass=False,
            dkim_pass=False,
        )
        self.assertEqual(res["layers"]["auth"]["icon"], "fa-times-circle")
        self.assertIn("Failed", res["layers"]["auth"]["detail"])


class TestAnalyzeRouteAuthIntegration(unittest.IsolatedAsyncioTestCase):
    """Tests end-to-end route handling in /api/v1/analyze for the three auth states."""

    def setUp(self):
        clear_analysis_store()

    async def test_route_null_auth_state(self):
        """Email with no SPF/DKIM headers (collapsed/indeterminate) produces 'Not verified'."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            payload = {
                "senderEmail": "colleague@example.com",
                "subject": "Lunch tomorrow?",
                "bodyText": "Are we still meeting at noon?",
                "spfPass": None,
                "dkimPass": None,
                "links": [],
                "hasAttachment": False,
            }
            resp = await client.post("/api/v1/analyze", json=payload)
            self.assertEqual(resp.status_code, 200)
            res = resp.json()
            auth = res["layers"]["auth"]
            self.assertEqual(auth["icon"], "fa-minus-circle")
            self.assertEqual(auth["detail"], "Not verified: Authentication headers missing")
            self.assertEqual(res["riskLevel"], "Safe")

    async def test_route_pass_auth_state(self):
        """Email with verified SPF and DKIM produces 'Pass'."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            payload = {
                "senderEmail": "newsletter@company.com",
                "subject": "Monthly Newsletter",
                "bodyText": "Here is our monthly team newsletter.",
                "spfPass": True,
                "dkimPass": True,
                "links": [],
                "hasAttachment": False,
            }
            resp = await client.post("/api/v1/analyze", json=payload)
            self.assertEqual(resp.status_code, 200)
            res = resp.json()
            auth = res["layers"]["auth"]
            self.assertEqual(auth["icon"], "fa-check-circle")
            self.assertEqual(auth["detail"], "Pass: Domain & identity verified")

    async def test_route_fail_auth_state(self):
        """Email with failed SPF produces 'Failed'."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            payload = {
                "senderEmail": "security@bdo-update.com",
                "subject": "Account Locked - Action Required",
                "bodyText": "Verify your identity immediately.",
                "spfPass": False,
                "dkimPass": False,
                "links": [],
                "hasAttachment": False,
            }
            resp = await client.post("/api/v1/analyze", json=payload)
            self.assertEqual(resp.status_code, 200)
            res = resp.json()
            auth = res["layers"]["auth"]
            self.assertEqual(auth["icon"], "fa-times-circle")
            self.assertIn("Failed", auth["detail"])
            # Score must reflect heuristic penalties
            self.assertGreaterEqual(res["score"], 45)


if __name__ == "__main__":
    unittest.main()
