"""
Aegis: AI-Powered Phishing Context Analyzer
Unit Tests: Meta-Classifier Risk Synthesis & Explainable AI (XAI) Generator
Specification: Implementation Plan §6.1, §6.5, §6.6 (Milestone 3.4)
"""

import sys
from pathlib import Path
import unittest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from modules.meta_classifier import (
    ACTIVE_PRELIMINARY_WEIGHT_SUM,
    TIER_SAFE_MAX,
    TIER_WARNING_MAX,
    WEIGHT_BEHAVIORAL,
    WEIGHT_HEURISTIC,
    WEIGHT_NLP,
    WEIGHT_VT,
    build_layers_status,
    clamp_score,
    derive_risk_tier,
    generate_xai_rationale,
    synthesize_assessment,
    synthesize_composite_score,
)


class TestMetaClassifier(unittest.TestCase):
    """Comprehensive test suite for Meta-Classifier and XAI rationale generation."""

    def test_weight_constants_and_sum(self):
        """Validates §6.1 mathematical formulation weight constraints."""
        total_weight = WEIGHT_HEURISTIC + WEIGHT_NLP + WEIGHT_BEHAVIORAL + WEIGHT_VT
        self.assertAlmostEqual(total_weight, 1.00, places=6)
        self.assertEqual(WEIGHT_HEURISTIC, 0.25)
        self.assertEqual(WEIGHT_NLP, 0.45)
        self.assertEqual(WEIGHT_BEHAVIORAL, 0.15)
        self.assertEqual(WEIGHT_VT, 0.15)
        self.assertAlmostEqual(ACTIVE_PRELIMINARY_WEIGHT_SUM, 0.85, places=6)

    def test_composite_score_synthesis_completed(self):
        """Verifies 4-layer weighted sum when all layers are completed."""
        # Zero bounds
        self.assertEqual(synthesize_composite_score(0, 0, 0, 0), 0)

        # Max bounds
        self.assertEqual(synthesize_composite_score(100, 100, 100, 100), 100)

        # Mixed calculation: 0.25*40 + 0.45*60 + 0.15*20 + 0.15*50 = 10 + 27 + 3 + 7.5 = 47.5 -> 48
        self.assertEqual(synthesize_composite_score(40, 60, 20, 50), 48)

        # Layer sensitivity checks
        base = synthesize_composite_score(20, 20, 20, 20)
        more_nlp = synthesize_composite_score(20, 80, 20, 20)
        more_heur = synthesize_composite_score(80, 20, 20, 20)
        self.assertGreater(more_nlp, more_heur)  # NLP weight 0.45 > Heuristic weight 0.25

    def test_composite_score_synthesis_pending_vt(self):
        """Verifies 3-layer preliminary scaling over active weights (0.85 divisor)."""
        # (0.25*40 + 0.45*60 + 0.15*20) / 0.85 = (10 + 27 + 3) / 0.85 = 40 / 0.85 = 47.058 -> 47
        score_pending = synthesize_composite_score(40, 60, 20, 0, vt_pending=True)
        self.assertEqual(score_pending, 47)

        # Zero input pending
        self.assertEqual(synthesize_composite_score(0, 0, 0, 0, vt_pending=True), 0)

        # Max input pending
        self.assertEqual(synthesize_composite_score(100, 100, 100, 0, vt_pending=True), 100)

    def test_score_clamping(self):
        """Verifies strict integer bounds [0, 100]."""
        self.assertEqual(clamp_score(-50), 0)
        self.assertEqual(clamp_score(0), 0)
        self.assertEqual(clamp_score(55.4), 55)
        self.assertEqual(clamp_score(55.6), 56)
        self.assertEqual(clamp_score(150), 100)

        # Passing clamped out-of-bound arguments into synthesize_composite_score
        self.assertEqual(synthesize_composite_score(-20, -10, -5, -30), 0)
        self.assertEqual(synthesize_composite_score(120, 150, 110, 130), 100)

    def test_critical_threat_floor_enforcement(self):
        """
        Verifies §6.5 Critical Threat Floor:
        Confirmed external malicious links (S_vt >= 50) elevate score to at least 75
        when critical_floor=True, preventing severe threats from being diluted.
        """
        # Raw score without floor: 0.25*0 + 0.45*0 + 0.15*0 + 0.15*50 = 7.5 -> 8
        raw_score = synthesize_composite_score(0, 0, 0, 50, critical_floor=False)
        self.assertEqual(raw_score, 8)

        # With critical threat floor enabled
        floored_score = synthesize_composite_score(0, 0, 0, 50, critical_floor=True)
        self.assertEqual(floored_score, 75)

        # When raw score is already higher than 75, floor does not diminish it
        # 0.25*80 + 0.45*80 + 0.15*60 + 0.15*60 = 20 + 36 + 9 + 9 = 74 -> elevated to 75
        elevated = synthesize_composite_score(80, 80, 60, 60, critical_floor=True)
        self.assertEqual(elevated, 75)

        # High raw score preserved
        high_score = synthesize_composite_score(90, 90, 80, 80, critical_floor=True)
        self.assertEqual(high_score, 87)

    def test_derive_risk_tier_cutoffs(self):
        """Verifies categorical risk tier thresholds per §6.6."""
        # Safe (< 45)
        lvl, cls, desc = derive_risk_tier(0)
        self.assertEqual(lvl, "Safe")
        self.assertEqual(cls, "risk-safe")

        lvl, cls, desc = derive_risk_tier(TIER_SAFE_MAX)  # 44
        self.assertEqual(lvl, "Safe")
        self.assertEqual(cls, "risk-safe")

        # Warning (45 - 74)
        lvl, cls, desc = derive_risk_tier(45)
        self.assertEqual(lvl, "Warning")
        self.assertEqual(cls, "risk-warning")

        lvl, cls, desc = derive_risk_tier(TIER_WARNING_MAX)  # 74
        self.assertEqual(lvl, "Warning")
        self.assertEqual(cls, "risk-warning")

        # Critical (>= 75)
        lvl, cls, desc = derive_risk_tier(75)
        self.assertEqual(lvl, "Critical")
        self.assertEqual(cls, "risk-critical")

        lvl, cls, desc = derive_risk_tier(100)
        self.assertEqual(lvl, "Critical")
        self.assertEqual(cls, "risk-critical")

    def test_generate_xai_rationale_benign_email(self):
        """Verifies XAI narrative for a clean, verified email."""
        xai = generate_xai_rationale(
            risk_level="Safe",
            flags=[],
            s_heuristic=0,
            s_nlp=10,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            links_count=0,
        )
        self.assertIn("standard communication patterns", xai)
        self.assertIn("No deceptive URLs", xai)

    def test_generate_xai_rationale_threat_indicators(self):
        """Verifies XAI narrative synthesizing multi-layer threats."""
        flags = [
            {"title": "Display Name Spoofing", "evidence": "Sender claims 'BDO' from external domain"},
            {"title": "SPF Authentication Failure", "evidence": "Domain SPF record marked fail"},
        ]
        behavioral_meta = {
            "reason": "off_hours_anomaly",
            "minCircularDistanceH": 8.5,
            "interactionCount": 6,
        }

        xai = generate_xai_rationale(
            risk_level="Critical",
            flags=flags,
            s_heuristic=75,
            s_nlp=85,
            s_behavioral=20,
            s_vt=100,
            vt_status="completed",
            links_count=2,
            behavioral_meta=behavioral_meta,
        )

        # Must articulate findings across layers
        self.assertIn("CRITICAL SECURITY ALERT", xai)
        self.assertIn("Display Name Spoofing", xai)
        self.assertIn("DistilBERT neural semantic classification", xai)
        self.assertIn("8.5h circular deviation", xai)
        self.assertIn("VirusTotal threat intelligence confirmed", xai)
        self.assertIn("Do not click links", xai)

    def test_generate_xai_rationale_pending_vt(self):
        """Verifies XAI narrative when VirusTotal is actively scanning."""
        xai = generate_xai_rationale(
            risk_level="Warning",
            flags=[],
            s_heuristic=20,
            s_nlp=40,
            s_behavioral=15,
            s_vt=0,
            vt_status="pending",
            links_count=2,
        )
        self.assertIn("actively analyzing 2 external hyperlink destination(s)", xai)
        self.assertIn("Aegis detected suspicious characteristics", xai)

    def test_build_layers_status(self):
        """Verifies canonical 5-layer overlay breakdown structure."""
        flags = [{"title": "SPF Authentication Failure", "evidence": "SPF HardFail"}]
        layers = build_layers_status(
            s_heuristic=40,
            s_nlp=10,
            s_behavioral=20,
            s_vt=0,
            vt_status="completed",
            flags=flags,
            urls=["https://company.com"],
            vt_result={"malicious_count": 0},
            behavioral_meta={"reason": "off_hours_anomaly", "minCircularDistanceH": 7.0},
        )

        expected_keys = {"sanitization", "auth", "attach", "behavior", "nlp"}
        self.assertEqual(set(layers.keys()), expected_keys)

        # Auth failed
        self.assertEqual(layers["auth"]["icon"], "fa-times-circle")
        self.assertIn("Failed", layers["auth"]["detail"])

        # Behavioral off-hours
        self.assertEqual(layers["behavior"]["icon"], "fa-exclamation-triangle")
        self.assertIn("Off-hours anomaly", layers["behavior"]["detail"])

        # Link verified clean
        self.assertEqual(layers["nlp"]["icon"], "fa-check-circle")
        self.assertIn("verified clean", layers["nlp"]["detail"])

    def test_synthesize_assessment_orchestration(self):
        """Verifies end-to-end full response dict generated by synthesize_assessment."""
        result = synthesize_assessment(
            email_hash="a1b2c3d4e5f6",
            s_heuristic=10,
            s_nlp=15,
            s_behavioral=0,
            s_vt=0,
            vt_status="completed",
            flags=[],
            urls=[],
            execution_time_ms=42,
        )

        self.assertIn("score", result)
        self.assertIn("riskLevel", result)
        self.assertIn("riskClass", result)
        self.assertIn("desc", result)
        self.assertIn("layers", result)
        self.assertIn("flags", result)
        self.assertIn("xai", result)
        self.assertEqual(result["emailHash"], "a1b2c3d4e5f6")
        self.assertEqual(result["_executionTimeMs"], 42)
        self.assertEqual(result["riskLevel"], "Safe")


class TestMetaClassifierIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests verifying route-level client behavioral ingestion."""

    def setUp(self):
        from routes.analyze import clear_analysis_store
        clear_analysis_store()

    async def test_analyze_route_ingests_behavioral_context(self):
        """Ensures _behavioral sent from Chrome extension influences Layer 3 and XAI."""
        import httpx
        from main import app

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            payload = {
                "senderEmail": "colleague@company.com",
                "senderName": "Internal Colleague",
                "subject": "Quarterly review sync",
                "bodyText": "Let's review the quarterly slides this afternoon.",
                "links": [],
                "hasAttachment": False,
                "_behavioral": {
                    "score": 20,
                    "reason": "off_hours_anomaly",
                    "interactionCount": 8,
                    "minCircularDistanceH": 7.5,
                },
            }
            resp = await client.post("/api/v1/analyze", json=payload)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["s_behavioral"], 20)
            self.assertIn("Off-hours anomaly", data["layers"]["behavior"]["detail"])
            self.assertIn("7.5h circular deviation", data["xai"])


if __name__ == "__main__":
    unittest.main()

