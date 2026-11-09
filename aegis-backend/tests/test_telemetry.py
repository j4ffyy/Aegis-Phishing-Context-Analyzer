"""
Unit Tests for Aegis Backend Telemetry & Log Result Sanitation (Post-Defense Item 3)
"""

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from routes.analyze import (
    LogResultPayload,
    extract_sender_domain,
    scrub_subject_text,
    log_result,
    _detection_log,
)


class TestTelemetrySanitization(unittest.TestCase):

    def setUp(self):
        _detection_log.clear()

    def test_extract_sender_domain(self):
        """Validates that sender addresses are reduced strictly to their domain."""
        self.assertEqual(extract_sender_domain("user@phish-bank.com"), "phish-bank.com")
        self.assertEqual(extract_sender_domain("John Doe <alert@sub.example.org>"), "sub.example.org")
        self.assertEqual(extract_sender_domain("raw-domain.com"), "raw-domain.com")
        self.assertEqual(extract_sender_domain(""), "[DOMAIN]")

    def test_scrub_subject_text(self):
        """Validates that email addresses and phone/account numbers are redacted."""
        raw_subj = "Payment alert for user@victim.com: call +1-800-555-0199 immediately"
        scrubbed = scrub_subject_text(raw_subj)
        self.assertNotIn("user@victim.com", scrubbed)
        self.assertNotIn("+1-800-555-0199", scrubbed)
        self.assertIn("[EMAIL]", scrubbed)
        self.assertIn("[PHONE]", scrubbed)

    async def async_test_log_result_sanitizes_storage(self):
        """Validates that /api/v1/log-result stores only sanitized domain and scrubbed subject."""
        payload = LogResultPayload(
            emailHash="abcd1234efgh5678",
            score=85,
            riskLevel="Critical",
            sender="Security Dept <phisher@spoofed-target.com>",
            subject="Security notice regarding account 123456789 and email alert@victim.org",
        )
        res = await log_result(payload)
        self.assertTrue(res["ok"])
        self.assertEqual(len(_detection_log), 1)

        stored = _detection_log[0]
        self.assertEqual(stored["sender"], "spoofed-target.com")
        self.assertNotIn("phisher@", stored["sender"])
        self.assertNotIn("123456789", stored["subject"])
        self.assertNotIn("alert@victim.org", stored["subject"])
        self.assertIn("[NUMBER]", stored["subject"])
        self.assertIn("[EMAIL]", stored["subject"])

    def test_async_wrapper(self):
        import asyncio
        asyncio.run(self.async_test_log_result_sanitizes_storage())


if __name__ == "__main__":
    unittest.main()
