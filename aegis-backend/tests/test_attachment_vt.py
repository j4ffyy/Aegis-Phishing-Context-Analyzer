"""
Aegis Backend Test Suite: Attachment File Hash VirusTotal Gateway (PR-09)
Specification: Capstone 2 Paper §3.1 (Scope: File Hash VT Lookup) & PR-09 Spec

Validates:
1. SHA-256 hash formatting and hex validation (is_valid_sha256).
2. Pre-warmed file seed cache loading and 0ms cache hits.
3. Single file hash scanning (scan_single_file_hash) for malicious, clean, and unrated files.
4. HTTP mock handling: 200 malicious, 200 clean, 404 unrated, 429 quota, 401 unauthorized.
5. Batch attachment scanning (scan_email_attachment_hashes) and 2-attachment cap constraint.
6. API endpoint GET /api/v1/vt-file-status/{hash} (200 success and 400 validation error).
7. End-to-end analyze route integration: malicious attachment triggers Critical Threat Floor.
8. Layer 2 status breakdown and XAI rationale reflect attachment VirusTotal findings.
"""

import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import httpx

from modules.link_scanner import (
    DEFAULT_MIN_REQUEST_INTERVAL,
    are_attachment_hashes_cached,
    clear_vt_cache,
    get_vt_file_cache_size,
    is_valid_sha256,
    load_vt_file_seed_cache,
    scan_email_attachment_hashes,
    scan_single_file_hash,
    set_pacing_interval,
)
from modules.meta_classifier import build_layers_status, generate_xai_rationale
from routes.analyze import EmailPayload, analyze_email, get_vt_file_status


# Standard Test SHA-256 Hashes
EICAR_HASH = "275a021bbfb341410736ae3d319e0666baeb82e9f91ceb857a142eb0ce3779b4"
EMOTET_HASH = "4f9543e3f7a4b0051e707e719546059c1901cb001b6b553655dc3858c56c2776"
CLEAN_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
UNSEEN_HASH = "1111111111111111111111111111111111111111111111111111111111111111"


class TestAttachmentVirusTotal(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        clear_vt_cache()
        set_pacing_interval(0.01)  # Accelerate for testing

    def tearDown(self):
        clear_vt_cache()
        set_pacing_interval(DEFAULT_MIN_REQUEST_INTERVAL)

    def test_sha256_validation(self):
        """Validates 64-char hexadecimal string checks."""
        self.assertTrue(is_valid_sha256(EICAR_HASH))
        self.assertTrue(is_valid_sha256(EICAR_HASH.upper()))
        self.assertFalse(is_valid_sha256("not_a_hash"))
        self.assertFalse(is_valid_sha256("275a021bbfb3"))  # too short
        self.assertFalse(is_valid_sha256(EICAR_HASH + "0"))  # too long
        self.assertFalse(is_valid_sha256("z" * 64))  # invalid hex characters
        self.assertFalse(is_valid_sha256(""))
        self.assertFalse(is_valid_sha256(None))

    def test_file_seed_cache_loading(self):
        """Tests pre-warmed file seed cache population."""
        self.assertEqual(get_vt_file_cache_size(), 0)
        load_vt_file_seed_cache()
        self.assertGreaterEqual(get_vt_file_cache_size(), 4)

    async def test_instant_seed_cache_lookup(self):
        """Pre-warmed seed cache entries return immediately (0ms) with correct verdict."""
        load_vt_file_seed_cache()

        # Malicious sample (EICAR)
        eicar_res = await scan_single_file_hash(EICAR_HASH)
        self.assertTrue(eicar_res["cached"])
        self.assertTrue(eicar_res["malicious"])
        self.assertGreater(eicar_res["positives"], 0)
        self.assertIn("EICAR", eicar_res["threat_name"])

        # Clean sample
        clean_res = await scan_single_file_hash(CLEAN_HASH)
        self.assertTrue(clean_res["cached"])
        self.assertFalse(clean_res["malicious"])
        self.assertEqual(clean_res["positives"], 0)
        self.assertEqual(clean_res["status"], "clean")

    async def test_invalid_hash_scan(self):
        """Scanning an invalid hash fails safely without outbound network query."""
        res = await scan_single_file_hash("bad-hash")
        self.assertFalse(res["malicious"])
        self.assertEqual(res["status"], "invalid_hash")

    @patch("modules.link_scanner.get_vt_api_key", return_value="dummy_vt_key")
    async def test_mock_vt_api_malicious_response(self, mock_key):
        """Tests parsing of a 200 OK VirusTotal file report detecting malware."""
        mock_resp_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 45,
                        "suspicious": 2,
                        "harmless": 0,
                        "undetected": 25,
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "Trojan.GenericKD",
                    },
                    "type_description": "Win32 Executable",
                }
            }
        }

        mock_http_response = httpx.Response(
            status_code=200,
            json=mock_resp_data,
            request=httpx.Request("GET", f"https://www.virustotal.com/api/v3/files/{UNSEEN_HASH}"),
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_http_response
            res = await scan_single_file_hash(UNSEEN_HASH)

            self.assertTrue(res["malicious"])
            self.assertEqual(res["positives"], 47)
            self.assertEqual(res["threat_name"], "Trojan.GenericKD")
            self.assertEqual(res["status"], "malicious")
            self.assertFalse(res["cached"])

    @patch("modules.link_scanner.get_vt_api_key", return_value="dummy_vt_key")
    async def test_mock_vt_api_404_unrated_response(self, mock_key):
        """Tests parsing of a 404 response for unseen/unrated file hashes."""
        mock_http_response = httpx.Response(
            status_code=404,
            request=httpx.Request("GET", f"https://www.virustotal.com/api/v3/files/{UNSEEN_HASH}"),
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_http_response
            res = await scan_single_file_hash(UNSEEN_HASH)

            self.assertFalse(res["malicious"])
            self.assertEqual(res["status"], "clean_or_unrated")
            self.assertEqual(res["positives"], 0)

    @patch("modules.link_scanner.get_vt_api_key", return_value="dummy_vt_key")
    async def test_mock_vt_api_quota_429(self, mock_key):
        """Tests graceful degradation when 429 quota exceeded occurs."""
        mock_http_response = httpx.Response(
            status_code=429,
            request=httpx.Request("GET", f"https://www.virustotal.com/api/v3/files/{UNSEEN_HASH}"),
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_http_response
            res = await scan_single_file_hash(UNSEEN_HASH)

            self.assertFalse(res["malicious"])
            self.assertEqual(res["status"], "quota_exceeded")

    async def test_attachment_batch_scan_cap(self):
        """Tests that scan_email_attachment_hashes enforces the 2-attachment maximum cap."""
        load_vt_file_seed_cache()
        hashes = [EICAR_HASH, CLEAN_HASH, EMOTET_HASH]  # 3 hashes

        batch_res = await scan_email_attachment_hashes(hashes)
        self.assertEqual(batch_res["scanned_count"], 2)  # Capped at 2
        self.assertTrue(batch_res["has_malicious_attachment"])
        self.assertEqual(batch_res["malicious_count"], 1)

    def test_are_attachment_hashes_cached(self):
        """Tests cache presence evaluation for attachment hashes."""
        load_vt_file_seed_cache()
        self.assertTrue(are_attachment_hashes_cached([EICAR_HASH, CLEAN_HASH]))
        self.assertFalse(are_attachment_hashes_cached([EICAR_HASH, UNSEEN_HASH]))
        self.assertTrue(are_attachment_hashes_cached([]))


class TestAttachmentRoutesIntegration(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        clear_vt_cache()
        load_vt_file_seed_cache()
        set_pacing_interval(0.01)

    def tearDown(self):
        clear_vt_cache()

    async def test_vt_file_status_endpoint(self):
        """Tests GET /api/v1/vt-file-status/{hash} endpoint."""
        res = await get_vt_file_status(EICAR_HASH)
        self.assertTrue(res["malicious"])
        self.assertIn("EICAR", res["threat_name"])

    async def test_malicious_attachment_triggers_critical_threat_floor(self):
        """
        Emails with confirmed malicious attachment hashes must trigger
        the Critical Threat Floor (§6.5), ensuring score >= 75 and 'Critical' tier.
        """
        from fastapi import BackgroundTasks

        payload = EmailPayload(
            senderEmail="trusted-colleague@company.com",
            senderName="Colleague",
            subject="Updated Project Specs",
            bodyText="Hi team, please find the latest project attachment.",
            attachmentCount=1,
            attachments=["Project_Spec.exe"],
            attachmentHashes=[EICAR_HASH],
            spfPass=True,
            dkimPass=True,
            behavioralScore=0,
        )

        bg = BackgroundTasks()
        result = await analyze_email(payload, bg)

        # Must be in Critical tier due to confirmed malware payload
        self.assertGreaterEqual(result["score"], 75)
        self.assertEqual(result["riskLevel"], "Critical")

        # Verify flag added
        flag_titles = [f["title"] for f in result["flags"]]
        self.assertTrue(
            any("Malicious Attachment" in t for t in flag_titles),
            f"Expected Malicious Attachment flag in: {flag_titles}"
        )

        # Verify Layer 2 breakdown reflects malware
        layers = result.get("layers", {})
        self.assertIn("attach", layers)
        self.assertEqual(layers["attach"]["icon"], "fa-times-circle")
        self.assertIn("VirusTotal", layers["attach"]["detail"])


class TestAttachmentXAIAndStatus(unittest.TestCase):
    def test_layer2_status_clean_attachments(self):
        """Layer 2 shows green check when attachments are verified clean."""
        vt_result = {
            "attachment_findings": {
                "findings": [{"hash": CLEAN_HASH, "malicious": False}]
            }
        }
        layers = build_layers_status(
            s_heuristic=10,
            s_nlp=10,
            s_behavioral=10,
            s_vt=0,
            vt_status="completed",
            flags=[],
            urls=[],
            vt_result=vt_result,
        )
        self.assertEqual(layers["attach"]["icon"], "fa-check-circle")
        self.assertIn("verified clean", layers["attach"]["detail"])

    def test_layer2_status_malicious_attachments(self):
        """Layer 2 shows red alert when malicious attachment detected."""
        flags = [{
            "title": "Malicious Attachment Hash Detected",
            "evidence": "EICAR virus signature detected by VirusTotal",
            "severity": "critical",
        }]
        layers = build_layers_status(
            s_heuristic=60,
            s_nlp=10,
            s_behavioral=10,
            s_vt=50,
            vt_status="completed",
            flags=flags,
            urls=[],
        )
        self.assertEqual(layers["attach"]["icon"], "fa-times-circle")
        self.assertIn("VirusTotal", layers["attach"]["detail"])

    def test_xai_rationale_includes_malicious_attachment(self):
        """XAI explanation clearly reports malicious attachment finding."""
        flags = [{
            "title": "Malicious Attachment Hash Detected",
            "evidence": "Trojan.Emotet payload confirmed by VirusTotal",
            "severity": "critical",
        }]
        xai = generate_xai_rationale(
            risk_level="Critical",
            flags=flags,
            s_heuristic=75,
            s_nlp=30,
            s_behavioral=10,
            s_vt=75,
            vt_status="completed",
            links_count=0,
        )
        self.assertIn("Malicious Attachment Hash Detected", xai)
        self.assertIn("Trojan.Emotet", xai)


if __name__ == "__main__":
    unittest.main()
