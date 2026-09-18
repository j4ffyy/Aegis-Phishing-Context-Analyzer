"""
Unit Tests for Aegis DistilBERT ONNX NLP Classifier Module
Specification: Implementation Plan §5.2.1, §6.3 (Milestone 3.1)
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np

# Ensure aegis-backend root is on sys.path
BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from modules.nlp_classifier import (
    CLASS_LABELS,
    classify_email_text,
    is_model_warm,
    load_nlp_model,
    softmax,
    warm_up_nlp,
)


class TestNLPClassifier(unittest.TestCase):
    """Test suite validating numerical stability, label mapping, and Layer 2 scoring."""

    def test_softmax_basic_properties(self):
        """Softmax outputs should be non-negative and sum to 1.0."""
        logits = np.array([2.0, 1.0, 0.1, -1.0])
        probs = softmax(logits)

        self.assertEqual(len(probs), 4)
        self.assertTrue(np.all(probs >= 0.0))
        self.assertTrue(np.all(probs <= 1.0))
        self.assertAlmostEqual(float(np.sum(probs)), 1.0, places=5)
        # Highest logit should have highest probability
        self.assertEqual(int(np.argmax(probs)), 0)

    def test_softmax_numerical_stability_extreme_values(self):
        """Softmax must not overflow to Inf or NaN on very large logits."""
        # Very large positive logits that would overflow naive exp(1000)
        huge_logits = np.array([1000.0, 999.0, 500.0, 0.0])
        probs = softmax(huge_logits)

        self.assertFalse(np.isnan(probs).any(), "Softmax produced NaN on large inputs")
        self.assertFalse(np.isinf(probs).any(), "Softmax produced Inf on large inputs")
        self.assertAlmostEqual(float(np.sum(probs)), 1.0, places=5)
        self.assertGreater(probs[0], probs[1])

        # Very large negative logits that would underflow
        tiny_logits = np.array([-1000.0, -1000.0, -1000.0, -1000.0])
        probs_tiny = softmax(tiny_logits)
        self.assertFalse(np.isnan(probs_tiny).any())
        self.assertAlmostEqual(float(np.sum(probs_tiny)), 1.0, places=5)

    def test_class_label_indices(self):
        """Verifies exact 4-class label taxonomy specified in §6.3."""
        self.assertEqual(CLASS_LABELS[0], "legitimate_email")
        self.assertEqual(CLASS_LABELS[1], "phishing_url_context")
        self.assertEqual(CLASS_LABELS[2], "legitimate_url_context")
        self.assertEqual(CLASS_LABELS[3], "alternative_phishing")

    def test_scoring_piecewise_formula_high_phishing_prob(self):
        """
        When P_phish > 0.50:
            S_base = 60 * P_phish
            S_nlp = min(100, round(S_base + S_urgency + S_bec))
        """
        # Mock session to return logits favoring phishing classes (Index 1 and 3)
        mock_session = MagicMock()
        # [P0=0.05, P1=0.50, P2=0.05, P3=0.40] -> P_phish = 0.90
        mock_logits = np.array([[-1.0, 2.0, -1.0, 1.8]])
        mock_session.get_inputs.return_value = [
            MagicMock(name="input_ids"),
            MagicMock(name="attention_mask"),
        ]
        mock_session.run.return_value = [mock_logits]

        mock_tokenizer = MagicMock()
        mock_tokenizer.return_value = {
            "input_ids": np.ones((1, 10), dtype=np.int64),
            "attention_mask": np.ones((1, 10), dtype=np.int64),
        }

        with patch("modules.nlp_classifier._session", mock_session), \
             patch("modules.nlp_classifier._tokenizer", mock_tokenizer):
            res = classify_email_text(
                "Urgent account verification required",
                urgency_penalty=15,
                bec_penalty=10,
            )

            self.assertGreater(res["p_phish"], 0.50)
            expected_base = 60.0 * res["p_phish"]
            self.assertAlmostEqual(res["s_base"], round(expected_base, 2))
            expected_total = min(100, round(expected_base + 15 + 10))
            self.assertEqual(res["nlp_score"], expected_total)
            self.assertEqual(res["s_urgency"], 15)
            self.assertEqual(res["s_bec"], 10)
            self.assertTrue(res["model_warm"])

    def test_scoring_piecewise_formula_low_phishing_prob(self):
        """
        When P_phish <= 0.50:
            S_base = 10 * (1 - P_phish)
            S_nlp = min(100, round(S_base + S_urgency + S_bec))
        """
        mock_session = MagicMock()
        # Strongly favors legitimate email (Index 0)
        mock_logits = np.array([[5.0, -2.0, 1.0, -3.0]])
        mock_session.get_inputs.return_value = [
            MagicMock(name="input_ids"),
            MagicMock(name="attention_mask"),
        ]
        mock_session.run.return_value = [mock_logits]

        mock_tokenizer = MagicMock()
        mock_tokenizer.return_value = {
            "input_ids": np.ones((1, 10), dtype=np.int64),
            "attention_mask": np.ones((1, 10), dtype=np.int64),
        }

        with patch("modules.nlp_classifier._session", mock_session), \
             patch("modules.nlp_classifier._tokenizer", mock_tokenizer):
            res = classify_email_text("Meeting agenda for team sync next Tuesday")

            self.assertLessEqual(res["p_phish"], 0.50)
            expected_base = 10.0 * (1.0 - res["p_phish"])
            self.assertAlmostEqual(res["s_base"], round(expected_base, 2))
            self.assertEqual(res["nlp_score"], round(expected_base))
            self.assertEqual(res["predicted_label"], "legitimate_email")

    def test_score_clamps_at_100(self):
        """S_nlp must never exceed 100 points even with maximum adjustments."""
        mock_session = MagicMock()
        mock_logits = np.array([[-5.0, 10.0, -5.0, 10.0]])  # P_phish ~ 1.0 -> S_base ~ 60
        mock_session.get_inputs.return_value = [
            MagicMock(name="input_ids"),
            MagicMock(name="attention_mask"),
        ]
        mock_session.run.return_value = [mock_logits]

        mock_tokenizer = MagicMock()
        mock_tokenizer.return_value = {
            "input_ids": np.ones((1, 10), dtype=np.int64),
            "attention_mask": np.ones((1, 10), dtype=np.int64),
        }

        with patch("modules.nlp_classifier._session", mock_session), \
             patch("modules.nlp_classifier._tokenizer", mock_tokenizer):
            res = classify_email_text(
                "Suspicious text",
                urgency_penalty=50,  # exceeds 20 cap
                bec_penalty=50,      # exceeds 20 cap
            )
            self.assertLessEqual(res["nlp_score"], 100)
            self.assertEqual(res["s_urgency"], 20)  # clamped to 20
            self.assertEqual(res["s_bec"], 20)      # clamped to 20

    def test_fallback_mode_when_unprimed(self):
        """When session is None, classify_email_text should safely degrade."""
        with patch("modules.nlp_classifier._session", None), \
             patch("modules.nlp_classifier._tokenizer", None):
            res = classify_email_text("Sample email", urgency_penalty=10)

            self.assertFalse(res["model_warm"])
            self.assertIn("nlp_score", res)
            self.assertIn("probabilities", res)
            self.assertIn("predicted_label", res)


if __name__ == "__main__":
    unittest.main()
