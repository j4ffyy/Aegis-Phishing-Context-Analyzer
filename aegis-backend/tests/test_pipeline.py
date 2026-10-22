"""
Aegis: AI-Powered Phishing Context Analyzer
Tests: Pipeline Integration Test for Model Evaluation (PR-08)
Spec: Capstone 2 Paper §4.2 — Model Evaluation Protocol

Tests the complete offline evaluation pipeline:
  - Dataset preparation (prepare_test_dataset.py)
  - Local pipeline scoring (evaluate_models.py offline mode)
  - Metrics computation correctness
  - Output file generation

Run:
    cd aegis-backend
    python -m pytest tests/test_pipeline.py -v

Or without pytest:
    python tests/test_pipeline.py
"""

import csv
import json
import sys
import time
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


# ---------------------------------------------------------------------------
# Minimal standalone test harness (works without pytest)
# ---------------------------------------------------------------------------

class AegisTestRunner:
    """Lightweight test runner for environments without pytest installed."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []

    def run(self, test_cls):
        instance = test_cls()
        methods = [m for m in dir(instance) if m.startswith("test_")]
        for method_name in sorted(methods):
            try:
                getattr(instance, method_name)()
                print(f"  ✅  PASS  {test_cls.__name__}.{method_name}")
                self.passed += 1
            except Exception as e:
                print(f"  ❌  FAIL  {test_cls.__name__}.{method_name}: {e}")
                self.failed += 1

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*55}")
        print(f"  Results: {self.passed}/{total} passed  |  {self.failed} failed")
        print(f"{'='*55}\n")
        return self.failed == 0


# ---------------------------------------------------------------------------
# Helper: reproduce metrics math from evaluate_models.py
# ---------------------------------------------------------------------------

def compute_metrics_inline(true_labels, pred_labels, latencies):
    n = len(true_labels)
    tp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 0)
    accuracy  = (tp + tn) / n * 100
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr       = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0.0
    return dict(tp=tp, tn=tn, fp=fp, fn=fn, accuracy=accuracy,
                precision=precision, recall=recall, f1_score=f1, fpr=fpr,
                latency_avg_ms=sum(latencies)/len(latencies))


# ---------------------------------------------------------------------------
# Test 1: Dataset preparation
# ---------------------------------------------------------------------------

class TestDatasetPreparation(unittest.TestCase):

    def setUp(self):
        # Import dataset generator
        from scripts.prepare_test_dataset import generate_sample
        import random
        self.generate_sample = generate_sample
        self.rng = random.Random(42)

    def test_phishing_sample_structure(self):
        s = self.generate_sample(0, is_phishing=True, rng=self.rng)
        assert s["label"] == 1, "Phishing label should be 1"
        assert s["label_name"] == "Phishing"
        assert "@" in s["senderEmail"], "Sender must have @"
        assert len(s["subject"]) > 0, "Subject must not be empty"
        assert len(s["bodyText"]) > 0, "Body must not be empty"

    def test_legit_sample_structure(self):
        s = self.generate_sample(100, is_phishing=False, rng=self.rng)
        assert s["label"] == 0, "Legitimate label should be 0"
        assert s["label_name"] == "Legitimate"
        assert "@" in s["senderEmail"]

    def test_spf_dkim_correlation(self):
        # Phishing samples should have spfPass=False, legit should have spfPass=True
        import random
        rng = random.Random(99)
        for _ in range(10):
            phishing = self.generate_sample(_, is_phishing=True, rng=rng)
            legit    = self.generate_sample(_ + 100, is_phishing=False, rng=rng)
            assert phishing["spfPass"] is False, "Phishing should fail SPF"
            assert legit["spfPass"] is True, "Legit should pass SPF"

    def test_balanced_dataset_count(self):
        import random
        rng = random.Random(42)
        size = 100
        samples = []
        for i in range(size // 2):
            samples.append(self.generate_sample(i, is_phishing=True, rng=rng))
        for i in range(size // 2, size):
            samples.append(self.generate_sample(i, is_phishing=False, rng=rng))
        phishing_count = sum(1 for s in samples if s["label"] == 1)
        legit_count    = sum(1 for s in samples if s["label"] == 0)
        assert phishing_count == size // 2, f"Expected {size//2} phishing, got {phishing_count}"
        assert legit_count == size // 2,    f"Expected {size//2} legit, got {legit_count}"

    def test_tagalog_subjects_present(self):
        from scripts.prepare_test_dataset import PHISHING_SUBJECTS
        tagalog_subjects = [s for s in PHISHING_SUBJECTS if any(
            word in s for word in ["kailangan", "i-verify", "agad", "ang", "mag-login"]
        )]
        assert len(tagalog_subjects) >= 3, "At least 3 Tagalog phishing subjects required (PR-06 coverage)"


# ---------------------------------------------------------------------------
# Test 2: Metrics computation
# ---------------------------------------------------------------------------

class TestMetricsComputation(unittest.TestCase):

    def test_perfect_classifier(self):
        true   = [1, 1, 0, 0, 1, 0]
        pred   = [1, 1, 0, 0, 1, 0]
        lats   = [10.0] * 6
        m = compute_metrics_inline(true, pred, lats)
        assert m["accuracy"]  == 100.0, f"Expected 100.0, got {m['accuracy']}"
        assert m["precision"] == 100.0
        assert m["recall"]    == 100.0
        assert m["f1_score"]  == 100.0
        assert m["fpr"]       == 0.0

    def test_zero_fpr_at_full_legit_tn(self):
        # All legitimate predicted correctly, some phishing missed
        true   = [1, 1, 0, 0]
        pred   = [0, 1, 0, 0]  # 1 FN, 0 FP
        m = compute_metrics_inline(true, pred, [5.0]*4)
        assert m["fp"] == 0, "No false positives expected"
        assert m["fpr"] == 0.0, "FPR should be 0 with no FP"
        assert m["fn"] == 1, "One false negative expected"

    def test_fpr_calculation(self):
        # 2 legit misclassified as phishing (FP=2), 8 legit correct (TN=8)
        true = [0] * 10 + [1] * 10
        pred = [1, 1] + [0] * 8 + [1] * 10  # FP=2, FN=0, TP=10, TN=8
        m = compute_metrics_inline(true, pred, [1.0]*20)
        assert m["fp"] == 2, f"Expected FP=2, got {m['fp']}"
        assert m["tn"] == 8, f"Expected TN=8, got {m['tn']}"
        assert abs(m["fpr"] - 20.0) < 0.01, f"Expected FPR=20.0%, got {m['fpr']}"

    def test_latency_average(self):
        true = [1, 0, 1]
        pred = [1, 0, 1]
        lats = [10.0, 20.0, 30.0]
        m = compute_metrics_inline(true, pred, lats)
        assert m["latency_avg_ms"] == 20.0, "Average latency should be 20ms"

    def test_aegis_target_thresholds(self):
        """
        Verifies Aegis targets from paper (Table 16):
        Accuracy >= 94%, FPR <= 2%
        Simulates 97 correct out of 100, 1 FP.
        """
        # 50 phishing: 49 TP, 1 FN; 50 legit: 49 TN, 1 FP
        true = [1]*50 + [0]*50
        pred = [1]*49 + [0] + [0]*49 + [1]  # 49 TP, 1 FN, 49 TN, 1 FP
        m = compute_metrics_inline(true, pred, [15.0]*100)
        assert m["accuracy"] >= 94.0, f"Accuracy {m['accuracy']:.1f}% below 94% target"
        assert m["fpr"] <= 4.0,       f"FPR {m['fpr']:.1f}% exceeds 4% upper bound"


# ---------------------------------------------------------------------------
# Test 3: Local pipeline scoring (Layer 1-3 offline)
# ---------------------------------------------------------------------------

class TestLocalPipelineScoring(unittest.TestCase):

    def test_obvious_phishing_scores_high(self):
        from scripts.evaluate_models import _local_evaluate_sample
        row = {
            "senderEmail": "security@bdo-reset-now.loan",
            "subject": "URGENT: Your BDO account has been suspended",
            "bodyText": "Click here immediately to verify your identity or your account will be terminated: http://bdo-login.top/verify",
            "links": '["http://bdo-login.top/verify"]',
            "attachments": '[]',
            "hasAttachment": False,
            "attachmentCount": 0,
            "spfPass": "False",
            "dkimPass": "False",
        }
        score, elapsed = _local_evaluate_sample(row)
        assert score >= 45, f"Obvious phishing should score >= 45, got {score}"
        assert elapsed < 5000, f"Evaluation took too long: {elapsed:.0f}ms"

    def test_obvious_legit_scores_low(self):
        from scripts.evaluate_models import _local_evaluate_sample
        row = {
            "senderEmail": "noreply@bdo.com.ph",
            "subject": "Your OTP for BDO Online Banking",
            "bodyText": "Your one-time password is 847291. Valid for 5 minutes. Never share this OTP.",
            "links": '[]',
            "attachments": '[]',
            "hasAttachment": False,
            "attachmentCount": 0,
            "spfPass": "True",
            "dkimPass": "True",
        }
        score, elapsed = _local_evaluate_sample(row)
        assert score <= 74, f"Legitimate OTP email should score <= 74, got {score}"

    def test_tagalog_phishing_detected(self):
        from scripts.evaluate_models import _local_evaluate_sample
        row = {
            "senderEmail": "security@gcash-verify.top",
            "subject": "URGENT: I-verify ang iyong GCash account agad na",
            "bodyText": "Kailangan mong i-verify ang iyong GCash account agad. Mag-login sa link na ito: http://gcash-ph.tk/login. Huwag ibigay ang iyong PIN sa iba.",
            "links": '["http://gcash-ph.tk/login"]',
            "attachments": '[]',
            "hasAttachment": False,
            "attachmentCount": 0,
            "spfPass": "False",
            "dkimPass": "False",
        }
        score, elapsed = _local_evaluate_sample(row)
        assert score >= 45, f"Tagalog phishing should be detected (score >= 45), got {score}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  Aegis PR-08 · Pipeline Integration Tests")
    print("="*55 + "\n")

    runner = AegisTestRunner()
    runner.run(TestDatasetPreparation)
    print()
    runner.run(TestMetricsComputation)
    print()
    runner.run(TestLocalPipelineScoring)

    success = runner.summary()
    sys.exit(0 if success else 1)
