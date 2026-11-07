"""
Statistical Sample Size & Wilson Lower-Bound Calculator for NFR04 (E-32)
Implementation Plan §7 (Item I-03)
Objective:
  Compute the minimum sample size of phishing emails required to formally
  confirm NFR04 (recall >= 90.0%) with 95% statistical confidence (Wilson Score Interval).
"""

import math
import sys
from datetime import datetime, timezone
from pathlib import Path

Z_95 = 1.959963984540054  # Two-sided 95% standard normal quantile


def wilson_interval(k: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """Computes exact two-sided Wilson score confidence interval [lower, upper]."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1.0 + (z**2 / n)
    center = (p + (z**2 / (2.0 * n))) / denom
    spread = (z * math.sqrt((p * (1.0 - p) / n) + (z**2 / (4.0 * n**2)))) / denom
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return lower * 100.0, upper * 100.0


def compute_min_sample_size(target_p: float, threshold_lower: float = 90.0, z: float = Z_95) -> tuple[int, int, float, float]:
    """Finds minimal N such that Wilson lower bound >= threshold_lower."""
    for n in range(5, 5000):
        k = round(target_p * n)
        low, high = wilson_interval(k, n, z)
        if low >= threshold_lower:
            return n, k, low, high
    return -1, -1, 0.0, 0.0


def generate_report() -> str:
    now_utc = datetime.now(timezone.utc).isoformat()
    lines = [
        "=" * 80,
        "AEGIS PHISHING ANALYZER -- STATISTICAL SAMPLE SIZE CALCULATION (E-32)",
        "Item: I-03 (Full-Pipeline Evaluation & NFR04 Sample Size Justification)",
        f"Generated: {now_utc}",
        "Reference Standard: Wilson Score Confidence Interval (95% Two-Sided, z=1.95996)",
        "=" * 80,
        "",
        "1. BACKGROUND & REQUIREMENT SPECIFICATION",
        "-" * 80,
        "Non-Functional Requirement 04 (NFR04) specifies:",
        "  'The system shall achieve a minimum threat recall of 90.0% on phishing vectors.'",
        "",
        "In empirical hypothesis testing, achieving a point estimate recall >= 90% is",
        "insufficient if the confidence interval lower bound spans below 90.0%.",
        "To rigorously confirm NFR04 at alpha = 0.05, the lower bound of the 95% Wilson",
        "score interval must satisfy: L_95(Recall) >= 90.0%.",
        "",
        "2. MINIMUM PHISHING SAMPLES NEEDED BY OBSERVED RECALL RATE",
        "-" * 80,
        f"{'Observed Recall':<18} | {'Min N Phishing':<16} | {'True Positives (k)':<20} | {'Wilson 95% CI':<20}",
        "-" * 80,
    ]

    p_targets = [0.91, 0.92, 0.93, 0.94, 0.95, 0.96, 0.97, 0.98, 0.99, 1.00]
    for p in p_targets:
        n, k, low, high = compute_min_sample_size(p, threshold_lower=90.0)
        lines.append(f"{p * 100:5.1f}%             | {n:<16} | {k:<20} | [{low:5.2f}%, {high:5.2f}%]")

    lines.extend([
        "-" * 80,
        "",
        "3. EVALUATION OF CAPSTONE 2 TEST DATASET (N = 50 Phishing Emails)",
        "-" * 80,
        "The Capstone 2 offline test dataset evaluates 50 curated phishing emails.",
        "Below are the exact Wilson 95% confidence intervals for observed outcomes:",
        "",
        "a) Perfect Detection (Hypothetical Upper Bound, 50/50, 100.0%):",
    ])
    low_100, high_100 = wilson_interval(50, 50)
    lines.append(f"   Recall: 100.0% -> Wilson 95% CI: [{low_100:.2f}%, {high_100:.2f}%] (Lower bound >= 90% PASSES)")

    lines.append("\nb) Placeholder Benchmark with Synthetic Auth Cues (43/50, 86.0% Recall):")
    low_86, high_86 = wilson_interval(43, 50)
    lines.append(f"   Recall:  86.0% -> Wilson 95% CI: [{low_86:.2f}%, {high_86:.2f}%] (Lower bound < 90% FAILS NFR04)")

    lines.append("\nc) Neutralized Auth Pipeline Benchmark (33/50, 66.0% Recall):")
    low_66, high_66 = wilson_interval(33, 50)
    lines.append(f"   Recall:  66.0% -> Wilson 95% CI: [{low_66:.2f}%, {high_66:.2f}%] (Lower bound < 90% FAILS NFR04)")

    lines.extend([
        "",
        "4. METHODOLOGICAL FINDING & AUDIT CONCLUSION",
        "-" * 80,
        "1. If true operational recall is 95.0%, a minimum of N = 127 phishing emails",
        "   is mathematically necessary for the 95% lower bound to clear 90.0%.",
        "2. At N = 50 phishing emails, any observed recall below 98.0% (k <= 48/50)",
        "   yields a Wilson lower bound strictly below 90.0%.",
        "3. Therefore, with N = 50 samples, NFR04 cannot be formally validated as met",
        "   under neutral authentication conditions. As required by Plan §7 (Item I-03),",
        "   the manuscript must honestly report that NFR04 was NOT formally met under",
        "   neutral authentication, and the sample size was statistically constrained.",
        "=" * 80,
    ])

    return "\n".join(lines) + "\n"


def main():
    report = generate_report()
    out_txt = Path("evidence/E-32_nfr04-sample-size/E-32_nfr04-sample-size_output_20261107_91e1e8d.txt")
    out_py = Path("evidence/E-32_nfr04-sample-size/E-32_nfr04-sample-size_script_20261107_91e1e8d.py")

    out_txt.parent.mkdir(parents=True, exist_ok=True)
    out_txt.write_bytes(report.encode("utf-8"))

    script_bytes = Path(__file__).read_bytes()
    out_py.write_bytes(script_bytes)

    print(f"Wrote {out_txt}")
    print(f"Wrote {out_py}")


if __name__ == "__main__":
    main()
