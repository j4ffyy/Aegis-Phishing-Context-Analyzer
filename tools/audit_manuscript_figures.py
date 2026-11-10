"""
Aegis Manuscript Text and Claim Audit Tool (E-12)
Audits documentation and markdown files across the repository for deprecated
metrics, outdated risk tier terminology, and disavowed integration claims.

Audit Targets:
  1. Deprecated Metrics: 97.5%, 96.0%, 93.8%, 0.955, 86.0%, 93.0%, 83.0%
  2. Legacy Risk Tier Labels: 'High' Risk Tier (Aegis uses Safe, Warning, Critical)
  3. Disavowed Claims: Direct Gmail API integration, runtime DMARC enforcement
"""

import argparse
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SEARCH_PATTERNS = [
    ("Metric: 97.5% Phishing Recall", re.compile(r"97\.5%?")),
    ("Metric: 96.0% Baseline Accuracy", re.compile(r"96\.0%?")),
    ("Metric: 93.8% Offline Accuracy", re.compile(r"93\.8%?")),
    ("Metric: 0.955 ROC-AUC", re.compile(r"0\.955\b")),
    ("Metric: 86.0% Unloaded Phishing Recall", re.compile(r"86\.0%?")),
    ("Metric: 93.0% Unloaded Accuracy", re.compile(r"93\.0%?")),
    ("Metric: 83.0% Neutral Auth Accuracy", re.compile(r"83(?:\.0)?%?")),
    ("Tier Label: 'High' Risk Tier", re.compile(r"\bHigh\s+Risk\b|\bHigh\s+Tier\b|\bTier:\s*High\b", re.IGNORECASE)),
    ("Disavowed: Gmail API Claim", re.compile(r"\bGmail\s+API\b", re.IGNORECASE)),
    ("Disavowed: DMARC Enforcement", re.compile(r"\bDMARC\b")),
]

AUDIT_DIRS = [
    REPO_ROOT / "docs",
    REPO_ROOT / "demo_emails",
]
AUDIT_FILES = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "implementation_plan.md",
    REPO_ROOT / "LIVE_DEMONSTRATION_GUIDE.md",
    REPO_ROOT.parent / "README.md",
]


def audit_files(commit: str) -> str:
    now_utc = datetime.now(timezone.utc).isoformat()
    lines = [
        "=" * 80,
        "AEGIS MANUSCRIPT FIGURE & CLAIM AUDIT (E-12)",
        f"Commit: {commit} | Timestamp (UTC): {now_utc}",
        "=" * 80,
        "",
        "Audited Patterns:",
    ]
    for label, pat in SEARCH_PATTERNS:
        lines.append(f"  - {label} (pattern: {pat.pattern})")
    lines.append("")
    lines.append("=" * 80)
    lines.append("AUDIT FINDINGS BY FILE")
    lines.append("=" * 80)

    files_to_check = []
    for d in AUDIT_DIRS:
        if d.is_dir():
            for f in sorted(d.rglob("*.md")):
                files_to_check.append(f)
    for f in AUDIT_FILES:
        if f.is_file():
            files_to_check.append(f)

    total_hits = 0

    for file_path in files_to_check:
        try:
            rel_path = file_path.relative_to(REPO_ROOT.parent)
        except ValueError:
            rel_path = file_path

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        file_hit_lines = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            for label, pat in SEARCH_PATTERNS:
                if pat.search(line):
                    file_hit_lines.append((line_no, label, line.strip()))
                    total_hits += 1

        if file_hit_lines:
            lines.append(f"\n[FILE] {rel_path} ({len(file_hit_lines)} hits)")
            lines.append("-" * 80)
            for lno, lbl, ltext in file_hit_lines:
                lines.append(f"  L{lno:4d} | [{lbl}]")
                lines.append(f"         {ltext[:120]}")
        else:
            lines.append(f"\n[FILE] {rel_path} -- CLEAN (0 hits)")

    lines.append("\n" + "=" * 80)
    lines.append(f"AUDIT SUMMARY: Total flagged occurrences across audited files: {total_hits}")
    lines.append("=" * 80)
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Aegis Manuscript Figure & Claim Auditor")
    parser.add_argument("--commit", type=str, default="", help="7-char commit hash")
    args = parser.parse_args()

    c_hash = args.commit
    if not c_hash:
        cmd = ["git", "rev-parse", "--short", "HEAD"]
        p = subprocess.run(cmd, capture_output=True, text=True, check=True)
        c_hash = p.stdout.strip()[:7]

    output_text = audit_files(c_hash)
    e12_dir = REPO_ROOT / "evidence" / "E-12_manuscript-figure-audit"
    e12_dir.mkdir(parents=True, exist_ok=True)
    out_path = e12_dir / f"E-12_manuscript-figure-audit_20261107_{c_hash}.txt"
    out_path.write_bytes(output_text.encode("utf-8"))
    print(f"Audit complete. Flagged occurrences logged to {out_path}")


if __name__ == "__main__":
    main()
