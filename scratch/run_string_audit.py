#!/usr/bin/env python3
"""
Aegis String Audit Script (I-13 / E-36)
Audits codebase for:
1. DMARC occurrences
2. "High" risk tier label usage (valid tiers: Safe, Warning, Critical)
3. URL masking references
4. Gmail integration / API claims
"""

import datetime
import os
import re
import subprocess
from pathlib import Path

def main():
    repo_root = Path(__file__).resolve().parent.parent
    backend_dir = repo_root / "aegis-backend"
    ext_dir = repo_root / "aegis-extension"

    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short=7", "HEAD"],
            cwd=str(repo_root),
            text=True,
        ).strip()
    except Exception:
        commit = "unknown"

    date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    out_dir = repo_root / "evidence" / "E-36_string-audit"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"E-36_string-audit_{date_str}_{commit}.txt"

    search_targets = [
        ("1. DMARC occurrences", re.compile(r"\bDMARC\b", re.IGNORECASE),
         "DMARC protocol checks are not implemented in the Aegis extension or backend (SPF and DKIM only)."),
        ("2. 'High' risk tier occurrences", re.compile(r"['\"]High['\"]|\bHigh\s+Risk\b", re.IGNORECASE),
         "The Aegis three-tier system defines tiers: Safe (0-44), Warning (45-74), and Critical (75-100). 'High' should not be used as an independent tier label."),
        ("3. URL masking occurrences", re.compile(r"\bURL\s+masking\b|\bmasking\b", re.IGNORECASE),
         "Verification of URL masking claims in detection logic and heuristics."),
        ("4. Gmail API / integration claims", re.compile(r"\bGmail\s+API\b|\bGoogle\s+Workspace\s+Marketplace\b|\bWorkspace\s+add-on\b", re.IGNORECASE),
         "Aegis integrates via Chrome Extension DOM extraction/MutationObserver, not direct Gmail REST API or Workspace Marketplace add-on."),
    ]

    paths_to_search = []
    for base in [backend_dir, ext_dir]:
        for p in base.rglob("*"):
            if p.is_file() and not any(part.startswith(".") or part in ["__pycache__", ".venv", "venv", "node_modules", "dist", "results", "data", "extracted_media", "evidences"] for part in p.parts):
                if p.suffix.lower() in [".py", ".js", ".html", ".css", ".json", ".md"]:
                    paths_to_search.append(p)

    paths_to_search.sort()

    lines = []
    lines.append(f"# Aegis String Audit Report (E-36 / I-13)")
    lines.append(f"# Date (UTC): {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    lines.append(f"# Git Commit: {commit}")
    lines.append(f"# Total files scanned: {len(paths_to_search)}")
    lines.append(f"# Scope: aegis-backend/ and aegis-extension/ source trees")
    lines.append("")

    for title, regex, description in search_targets:
        lines.append("=" * 80)
        lines.append(f"## {title}")
        lines.append(f"Description: {description}")
        lines.append(f"Regex Pattern: {regex.pattern}")
        lines.append("-" * 80)
        
        matches = []
        for p in paths_to_search:
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                for line_no, line in enumerate(content.splitlines(), start=1):
                    if regex.search(line):
                        rel = p.relative_to(repo_root).as_posix()
                        matches.append((rel, line_no, line.strip()))
            except Exception as e:
                pass

        if matches:
            lines.append(f"Found {len(matches)} match(es):")
            for rel, line_no, text in matches:
                lines.append(f"  {rel}:{line_no}: {text}")
        else:
            lines.append("Found 0 matches across all scanned files.")
        lines.append("")

    report_content = "\n".join(lines) + "\n"
    out_file.write_text(report_content, encoding="utf-8")
    print(f"Wrote string audit to {out_file.relative_to(repo_root)}")
    print(f"File size: {out_file.stat().st_size} bytes")

if __name__ == "__main__":
    main()
