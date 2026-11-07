import subprocess
import time
from pathlib import Path

results = []
timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
results.append("=================================================================")
results.append(f"  AEGIS UNIT & INTEGRATION TEST VERIFICATION SUITE")
results.append(f"  Execution Timestamp: {timestamp}")
results.append("=================================================================\n")

# Run Extension Tests
node_tests = [
    ("Behavioral Baseline (TC-06, TC-07)", "node tests/test_behavioral_baseline.js", "aegis-extension"),
    ("Whitelist & SPF/DKIM Auto-Revocation (TC-10)", "node tests/test_whitelist.js", "aegis-extension"),
    ("Content Script Auth Extraction (TC-10)", "node tests/test_content_script_auth.js", "aegis-extension"),
    ("Local Heuristics & URL Obfuscation (TC-04)", "node tests/test_local_heuristics.js", "aegis-extension"),
    ("PII Scrubber", "node tests/test_pii_scrubber.js", "aegis-extension"),
    ("Attachment Hash Extraction (TC-08)", "node tests/test_attachment_hash.js", "aegis-extension"),
]

for name, cmd, cwd in node_tests:
    results.append(f"--- Running {name} ---")
    proc = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    results.append(f"Exit Code: {proc.returncode}")
    results.append(proc.stdout)
    if proc.stderr:
        results.append("STDERR:\n" + proc.stderr)
    results.append("\n")

# Run Backend Tests
backend_tests = [
    ("Meta-Classifier & XAI Rationale (TC-05)", ".\\.venv\\Scripts\\python.exe -m unittest tests/test_meta_classifier.py", "aegis-backend"),
    ("Attachment & VirusTotal Floor Override (TC-08, TC-09)", ".\\.venv\\Scripts\\python.exe -m unittest tests/test_attachment_vt.py", "aegis-backend"),
    ("Pipeline & Full Route Analysis (TC-01, TC-02, TC-03)", ".\\.venv\\Scripts\\python.exe -m unittest tests/test_pipeline.py", "aegis-backend"),
]

for name, cmd, cwd in backend_tests:
    results.append(f"--- Running {name} ---")
    proc = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    results.append(f"Exit Code: {proc.returncode}")
    results.append(proc.stdout)
    if proc.stderr:
        results.append("STDERR:\n" + proc.stderr)
    results.append("\n")

final_text = "\n".join(results)
Path("evidences/07_unit_tests_run.txt").write_text(final_text, encoding="utf-8")
print(f"Completed all test runs! Output saved to evidences/07_unit_tests_run.txt ({len(final_text)} bytes).")
