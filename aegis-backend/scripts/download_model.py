"""
Aegis: AI-Powered Phishing Context Analyzer
Script: Build-Time Model Downloader

Specification: Implementation Plan §5.2.1, Milestone 1.5

Executed during Docker image BUILD (not at container startup) to bake
the DistilBERT ONNX model and tokenizer assets into the image filesystem.
This eliminates runtime downloads and prevents cold-start latency spikes
on Render.com container restarts after 15-minute idle spin-downs.

Usage:
    Invoked automatically via Dockerfile:
        RUN python scripts/download_model.py

    Can also be run locally to pre-populate models/ for offline development:
        python scripts/download_model.py

Repository: lemonade-sdk/phishing-email-detection-distilbert-ONNX
Verified files (2026-09-05): model.onnx, tokenizer.json,
    tokenizer_config.json, vocab.txt, special_tokens_map.json
"""

from pathlib import Path
import urllib.request

REPO_ID = "lemonade-sdk/phishing-email-detection-distilbert-ONNX"
DEST = Path("models/phishing_distilbert")
DEST.mkdir(parents=True, exist_ok=True)

FILES = [
    "config.json",
    "model.onnx",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.txt",
    "special_tokens_map.json",
]

BASE_URL = f"https://huggingface.co/{REPO_ID}/resolve/main"

import shutil
import subprocess

def download_file_with_resume(url: str, target_file: Path, fname: str) -> None:
    """Downloads a file with HTTP Range resume support and curl acceleration."""
    # Check if curl is available for fastest, robust downloading
    curl_bin = shutil.which("curl") or shutil.which("curl.exe")

    req = urllib.request.Request(url, headers={"User-Agent": "Aegis-Model-Downloader/1.0"}, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            total_size = int(resp.headers.get("Content-Length", 0))
    except Exception as e:
        total_size = 0

    current_size = target_file.stat().st_size if target_file.exists() else 0
    if total_size > 0 and current_size >= total_size:
        print(f"[Aegis Build]   {fname} already complete ({current_size} bytes).", flush=True)
        return

    if curl_bin:
        print(f"[Aegis Build]   Downloading {fname} via curl accelerator...", flush=True)
        cmd = [curl_bin, "-L", "-C", "-", url, "-o", str(target_file)]
        subprocess.run(cmd, check=True)
        print(f"[Aegis Build]   Completed {fname} ({target_file.stat().st_size} bytes)", flush=True)
        return

    while current_size < total_size:
        headers = {"User-Agent": "Aegis-Model-Downloader/1.0"}
        if current_size > 0:
            headers["Range"] = f"bytes={current_size}-"
            print(f"[Aegis Build]   Resuming {fname} from {current_size / (1024*1024):.1f} MB...", flush=True)
        else:
            print(f"[Aegis Build]   Downloading {fname} ({total_size / (1024*1024):.1f} MB)...", flush=True)

        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp, open(target_file, "ab" if current_size > 0 else "wb") as out_f:
            chunk_size = 1024 * 1024
            last_printed = current_size
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                out_f.write(chunk)
                current_size += len(chunk)
                if current_size - last_printed >= 10 * 1024 * 1024 or current_size >= total_size:
                    pct = (current_size / total_size * 100.0) if total_size > 0 else 0
                    print(f"[Aegis Build]     {fname}: {current_size/(1024*1024):.1f}/{total_size/(1024*1024):.1f} MB ({pct:.1f}%)", flush=True)
                    last_printed = current_size
                    out_f.flush()

    print(f"[Aegis Build]   Completed {fname} ({target_file.stat().st_size} bytes)", flush=True)


print(f"[Aegis Build] Baking ONNX model and tokenizer from {REPO_ID}...", flush=True)
for fname in FILES:
    target_file = DEST / fname
    url = f"{BASE_URL}/{fname}"
    download_file_with_resume(url, target_file, fname)

print(f"[Aegis Build] Model and tokenizer successfully baked into {DEST}/", flush=True)
print(f"[Aegis Build] Files: {[f.name for f in DEST.iterdir() if f.is_file()]}", flush=True)
