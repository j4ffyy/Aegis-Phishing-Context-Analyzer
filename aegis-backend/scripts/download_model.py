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

from huggingface_hub import hf_hub_download

REPO_ID = "lemonade-sdk/phishing-email-detection-distilbert-ONNX"
DEST = Path("models/phishing_distilbert")
DEST.mkdir(parents=True, exist_ok=True)

FILES = [
    "model.onnx",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.txt",
    "special_tokens_map.json",
]

print(f"[Aegis Build] Baking ONNX model and tokenizer from {REPO_ID}...")
for fname in FILES:
    print(f"[Aegis Build]   Downloading {fname}...")
    hf_hub_download(repo_id=REPO_ID, filename=fname, local_dir=str(DEST))

print(f"[Aegis Build] Model and tokenizer successfully baked into {DEST}/")
print(f"[Aegis Build] Files: {[f.name for f in DEST.iterdir()]}")
