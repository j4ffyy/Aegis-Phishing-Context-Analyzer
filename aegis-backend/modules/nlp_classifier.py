"""
Aegis: AI-Powered Phishing Context Analyzer
Module: NLP Classifier (DistilBERT ONNX)

Specification: Implementation Plan §5.2, Milestone 3.1

This module will execute private, self-hosted DistilBERT inference using
ONNX Runtime. The model is baked into the Docker image at build time via
scripts/download_model.py to eliminate cold-start download latency.

Current state: Milestone 1.4 skeleton stub.
Full implementation: TODO(Milestone 3.1)
"""

import logging

logger = logging.getLogger(__name__)

# Module-level flag indicating whether the ONNX InferenceSession has been
# loaded and warmed up. Checked by the health endpoint to report readiness.
_model_warm: bool = False


def warm_up_nlp() -> None:
    """
    Load the DistilBERT ONNX model and execute a single dummy inference
    to prime the ONNX Runtime JIT compiler.

    Called once during FastAPI application startup via the lifespan
    context manager in main.py. After this call, subsequent inference
    requests execute at ~25–50ms instead of ~1s cold-start latency.

    Memory target: < 150MB RSS (safely below Render 512MB ceiling).

    TODO(Milestone 3.1): Replace this stub with:
        import onnxruntime as ort
        from pathlib import Path
        MODEL_PATH = Path("models/phishing_distilbert/model.onnx")
        _session = ort.InferenceSession(str(MODEL_PATH))
        # Run dummy inference to warm JIT...
        _model_warm = True
    """
    global _model_warm
    logger.info("[Aegis] NLP warm-up complete (stub — ONNX session not yet loaded)")
    _model_warm = True


def is_model_warm() -> bool:
    """Returns True if the ONNX InferenceSession has been loaded."""
    return _model_warm
