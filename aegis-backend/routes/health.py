"""
Aegis: AI-Powered Phishing Context Analyzer
Route: Health Probe

Provides a lightweight liveness and readiness endpoint for:
- Docker health checks during container orchestration.
- Render.com deployment verification.
- Chrome Extension background.js connectivity check on startup.
"""

from fastapi import APIRouter

from modules.link_scanner import get_vt_cache_size
from modules.nlp_classifier import get_model_id, is_model_warm

router = APIRouter()


@router.get("/health")
async def health() -> dict:
    """
    Returns the current service liveness and readiness state.

    Response fields:
        status        — "ok" if the service is accepting requests.
        model         — "warm" if the ONNX InferenceSession is loaded,
                        "cold" if warm-up has not yet completed.
        model_loaded  — True if the ONNX InferenceSession is ready for inference.
        model_id      — Model checkpoint identifier ("phishing_distilbert_onnx_4cls" or "none").
        vt_cache      — Number of pre-loaded VirusTotal URL cache entries.
    """
    loaded = is_model_warm()
    return {
        "status": "ok",
        "model": "warm" if loaded else "cold",
        "model_loaded": loaded,
        "model_id": get_model_id(),
        "vt_cache": get_vt_cache_size(),
    }
