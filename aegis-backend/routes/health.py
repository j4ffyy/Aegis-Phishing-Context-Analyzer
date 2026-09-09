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
from modules.nlp_classifier import is_model_warm

router = APIRouter()


@router.get("/health")
async def health() -> dict:
    """
    Returns the current service liveness and readiness state.

    Response fields:
        status    — "ok" if the service is accepting requests.
        model     — "warm" if the ONNX InferenceSession is loaded,
                    "cold" if warm-up has not yet completed.
        vt_cache  — Number of pre-loaded VirusTotal URL cache entries.
    """
    return {
        "status": "ok",
        "model": "warm" if is_model_warm() else "cold",
        "vt_cache": get_vt_cache_size(),
    }
