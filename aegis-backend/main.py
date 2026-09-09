"""
Aegis: AI-Powered Phishing Context Analyzer
Component: FastAPI Application Entry Point

Responsibilities:
- Application lifecycle management via lifespan context manager.
- CORS policy enforcement (dev: wildcard, prod: locked to extension origin).
- Route registration for health and analysis endpoints.
"""

from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from modules.link_scanner import load_vt_seed_cache
from modules.nlp_classifier import warm_up_nlp
from routes.health import router as health_router

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.

    Runs warm-up routines on startup before the server begins accepting
    requests. Using the lifespan pattern (FastAPI v0.93+) instead of the
    deprecated @app.on_event("startup") decorator, which was removed in
    FastAPI 0.110.

    Startup sequence:
        1. warm_up_nlp()         — Load and warm ONNX InferenceSession.
        2. load_vt_seed_cache()  — Pre-populate in-memory VT URL cache
                                   from data/vt_seed_cache.json.
    """
    warm_up_nlp()
    load_vt_seed_cache()
    yield


app = FastAPI(
    title="Aegis Phishing Analyzer API",
    description=(
        "Private backend inference service for the Aegis Chrome Extension. "
        "Executes the 4-layer phishing analysis pipeline and returns a "
        "composite risk score with plain-language XAI rationale."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS Configuration
#
# IMPORTANT: Starlette's CORSMiddleware does NOT evaluate glob patterns.
# "chrome-extension://*" is treated as a literal string and will reject every
# real extension request. Use ["*"] during local development.
#
# Before Week 5 Render.com deployment, replace "*" with the specific
# extension origin visible at chrome://extensions after loading unpacked:
#   allow_origins=["chrome-extension://YOUR_EXTENSION_ID_HERE"]
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(health_router, prefix="/api/v1")


# ---------------------------------------------------------------------------
# Stub Analysis Endpoint
# TODO(Milestone 2.x): Replace this inline stub by mounting the modular
# router from routes/analyze.py:
#
#   from routes.analyze import router as analyze_router
#   app.include_router(analyze_router, prefix="/api/v1")
#
# Do NOT leave both the stub route and the mounted router active
# simultaneously — FastAPI will raise a route registration conflict.
# ---------------------------------------------------------------------------
@app.post("/api/v1/analyze")
async def analyze_stub(payload: dict) -> dict:
    """
    Week 1 developer skeleton stub.
    Returns a placeholder response so the Chrome Extension can confirm
    end-to-end connectivity before the real analysis pipeline is wired.
    """
    return {"status": "stub", "mode": "DEV_SKELETON"}
