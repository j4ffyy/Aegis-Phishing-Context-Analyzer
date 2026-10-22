"""
Aegis: AI-Powered Phishing Context Analyzer
Component: FastAPI Application Entry Point

Responsibilities:
- Application lifecycle management via lifespan context manager.
- CORS policy enforcement (dev: wildcard, prod: locked to extension origin).
- Route registration for health and analysis endpoints.
"""

from contextlib import asynccontextmanager

import logging
import os

from dotenv import load_dotenv

# Silence non-critical HuggingFace transformers PyTorch detection notice
# Aegis uses ONNX Runtime for CPU inference and only requires transformers for tokenization.
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from modules.link_scanner import load_vt_seed_cache
from modules.nlp_classifier import warm_up_nlp
from routes.analyze import router as analyze_router
from routes.health import router as health_router

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PR-07: Environment-Driven CORS Configuration
#
# CORS origin is controlled by two environment variables:
#
#   CORS_ORIGIN   — The exact Chrome Extension origin to allow in production.
#                   Format: chrome-extension://<32-char-extension-id>
#                   Obtain from chrome://extensions after loading the extension.
#
#   ENVIRONMENT   — Runtime environment tag. Set to "production" on Render.com.
#                   Any value other than "production" enables the open wildcard
#                   fallback for local development convenience.
#
# Resolution priority:
#   1. If CORS_ORIGIN is explicitly set  → use it (regardless of ENVIRONMENT).
#   2. Elif ENVIRONMENT == "production"  → raise a RuntimeError (unsafe to run
#      production without an explicit origin).
#   3. Otherwise (local / dev)           → allow_origins=["*"] (open wildcard).
#
# NOTE: Starlette's CORSMiddleware does NOT support glob patterns.
#       "chrome-extension://*" is treated as a literal string and would reject
#       every real extension request. Always use the exact extension ID.
# ---------------------------------------------------------------------------

_CORS_ORIGIN_ENV    = os.getenv("CORS_ORIGIN", "").strip()
_ENVIRONMENT        = os.getenv("ENVIRONMENT", "development").strip().lower()
RENDER_BACKEND_URL  = "https://aegis-backend.onrender.com"  # PR-07: canonical production URL

if _CORS_ORIGIN_ENV:
    # Explicit origin configured — strict production lockdown.
    _CORS_ORIGINS: list = [_CORS_ORIGIN_ENV]
    _CORS_MODE = f"PRODUCTION LOCKDOWN → {_CORS_ORIGIN_ENV}"
elif _ENVIRONMENT == "production":
    # Production flag set but no origin provided — fail loudly rather than
    # silently opening the wildcard in a deployed environment.
    raise RuntimeError(
        "[Aegis] ENVIRONMENT=production but CORS_ORIGIN is not set. "
        "Set CORS_ORIGIN=chrome-extension://<your-extension-id> in "
        "Render.com environment variables before deploying."
    )
else:
    # Local / development — open wildcard for convenience.
    _CORS_ORIGINS = ["*"]
    _CORS_MODE = "DEVELOPMENT (wildcard '*')"


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
    logger.info("[Aegis] CORS mode: %s", _CORS_MODE)
    logger.info("[Aegis] Render backend: %s", RENDER_BACKEND_URL)
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
# CORS Middleware — origin list resolved above based on env configuration (PR-07)
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(health_router, prefix="/api/v1")
app.include_router(analyze_router, prefix="/api/v1")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Silence browser favicon requests without generating 404 logs."""
    from fastapi import Response
    return Response(status_code=204)
