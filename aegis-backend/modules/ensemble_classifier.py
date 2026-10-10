"""
Aegis: AI-Powered Phishing Context Analyzer
Module: Ensemble ML Classifier (Layer 1 Augmentation)
Spec: Capstone 2 Paper §4.3 Layer 1, Implementation Plan Recommendation 1

Loads pre-trained Random Forest and XGBoost models (serialized with joblib) and
scores email payloads using URL-pattern and linguistic feature vectors.

The ensemble score (S_ensemble) is blended with the existing rule-based heuristic
score (S_heuristic) to form a strengthened Layer 1 signal:

    S_layer1_final = 0.60 * S_heuristic + 0.40 * S_ensemble

If model files are absent (i.e., train_ensemble.py has not been run yet), the
module degrades gracefully: S_ensemble = 0, layer 1 runs purely on rule-based heuristics.

Model Files (relative to aegis-backend/):
    models/ensemble_rf.pkl   — Random Forest classifier (joblib)
    models/ensemble_xgb.pkl  — XGBoost classifier (joblib)

Feature Vector (17 features, in order):
    URL features (8):
        0  url_count              — number of extracted URLs
        1  ip_url_present         — 1 if any URL uses a raw IP host
        2  suspicious_tld         — 1 if any URL TLD in blocklist
        3  max_url_length         — length of longest URL
        4  subdomain_depth_max    — max subdomain depth across all URLs
        5  at_symbol_in_url       — 1 if any URL contains @
        6  double_slash_redirect  — 1 if any URL contains //redirect pattern
        7  port_in_url            — 1 if any URL specifies a non-standard port

    Linguistic / structural features (9):
        8  urgency_keyword_count  — total urgency keyword hits
        9  has_typosquatting      — 1 if brand typosquatting was detected
        10 body_length            — character length of body text
        11 subject_length         — character length of subject line
        12 html_link_count        — number of hyperlinks in body
        13 has_attachment         — 1 if attachments present
        14 attachment_count       — total attachment count
        15 has_dangerous_ext      — 1 if any dangerous attachment extension
        16 spf_fail               — 1 if SPF explicitly failed (False), 0 otherwise
"""

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODELS_DIR = Path(__file__).parent.parent / "models"
RF_MODEL_PATH = MODELS_DIR / "ensemble_rf.pkl"
XGB_MODEL_PATH = MODELS_DIR / "ensemble_xgb.pkl"

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",  # free abuse-prone TLDs
    "xyz", "top", "click", "link", "online", "site",
    "icu", "buzz", "cam", "loan", "win", "download",
    "work", "party", "date", "men", "review",
}

_rf_model = None
_xgb_model = None
_models_loaded = False
_models_unavailable = False  # set True after first failed load attempt


# ---------------------------------------------------------------------------
# Model Loading (lazy, once)
# ---------------------------------------------------------------------------

def _load_models() -> None:
    """Attempts to load serialized joblib model files. Called once on first use."""
    global _rf_model, _xgb_model, _models_loaded, _models_unavailable

    if _models_loaded or _models_unavailable:
        return

    try:
        import joblib  # noqa: PLC0415

        if RF_MODEL_PATH.exists() and XGB_MODEL_PATH.exists():
            _rf_model = joblib.load(RF_MODEL_PATH)
            _xgb_model = joblib.load(XGB_MODEL_PATH)
            _models_loaded = True
            logger.info(
                "[EnsembleClassifier] Models loaded — RF: %s, XGB: %s",
                RF_MODEL_PATH.name,
                XGB_MODEL_PATH.name,
            )
        else:
            missing = []
            if not RF_MODEL_PATH.exists():
                missing.append(str(RF_MODEL_PATH))
            if not XGB_MODEL_PATH.exists():
                missing.append(str(XGB_MODEL_PATH))
            logger.warning(
                "[EnsembleClassifier] Model files not found: %s. "
                "Run scripts/train_ensemble.py to train. "
                "Layer 1 will use rule-based heuristics only.",
                ", ".join(missing),
            )
            _models_unavailable = True

    except ImportError:
        logger.warning(
            "[EnsembleClassifier] joblib not installed. "
            "Layer 1 will use rule-based heuristics only."
        )
        _models_unavailable = True
    except Exception as exc:  # noqa: BLE001
        logger.error("[EnsembleClassifier] Failed to load models: %s", exc)
        _models_unavailable = True


# ---------------------------------------------------------------------------
# Feature Extraction
# ---------------------------------------------------------------------------

def _extract_features(
    urls: List[str],
    subject: str,
    body: str,
    urgency_keyword_count: int,
    has_typosquatting: bool,
    has_attachment: bool,
    attachment_count: int,
    attachments: List[str],
    spf_pass: Optional[bool],
) -> List[float]:
    """
    Builds the 17-element feature vector from email payload fields.
    All features are numeric (int or float) for scikit-learn / XGBoost compatibility.
    """
    # --- URL features ---
    url_count = len(urls)
    ip_url_present = 0
    suspicious_tld = 0
    max_url_length = 0
    subdomain_depth_max = 0
    at_symbol_in_url = 0
    double_slash_redirect = 0
    port_in_url = 0

    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

    for raw_url in urls:
        try:
            parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
            hostname = parsed.hostname or ""
            path = parsed.path or ""

            # IP-host URL
            if ip_pattern.match(hostname):
                ip_url_present = 1

            # Suspicious TLD
            tld = hostname.split(".")[-1].lower() if "." in hostname else ""
            if tld in SUSPICIOUS_TLDS:
                suspicious_tld = 1

            # URL length
            max_url_length = max(max_url_length, len(raw_url))

            # Subdomain depth
            parts = hostname.split(".")
            depth = max(0, len(parts) - 2)
            subdomain_depth_max = max(subdomain_depth_max, depth)

            # @ symbol (credential theft obfuscation)
            if "@" in raw_url:
                at_symbol_in_url = 1

            # Double-slash redirect pattern
            if "//" in path:
                double_slash_redirect = 1

            # Non-standard port
            if parsed.port and parsed.port not in (80, 443):
                port_in_url = 1

        except Exception:  # noqa: BLE001
            pass

    # --- Linguistic / structural features ---
    DANGEROUS_EXTS = {
        "exe", "scr", "vbs", "iso", "bat", "cmd",
        "js", "wsf", "ps1", "html", "htm", "hta", "apk",
    }
    has_dangerous_ext = int(
        any(
            att.split(".")[-1].lower() in DANGEROUS_EXTS
            for att in attachments
            if "." in att
        )
    )
    spf_fail = 1 if spf_pass is False else 0

    return [
        float(url_count),
        float(ip_url_present),
        float(suspicious_tld),
        float(max_url_length),
        float(subdomain_depth_max),
        float(at_symbol_in_url),
        float(double_slash_redirect),
        float(port_in_url),
        float(urgency_keyword_count),
        float(int(has_typosquatting)),
        float(len(body)),
        float(len(subject)),
        float(url_count),           # html_link_count ≈ url_count at extraction stage
        float(int(has_attachment)),
        float(attachment_count),
        float(has_dangerous_ext),
        float(spf_fail),
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_with_ensemble(
    urls: List[str],
    subject: str,
    body: str,
    urgency_keyword_count: int,
    has_typosquatting: bool,
    has_attachment: bool,
    attachment_count: int,
    attachments: List[str],
    spf_pass: Optional[bool],
) -> Dict[str, Any]:
    """
    Scores an email payload using the pre-trained RF + XGB ensemble.

    Returns a dict with:
        ensemble_score  (int, 0-100) — blended phishing probability converted to score
        ensemble_used   (bool)       — True if model files were loaded successfully
        rf_prob         (float|None) — RF P(phishing) [0-1]
        xgb_prob        (float|None) — XGB P(phishing) [0-1]

    If models are unavailable, returns ensemble_score=0, ensemble_used=False.
    """
    _load_models()

    if not _models_loaded:
        return {
            "ensemble_score": 0,
            "ensemble_used": False,
            "rf_prob": None,
            "xgb_prob": None,
        }

    features = _extract_features(
        urls=urls,
        subject=subject,
        body=body,
        urgency_keyword_count=urgency_keyword_count,
        has_typosquatting=has_typosquatting,
        has_attachment=has_attachment,
        attachment_count=attachment_count,
        attachments=attachments,
        spf_pass=spf_pass,
    )

    try:
        import numpy as np  # noqa: PLC0415

        X = np.array([features], dtype=np.float32)

        # Random Forest — probability of phishing class (index 1)
        rf_proba = _rf_model.predict_proba(X)[0]
        rf_phish_prob = float(rf_proba[1]) if len(rf_proba) > 1 else float(rf_proba[0])

        # XGBoost — probability of phishing class
        xgb_proba = _xgb_model.predict_proba(X)[0]
        xgb_phish_prob = float(xgb_proba[1]) if len(xgb_proba) > 1 else float(xgb_proba[0])

        # Average ensemble probability
        avg_prob = (rf_phish_prob + xgb_phish_prob) / 2.0

        # Convert probability to 0-100 score (same piecewise logic as NLP layer)
        if avg_prob > 0.50:
            raw_score = 60 * avg_prob
        else:
            raw_score = 10 * (1 - avg_prob)

        ensemble_score = min(100, max(0, round(raw_score)))

        logger.debug(
            "[EnsembleClassifier] rf=%.3f xgb=%.3f avg=%.3f → score=%d",
            rf_phish_prob, xgb_phish_prob, avg_prob, ensemble_score,
        )

        return {
            "ensemble_score": ensemble_score,
            "ensemble_used": True,
            "rf_prob": rf_phish_prob,
            "xgb_prob": xgb_phish_prob,
        }

    except Exception as exc:  # noqa: BLE001
        logger.error("[EnsembleClassifier] Inference error: %s", exc)
        return {
            "ensemble_score": 0,
            "ensemble_used": False,
            "rf_prob": None,
            "xgb_prob": None,
        }
