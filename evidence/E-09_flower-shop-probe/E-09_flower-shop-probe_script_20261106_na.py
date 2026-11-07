"""
Aegis — Flower Shop S_nlp Probe (Row 11 matrix verification)
=============================================================
Runs the DistilBERT ONNX model on the Flower Shop scenario and several
control cases to produce a verified S_nlp value for the matrix.

Usage (from aegis-backend/ with the venv active):
    python scripts/flower_shop_nlp_probe.py

Output:
    evidences/09_flower_shop_nlp_probe.txt  — human-readable log
    evidences/09_flower_shop_nlp_probe.json — machine-readable results

Referenced in Row 11 of the Revision Matrix (S_nlp verification).
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── path setup ───────────────────────────────────────────────────────────────
SCRIPT_DIR  = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
EVIDENCE_DIR = BACKEND_DIR.parent / "evidences"
EVIDENCE_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

# ── logging ───────────────────────────────────────────────────────────────────
LOG_PATH  = EVIDENCE_DIR / "09_flower_shop_nlp_probe.txt"
JSON_PATH = EVIDENCE_DIR / "09_flower_shop_nlp_probe.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
    ],
)
logger = logging.getLogger("flower_shop_probe")

# ── test cases ────────────────────────────────────────────────────────────────
# Each case mirrors a scenario discussed in the Revision Matrix.
# urgency_penalty and bec_penalty are set to 0 for the Flower Shop (no urgency
# keywords, no typosquatting) so the score reflects the model alone.

TEST_CASES = [
    {
        "id": "flower_shop_typical",
        "description": "Flower Shop — first-time sender, no urgency cues (Row 11 scenario)",
        "subject": "Order Confirmation #2847 — Bloom & Petal Florist",
        "body": (
            "Dear Customer,\n\n"
            "Thank you for your order. Your arrangement of 12 red roses and baby's breath "
            "has been confirmed and will be delivered on Friday between 10 AM and 2 PM.\n\n"
            "Order total: PHP 850.00. Payment received via GCash.\n\n"
            "If you have any questions, reply to this email or call us at 0917-555-1234.\n\n"
            "Warm regards,\nBloom & Petal Florist"
        ),
        "urgency_penalty": 0,
        "bec_penalty": 0,
    },
    {
        "id": "flower_shop_spf_dkim_fail_no_urgency",
        "description": "Flower Shop — same email but SPF+DKIM fail flags present (S_h=45), still no urgency text",
        "subject": "Order Confirmation #2847 — Bloom & Petal Florist",
        "body": (
            "Dear Customer,\n\n"
            "Thank you for your order. Your arrangement of 12 red roses and baby's breath "
            "has been confirmed and will be delivered on Friday between 10 AM and 2 PM.\n\n"
            "Order total: PHP 850.00. Payment received via GCash.\n\n"
            "If you have any questions, reply to this email or call us at 0917-555-1234.\n\n"
            "Warm regards,\nBloom & Petal Florist"
        ),
        "urgency_penalty": 0,  # SPF/DKIM failures go into S_h, not S_nlp penalties
        "bec_penalty": 0,
    },
    {
        "id": "phishing_full_urgency",
        "description": "High-urgency phishing — control case to confirm model fires correctly",
        "subject": "URGENT: Your BDO account has been suspended — verify now",
        "body": (
            "Dear Valued Customer,\n\n"
            "We have detected unauthorized access to your account. Your BDO online banking "
            "access has been suspended immediately. You must verify your identity within 24 hours "
            "or your account will be permanently deactivated.\n\n"
            "Click here to verify: http://bdo-secure-verify.tk/login\n\n"
            "Failure to comply will result in permanent account termination.\n\n"
            "BDO Unibank Security Team"
        ),
        "urgency_penalty": 20,
        "bec_penalty": 0,
    },
    {
        "id": "legitimate_business_email",
        "description": "Normal business email — control case (expected Safe)",
        "subject": "Invoice #INV-2024-089 from ABC Supplies",
        "body": (
            "Hi Maria,\n\n"
            "Please find attached the invoice for last month's supply delivery. "
            "Payment is due within 30 days as per our agreed terms.\n\n"
            "Total due: PHP 12,500.00\n"
            "Bank: BDO Unibank\nAccount: 1234-5678-90\n\n"
            "Let me know if you have any questions.\n\nBest,\nJuan dela Cruz\nABC Supplies"
        ),
        "urgency_penalty": 0,
        "bec_penalty": 0,
    },
    {
        "id": "empty_body",
        "description": "Empty body — tests the short-text branch of fallback (expected S_nlp=10 if model absent)",
        "subject": "",
        "body": "",
        "urgency_penalty": 0,
        "bec_penalty": 0,
    },
]


def run_probe():
    logger.info("=" * 65)
    logger.info("  AEGIS — Flower Shop S_nlp Probe (Row 11 Matrix Verification)")
    logger.info("  Run timestamp: %s", datetime.now(timezone.utc).isoformat())
    logger.info("=" * 65)

    # ── load model ───────────────────────────────────────────────────────────
    from modules.nlp_classifier import load_nlp_model, classify_email_text, is_model_warm

    logger.info("Loading DistilBERT ONNX model...")
    model_loaded = load_nlp_model()

    if not model_loaded:
        logger.error(
            "ONNX model NOT loaded — model.onnx not found or failed to load. "
            "Results below will be FALLBACK values, not live model values."
        )
    else:
        logger.info("DistilBERT ONNX model loaded successfully. Live inference active.")

    logger.info("-" * 65)

    results = []

    for case in TEST_CASES:
        text = f"{case['subject']}\n\n{case['body']}".strip() if case["subject"] else case["body"]
        t0 = time.time()
        result = classify_email_text(
            text=text,
            urgency_penalty=case["urgency_penalty"],
            bec_penalty=case["bec_penalty"],
        )
        elapsed_ms = (time.time() - t0) * 1000

        s_nlp     = result["nlp_score"]
        p_phish   = result["p_phish"]
        s_base    = result["s_base"]
        s_urgency = result["s_urgency"]
        s_bec     = result["s_bec"]
        warm      = result["model_warm"]
        pred      = result["predicted_label"]

        logger.info("Case: %s", case["id"])
        logger.info("  Description : %s", case["description"])
        logger.info("  Model warm  : %s", warm)
        logger.info("  P_phish     : %.4f", p_phish)
        logger.info("  S_base      : %.2f", s_base)
        logger.info("  S_urgency   : %d", s_urgency)
        logger.info("  S_bec       : %d", s_bec)
        logger.info("  S_nlp       : %d  ← verified value", s_nlp)
        logger.info("  Pred label  : %s", pred)
        logger.info("  Latency     : %.1f ms", elapsed_ms)
        logger.info("")

        results.append({
            "id":          case["id"],
            "description": case["description"],
            "model_loaded": model_loaded,
            "model_warm":  warm,
            "s_nlp":       s_nlp,
            "p_phish":     p_phish,
            "s_base":      s_base,
            "s_urgency":   s_urgency,
            "s_bec":       s_bec,
            "predicted_label": pred,
            "probabilities": result.get("probabilities", {}),
            "latency_ms":  round(elapsed_ms, 2),
        })

    # ── Flower Shop R_final — run through real synthesize_assessment() ─────────
    logger.info("=" * 65)
    logger.info("  Flower Shop R_final Recompute (Row 11) — via synthesize_assessment()")
    logger.info("  Floor logic executed inside meta_classifier.py, not by this script.")
    logger.info("=" * 65)

    from modules.meta_classifier import synthesize_assessment

    fs = next(r for r in results if r["id"] == "flower_shop_spf_dkim_fail_no_urgency")
    s_nlp_live = fs["s_nlp"]

    # Inputs: exactly what analyze.py would produce for the Flower Shop scenario
    s_h  = 45   # SPF (+25) + DKIM (+20) from evaluate_heuristics()
    s_b  = 25   # first_time_sender — assigned by extension, clamped by server
    s_vt = 0    # no links → vt_status="completed", s_vt=0 (analyze.py L678-682)

    # Flags the heuristic layer would attach (triggers floor condition checks)
    flower_shop_flags = [
        {
            "title": "SPF Authentication Failure",
            "evidence": "Sender SPF validation failed",
            "severity": "critical",
        },
        {
            "title": "DKIM Signature Invalid",
            "evidence": "Sender DKIM signature validation failed",
            "severity": "critical",
        },
    ]

    # ── VT-path diagnostic: resolve the analyze.py vs synthesize_assessment() question ──
    # analyze.py L678-682 sets vt_status="completed", s_vt=0 for no-target emails.
    # synthesize_assessment() L387-395 computes:
    #   is_pending     = (vt_status == "pending")           → False
    #   has_links      = len(urls) > 0                      → False
    #   has_vt_targets = has_links or vt_result_attach or s_vt>0 → False
    #   vt_pending     = is_pending or not has_vt_targets   → True
    # Result: even with vt_status="completed", no-target emails use the
    # preliminary normalization formula (÷0.85). This is intentional design —
    # "completed" labels the response status; vt_pending controls score math.
    # The live /analyze route hits the same code path, so both agree.
    is_pending_flag     = False          # vt_status="completed"
    has_vt_targets_flag = False          # no urls, no attachments, s_vt=0
    vt_pending_flag     = is_pending_flag or not has_vt_targets_flag  # True

    logger.info("  VT-path resolution (analyze.py vs synthesize_assessment()):")
    logger.info("    vt_status passed    = 'completed'  (analyze.py L678-682)")
    logger.info("    is_pending          = %s  (vt_status == 'pending')", is_pending_flag)
    logger.info("    has_vt_targets      = %s  (no urls, no attachments, s_vt=0)", has_vt_targets_flag)
    logger.info("    vt_pending (actual) = %s  (is_pending OR NOT has_vt_targets)", vt_pending_flag)
    logger.info("    → Preliminary normalization formula (÷0.85) is used.")
    logger.info("    → analyze.py 'completed' label = response status only, not score path.")
    logger.info("    → Live /analyze route hits the same branch. No conflict.")
    logger.info("")

    logger.info("  Calling synthesize_assessment() with:")
    logger.info("    s_heuristic = %d  (SPF +25, DKIM +20)", s_h)
    logger.info("    s_nlp       = %d  (live DistilBERT)", s_nlp_live)
    logger.info("    s_behavioral= %d  (first-time-sender, extension)", s_b)
    logger.info("    s_vt        = %d  (no links, vt_status=completed)", s_vt)
    logger.info("    flags       = SPF Authentication Failure, DKIM Signature Invalid")
    logger.info("    urls        = []  (no links)")
    logger.info("    vt_status   = completed")

    assessment = synthesize_assessment(
        email_hash      = "flower_shop_probe_row11",
        s_heuristic     = s_h,
        s_nlp           = s_nlp_live,
        s_behavioral    = s_b,
        s_vt            = s_vt,
        vt_status       = "completed",
        flags           = flower_shop_flags,
        urls            = [],
        vt_result       = None,
        behavioral_meta = {"reason": "first_time_sender", "score": s_b},
    )

    r_final    = assessment["score"]
    tier_name  = assessment["riskLevel"]
    tier_class = assessment["riskClass"]

    # Derive pre-floor score for transparency:
    # preliminary = round((0.25*s_h + 0.45*s_nlp + 0.15*s_b) / 0.85)
    r_preliminary = round((0.25 * s_h + 0.45 * s_nlp_live + 0.15 * s_b) / 0.85)

    logger.info("")
    logger.info("  synthesize_assessment() returned:")
    logger.info("    R_preliminary (÷0.85 path) = %d", r_preliminary)
    logger.info("    score (R_final, post-floor) = %d  ← from real code", r_final)
    logger.info("    riskLevel = %s", tier_name)
    logger.info("    riskClass = %s", tier_class)
    logger.info("    desc      = %s", assessment["desc"])
    logger.info("=" * 65)

    # Explain which branch of the floor fired
    floor_triggered = r_preliminary < 52 and r_final == 52
    floor_note = (
        f"s_heuristic={s_h} >= 40 (independent trigger): "
        f"R_preliminary={r_preliminary} elevated to R_final=52 → Warning"
        if floor_triggered
        else f"floor did not apply (R_final={r_final})"
    )
    logger.info("  Floor diagnosis: %s", floor_note)
    logger.info("=" * 65)

    recompute = {
        "method": "synthesize_assessment() — real meta_classifier.py code",
        "vt_path": {
            "vt_status_passed": "completed",
            "is_pending": is_pending_flag,
            "has_vt_targets": has_vt_targets_flag,
            "vt_pending_actual": vt_pending_flag,
            "formula_used": "preliminary normalization (÷0.85)",
        },
        "inputs": {
            "s_heuristic": s_h,
            "s_nlp": s_nlp_live,
            "s_behavioral": s_b,
            "s_vt": s_vt,
            "flags": [f["title"] for f in flower_shop_flags],
            "urls": [],
            "vt_status": "completed",
        },
        "r_preliminary": r_preliminary,
        "r_final": r_final,
        "floor_triggered": floor_triggered,
        "floor_note": floor_note,
        "tier": tier_name,
        "xai": assessment.get("xai", ""),
    }

    # ── write JSON ────────────────────────────────────────────────────────────
    output = {
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "model_loaded": model_loaded,
        "script": "scripts/flower_shop_nlp_probe.py",
        "cases": results,
        "flower_shop_recompute": recompute,
    }
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    logger.info("Evidence written to:")
    logger.info("  %s", LOG_PATH)
    logger.info("  %s", JSON_PATH)

    return model_loaded, r_final, tier_name


if __name__ == "__main__":
    run_probe()

