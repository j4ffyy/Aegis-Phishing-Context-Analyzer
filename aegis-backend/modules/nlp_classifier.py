"""
Aegis: AI-Powered Phishing Context Analyzer
Module: NLP Classifier (DistilBERT ONNX Inference Engine)
Specification: Implementation Plan §5.2.1, §6.3 (Milestone 3.1)

Executes self-hosted DistilBERT sequence classification via ONNX Runtime
(CPUExecutionProvider) within a memory footprint < 150MB RSS.

Label mapping:
    Index 0 (LABEL_0): Legitimate Email
    Index 1 (LABEL_1): Phishing URL Context
    Index 2 (LABEL_2): Legitimate URL Context
    Index 3 (LABEL_3): Alternative Phishing Structure

Scoring formulation:
    P_phish = P(1) + P(3)
    S_base = 60 * P_phish if P_phish > 0.50 else 10 * (1 - P_phish)
    S_nlp = min(100, round(S_base + S_urgency + S_bec))
"""

import logging
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np

logger = logging.getLogger(__name__)

# Model and Tokenizer Paths
MODEL_DIR = Path(__file__).resolve().parent.parent / "models" / "phishing_distilbert"
ONNX_MODEL_FILE = MODEL_DIR / "model.onnx"
MAX_SEQUENCE_LENGTH = 512

# Class label index definitions (§6.3)
CLASS_LABELS: Dict[int, str] = {
    0: "legitimate_email",
    1: "phishing_url_context",
    2: "legitimate_url_context",
    3: "alternative_phishing",
}

# Module-level state
_session: Optional[Any] = None
_tokenizer: Optional[Any] = None
_model_warm: bool = False


# ---------------------------------------------------------------------------
# Numerically Stable Softmax Formulation (§6.3)
# ---------------------------------------------------------------------------

def softmax(logits: np.ndarray) -> np.ndarray:
    """
    Computes numerically stable softmax over logits:
        P(k) = exp(z_k - max(z)) / sum(exp(z_j - max(z)))

    Prevents floating-point overflow for large positive values and
    underflow for large negative values.
    """
    logits = np.asarray(logits, dtype=np.float32)
    shifted = logits - np.max(logits, axis=-1, keepdims=True)
    exp_vals = np.exp(shifted)
    sum_exp = np.sum(exp_vals, axis=-1, keepdims=True)
    # Avoid zero division
    sum_exp = np.where(sum_exp == 0.0, 1e-12, sum_exp)
    return exp_vals / sum_exp


# ---------------------------------------------------------------------------
# Model & Tokenizer Lifecycle Management
# ---------------------------------------------------------------------------

def load_nlp_model(custom_dir: Optional[Path] = None) -> bool:
    """
    Loads the ONNX InferenceSession and DistilBERT Tokenizer.
    Returns True if successfully loaded, False otherwise.
    """
    global _session, _tokenizer, _model_warm

    target_dir = custom_dir or MODEL_DIR
    model_path = target_dir / "model.onnx"

    if not model_path.exists():
        logger.warning(
            "[Aegis NLP] ONNX model file not found at %s. Operating in safe fallback mode.",
            model_path,
        )
        _session = None
        _tokenizer = None
        _model_warm = False
        return False

    try:
        import onnxruntime as ort
        from transformers import AutoTokenizer

        # 1. Initialize ONNX Runtime Session (CPUExecutionProvider)
        sess_options = ort.SessionOptions()
        sess_options.intra_op_num_threads = 2
        sess_options.graph_optimization_level = (
            ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        )

        _session = ort.InferenceSession(
            str(model_path),
            sess_options=sess_options,
            providers=["CPUExecutionProvider"],
        )

        # 2. Initialize fast Rust-backed Tokenizer without PyTorch
        _tokenizer = AutoTokenizer.from_pretrained(str(target_dir))

        logger.info(
            "[Aegis NLP] DistilBERT ONNX session and tokenizer loaded successfully from %s",
            target_dir.name,
        )
        return True
    except Exception as exc:
        logger.error("[Aegis NLP] Failed to load ONNX model or tokenizer: %s", exc, exc_info=True)
        _session = None
        _tokenizer = None
        _model_warm = False
        return False


def warm_up_nlp(custom_dir: Optional[Path] = None) -> None:
    """
    Executes a single dummy inference pass during FastAPI lifespan startup
    to prime the ONNX Runtime JIT compiler and tokenizer.
    Ensures subsequent real user inferences execute within ~25–50ms.
    """
    global _model_warm

    loaded = load_nlp_model(custom_dir=custom_dir)
    if not loaded or _session is None or _tokenizer is None:
        logger.info("[Aegis NLP] Warm-up completed in heuristic fallback mode (assets pending).")
        _model_warm = False
        return

    try:
        dummy_text = "Aegis security analyzer warm-up test email verification."
        classify_email_text(dummy_text)
        _model_warm = True
        logger.info("[Aegis NLP] Model warm-up successful. Ready for high-throughput inference.")
    except Exception as exc:
        logger.warning("[Aegis NLP] Dummy warm-up inference failed: %s", exc)
        _model_warm = False


def is_model_warm() -> bool:
    """Returns True if the ONNX InferenceSession has been primed and ready."""
    return _model_warm


# ---------------------------------------------------------------------------
# Inference & Risk Intent Evaluation (§6.3)
# ---------------------------------------------------------------------------

def classify_email_text(
    text: str,
    urgency_penalty: int = 0,
    bec_penalty: int = 0,
) -> Dict[str, Any]:
    """
    Classifies email text using the DistilBERT ONNX model.

    Mathematical formulation (§6.3):
        P_phish = P(1) + P(3)
        S_base = 60 * P_phish if P_phish > 0.50 else 10 * (1 - P_phish)
        S_nlp = min(100, round(S_base + S_urgency + S_bec))

    Args:
        text: Sanitized plain text of email subject + body.
        urgency_penalty: Heuristic urgency adjustment (0–20 points).
        bec_penalty: Business Email Compromise pattern adjustment (0–20 points).

    Returns:
        Structured classification dictionary.
    """
    clean_text = (text or "").strip()
    urgency_adj = max(0, min(20, int(urgency_penalty)))
    bec_adj = max(0, min(20, int(bec_penalty)))

    # Fallback mode if model assets are not loaded
    if _session is None or _tokenizer is None:
        return _fallback_classification(clean_text, urgency_adj, bec_adj)

    try:
        # 1. Tokenize input bounded to 512 tokens
        encoded = _tokenizer(
            clean_text,
            max_length=MAX_SEQUENCE_LENGTH,
            truncation=True,
            padding=True,
            return_tensors="np",
        )

        ort_inputs = {}
        for inp in _session.get_inputs():
            if inp.name in encoded:
                ort_inputs[inp.name] = np.asarray(encoded[inp.name], dtype=np.int64)

        # 2. Run ONNX inference pass
        ort_outputs = _session.run(None, ort_inputs)
        raw_logits = ort_outputs[0][0]  # Shape: (4,)

        # 3. Apply numerically stable softmax
        probs = softmax(raw_logits)

        p_0 = float(probs[0])
        p_1 = float(probs[1])
        p_2 = float(probs[2])
        p_3 = float(probs[3])

        # 4. Joint phishing probability: P_phish = P(1) + P(3)
        p_phish = float(p_1 + p_3)
        p_legitimate = float(p_0 + p_2)

        # 5. Base model score piecewise calculation (§6.3 step 4)
        if p_phish > 0.50:
            s_base = 60.0 * p_phish
        else:
            s_base = 10.0 * (1.0 - p_phish)

        # 6. Add heuristic adjustments and clamp to [0, 100]
        s_nlp = min(100, round(s_base + urgency_adj + bec_adj))

        # 7. Identify predicted label class
        pred_idx = int(np.argmax(probs))
        predicted_label = CLASS_LABELS.get(pred_idx, f"LABEL_{pred_idx}")

        return {
            "nlp_score": s_nlp,
            "p_phish": round(p_phish, 4),
            "p_legitimate": round(p_legitimate, 4),
            "probabilities": {
                "legitimate_email": round(p_0, 4),
                "phishing_url_context": round(p_1, 4),
                "legitimate_url_context": round(p_2, 4),
                "alternative_phishing": round(p_3, 4),
            },
            "predicted_label": predicted_label,
            "s_base": round(s_base, 2),
            "s_urgency": urgency_adj,
            "s_bec": bec_adj,
            "model_warm": True,
        }

    except Exception as exc:
        logger.error("[Aegis NLP] Inference error: %s. Falling back.", exc, exc_info=True)
        return _fallback_classification(clean_text, urgency_adj, bec_adj)


def _fallback_classification(
    text: str,
    urgency_adj: int,
    bec_adj: int,
) -> Dict[str, Any]:
    """Provides resilient heuristic scoring when model weights are not loaded."""
    # Basic intent estimation from text length and adjustments
    base = 20 if len(text) > 100 else 10
    total = min(100, round(base + urgency_adj + bec_adj))

    return {
        "nlp_score": total,
        "p_phish": 0.20 if total < 45 else 0.65,
        "p_legitimate": 0.80 if total < 45 else 0.35,
        "probabilities": {
            "legitimate_email": 0.80 if total < 45 else 0.35,
            "phishing_url_context": 0.10 if total < 45 else 0.40,
            "legitimate_url_context": 0.05 if total < 45 else 0.05,
            "alternative_phishing": 0.05 if total < 45 else 0.20,
        },
        "predicted_label": "legitimate_email" if total < 45 else "phishing_url_context",
        "s_base": float(base),
        "s_urgency": urgency_adj,
        "s_bec": bec_adj,
        "model_warm": False,
    }
