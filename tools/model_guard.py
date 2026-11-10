"""
Shared Model-Loaded & Warm-Up Guard for Aegis Evaluation Harnesses.
Specification: Post-Defense Review Integrity Mandate (Item 1).

Guarantees that:
1. DistilBERT ONNX runtime session and tokenizer are actively initialized into memory.
2. An initial dummy forward pass executes, priming the session and setting _model_warm = True.
3. Asserts is_model_warm() is True, aborting immediately with exit code 1 if unprimed.
4. Returns the genuine runtime model status (bool) and model identifier (str).
"""

import sys
import logging
from pathlib import Path
from typing import Tuple

logger = logging.getLogger("aegis.model_guard")

# Resolve repository paths
REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "aegis-backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

try:
    from modules.nlp_classifier import warm_up_nlp, is_model_warm, get_model_id
except ImportError as exc:
    logger.error("Failed to import nlp_classifier module: %s", exc)
    raise


def ensure_model_loaded_and_warm(custom_dir: Path | None = None) -> Tuple[bool, str]:
    """
    Executes model warm-up, asserts model is loaded and primed, and returns (status, model_id).
    Aborts execution with SystemExit(1) if is_model_warm() is False.
    """
    warm_up_nlp(custom_dir=custom_dir)
    warm = is_model_warm()
    model_id = get_model_id()

    if not warm:
        error_msg = (
            f"FATAL MODEL GUARD FAILURE: DistilBERT model '{model_id}' reported warm=False. "
            "Evaluation harness aborted to prevent unprimed/fallback benchmark execution."
        )
        print(f"\n[ERROR] {error_msg}\n", file=sys.stderr)
        logger.critical(error_msg)
        sys.exit(1)

    print(f"[ModelGuard] DistilBERT verified loaded and warm: {warm} | Model ID: {model_id}")
    return warm, model_id


if __name__ == "__main__":
    status, mid = ensure_model_loaded_and_warm()
    print(f"Self-test: status={status}, model_id={mid}")

