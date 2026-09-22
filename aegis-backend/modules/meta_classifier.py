"""
Aegis: AI-Powered Phishing Context Analyzer
Module: Meta-Classifier Risk Synthesis & Explainable AI (XAI) Generator
Specification: Implementation Plan §6.1, §6.5, §6.6 (Milestone 3.4)

Synthesizes the 4 analytical defense layers:
    - Layer 1: Heuristic Syntactic & Domain Spoof Detection ($S_{heuristic}$, weight=0.25)
    - Layer 2: DistilBERT NLP Semantic Intent Classification ($S_{nlp}$, weight=0.45)
    - Layer 3: Behavioral Baseline & Temporal Circadian Anomaly ($S_{behavioral}$, weight=0.15)
    - Layer 4: VirusTotal Real-Time URL Threat Intelligence ($S_{vt}$, weight=0.15)
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Empirical Weights Formulation (§6.1)
# ---------------------------------------------------------------------------

WEIGHT_HEURISTIC: float = 0.25
WEIGHT_NLP: float = 0.45
WEIGHT_BEHAVIORAL: float = 0.15
WEIGHT_VT: float = 0.15

# Preliminary normalization factor when VirusTotal background scan is pending (0.25 + 0.45 + 0.15 = 0.85)
ACTIVE_PRELIMINARY_WEIGHT_SUM: float = WEIGHT_HEURISTIC + WEIGHT_NLP + WEIGHT_BEHAVIORAL

# Categorical Risk Tier Cutoffs (§6.6)
TIER_SAFE_MAX: int = 44        # Score < 45 -> Safe
TIER_WARNING_MAX: int = 74     # Score 45-74 -> Warning
                               # Score >= 75 -> Critical


# ---------------------------------------------------------------------------
# Composite Score Synthesis (§6.1)
# ---------------------------------------------------------------------------

def clamp_score(score: float) -> int:
    """Clamps a numeric score strictly to integer bounds [0, 100]."""
    return max(0, min(100, int(round(score))))


def synthesize_composite_score(
    s_heuristic: int,
    s_nlp: int,
    s_behavioral: int,
    s_vt: int,
    vt_pending: bool = False,
    critical_floor: bool = False,
) -> int:
    """
    Computes the composite risk score R_final in [0, 100] per §6.1:
    R_final = min(100, round(0.25 * S_h + 0.45 * S_nlp + 0.15 * S_b + 0.15 * S_vt))

    When VirusTotal is pending background completion, scales over the active weights (sum = 0.85):
    R_preliminary = min(100, round((0.25 * S_h + 0.45 * S_nlp + 0.15 * S_b) / 0.85))

    Critical Threat Floor (§6.5):
    If critical_floor is True and VirusTotal confirms malicious links (S_vt >= 50),
    the score is bounded by a minimum threshold of 75 to prevent severe external malware from being diluted.
    """
    s_h = clamp_score(s_heuristic)
    s_nlp = clamp_score(s_nlp)
    s_b = clamp_score(s_behavioral)
    s_vt = clamp_score(s_vt)

    if vt_pending:
        raw_score = (
            WEIGHT_HEURISTIC * s_h
            + WEIGHT_NLP * s_nlp
            + WEIGHT_BEHAVIORAL * s_b
        ) / ACTIVE_PRELIMINARY_WEIGHT_SUM
        final_score = clamp_score(raw_score)
    else:
        raw_score = (
            WEIGHT_HEURISTIC * s_h
            + WEIGHT_NLP * s_nlp
            + WEIGHT_BEHAVIORAL * s_b
            + WEIGHT_VT * s_vt
        )
        final_score = clamp_score(raw_score)

        # Enforce Critical Threat Floor if external link scanner confirmed malicious payload
        if critical_floor and s_vt >= 50 and final_score < 75:
            logger.info(
                "[MetaClassifier] Elevating score %d -> 75 due to confirmed malicious link (S_vt=%d)",
                final_score,
                s_vt,
            )
            final_score = 75

    return final_score


# ---------------------------------------------------------------------------
# Risk Classification Mapping (§6.6)
# ---------------------------------------------------------------------------

def derive_risk_tier(score: int) -> Tuple[str, str, str]:
    """
    Categorizes continuous composite score R_final into categorical risk tier:
        - Safe (< 45%): Standard display; informational overlay available.
        - Warning (45% - 74%): Amber alert requiring scrutiny of sender/links.
        - Critical (>= 75%): Crimson alert requiring explicit user confirmation.

    Returns:
        (riskLevel, riskClass, description)
    """
    bounded = clamp_score(score)
    if bounded <= TIER_SAFE_MAX:
        return (
            "Safe",
            "risk-safe",
            "No significant threats detected. Standard communication pattern.",
        )
    elif bounded <= TIER_WARNING_MAX:
        return (
            "Warning",
            "risk-warning",
            "Suspicious characteristics detected. Exercise caution before opening links or attachments.",
        )
    else:
        return (
            "Critical",
            "risk-critical",
            "High-probability phishing attempt detected. Do not click links, send funds, or disclose credentials.",
        )


# ---------------------------------------------------------------------------
# Explainable AI (XAI) Rationale Generation (§6.1, §6.6)
# ---------------------------------------------------------------------------

def generate_xai_rationale(
    risk_level: str,
    flags: List[Dict[str, Any]],
    s_heuristic: int,
    s_nlp: int,
    s_behavioral: int,
    s_vt: int,
    vt_status: str,
    links_count: int,
    behavioral_meta: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generates plain-language, multi-factor Explainable AI rationale synthesizing
    all 4 analytical defense layers into actionable guidance for SME employees.
    """
    evidence_points: List[str] = []

    # 1. Syntactic & Domain Flags (Layer 1)
    if flags:
        flag_summaries = []
        for f in flags[:3]:
            title = f.get("title", "")
            evidence = f.get("evidence", "")
            if evidence:
                flag_summaries.append(f"{title} ({evidence})")
            elif title:
                flag_summaries.append(title)
        if flag_summaries:
            evidence_points.append(f"Syntactic indicators flagged: {'; '.join(flag_summaries)}.")

    # 2. NLP Semantic Intent (Layer 2)
    if s_nlp >= 60:
        evidence_points.append(
            "DistilBERT neural semantic classification identified patterns indicative of credential harvesting, coercion, or financial urgency."
        )
    elif s_nlp >= 35:
        evidence_points.append(
            "NLP semantic analysis flagged elevated urgency or persuasive phrasing."
        )

    # 3. Behavioral Baseline (Layer 3)
    b_reason = (behavioral_meta or {}).get("reason", "")
    b_dist = (behavioral_meta or {}).get("minCircularDistanceH")
    if s_behavioral == 20 or b_reason == "off_hours_anomaly":
        dist_str = f" ({b_dist}h circular deviation)" if b_dist is not None else ""
        evidence_points.append(
            f"Sender interaction deviated significantly from historical schedule{dist_str}, indicating an off-hours communication anomaly."
        )
    elif s_behavioral == 25 or b_reason == "first_time_sender":
        evidence_points.append("First-time sender: No prior communication history exists in local baseline.")
    elif s_behavioral == 15 or b_reason == "unfamiliar_sender":
        evidence_points.append("Unfamiliar sender with limited past interaction history.")

    # 4. Link & VirusTotal Intelligence (Layer 4)
    if vt_status == "pending":
        evidence_points.append(
            f"VirusTotal is actively analyzing {links_count} external hyperlink destination(s) under rate-paced scanning."
        )
    elif s_vt >= 50:
        mal_count = max(1, s_vt // 50)
        evidence_points.append(
            f"VirusTotal threat intelligence confirmed {mal_count} malicious or phishing URL destination(s)."
        )
    elif links_count > 0:
        evidence_points.append(
            f"All {links_count} external hyperlink destination(s) were verified clean by threat intelligence."
        )

    # 5. Composite Tier Synthesis & Recommendation
    findings_body = " ".join(evidence_points).strip()

    if risk_level == "Safe":
        if not findings_body:
            return (
                "This email follows standard communication patterns. No deceptive URLs, authentication failures, "
                "or coercive urgency triggers were detected across analytical layers."
            )
        return (
            f"Aegis evaluated this email as Safe. {findings_body} Communication aligns with nominal operational baselines."
        )
    elif risk_level == "Warning":
        rec = "Exercise caution. Verify the sender's identity through an independent channel before clicking links or executing requested actions."
        if findings_body:
            return f"Aegis detected suspicious characteristics requiring verification. {findings_body} {rec}"
        return f"Aegis detected potential anomalies requiring verification. {rec}"
    else:  # Critical
        rec = "Aegis strongly advises blocking this communication. Do not click links, provide credentials, or transfer funds."
        if findings_body:
            return f"CRITICAL SECURITY ALERT: High-confidence phishing indicators confirmed across analytical layers. {findings_body} {rec}"
        return f"CRITICAL SECURITY ALERT: High-confidence phishing indicators confirmed. {rec}"


# ---------------------------------------------------------------------------
# Layer Status Breakdown for Overlay (§6.1, §6.6)
# ---------------------------------------------------------------------------

def build_layers_status(
    s_heuristic: int,
    s_nlp: int,
    s_behavioral: int,
    s_vt: int,
    vt_status: str,
    flags: List[Dict[str, Any]],
    urls: List[str],
    vt_result: Optional[Dict[str, Any]] = None,
    behavioral_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Dict[str, str]]:
    """
    Constructs the canonical 5-layer status structure utilized by the Aegis overlay
    and Full Analysis Modal (FAM).
    """
    # Layer 1: Auth & Spoofing
    auth_icon = "fa-check-circle"
    auth_detail = "Pass: Domain & identity verified"
    for f in flags:
        if "SPF" in f.get("title", "") or "DKIM" in f.get("title", ""):
            auth_icon = "fa-times-circle"
            auth_detail = f"Failed: {f.get('evidence', 'Auth validation failure')}"
            break
        elif "Spoofing" in f.get("title", "") or "Typosquatting" in f.get("title", ""):
            auth_icon = "fa-times-circle"
            auth_detail = f"Flagged: {f.get('title', 'Domain mismatch')}"
            break

    # Layer 2: Attachment Intelligence
    has_attachment_flag = any("Attachment" in f.get("title", "") for f in flags)
    if has_attachment_flag:
        attach_icon = "fa-times-circle"
        attach_detail = "Suspicious or executable attachment detected"
    elif s_heuristic >= 30:
        attach_icon = "fa-minus-circle"
        attach_detail = "Elevated heuristic risk in attachments"
    else:
        attach_icon = "fa-check-circle"
        attach_detail = "No dangerous attachment payloads detected"

    # Layer 3: Behavioral Analysis
    b_reason = (behavioral_meta or {}).get("reason", "")
    if s_behavioral == 20 or b_reason == "off_hours_anomaly":
        behavior_icon = "fa-exclamation-triangle"
        dist = (behavioral_meta or {}).get("minCircularDistanceH")
        behavior_detail = f"Off-hours anomaly: >{dist or 6}h deviation from baseline"
    elif s_behavioral == 25 or b_reason == "first_time_sender":
        behavior_icon = "fa-minus-circle"
        behavior_detail = "First-time sender: Establishing baseline"
    elif s_behavioral == 15 or b_reason == "unfamiliar_sender":
        behavior_icon = "fa-minus-circle"
        behavior_detail = "Unfamiliar sender: Limited historical records"
    else:
        behavior_icon = "fa-check-circle"
        behavior_detail = "Sender communication matches historical schedule"

    # Layer 4: Deep NLP Context & Link Threat Intelligence
    if vt_status == "pending":
        nlp_icon = "fa-spinner"
        nlp_detail = f"Scanning {len(urls)} link(s) (rate-paced VT v3)..."
    elif s_vt > 0:
        nlp_icon = "fa-times-circle"
        mal_count = vt_result.get("malicious_count", 1) if vt_result else 1
        nlp_detail = f"VirusTotal flagged {mal_count} malicious link destination(s)"
    elif urls:
        nlp_icon = "fa-check-circle"
        nlp_detail = f"{len(urls)} external hyperlink(s) verified clean"
    elif s_nlp > 20:
        nlp_icon = "fa-exclamation-triangle"
        nlp_detail = "Urgency / coercion patterns detected"
    else:
        nlp_icon = "fa-check-circle"
        nlp_detail = "Intent pattern nominal"

    return {
        "sanitization": {
            "text": "Pre-processing: HTML Sanitization",
            "detail": "Client-side PII scrubbed & HTML normalized",
            "icon": "fa-check-circle",
        },
        "auth": {
            "text": "Layer 1: Email Auth & Domain Spoofing",
            "detail": auth_detail,
            "icon": auth_icon,
        },
        "attach": {
            "text": "Layer 2: Attachment Intelligence",
            "detail": attach_detail,
            "icon": attach_icon,
        },
        "behavior": {
            "text": "Layer 3: Behavioral Analysis",
            "detail": behavior_detail,
            "icon": behavior_icon,
        },
        "nlp": {
            "text": "Layer 4: Deep NLP Context & Links",
            "detail": nlp_detail,
            "icon": nlp_icon,
        },
    }


# ---------------------------------------------------------------------------
# Complete Multi-Layer Assessment Orchestration
# ---------------------------------------------------------------------------

def synthesize_assessment(
    email_hash: str,
    s_heuristic: int,
    s_nlp: int,
    s_behavioral: int,
    s_vt: int,
    vt_status: str,
    flags: List[Dict[str, Any]],
    urls: List[str],
    vt_result: Optional[Dict[str, Any]] = None,
    behavioral_meta: Optional[Dict[str, Any]] = None,
    execution_time_ms: int = 0,
) -> Dict[str, Any]:
    """
    Orchestrates 4-layer risk synthesis, risk tier classification, XAI generation,
    and layer breakdowns into a standardized Aegis analysis dictionary.
    """
    is_pending = vt_status == "pending"
    final_score = synthesize_composite_score(
        s_heuristic=s_heuristic,
        s_nlp=s_nlp,
        s_behavioral=s_behavioral,
        s_vt=s_vt,
        vt_pending=is_pending,
        critical_floor=True,
    )

    risk_level, risk_class, desc = derive_risk_tier(final_score)

    xai = generate_xai_rationale(
        risk_level=risk_level,
        flags=flags,
        s_heuristic=s_heuristic,
        s_nlp=s_nlp,
        s_behavioral=s_behavioral,
        s_vt=s_vt,
        vt_status=vt_status,
        links_count=len(urls),
        behavioral_meta=behavioral_meta,
    )

    layers = build_layers_status(
        s_heuristic=s_heuristic,
        s_nlp=s_nlp,
        s_behavioral=s_behavioral,
        s_vt=s_vt,
        vt_status=vt_status,
        flags=flags,
        urls=urls,
        vt_result=vt_result,
        behavioral_meta=behavioral_meta,
    )

    return {
        "score": final_score,
        "riskLevel": risk_level,
        "riskClass": risk_class,
        "desc": desc,
        "layers": layers,
        "flags": flags,
        "xai": xai,
        "vt_status": vt_status,
        "emailHash": email_hash,
        "s_heuristic": s_heuristic,
        "s_nlp": s_nlp,
        "s_behavioral": s_behavioral,
        "s_vt": s_vt,
        "vt_result": vt_result or {},
        "_executionTimeMs": execution_time_ms,
    }
