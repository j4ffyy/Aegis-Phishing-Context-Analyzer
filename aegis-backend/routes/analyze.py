"""
Aegis: AI-Powered Phishing Context Analyzer
Route: Phishing Risk Analysis & Asynchronous VirusTotal Polling
Specification: Implementation Plan §3.1, §5.2, §6.1-§6.6 (Milestone 2.5)

Endpoints:
    - POST /api/v1/analyze:
        Executes initial multi-layer risk evaluation within < 350ms.
        If uncached hyperlinks exist, dispatches a background task to execute
        rate-paced VirusTotal scanning and returns vt_status="pending".
        If all links are cached or no links exist, returns vt_status="completed".
    - GET /api/v1/vt-status/{email_hash}:
        Allows the frontend to poll for completion of background VirusTotal scans.
        Returns the updated synthesized risk score and plain-language XAI rationale.
"""

import asyncio
import hashlib
import logging
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from modules.link_scanner import (
    MAX_LINKS_PER_EMAIL,
    are_urls_cached,
    get_vt_analysis,
    normalize_url,
    scan_email_links,
)
from modules.meta_classifier import (
    build_layers_status,
    derive_risk_tier,
    generate_xai_rationale,
    synthesize_assessment,
    synthesize_composite_score,
)
from modules.nlp_classifier import classify_email_text

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Analysis"])

# ---------------------------------------------------------------------------
# In-Memory Analysis & Task Tracking
# ---------------------------------------------------------------------------

# In-flight task tracking: email_hash -> metadata
_in_flight_scans: Dict[str, Dict[str, Any]] = {}

# Completed full analysis store: email_hash -> full analysis response dict
_analysis_store: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Pydantic Request & Response Schemas
# ---------------------------------------------------------------------------

class EmailPayload(BaseModel):
    """Sanitized email context received from the Chrome Extension."""
    model_config = ConfigDict(populate_by_name=True)

    senderEmail: str = Field(default="", description="Sender email address")
    senderName: Optional[str] = Field(default="", description="Sender display name")
    subject: Optional[str] = Field(default="", description="Email subject line")
    bodyText: Optional[str] = Field(default="", description="Sanitized plain text body")
    links: Optional[List[Any]] = Field(default_factory=list, description="Extracted hyperlinks")
    hasAttachment: Optional[bool] = Field(default=False, description="Whether attachments are present")
    attachments: Optional[List[str]] = Field(default_factory=list, description="Attachment filenames")
    attachmentCount: Optional[int] = Field(default=0, description="Total attachment count")
    timestamp: Optional[str] = Field(default="", description="Email received timestamp")
    spfPass: Optional[bool] = Field(default=None, description="SPF authentication status")
    dkimPass: Optional[bool] = Field(default=None, description="DKIM authentication status")
    emailHash: Optional[str] = Field(default=None, description="Client-derived SHA-256 hash")
    behavioralScore: Optional[int] = Field(default=None, description="Client-side behavioral anomaly score (0-100)")
    behavioral_meta: Optional[Dict[str, Any]] = Field(default=None, alias="_behavioral", description="Client-side behavioral context details")


# ---------------------------------------------------------------------------
# Helper Functions: Hashing & URL Extraction
# ---------------------------------------------------------------------------

def compute_email_hash(payload: EmailPayload) -> str:
    """Computes deterministic SHA-256 hash matching client derivation."""
    if payload.emailHash:
        return payload.emailHash.strip().lower()

    sender = (payload.senderEmail or "").lower().strip()
    subject = (payload.subject or "").strip()
    body_sample = (payload.bodyText or "")[:300].strip()

    raw_links = []
    for item in payload.links or []:
        if isinstance(item, str):
            raw_links.append(item)
        elif isinstance(item, dict) and "url" in item:
            raw_links.append(str(item["url"]))
    links_str = ",".join(sorted(raw_links))

    attach_count = payload.attachmentCount or len(payload.attachments or [])
    raw_key = f"{sender}|{subject}|{attach_count}|{links_str}|{body_sample}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def extract_url_strings(links: List[Any]) -> List[str]:
    """Extracts URL strings from mixed list of string or dict representations."""
    urls = []
    for item in links or []:
        if isinstance(item, str) and item.strip():
            urls.append(item.strip())
        elif isinstance(item, dict) and "url" in item and str(item["url"]).strip():
            urls.append(str(item["url"]).strip())
    return urls


# ---------------------------------------------------------------------------
# Layer 1: Heuristics & Spoof Detection Engine
# ---------------------------------------------------------------------------

PROTECTED_BRANDS = [
    {"name": "BDO Unibank", "brand": "bdo", "domain": "bdo.com.ph"},
    {"name": "BPI", "brand": "bpi", "domain": "bpi.com.ph"},
    {"name": "Metrobank", "brand": "metrobank", "domain": "metrobank.com.ph"},
    {"name": "UnionBank", "brand": "unionbank", "domain": "unionbankph.com"},
    {"name": "GCash", "brand": "gcash", "domain": "gcash.com"},
    {"name": "Maya", "brand": "maya", "domain": "maya.ph"},
    {"name": "PayPal", "brand": "paypal", "domain": "paypal.com"},
    {"name": "Google", "brand": "google", "domain": "google.com"},
    {"name": "Microsoft", "brand": "microsoft", "domain": "microsoft.com"},
    {"name": "Apple", "brand": "apple", "domain": "apple.com"},
    {"name": "Amazon", "brand": "amazon", "domain": "amazon.com"},
    {"name": "Netflix", "brand": "netflix", "domain": "netflix.com"},
]

URGENCY_REGEX = re.compile(
    r"\b(urgent(?:ly)?|immediate(?:ly)?|action required|immediate action|"
    r"account suspended|account blocked|account locked|access revoked|account terminated|"
    r"verify your (?:account|identity)|confirm your identity|verification required|re-activate|verify now|"
    r"unauthorized (?:login|access|transaction)|security breach|suspicious activity(?: detected)?|"
    r"within 24 hours|within 48 hours|24 hours? left|limited time|final notice|expires (?:today|soon)|"
    r"wire transfer|unauthorized payment|fraud alert|update billing|payment overdue|"
    r"password expired|reset password immediately|click here(?: to verify)?)\b",
    re.IGNORECASE,
)

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "vbs", "iso", "bat", "cmd", "js", "wsf", "ps1", "html", "htm", "hta"
}


def _levenshtein(s1: str, s2: str) -> int:
    """Computes Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def evaluate_heuristics(payload: EmailPayload) -> Dict[str, Any]:
    """
    Evaluates Layer 1 Heuristics (§6.2):
    - Brand typosquatting (+35 points)
    - Keyword urgency density (min(hits * 8, 30) points)
    - SPF/DKIM authentication failures (+25 / +20 points)
    - Dangerous executable attachments (+30 points)
    """
    score = 0
    flags = []
    has_typosquatting = False

    # 1. Domain typosquatting analysis
    sender_domain = ""
    if "@" in payload.senderEmail:
        sender_domain = payload.senderEmail.split("@")[1].lower().strip()

    if sender_domain:
        for brand_entry in PROTECTED_BRANDS:
            target_domain = brand_entry["domain"]
            target_brand = brand_entry["brand"]
            if sender_domain == target_domain:
                continue
            # Typosquatting checks
            dist = _levenshtein(sender_domain, target_domain)
            if dist in (1, 2) or (target_brand in sender_domain and sender_domain != target_domain):
                score += 35
                has_typosquatting = True
                flags.append({
                    "title": "Domain Typosquatting Detected",
                    "evidence": f"Sender domain '{sender_domain}' impersonates {brand_entry['name']}",
                    "severity": "critical",
                })
                break

    # 2. Urgency keyword density
    full_text = f"{payload.subject or ''} {payload.bodyText or ''}"
    keyword_hits = URGENCY_REGEX.findall(full_text)
    if keyword_hits:
        kw_penalty = min(len(keyword_hits) * 8, 30)
        score += kw_penalty
        unique_matches = list(set(k.lower() for k in keyword_hits))[:3]
        flags.append({
            "title": "Urgency / Coercive Language",
            "evidence": f"Found patterns: {', '.join(unique_matches)}",
            "severity": "warn" if kw_penalty < 20 else "critical",
        })

    # 3. Authentication Headers (SPF/DKIM)
    if payload.spfPass is False:
        score += 25
        flags.append({
            "title": "SPF Authentication Failure",
            "evidence": "Sender SPF validation failed",
            "severity": "critical",
        })
    if payload.dkimPass is False:
        score += 20
        flags.append({
            "title": "DKIM Signature Invalid",
            "evidence": "Sender DKIM signature validation failed",
            "severity": "critical",
        })

    # 4. Dangerous attachment extensions
    for att in payload.attachments or []:
        ext = att.split(".")[-1].lower() if "." in att else ""
        if ext in DANGEROUS_EXTENSIONS:
            score += 30
            flags.append({
                "title": "Dangerous Attachment Detected",
                "evidence": f"File '{att}' has executable/script extension .{ext}",
                "severity": "critical",
            })

    heuristic_score = min(100, score)
    return {
        "score": heuristic_score,
        "flags": flags,
        "keyword_hits": len(keyword_hits),
        "has_typosquatting": has_typosquatting,
    }


# ---------------------------------------------------------------------------
# Layer 2 & 3: Semantic NLP & Behavioral Baselines (Week 2 Stubs)
# ---------------------------------------------------------------------------

def evaluate_nlp_intent(
    payload: EmailPayload,
    keyword_hits: int,
    has_typosquatting: bool = False,
) -> int:
    """
    Evaluates Layer 2 Semantic Intent ($S_{nlp}$) using DistilBERT ONNX (§5.2.1, §6.3).
    Extracts email text context, calculates heuristic urgency and spoofing penalties,
    and returns the clamped composite NLP score.
    """
    subject = (payload.subject or "").strip()
    body = (payload.bodyText or "").strip()
    text = f"{subject}\n\n{body}".strip() if subject else body

    # Calculate heuristic adjustments (§6.3)
    urgency_penalty = min(keyword_hits * 8, 20)
    bec_penalty = 20 if has_typosquatting else 0

    if not text:
        # Default baseline when neither subject nor body text is available
        base = 10
        return min(100, base + urgency_penalty + bec_penalty)

    result = classify_email_text(
        text=text,
        urgency_penalty=urgency_penalty,
        bec_penalty=bec_penalty,
    )
    return int(result.get("nlp_score", 10))


def evaluate_behavioral(payload: EmailPayload) -> int:
    """
    Evaluates Layer 3 Behavioral Anomaly ($S_{behavioral}$).
    Ingests client-computed behavioral score if available (§6.4);
    otherwise defaults to neutral baseline 15.
    """
    if payload.behavioralScore is not None:
        try:
            return max(0, min(100, int(payload.behavioralScore)))
        except (ValueError, TypeError):
            pass
    if payload.behavioral_meta and isinstance(payload.behavioral_meta, dict):
        raw_score = payload.behavioral_meta.get("score")
        if raw_score is not None:
            try:
                return max(0, min(100, int(raw_score)))
            except (ValueError, TypeError):
                pass
    return 15


# ---------------------------------------------------------------------------
# Risk Synthesis Formulation (§6.1, §6.5, §6.6)
# Delegated to modules.meta_classifier
# ---------------------------------------------------------------------------

def build_analysis_response(
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
    """Constructs the canonical Aegis analysis payload compatible with the overlay via meta_classifier."""
    return synthesize_assessment(
        email_hash=email_hash,
        s_heuristic=s_heuristic,
        s_nlp=s_nlp,
        s_behavioral=s_behavioral,
        s_vt=s_vt,
        vt_status=vt_status,
        flags=flags,
        urls=urls,
        vt_result=vt_result,
        behavioral_meta=behavioral_meta,
        execution_time_ms=execution_time_ms,
    )


# ---------------------------------------------------------------------------
# Background Task Execution
# ---------------------------------------------------------------------------

async def _execute_background_vt_scan(
    urls: List[str],
    email_hash: str,
    base_state: Dict[str, Any],
) -> None:
    """
    Executes in the background via FastAPI BackgroundTasks.
    Runs rate-paced VirusTotal URL scan and synthesizes the updated composite score.
    """
    logger.info(
        "[Aegis Analysis] Background scan started for email_hash=%s (%d links)",
        email_hash[:8],
        len(urls),
    )
    start_time = time.time()

    try:
        # Perform rate-paced link scan
        vt_result = await scan_email_links(urls, email_hash=email_hash)
        s_vt = int(vt_result.get("vt_score", 0))

        # Re-evaluate flags: add malicious link flag if found
        flags = list(base_state["flags"])
        if s_vt > 0:
            flags.append({
                "title": "Malicious Hyperlink Detected",
                "evidence": f"VirusTotal flagged {vt_result.get('malicious_count', 1)} link destination(s)",
                "severity": "critical",
            })

        duration_ms = int((time.time() - start_time) * 1000)
        final_analysis = build_analysis_response(
            email_hash=email_hash,
            s_heuristic=base_state["s_heuristic"],
            s_nlp=base_state["s_nlp"],
            s_behavioral=base_state["s_behavioral"],
            s_vt=s_vt,
            vt_status="completed",
            flags=flags,
            urls=urls,
            vt_result=vt_result,
            behavioral_meta=base_state.get("behavioral_meta"),
            execution_time_ms=duration_ms,
        )

        # Store completed analysis for subsequent GET polling
        _analysis_store[email_hash] = final_analysis
        logger.info(
            "[Aegis Analysis] Background scan completed for email_hash=%s: score=%d in %dms",
            email_hash[:8],
            final_analysis["score"],
            duration_ms,
        )
    except Exception as exc:
        logger.error(
            "[Aegis Analysis] Background scan failed for email_hash=%s: %s",
            email_hash[:8],
            exc,
            exc_info=True,
        )
        # Fallback to completed state with zero VT score
        final_analysis = build_analysis_response(
            email_hash=email_hash,
            s_heuristic=base_state["s_heuristic"],
            s_nlp=base_state["s_nlp"],
            s_behavioral=base_state["s_behavioral"],
            s_vt=0,
            vt_status="completed",
            flags=base_state["flags"],
            urls=urls,
            vt_result={"status": "error", "error": str(exc)},
            behavioral_meta=base_state.get("behavioral_meta"),
            execution_time_ms=int((time.time() - start_time) * 1000),
        )
        _analysis_store[email_hash] = final_analysis
    finally:
        _in_flight_scans.pop(email_hash, None)


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@router.post("/analyze")
async def analyze_email(
    payload: EmailPayload,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    """
    Primary email analysis endpoint (§3.1 step 73-84).

    Executes Layers 1-3 synchronously (< 350ms).
    If links are uncached, returns vt_status="pending" and kicks off a
    background task to scan them under the 15.0s rate pacing lock.
    """
    start_time = time.time()
    email_hash = compute_email_hash(payload)

    # 1. Check if we already have a fully completed analysis cached
    if email_hash in _analysis_store:
        logger.info("[Aegis Analysis] Analysis store HIT for email_hash=%s", email_hash[:8])
        cached_result = dict(_analysis_store[email_hash])
        cached_result["_cacheHit"] = True
        return cached_result

    # 2. Extract hyperlinks
    urls = extract_url_strings(payload.links or [])

    # 3. Synchronous evaluation of Layer 1 (Heuristics)
    heuristics = evaluate_heuristics(payload)
    s_heuristic = heuristics["score"]
    flags = heuristics["flags"]

    # 4. Synchronous evaluation of Layer 2 & Layer 3
    s_nlp = evaluate_nlp_intent(
        payload,
        heuristics["keyword_hits"],
        has_typosquatting=heuristics.get("has_typosquatting", False),
    )
    s_behavioral = evaluate_behavioral(payload)

    # 5. Check Layer 4 Links status
    if not urls:
        # No links: instant completion
        vt_status = "completed"
        s_vt = 0
        vt_result = {"status": "no_links", "vt_score": 0}
    elif are_urls_cached(urls):
        # All candidate links pre-warmed in cache: instant completion (0ms)
        vt_result = await scan_email_links(urls, email_hash=email_hash)
        s_vt = int(vt_result.get("vt_score", 0))
        vt_status = "completed"
        if s_vt > 0:
            flags.append({
                "title": "Malicious Hyperlink Detected",
                "evidence": f"VirusTotal flagged {vt_result.get('malicious_count', 1)} link destination(s)",
                "severity": "critical",
            })
    else:
        # Links are uncached: dispatch background task and return pending status
        vt_status = "pending"
        s_vt = 0
        vt_result = None

    execution_time_ms = int((time.time() - start_time) * 1000)

    analysis_response = build_analysis_response(
        email_hash=email_hash,
        s_heuristic=s_heuristic,
        s_nlp=s_nlp,
        s_behavioral=s_behavioral,
        s_vt=s_vt,
        vt_status=vt_status,
        flags=flags,
        urls=urls,
        vt_result=vt_result,
        behavioral_meta=payload.behavioral_meta,
        execution_time_ms=execution_time_ms,
    )

    if vt_status == "completed":
        # Save to analysis store
        _analysis_store[email_hash] = analysis_response
    else:
        # Track in-flight and dispatch background task
        base_state = {
            "s_heuristic": s_heuristic,
            "s_nlp": s_nlp,
            "s_behavioral": s_behavioral,
            "flags": flags,
            "behavioral_meta": payload.behavioral_meta,
        }
        _in_flight_scans[email_hash] = {
            "status": "pending",
            "start_time": time.time(),
        }
        background_tasks.add_task(
            _execute_background_vt_scan,
            urls=urls,
            email_hash=email_hash,
            base_state=base_state,
        )

    return analysis_response


@router.get("/vt-status/{email_hash}")
async def get_vt_status(email_hash: str) -> Dict[str, Any]:
    """
    Polling endpoint for background VirusTotal scanning completion (§3.1 step 85-88).
    """
    clean_hash = email_hash.strip().lower()

    # 1. Check completed store
    if clean_hash in _analysis_store:
        completed_data = _analysis_store[clean_hash]
        return {
            "status": "completed",
            "email_hash": clean_hash,
            "data": completed_data,
        }

    # 2. Check in-flight registry
    if clean_hash in _in_flight_scans:
        return {
            "status": "pending",
            "email_hash": clean_hash,
        }

    # 3. Check link_scanner's internal composite cache
    existing_vt = get_vt_analysis(clean_hash)
    if existing_vt:
        return {
            "status": "completed",
            "email_hash": clean_hash,
            "vt_result": existing_vt,
        }

    # Not found
    raise HTTPException(
        status_code=404,
        detail=f"No scan job found for email_hash: {clean_hash}",
    )


# ---------------------------------------------------------------------------
# Utility functions for testing
# ---------------------------------------------------------------------------

def clear_analysis_store() -> None:
    """Clears in-memory stores (for automated tests)."""
    _analysis_store.clear()
    _in_flight_scans.clear()
