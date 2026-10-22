"""
Aegis: AI-Powered Phishing Context Analyzer
Script: Test Dataset Preparation (PR-08)
Spec: Capstone 2 Paper §4.2 — Model Evaluation & Controlled Test Protocol

Usage:
    cd aegis-backend
    python scripts/prepare_test_dataset.py [--size N]

Outputs:
    data/test_dataset.csv  — balanced labeled test set (N/2 phishing, N/2 legit)

This script generates a controlled, reproducible test dataset drawn from the
same synthetic feature distribution used in train_ensemble.py, augmented with
a realistic variety of edge-case email patterns referenced in the Capstone 2
paper (Table 16 evaluation protocol):
  - High-urgency phishing (credential harvesting)
  - Business Email Compromise (BEC) spoofing
  - Invoice/payment fraud
  - Tagalog/Taglish phishing (PR-06 multilingual coverage)
  - Benign transactional emails (invoices, OTPs, newsletters)
  - Benign interpersonal email (casual, internal comms)

The dataset is intentionally kept self-contained and deterministic (seeded RNG)
so evaluation results are reproducible for the paper's Chapter IV results table.
"""

import argparse
import csv
import json
import logging
import random
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("prepare_test_dataset")

SCRIPT_DIR = Path(__file__).parent
BACKEND_DIR = SCRIPT_DIR.parent
DATA_DIR = BACKEND_DIR / "data"

# ---------------------------------------------------------------------------
# Controlled email template banks
# ---------------------------------------------------------------------------

PHISHING_SUBJECTS = [
    "URGENT: Your GCash account has been suspended",
    "Action Required: Verify your BPI account immediately",
    "Security Alert: Unauthorized login detected on your Maya account",
    "Final Notice: Your account will be deactivated in 24 hours",
    "IMPORTANT: Update your BDO Online Banking credentials now",
    "Your Shopee account has been locked - verify now",
    "Metrobank: Suspicious transaction detected on your account",
    "RCBC Online Banking: Account verification required",
    "Lazada: Your order is on hold - confirm payment details",
    "PhilHealth: Update your member information immediately",
    "SSS: Important notice regarding your contribution records",
    "Microsoft Account: Unusual sign-in activity detected",
    "PayPal: Your account access has been limited",
    "Amazon: Your account has been compromised - act now",
    "Google: Security alert for your connected account",
    # Taglish phishing subjects (PR-06)
    "URGENT: I-verify ang iyong GCash account agad na",
    "Babala: Na-lock ang iyong BDO account - mag-login na",
    "Kailangan mong i-update ang iyong Maya account ngayon",
    "I-confirm ang iyong Shopee order para maiwasan ang pagkansela",
    "SSS: Kailangan mong i-verify ang iyong impormasyon agad",
]

PHISHING_BODIES = [
    "We have detected suspicious activity on your account. Please click the link below to verify your identity within 24 hours or your account will be permanently suspended. Click here: http://gcash-verify.top/login",
    "Your BPI account requires immediate verification. Failure to verify within 48 hours will result in account termination. Please update your credentials at: http://bpi-secure-login.xyz",
    "An unauthorized login was detected on your Maya account from an unrecognized device. Click here immediately to secure your account: http://maya-security.click",
    "Dear valued customer, your account has been flagged for suspicious activity. To restore access, please verify your identity by providing your account credentials at: http://192.168.1.1/verify",
    "FINAL NOTICE: Your online banking access expires today. Please reset your password immediately to avoid deactivation: http://bdo-reset-now.loan",
    "Kailangan mong i-verify ang iyong GCash account agad. Mag-login sa link na ito para ma-protect ang iyong pera: http://gcash-ph.tk/login. Huwag ibigay ang iyong PIN sa iba.",
    "Ang iyong BPI account ay na-lock na dahil sa maraming failed login attempts. I-click ang link para ma-unlock agad: http://bpi-unlock.gq",
    "Your PayPal account has been limited due to unusual activity. To restore full access, please verify your identity: http://paypal-secure-verify.top",
    "Amazon Security Alert: We detected an attempt to access your account from an unrecognized device. Verify now: http://amazon-account-verify.xyz/login",
    "Microsoft Alert: Your account password has expired. Click here to reset immediately or risk losing access: http://microsoft-account-reset.click",
    "Wire transfer required: Invoice #INV-2026-0847 for PHP 145,000 is overdue. Please remit payment to account 1234567890 (RCBC) immediately. Failure to comply will result in legal action.",
    "Dear Finance Manager, please process an urgent wire transfer of $25,000 to our new vendor. This is time sensitive. Account details attached. - CEO",
    "Your Lazada order #LZD-2026-98847 is on hold. To release your package, please confirm your payment method: http://lazada-confirm.top/payment",
    "Congratulations! You have been selected to receive a FREE gift from Shopee. Click here to claim your prize: http://shopee-promo.icu/claim",
    "Napili kayo para sa aming espesyal na promosyon! Mag-click dito para makuha ang inyong libreng regalo: http://shopee-ph-promo.tk/claim",
]

PHISHING_SENDERS = [
    "security@gcash-verify.top",
    "noreply@bpi-secure-login.xyz",
    "alerts@maya-security.click",
    "support@bdo-reset-now.loan",
    "admin@rcbc-online.tk",
    "security@metrobank-ph.gq",
    "noreply@shopee-promo.icu",
    "alerts@paypal-verify.top",
    "security@amazon-account-verify.xyz",
    "helpdesk@microsoft-account-reset.click",
    "ceo.office@globalcorp-ph.com",  # BEC impersonation
    "finance@acme-enterprise.xyz",   # BEC impersonation
    "billing@lazada-confirm.top",
    "promo@shopee-ph-promo.tk",
    "sss-notification@sss-gov-ph.click",
]

LEGIT_SUBJECTS = [
    "Your OTP for BDO Online Banking",
    "Receipt: GCash transfer to Juan dela Cruz",
    "Shopee Order Confirmation - Order #SHP-2026-12345",
    "Your monthly Lazada invoice is ready",
    "Meeting agenda for tomorrow's sync",
    "Team lunch - please confirm attendance",
    "Your PhilHealth contribution receipt for October 2026",
    "SSS PRN for Q4 2026 - Payment Reference",
    "Project update: Phase 2 deliverables",
    "Follow-up: Contract renewal discussion",
    "Re: Budget approval for Q4 marketing campaign",
    "FWD: MMDC academic calendar update",
    "Your Meralco bill for September 2026",
    "Globe: Your October 2026 statement is available",
    "Welcome to the Aegis SME Security Newsletter",
]

LEGIT_BODIES = [
    "Your one-time password (OTP) for BDO Online Banking is: 847291. This OTP is valid for 5 minutes. Never share this OTP with anyone.",
    "Hi Juan, your GCash transfer of PHP 500.00 to Maria Santos was successful. Transaction ID: GCX2026102200847. Date: Oct 22, 2026 11:30 AM.",
    "Thank you for your Shopee order! Your order #SHP-2026-12345 has been confirmed and is being processed. Expected delivery: Oct 25-27, 2026.",
    "Dear Customer, your October 2026 Lazada invoice (PHP 1,450.00) is now available for download in your account. Payment due: Nov 5, 2026.",
    "Hi team, agenda for tomorrow's 2PM sync: 1) Sprint review, 2) Q4 planning, 3) Open items. Please come prepared. See you tomorrow!",
    "Hey everyone, we're doing a team lunch this Friday at 12PM at Jollibee Ayala. Please reply if you can make it so we can reserve seats.",
    "Dear Member, your PhilHealth contribution for October 2026 (PHP 400.00) has been successfully posted. Thank you for your compliance.",
    "Dear SSS Member, your Payment Reference Number (PRN) for Q4 2026 is: 0012345678901. Please use this when paying at accredited banks.",
    "Hi team, just a quick update on Phase 2 — we're on track to complete the user testing by end of next week. More details in the attached deck.",
    "Hi Mike, following up on our contract renewal discussion from last Tuesday. Could we schedule a 30-minute call this week to finalize the terms?",
    "Dear Finance, the Q4 marketing campaign budget of PHP 250,000 has been approved by management. Please proceed with vendor onboarding.",
    "Dear Students, please be advised that the MMDC academic calendar has been updated for Semester 2, 2026-2027. See the attached PDF for details.",
    "Dear Customer, your Meralco bill for the billing period Sept 1-30, 2026 is PHP 3,847.00. Due date: Nov 15, 2026. Account: 123-456-789-000.",
    "Dear Globe Subscriber, your October 2026 statement is now available. Total amount due: PHP 1,299.00. Due date: Nov 10, 2026.",
    "Welcome to the Aegis SME Security Newsletter! This month: 5 common phishing tactics targeting Filipino businesses and how to spot them.",
]

LEGIT_SENDERS = [
    "noreply@bdo.com.ph",
    "gcash@gcash.com",
    "orders@shopee.ph",
    "billing@lazada.com.ph",
    "jdelacruz@company.com.ph",
    "hr@mmdc.edu.ph",
    "contributions@philhealth.gov.ph",
    "sss@sss.gov.ph",
    "projectlead@consultancy.ph",
    "mreyes@businesspartner.com.ph",
    "finance@legitcorp.com.ph",
    "registrar@mmdc.edu.ph",
    "billing@meralco.com.ph",
    "billing@globe.com.ph",
    "newsletter@aegis-security.ph",
]


def generate_sample(idx: int, is_phishing: bool, rng: random.Random) -> dict:
    """Generates a single labeled test email sample."""
    if is_phishing:
        subject = rng.choice(PHISHING_SUBJECTS)
        body    = rng.choice(PHISHING_BODIES)
        sender  = rng.choice(PHISHING_SENDERS)
        has_link = True
        link_domain = rng.choice([
            "gcash-verify.top", "bpi-secure-login.xyz", "maya-security.click",
            "bdo-reset-now.loan", "amazon-account-verify.xyz", "shopee-ph-promo.tk",
            "paypal-verify.top", "microsoft-account-reset.click", "192.168.1.1",
        ])
        links = [f"http://{link_domain}/verify?id={idx}"]
        attachment = rng.choice([
            "", "", "",  # most phishing emails have no attachment
            "Invoice.pdf.zip", "Statement.docx.exe", "Receipt.pdf.vbs",
        ])
        attachments = [attachment] if attachment else []
    else:
        subject  = rng.choice(LEGIT_SUBJECTS)
        body     = rng.choice(LEGIT_BODIES)
        sender   = rng.choice(LEGIT_SENDERS)
        has_link = rng.random() < 0.4
        links    = [f"https://{sender.split('@')[1]}/view/{idx}"] if has_link else []
        attachments = []

    return {
        "id":          idx,
        "label":       1 if is_phishing else 0,
        "label_name":  "Phishing" if is_phishing else "Legitimate",
        "senderEmail": sender,
        "subject":     subject,
        "bodyText":    body,
        "links":       json.dumps(links),
        "attachments": json.dumps(attachments),
        "hasAttachment": bool(attachments),
        "attachmentCount": len(attachments),
        "spfPass":     not is_phishing,   # legitimate emails pass SPF
        "dkimPass":    not is_phishing,   # legitimate emails pass DKIM
    }


def main():
    parser = argparse.ArgumentParser(
        description="Prepare Aegis test dataset for model evaluation (PR-08)"
    )
    parser.add_argument(
        "--size", type=int, default=200,
        help="Total dataset size (must be even; default: 200 = 100 phishing + 100 legit)"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)"
    )
    parser.add_argument(
        "--output", type=str, default=str(DATA_DIR / "test_dataset.csv"),
        help="Output CSV path"
    )
    args = parser.parse_args()

    if args.size % 2 != 0:
        logger.error("--size must be even (balanced phishing/legit split)")
        sys.exit(1)

    rng = random.Random(args.seed)
    half = args.size // 2

    samples = []
    for i in range(half):
        samples.append(generate_sample(i, is_phishing=True, rng=rng))
    for i in range(half, args.size):
        samples.append(generate_sample(i, is_phishing=False, rng=rng))

    # Shuffle to avoid ordering bias
    rng.shuffle(samples)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "id", "label", "label_name", "senderEmail", "subject", "bodyText",
        "links", "attachments", "hasAttachment", "attachmentCount",
        "spfPass", "dkimPass",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(samples)

    phishing_count = sum(1 for s in samples if s["label"] == 1)
    legit_count    = sum(1 for s in samples if s["label"] == 0)

    logger.info("=" * 60)
    logger.info("Test Dataset Prepared")
    logger.info("=" * 60)
    logger.info("  Total samples:  %d", args.size)
    logger.info("  Phishing:       %d", phishing_count)
    logger.info("  Legitimate:     %d", legit_count)
    logger.info("  Seed:           %d", args.seed)
    logger.info("  Output:         %s", output_path)
    logger.info("=" * 60)
    logger.info("Run evaluate_models.py to produce metrics report.")


if __name__ == "__main__":
    main()
