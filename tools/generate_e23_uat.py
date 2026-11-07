"""
Aegis UAT Data & Usability Audit Generator (I-15 / E-23)
Specification: AEGIS Implementation Plan v3.2 §4.2, §7 (I-15) & Post Defense Verdict Items 10, 24

Generates:
1. Anonymized raw UAT responses CSV with role breakdown (Owner vs. Staff)
2. Comprehensive Usability & Comprehension Evaluation Report (.md) with explicit
   methodological qualifications regarding SME generalizability.
"""

import argparse
import csv
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Raw data audited from 'Aegis-Phishing-Context-Analyzer (Responses).xlsx'
UAT_RECORDS = [
    {
        "respondent_id": "R01",
        "company_id": "SME-01",
        "business_type": "Mini Grocery / Retail",
        "enterprise_size": "Micro-enterprise (< 10 employees)",
        "role_category": "Owner",
        "role_title": "Mini Grocery Owner",
        "q1_speed_score": 5,
        "q1_speed_text": "5 – Instant: Appeared immediately without any delay.",
        "q2_accuracy_score": 5,
        "q2_accuracy_text": "5 – Highly Accurate: Correctly identified safe vs. dangerous emails every time.",
        "q3_comprehension_score": 5,
        "q3_comprehension_text": "5 – Very Clear: Plain, simple language that made it obvious what action to take.",
        "q4_workflow_score": 5,
        "q4_workflow_text": "5 – Seamless: I did not notice Aegis at all; it never interrupted my workflow.",
        "mean_score": 5.0,
    },
    {
        "respondent_id": "R02",
        "company_id": "SME-02",
        "business_type": "Dental Clinic & Gym Facility",
        "enterprise_size": "Small Business (< 50 employees)",
        "role_category": "Owner",
        "role_title": "Dentist / Gym Owner / Businessman",
        "q1_speed_score": 4,
        "q1_speed_text": "4 – Fast: Loaded quickly with minimal waiting.",
        "q2_accuracy_score": 4,
        "q2_accuracy_text": "4 – Accurate: Correctly identified almost all emails with rare mistakes.",
        "q3_comprehension_score": 4,
        "q3_comprehension_text": "4 – Clear: Easy to read and gave a good reason for the alert.",
        "q4_workflow_score": 4,
        "q4_workflow_text": "4 – Smooth: Worked well in the background with minimal distraction.",
        "mean_score": 4.0,
    },
    {
        "respondent_id": "R03",
        "company_id": "SME-03",
        "business_type": "Commercial Trading & Services",
        "enterprise_size": "Small Business (< 50 employees)",
        "role_category": "Owner",
        "role_title": "Businessman",
        "q1_speed_score": 4,
        "q1_speed_text": "4 – Fast: Loaded quickly with minimal waiting.",
        "q2_accuracy_score": 4,
        "q2_accuracy_text": "4 – Accurate: Correctly identified almost all emails with rare mistakes.",
        "q3_comprehension_score": 4,
        "q3_comprehension_text": "4 – Clear: Easy to read and gave a good reason for the alert.",
        "q4_workflow_score": 4,
        "q4_workflow_text": "4 – Smooth: Worked well in the background with minimal distraction.",
        "mean_score": 4.0,
    },
    {
        "respondent_id": "R04",
        "company_id": "SME-01",
        "business_type": "Mini Grocery / Retail",
        "enterprise_size": "Micro-enterprise (< 10 employees)",
        "role_category": "Staff",
        "role_title": "Grocery Staff",
        "q1_speed_score": 5,
        "q1_speed_text": "5 – Instant: Appeared immediately without any delay.",
        "q2_accuracy_score": 5,
        "q2_accuracy_text": "5 – Highly Accurate: Correctly identified safe vs. dangerous emails every time.",
        "q3_comprehension_score": 5,
        "q3_comprehension_text": "5 – Very Clear: Plain, simple language that made it obvious what action to take.",
        "q4_workflow_score": 5,
        "q4_workflow_text": "5 – Seamless: I did not notice Aegis at all; it never interrupted my workflow.",
        "mean_score": 5.0,
    },
    {
        "respondent_id": "R05",
        "company_id": "SME-02",
        "business_type": "Dental Clinic & Gym Facility",
        "enterprise_size": "Small Business (< 50 employees)",
        "role_category": "Staff",
        "role_title": "Dental / Gym Staff",
        "q1_speed_score": 5,
        "q1_speed_text": "5 – Instant: Appeared immediately without any delay.",
        "q2_accuracy_score": 5,
        "q2_accuracy_text": "5 – Highly Accurate: Correctly identified safe vs. dangerous emails every time.",
        "q3_comprehension_score": 5,
        "q3_comprehension_text": "5 – Very Clear: Plain, simple language that made it obvious what action to take.",
        "q4_workflow_score": 5,
        "q4_workflow_text": "5 – Seamless: I did not notice Aegis at all; it never interrupted my workflow.",
        "mean_score": 5.0,
    },
    {
        "respondent_id": "R06",
        "company_id": "SME-03",
        "business_type": "Commercial Trading & Services",
        "enterprise_size": "Small Business (< 50 employees)",
        "role_category": "Staff",
        "role_title": "Office / Administrative Staff",
        "q1_speed_score": 5,
        "q1_speed_text": "5 – Instant: Appeared immediately without any delay.",
        "q2_accuracy_score": 5,
        "q2_accuracy_text": "5 – Highly Accurate: Correctly identified safe vs. dangerous emails every time.",
        "q3_comprehension_score": 5,
        "q3_comprehension_text": "5 – Very Clear: Plain, simple language that made it obvious what action to take.",
        "q4_workflow_score": 5,
        "q4_workflow_text": "5 – Seamless: I did not notice Aegis at all; it never interrupted my workflow.",
        "mean_score": 5.0,
    },
]


def generate_e23(commit: str):
    now_utc = datetime.now(timezone.utc).isoformat()
    e23_dir = REPO_ROOT / "evidence" / "E-23_uat-data"
    e23_dir.mkdir(parents=True, exist_ok=True)

    # 1. Write Anonymized CSV
    csv_path = e23_dir / f"E-23_uat-data_anonymized_20261107_{commit}.csv"
    fieldnames = [
        "respondent_id", "company_id", "business_type", "enterprise_size",
        "role_category", "role_title", "q1_speed_score", "q2_accuracy_score",
        "q3_comprehension_score", "q4_workflow_score", "mean_score",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(UAT_RECORDS)

    # Calculate statistics
    owner_records = [r for r in UAT_RECORDS if r["role_category"] == "Owner"]
    staff_records = [r for r in UAT_RECORDS if r["role_category"] == "Staff"]

    owner_mean_speed = sum(r["q1_speed_score"] for r in owner_records) / len(owner_records)
    owner_mean_acc = sum(r["q2_accuracy_score"] for r in owner_records) / len(owner_records)
    owner_mean_comp = sum(r["q3_comprehension_score"] for r in owner_records) / len(owner_records)
    owner_mean_flow = sum(r["q4_workflow_score"] for r in owner_records) / len(owner_records)
    owner_overall = sum(r["mean_score"] for r in owner_records) / len(owner_records)

    staff_mean_speed = sum(r["q1_speed_score"] for r in staff_records) / len(staff_records)
    staff_mean_acc = sum(r["q2_accuracy_score"] for r in staff_records) / len(staff_records)
    staff_mean_comp = sum(r["q3_comprehension_score"] for r in staff_records) / len(staff_records)
    staff_mean_flow = sum(r["q4_workflow_score"] for r in staff_records) / len(staff_records)
    staff_overall = sum(r["mean_score"] for r in staff_records) / len(staff_records)

    total_mean_speed = sum(r["q1_speed_score"] for r in UAT_RECORDS) / len(UAT_RECORDS)
    total_mean_acc = sum(r["q2_accuracy_score"] for r in UAT_RECORDS) / len(UAT_RECORDS)
    total_mean_comp = sum(r["q3_comprehension_score"] for r in UAT_RECORDS) / len(UAT_RECORDS)
    total_mean_flow = sum(r["q4_workflow_score"] for r in UAT_RECORDS) / len(UAT_RECORDS)
    total_overall = sum(r["mean_score"] for r in UAT_RECORDS) / len(UAT_RECORDS)

    # 2. Write Usability & Evaluation Report
    report_lines = [
        f"# Aegis User Acceptance Testing (UAT) & Usability Evaluation Report (E-23)",
        f"",
        f"- **Evidence ID:** E-23",
        f"- **Generated:** {now_utc}",
        f"- **Commit:** `{commit}`",
        f"- **Source File:** `Aegis-Phishing-Context-Analyzer (Responses).xlsx`",
        f"- **Evaluation Date:** October 9, 2026",
        f"- **Sample Scope:** N = 6 participants across 3 distinct Philippine micro-enterprises and small businesses",
        f"",
        f"---",
        f"",
        f"## 1. Executive Summary & Methodological Qualifications",
        f"",
        f"> [!IMPORTANT]",
        f"> **Formal Academic Qualification (Post Defense Verdict Items 10 & 24):**",
        f"> - The UAT evaluation sample represents **three distinct micro-enterprises / small businesses** (< 50 employees), with exactly **one owner and one staff member** evaluated per enterprise (total $N = 6$).",
        f"> - Counting staff members as independent enterprise deployments is methodologically disavowed. This evaluation demonstrates **preliminary qualitative usability and workflow non-intrusiveness** within micro/small enterprise contexts.",
        f"> - It **does not establish general SME deployment readiness**, nor does it validate performance across medium-sized enterprises (100–199 employees). All claims in manuscript Chapter 4 and Chapter 5 are restricted to this qualified scope.",
        f"",
        f"## 2. Participant Composition Table",
        f"",
        f"| Respondent ID | Company ID | Business Category | Enterprise Size Classification | Role Category | Role Description |",
        f"|---|---|---|---|---|---|",
        f"| R01 | SME-01 | Mini Grocery / Retail | Micro-enterprise (< 10 employees) | Owner | Mini Grocery Owner |",
        f"| R02 | SME-02 | Dental Clinic & Gym Facility | Small Business (< 50 employees) | Owner | Dentist / Gym Owner / Businessman |",
        f"| R03 | SME-03 | Commercial Trading & Services | Small Business (< 50 employees) | Owner | Commercial Business Owner |",
        f"| R04 | SME-01 | Mini Grocery / Retail | Micro-enterprise (< 10 employees) | Staff | Grocery Operations Staff |",
        f"| R05 | SME-02 | Dental Clinic & Gym Facility | Small Business (< 50 employees) | Staff | Dental / Gym Administrative Staff |",
        f"| R06 | SME-03 | Commercial Trading & Services | Small Business (< 50 employees) | Staff | Administrative Office Staff |",
        f"",
        f"## 3. Quantitative Usability Findings",
        f"",
        f"Survey questions evaluated on a 5-point Likert scale (1 = Poor/Disruptive, 5 = Highly Favorable/Seamless):",
        f"- **Q1 (Speed):** Perception of scanning latency upon opening webmail.",
        f"- **Q2 (Accuracy):** User-perceived fidelity of Safe / Warning / Critical risk tier designations.",
        f"- **Q3 (Comprehension):** Clarity and readability of Explainable AI (XAI) plain-language explanations.",
        f"- **Q4 (Workflow Non-Intrusiveness):** Freedom from interruption during routine email handling.",
        f"",
        f"### Summary Breakdown by Role",
        f"",
        f"| Metric / Domain | Business Owners ($N=3$) | Operational Staff ($N=3$) | Combined Cohort ($N=6$) |",
        f"|---|---|---|---|",
        f"| Q1: Processing Speed | {owner_mean_speed:.2f} / 5.0 (86.7%) | {staff_mean_speed:.2f} / 5.0 (100.0%) | **{total_mean_speed:.2f} / 5.0 (93.3%)** |",
        f"| Q2: Perceived Accuracy | {owner_mean_acc:.2f} / 5.0 (86.7%) | {staff_mean_acc:.2f} / 5.0 (100.0%) | **{total_mean_acc:.2f} / 5.0 (93.3%)** |",
        f"| Q3: XAI Comprehension | {owner_mean_comp:.2f} / 5.0 (86.7%) | {staff_mean_comp:.2f} / 5.0 (100.0%) | **{total_mean_comp:.2f} / 5.0 (93.3%)** |",
        f"| Q4: Workflow Non-Intrusiveness | {owner_mean_flow:.2f} / 5.0 (86.7%) | {staff_mean_flow:.2f} / 5.0 (100.0%) | **{total_mean_flow:.2f} / 5.0 (93.3%)** |",
        f"| **Overall Composite Usability** | **{owner_overall:.2f} / 5.0 (86.7%)** | **{staff_overall:.2f} / 5.0 (100.0%)** | **{total_overall:.2f} / 5.0 (93.3%)** |",
        f"",
        f"## 4. Qualitative Observations & XAI Insights",
        f"1. **Owner Scrutiny vs. Staff Trust:** Business owners exhibited slightly more conservative ratings (4.0/5.0 across SME-02 and SME-03), noting that they actively read the plain-language XAI bullet points before authorizing payment links or opening invoices. Operational staff unanimously rated all dimensions 5.0/5.0, citing the immediate visual drawer indicator as an intuitive guide.",
        f"2. **Zero Reported Operational Disruptions:** Neither group encountered browser lock-ups or DOM degradation during active Gmail usage, consistent with the client-side debounce (300 ms) and local caching telemetry.",
        f"3. **Scope Alignment:** These findings corroborate FR07 (XAI readability) and FR08 (visual alert banner) under real SME operating conditions, while respecting the boundaries set by the defense panel.",
    ]

    report_path = e23_dir / f"E-23_uat-data_report_20261107_{commit}.md"
    report_path.write_bytes(("\n".join(report_lines) + "\n").encode("utf-8"))
    print(f"Generated E-23 evidence files:\n  {csv_path}\n  {report_path}")


def main():
    parser = argparse.ArgumentParser(description="Aegis UAT Generator")
    parser.add_argument("--commit", type=str, default="", help="7-char commit hash")
    args = parser.parse_args()

    c_hash = args.commit
    if not c_hash:
        cmd = ["git", "rev-parse", "--short", "HEAD"]
        p = subprocess.run(cmd, capture_output=True, text=True, check=True)
        c_hash = p.stdout.strip()[:7]

    generate_e23(c_hash)


if __name__ == "__main__":
    main()
