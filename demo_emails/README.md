# Aegis: Prototype Demonstration Emails & Test Attachments Dossier

This folder contains pre-scripted email scenarios and accompanying sample attachments designed to demonstrate the full capabilities of the **Aegis Phishing Context Analyzer** across Safe, Warning, and Critical tiers.

---

## 📁 Directory Structure

```text
demo_emails/
├── README.md                                  # This master demonstration guide
├── 01_SAFE_routine_workplace.md               # Tier 1: Safe baseline (5-15% score)
├── 02_WARNING_archive_attachment.md           # Tier 2: Warning tier with .zip archive (45-65% score)
├── 03_CRITICAL_credential_harvesting_link.md  # Tier 3: Critical URL theft via VirusTotal seed cache
├── 04_CRITICAL_malicious_html_attachment.md   # Tier 3: Critical HTML credential harvester attachment
├── 05_CRITICAL_executive_impersonation_bec.md # Tier 3: Critical BEC / Whitelist auto-revocation
└── attachments/
    ├── Company_Policy_Schedule.txt            # Clean text attachment (Safe demo)
    ├── Office365_Verification_Portal.html     # Simulated phishing HTML login form (Critical demo)
    ├── Payment_Receipt_Statement.vbs          # Harmless simulated VBScript dropper (Script sample)
    └── Urgent_Payroll_Update.ps1              # Harmless simulated PowerShell script (Script sample)
```

---

## 💡 Important Note on Gmail Attachment Policies

When testing with real **Google Gmail**:
1. **Allowed by Gmail & Flagged by Aegis:**
   - `.html` files (e.g. `Office365_Verification_Portal.html`): Gmail allows sending `.html` attachments, while Aegis detects them as potential offline credential harvesters.
   - `.zip` / `.rar` archives: Gmail allows standard archives (like `Audit_Archive.zip`), while Aegis flags them under its `RULE_ARCHIVE_ATTACHMENT` warning policy.
   - `.txt`, `.pdf`, `.docx`: Clean corporate documents that Aegis scores as benign.
2. **Blocked Outbound by Gmail:**
   - Raw `.exe`, `.vbs`, `.bat`, or `.ps1` files attached directly will trigger Google's *"Blocked for security reasons"* outbound filter.
   - *How attackers bypass this (and how you can test):* Pack them inside a password-protected zip, or test with the included `.html` attachment which sends cleanly through Gmail!

---

## 🎯 Quick Matrix: Which Email to Send for Each Tier

| Scenario | File Guide | Attachment Used | What It Triggers in Aegis | Resulting Badge |
| :--- | :--- | :--- | :--- | :--- |
| **1. Clean Workplace Email** | [`01_SAFE...md`](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/demo_emails/01_SAFE_routine_workplace.md) | `Company_Policy_Schedule.txt` | Normal collaborative language, benign document | 🟢 **SAFE (< 15%)** |
| **2. Suspicious Archive** | [`02_WARNING...md`](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/demo_emails/02_WARNING_archive_attachment.md) | Compressed `.zip` file | `RULE_ARCHIVE_ATTACHMENT`, moderate deadline | 🟡 **WARNING (~55%)** |
| **3. Malicious Link (VT)** | [`03_CRITICAL...md`](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/demo_emails/03_CRITICAL_credential_harvesting_link.md) | None (Link-based) | VirusTotal seed cache hit (18 malicious hits) + NLP | 🔴 **CRITICAL (95%+)** |
| **4. Phishing HTML File** | [`04_CRITICAL...md`](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/demo_emails/04_CRITICAL_malicious_html_attachment.md) | `Office365_Verification_Portal.html` | Executable `.html` attachment rule + coercion text | 🔴 **CRITICAL (90%+)** |
| **5. Executive BEC Spoof** | [`05_CRITICAL...md`](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/demo_emails/05_CRITICAL_executive_impersonation_bec.md) | None | Whitelist display-name auto-revocation trigger | 🔴 **CRITICAL (95%)** |
