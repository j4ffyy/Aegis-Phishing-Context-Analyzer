# Demo Email 2: Warning Tier (Suspicious Compressed Archive Attachment)

Use this email to demonstrate the **Warning Tier (Amber/Yellow)** where Aegis detects moderate urgency combined with a compressed archive file (`.zip`), which attackers frequently use to bypass basic email filters.

---

## 📧 Email Content to Send

| Field | Exact Text to Paste |
| :--- | :--- |
| **To** | *(Your own Gmail address)* |
| **Subject** | `ACTION REQUIRED: Overdue Invoice Discrepancies - Review Attached Archive Immediately` |
| **Attachment** | Attach [`demo_emails/attachments/Q3_Audit_Records.zip`](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/demo_emails/attachments/Q3_Audit_Records.zip) |

### Body Text:
```text
Hello Accounts Team,

ACTION REQUIRED: Please review the attached internal financial audit archive immediately.

We have detected past-due vendor invoices and unverified payment discrepancies regarding last month's software licensing renewals. To prevent service suspension within 24 hours, review the attached statement archive (Q3_Audit_Records.zip).

Extract the archive and verify that these vendor transactions match your department records before end of day.

Regards,
Internal Audit Department
```

---

## 🎯 Expected Aegis Output

| Layer / Indicator | Expected Result |
| :--- | :--- |
| **Risk Tier** | 🟡 **WARNING** (Amber/Yellow Overlay Badge) |
| **Risk Score** | **45% – 65%** |
| **Heuristics ($S_{\text{heuristic}}$)** | Flags **Compressed Archive Attachment (`.zip`)** (+15 pts) and moderate deadline keywords |
| **Attachment Intelligence** | Evaluated via `RULE_ARCHIVE_ATTACHMENT`: warns user that archives frequently hide payloads |
| **DistilBERT NLP ($S_{\text{nlp}}$)** | Low-to-moderate suspicion (mentions financial reconciliation without aggressive coercion) |

### 🎙️ What to Say to the Panel:
> *"Here, Aegis assigns an intermediate 'Warning' tier. While the email lacks blatant phishing links, our heuristic engine flags the compressed `.zip` archive and deadline pressure. The Explainable AI banner educates the employee to confirm the sender's identity before extracting unknown archives."*
