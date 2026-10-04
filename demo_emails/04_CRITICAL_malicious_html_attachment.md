# Demo Email 4: Critical Threat (Malicious HTML Phishing Attachment)

Use this email to demonstrate **Attachment Threat Intelligence** identifying a high-risk HTML credential-harvesting file (`.html`), a technique modern cybercriminals use to bypass conventional gateway URL scanners.

---

## 📧 Email Content to Send

| Field | Exact Text to Paste |
| :--- | :--- |
| **To** | *(Your own Gmail address)* |
| **Subject** | `ACTION REQUIRED: Microsoft 365 Account Session Expired` |
| **Attachment** | Attach [`demo_emails/attachments/Office365_Verification_Portal.html`](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/demo_emails/attachments/Office365_Verification_Portal.html) |

> [!NOTE]
> Gmail easily allows attaching `.html` files! When opened, this simulated file renders a fake Microsoft login prompt. Aegis inspects the file extension directly in the DOM.

### Body Text:
```text
Dear Employee,

Your Microsoft 365 corporate single-sign-on session has expired as of this morning. You will be unable to access shared corporate drives, internal documents, or customer tickets until identity re-authentication is completed.

Due to firewall updates, web-based verification is temporarily unavailable. Please open the attached offline authentication file (Office365_Verification_Portal.html) in your browser and enter your network password to restore access immediately.

Do not ignore this notification. Unverified accounts will be scheduled for deactivation within 12 hours.

IT Help Desk Operations
Security Administration
```

---

## 🎯 Expected Aegis Output

| Layer / Indicator | Expected Result |
| :--- | :--- |
| **Risk Tier** | 🔴 **CRITICAL** (Red Overlay Badge) |
| **Risk Score** | **85% – 95%** |
| **Attachment Intelligence** | **Dangerous Script/HTML Attachment Triggered**: Detects `.html` in `DANGEROUS_EXTENSIONS` (+30 to +35 pts) |
| **DistilBERT NLP ($S_{\text{nlp}}$)** | **High Phishing Probability**: Flags account expiration, credential demand, and coercive timeframe |
| **Heuristics ($S_{\text{heuristic}}$)** | Urgency keyword penalties (*"action required"*, *"session expired"*, *"restore access immediately"*) |

### 🎙️ What to Say to the Panel:
> *"Attackers often attach `.html` files so that the credential-theft form loads locally from the disk, bypassing traditional gateway URL scanners. Aegis inspects the extracted DOM attachment manifest, flags the executable HTML extension, correlates it with the coercive body text, and alerts the employee before they open the file."*
