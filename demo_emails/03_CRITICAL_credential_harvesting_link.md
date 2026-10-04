# Demo Email 3: Critical Phishing (Credential Theft & Seed-Cached Threat Link)

Use this email to demonstrate **Layer 2 (DistilBERT NLP) + Layer 4 (VirusTotal Link Scanner)** working in tandem to identify a severe credential-theft phishing attack.

> [!TIP]
> The hyperlink in this email (`http://paypal-verification-account-sec.com/login`) is pre-warmed in [`aegis-backend/data/vt_seed_cache.json`](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/aegis-backend/data/vt_seed_cache.json). Aegis will retrieve a confirmed 18-engine malicious rating in **0 milliseconds** without contacting the live API!

---

## 📧 Email Content to Send

| Field | Exact Text to Paste |
| :--- | :--- |
| **To** | *(Your own Gmail address)* |
| **Subject** | `URGENT: Unauthorized Security Access Detected - Immediate Action Required` |
| **Attachment** | *None (Link-based attack)* |

### Body Text:
```text
Dear Customer,

We have detected unauthorized login attempts and suspicious activity originating from an unknown device associated with your account. 

For your protection, your access has been temporarily restricted within 24 hours. To prevent permanent suspension and verify your identity, you must immediately confirm your account credentials through our secure verification gateway:

http://paypal-verification-account-sec.com/login

Failure to verify your identity within 24 hours will result in automatic account termination and forfeiture of all pending funds.

Sincerely,
Security & Fraud Prevention Operations
```

---

## 🎯 Expected Aegis Output

| Layer / Indicator | Expected Result |
| :--- | :--- |
| **Risk Tier** | 🔴 **CRITICAL** (Red Overlay Badge) |
| **Risk Score** | **95% – 100%** |
| **DistilBERT NLP ($S_{\text{nlp}}$)** | **High Confidence Phishing (>90%)**: Detects artificial urgency, account closure threats, and credential solicitation |
| **VirusTotal ($S_{\text{vt}}$)** | **Confirmed Malicious (18/75 detections)**: Instant cache hit from `vt_seed_cache.json` |
| **Heuristics ($S_{\text{heuristic}}$)** | Urgency keyword density trigger: *"urgent"*, *"action required"*, *"within 24 hours"*, *"verify your identity"* |
| **Critical Floor Rule** | Because $S_{\text{vt}} \ge 50$, the meta-classifier enforces a critical override floor of **85% minimum** |

### 🎙️ What to Say to the Panel:
> *"Here you see the full power of our multi-layered engine. The DistilBERT model recognizes coercive urgency and account restriction tactics, while our VirusTotal gateway immediately confirms the destination link has 18 active malicious vendor verdicts. Aegis alerts the user with an unmistakable critical banner and clear plain-language rationale."*
