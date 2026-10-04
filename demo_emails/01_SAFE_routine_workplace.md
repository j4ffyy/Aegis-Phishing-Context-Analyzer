# Demo Email 1: Safe Routine Workplace Communication

Use this email to demonstrate **Normal / Safe baseline behavior** where Aegis analyzes the email and confirms it poses no threat to the organization.

---

## 📧 Email Content to Send

| Field | Exact Text to Paste |
| :--- | :--- |
| **To** | *(Your own Gmail address)* |
| **Subject** | `Team Weekly Sync & Q4 Operations Planning Agenda` |
| **Attachment** | Attach [`demo_emails/attachments/Company_Policy_Schedule.txt`](file:///c:/Users/jafph/Desktop/Capstone%201%20-%20Phishing%20Analyzer/Aegis-Phishing-Context-Analyzer/demo_emails/attachments/Company_Policy_Schedule.txt) *(or send with no attachment)* |

### Body Text:
```text
Hi everyone,

I hope you are having a productive week. 

Please find attached our discussion agenda for tomorrow's quarterly planning session at 10:00 AM. We will be going over last month's project milestones, resource allocation, and team training schedules.

If there are any additional topics or department updates you would like to include on the agenda, please reply to this email before 4:00 PM today so we can finalize the slide deck.

Looking forward to our discussion tomorrow morning.

Best regards,
Operations Team
```

---

## 🎯 Expected Aegis Output

| Layer / Indicator | Expected Result |
| :--- | :--- |
| **Risk Tier** | 🟢 **SAFE** (Green Overlay Badge) |
| **Risk Score** | **5% – 15%** |
| **DistilBERT NLP ($S_{\text{nlp}}$)** | **Clean / Benign** (Zero urgency, no credential harvesting signals) |
| **Heuristics ($S_{\text{heuristic}}$)** | **0 Points** (No typosquatting, safe attachment extension `.txt`) |
| **Attachment Intelligence** | Clean text document; no scripts or executable payloads |
| **VirusTotal ($S_{\text{vt}}$)** | No external links present |

### 🎙️ What to Say to the Panel:
> *"Notice that Aegis recognizes routine, conversational language without triggering false alarms. The DistilBERT model accurately classifies the semantic intent as standard workplace coordination, resulting in a single-digit Safe score with zero user interruption."*
