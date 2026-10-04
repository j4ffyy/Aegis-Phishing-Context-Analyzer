# Demo Email 5: Critical Threat (Executive Impersonation / BEC)

Use this email to demonstrate **Business Email Compromise (BEC)** and **Display-Name Spoofing with Whitelist Dynamic Auto-Revocation**.

This attack contains **no hyperlinks and no attachments**, proving that Aegis detects semantic coercion and identity fraud where traditional filters completely fail!

---

## 📧 Email Setup & Content to Send

### Setup Step (Display Name Spoofing)
When sending from your alternate email or testing account, set your **Display Name** to an executive title (e.g. `Executive Director` or `Chief Executive Officer`), while your actual sending email address remains different.

| Field | Exact Text to Paste |
| :--- | :--- |
| **Sender Display Name** | `Executive Director` *(or CEO)* |
| **To** | *(Your primary Gmail account)* |
| **Subject** | `Urgent: Confidential Vendor Acquisition Wire Transfer` |
| **Attachment** | *None* |

### Body Text:
```text
Are you at your desk right now?

I am currently tied up in an urgent board meeting with external partners and cannot take phone calls. 

I need you to process an urgent wire transfer for a confidential contract milestone today before 3:00 PM. Please confirm your availability immediately so I can send over the vendor's routing numbers and settlement invoice. 

Keep this strictly between us until the acquisition announcement is official.

Thanks,
Executive Director
```

---

## 🎯 Expected Aegis Output

| Layer / Indicator | Expected Result |
| :--- | :--- |
| **Risk Tier** | 🔴 **CRITICAL** (Red Overlay Badge) |
| **Risk Score** | **90% – 95%** |
| **DistilBERT NLP ($S_{\text{nlp}}$)** | **High Phishing / BEC Intent**: Model detects high-urgency financial wire request without normal business formality |
| **Whitelist Revocation** | If "Executive Director" is in your Aegis Whitelist, Aegis immediately triggers: <br>`[AUTO-REVOKE TRIGGER 1] Display-name spoofing detected!` and forces score to **95% Critical** |
| **Heuristics ($S_{\text{heuristic}}$)** | Flags wire transfer coercion patterns (*"urgent wire transfer"*, *"confidential"*, *"cannot take phone calls"*) |

### 🎙️ What to Say to the Panel:
> *"Notice that this email contains neither malicious hyperlinks nor attachments—traditional signature filters like SpamAssassin will let this right through into the inbox. But Aegis's DistilBERT model detects executive pressure and financial coercion semantics. Furthermore, our Whitelist Auto-Revocation engine detects that the sender is claiming an executive identity from an unrecognized external address, instantly overriding trust."*
