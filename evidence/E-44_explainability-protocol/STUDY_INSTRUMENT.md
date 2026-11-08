# Study Instrument & Scenario Evaluation Form

**Participant ID:** `P___` | **Condition Order:** `[ ] A -> B  |  [ ] B -> A` | **Date:** `2026-___-___`  
**Proctor Name:** `____________________`  

---

## Scenario 1: Safe Tier (Legitimate Corporate Invoice)
**Context:** Routine monthly telecommunications invoice from an established corporate provider.  
**Email Subject:** *PLDT Enterprise Monthly Statement of Account - October 2026*  
**Sender:** `billing@pldtenterprise.com`  
**Authentication:** SPF: Pass, DKIM: Pass | **Attachment:** `PLDT_eSOA_Oct2026.pdf` | **Links:** None  
**Aegis Score:** 14/100 (Safe Tier)  

### Alert Views Displayed:
- **Condition A (Technical View - Toggle OFF):**  
  *Pre-processing: Clean HTML | Layer 1: Auth SPF=Pass, DKIM=Pass | Layer 1b: Domain Levenshtein=0 | Layer 2 NLP: Intent P(phish)=0.02 | Layer 3: Sender Baseline count=14, CircularDist=1.2h | Synthesis: R=14 (Tier: Safe).*
- **Condition B (Plain-Language View - Toggle ON):**  
  *Sender Legitimacy: Confirmed sent by genuine organization (not spoofed) | Message Tone: Normal context without fake urgency or threats | File Attachments: Attached files safe & verified | Sender Routine: Routine sender during normal business hours.*  
  *Recommendation: This email passed all security checks. Safe to proceed.*

### Questions:
1. **Comprehension Prompt:** *"In your own words, what is Aegis telling you about this email?"*  
   *Participant Response (Verbatim):*  
   `____________________________________________________________________________________`  
   `____________________________________________________________________________________`  
2. **Action Decision:** *"What action would you take right now?"*  
   - [ ] **A:** Open the attachment / proceed with invoice processing *(Correct / Safe)*  
   - [ ] **B:** Reply to sender to ask if it is real  
   - [ ] **C:** Call company IT helpdesk to verify  
   - [ ] **D:** Mark as spam and delete immediately  
3. **Task Completion Time:** `______` seconds (from display to action decision).

---

## Scenario 2: Warning Tier (Unfamiliar Supplier Payment Redirection)
**Context:** Email claiming to be from an existing vendor announcing new bank account deposit details, sent at 11:30 PM on Saturday.  
**Email Subject:** *Urgent Update: New Banking Deposit Details for Pending Invoices*  
**Sender:** `accounts@apexlogistics-ph.online` *(Spoofed; genuine domain is `apexlogistics.com.ph`)*  
**Authentication:** SPF: Pass (own domain), DKIM: Pass | **Attachment:** None | **Links:** `http://apexlogistics-ph.online/deposit-slip`  
**Aegis Score:** 52/100 (Warning Tier)  

### Alert Views Displayed:
- **Condition A (Technical View - Toggle OFF):**  
  *Layer 1: Brand Levenshtein edit distance = 2 | Layer 1b: Non-standard domain TLD (.online) | Layer 2 NLP: High financial keyword density | Layer 3: Unfamiliar sender (n=0), CircularDist=9.5h (Off-hours anomaly, Weekend transmission) | Synthesis: R=52 (Tier: Warning).*
- **Condition B (Plain-Language View - Toggle ON):**  
  *Sender Legitimacy: Warning: Sender address is unfamiliar and differs from verified company domain | Sender Routine: First-time sender transmitting at unusual late-night weekend hours | Message Tone: Urgent payment request detected.*  
  *Recommendation: CAUTION: Exercise care before responding or opening links. Verify banking changes via phone with known contact before remitting payments.*

### Questions:
1. **Comprehension Prompt:** *"In your own words, what is Aegis telling you about this email?"*  
   *Participant Response (Verbatim):*  
   `____________________________________________________________________________________`  
   `____________________________________________________________________________________`  
2. **Action Decision:** *"What action would you take right now?"*  
   - [ ] **A:** Click the link and update the payment banking records immediately  
   - [ ] **B:** Reply directly to this email asking for confirmation  
   - [ ] **C:** Call the vendor's known accounts manager via telephone to verify before paying *(Correct / Safe Policy)*  
   - [ ] **D:** Forward the link to all team members  
3. **Task Completion Time:** `______` seconds.

---

## Scenario 3: Critical Tier (Executive Impersonation / Banking Lock Lure)
**Context:** Email claiming to be BDO Online Security claiming immediate account deactivation unless user logs in.  
**Email Subject:** *URGENT: Your BDO Account Has Been Suspended - Verify Now*  
**Sender:** `security@bdo-online-security.net`  
**Authentication:** SPF: Fail, DKIM: Fail | **Attachment:** `VerificationForm.html` | **Links:** `http://bdo-login.top/verify`  
**Aegis Score:** 88/100 (Critical Tier)  

### Alert Views Displayed:
- **Condition A (Technical View - Toggle OFF):**  
  *Layer 1: SPF=Fail (+25), DKIM=Fail (+20) | Layer 1b: Typosquatting flagged (bdo-online-security.net, edit dist=1) | Layer 2 NLP: High urgency score (S_nlp=92, P_phish=0.998) | Layer 4: VT flagged 18 positive engine hits | Synthesis: R=88 (Tier: Critical, Threat floor enforced).*
- **Condition B (Plain-Language View - Toggle ON):**  
  *Sender Legitimacy: Warning: Sender address appears fake or spoofed | Message Tone: High-pressure urgency and fake security alerts detected | File Attachments: Warning: Dangerous attachment detected | External Threat Scan: Confirmed fake login website.*  
  *Recommendation: HIGH RISK WARNING: Do not click any links or download attachments. This email is an impersonation and fraud attempt. Report to IT and delete immediately.*

### Questions:
1. **Comprehension Prompt:** *"In your own words, what is Aegis telling you about this email?"*  
   *Participant Response (Verbatim):*  
   `____________________________________________________________________________________`  
   `____________________________________________________________________________________`  
2. **Action Decision:** *"What action would you take right now?"*  
   - [ ] **A:** Click the verification link to unlock the account  
   - [ ] **B:** Reply with your login credentials  
   - [ ] **C:** Call BDO directly using the phone number on your bank card  
   - [ ] **D:** Do not click anything; click 'Report Phishing' in Aegis and delete email *(Correct / Safe Policy)*  
3. **Task Completion Time:** `______` seconds.
