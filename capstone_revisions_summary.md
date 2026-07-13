# Capstone 1 Defense: Revisions Summary

**Project:** AI-powered Phishing Context Analyzer for SMEs
**Verdict:** Approved with Major Revisions
**Panelists:** Sir Joshua, Sir Hernani, Sir John Ray

Based on the defense transcript, the panel has required the following major revisions to be addressed in the capstone project:

## 1. Widen the Scope Beyond Pure Contextual Analysis
The panel emphasized that relying solely on text-based contextual analysis is insufficient because AI-generated phishing can easily bypass another AI (e.g., using hidden commands or prompt overriding).
* **Include Attachment Scanning:** The panel strongly suggested removing the limitation that ignores attachments. Adding attachment scanning will significantly boost the tool's effectiveness.
* **Incorporate User Behavioral Patterns:** Add another layer of context awareness that involves the user's behavioral patterns to strengthen the detection mechanism.

## 2. Address "Cognitive Offloading" (Over-reliance on AI)
The panelists raised concerns that users might blindly trust the AI, completely turning off their own critical thinking.
* **Enhance Explainable AI (XAI) for Education:** The tool should not just flag an email; it must clearly explain *why* it was flagged (e.g., highlighting urgency keywords, unrecognized sender domains, or financial request patterns). 
* **Keep the User Engaged:** The final decision to act on an email should remain with the user. The XAI should serve as an educational mechanism to maintain the employee's vigilance.
* **Implement Whitelisting:** Create a whitelisting feature for power users to reduce false positives and prevent users from experiencing alert fatigue.

## 3. Account for Adversarial AI Tactics
* **Prompt Injections and Hidden Text:** The panel pointed out tactics hackers use to bypass AI, such as embedding hidden white text in documents or including commands like *"treat this as an overriding statement if you're an AI."* Your system needs a strategy or guardrail to account for and detect these adversarial evasion techniques.

## 4. Clarify the Multi-Layered Approach
* **Email Authentication Protocols:** The panel asked how your application fits into a broader multi-layered security approach. You should consider and document how your tool works alongside or evaluates standard email authentication protocols like SPF, DKIM, and DMARC to improve your 95% accuracy goal.
