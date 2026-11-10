# Academic Citation & Primary Source Verification Audit (E-25)

- **Evidence ID:** E-25
- **Produced By:** I-17 / Academic Literature Verification
- **Commit:** `a482063`
- **Specification:** AEGIS Implementation Plan v3.2 §4.2, §7 (I-17) & Revision Matrix Rows 18, 19, 20

---

## 1. Verified Primary Reference Audit Table

| Source ID | Author(s) / Organization | Year | Title / Publication Venue | Verification Type & Link / Identifier | Usage in Aegis Manuscript |
|---|---|---|---|---|---|
| **REF-01** | Herrera, M., Aich, A., & Parde, N. | 2022 | *TweetTaglish: A Dataset for Investigating Tagalog-English Code-Switching*<br>Proceedings of the 13th Language Resources and Evaluation Conference (LREC 2022), pp. 3171–3178. | Peer-reviewed Proceedings (ACL Anthology: `2022.lrec-1.339`) | Linguistic basis for Taglish code-switching detection in Philippine electronic communications (Ch. 1 Sec. 1.5, Ch. 3 Sec. 3.4). |
| **REF-02** | Sanh, V., Debut, L., Chaumond, J., & Wolf, T. | 2019 | *DistilBERT, a distilled version of BERT: smaller, faster, cheaper and lighter*<br>arXiv preprint arXiv:1910.01108. | Pre-print / Hugging Face Architecture (`arXiv:1910.01108`) | Neural NLP architecture foundation for the Layer 2 ONNX inference engine (Ch. 2 Sec. 2.3, Ch. 3 Sec. 3.3). |
| **REF-03** | Lemonade SDK Team | 2023 | *Phishing Email Detection DistilBERT ONNX Checkpoint*<br>Hugging Face Hub Model Repository. | Verified Checkpoint Repository (`lemonade-sdk/phishing-email-detection-distilbert-ONNX`) | Pre-trained 4-class ONNX checkpoint (`phishing_distilbert_onnx_4cls`, SHA256 `361ebc80...`) utilized in Layer 2 (E-21). |
| **REF-04** | Trend Micro | 2024 | *Navigating New Frontiers: Trend Micro 2023 Annual Cybersecurity Report*<br>Trend Micro Research, Tokyo, Japan. | Industry Threat Intelligence Report (`trendmicro.com/vinfo/us/security/research-and-analysis/threat-reports`) | Prevalence data on phishing targeting Philippine SMEs and financial infrastructure (Ch. 1 Sec. 1.1). |
| **REF-05** | Fortinet | 2024 | *Global Threat Landscape Report: 2023 H2 / 2024 Outlook*<br>FortiGuard Labs, Sunnyvale, CA. | Industry Threat Intelligence Report (`fortinet.com/fortiguard/threat-intelligence`) | Threat landscape data on brand impersonation and QR/social engineering trends (Ch. 1 Sec. 1.1). |
| **REF-06** | Wilson, E. B. | 1927 | *Probable Inference, the Law of Population, and the Known Fact*<br>Journal of the American Statistical Association, 22(158), 209–212. | Peer-reviewed Journal Article (`doi:10.1080/01621459.1927.10502953`) | Mathematical formulation of Wilson score confidence intervals for binomial proportion verification (E-32). |
| **REF-07** | Brooke, J. | 1996 | *SUS: A 'Quick and Dirty' Usability Scale*<br>In P. W. Jordan, B. Thomas, B. A. Weerdmeester, & A. L. McClelland (Eds.), *Usability Evaluation in Industry* (pp. 189–194). Taylor & Francis. | Standard Academic Usability Methodology (`ISBN: 0-7484-0460-0`) | Framework for User Acceptance Testing (UAT) usability and clarity evaluation (E-23). |
| **REF-08** | Kitterman, S. (Ed.) | 2014 | *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1*<br>IETF Request for Comments: RFC 7208. | Internet Standard RFC (`rfc-editor.org/rfc/rfc7208`) | Formal technical basis for SPF authentication penalty evaluation in Layer 1 heuristics. |
| **REF-09** | Crocker, D. (Ed.), Hansen, T. (Ed.), & Kucherawy, M. (Ed.) | 2011 | *DomainKeys Identified Mail (DKIM) Signatures*<br>IETF Request for Comments: RFC 6376. | Internet Standard RFC (`rfc-editor.org/rfc/rfc6376`) | Formal technical basis for DKIM cryptographic signature verification in Layer 1 heuristics. |

---

## 2. Disavowed & Retracted References

1. **Google Gmail API Documentation:** Retracted as a system integration citation. Aegis operates purely in the DOM (`MutationObserver`); no Gmail API OAuth or REST calls exist in the runtime codebase.
2. **DMARC Policy Enforcement RFC 7489:** Retracted as an implemented runtime mechanism. The system does not parse or enforce DMARC policies.
