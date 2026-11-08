# Standard System Usability Scale (SUS) Questionnaire

**Participant ID:** `P___` | **Interface Evaluated:** Aegis Two-Tier XAI Overlay  
**Scale:** 1 = Strongly Disagree, 2 = Disagree, 3 = Neutral, 4 = Agree, 5 = Strongly Agree  

---

Please indicate your level of agreement with each of the following 10 statements:

| No. | Statement | 1 (SD) | 2 (D) | 3 (N) | 4 (A) | 5 (SA) |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **Q1** | I think that I would like to use Aegis frequently in my daily work. | [ ] | [ ] | [ ] | [ ] | [ ] |
| **Q2** | I found Aegis unnecessarily complex to understand. | [ ] | [ ] | [ ] | [ ] | [ ] |
| **Q3** | I thought Aegis was easy to use. | [ ] | [ ] | [ ] | [ ] | [ ] |
| **Q4** | I think that I would need the assistance of a technical person to be able to use Aegis. | [ ] | [ ] | [ ] | [ ] | [ ] |
| **Q5** | I found the various functions in Aegis were well integrated. | [ ] | [ ] | [ ] | [ ] | [ ] |
| **Q6** | I thought there was too much inconsistency in Aegis. | [ ] | [ ] | [ ] | [ ] | [ ] |
| **Q7** | I would imagine that most people would learn to use Aegis very quickly. | [ ] | [ ] | [ ] | [ ] | [ ] |
| **Q8** | I found Aegis very cumbersome to use. | [ ] | [ ] | [ ] | [ ] | [ ] |
| **Q9** | I felt very confident using Aegis to identify suspicious emails. | [ ] | [ ] | [ ] | [ ] | [ ] |
| **Q10** | I needed to learn a lot of things before I could get going with Aegis. | [ ] | [ ] | [ ] | [ ] | [ ] |

---

## SUS Composite Score Calculation Formula (Brooke, 1996)

For odd-numbered questions ($Q_1, Q_3, Q_5, Q_7, Q_9$):
$$\text{Score Contribution} = \text{Scale Position} - 1$$

For even-numbered questions ($Q_2, Q_4, Q_6, Q_8, Q_10$):
$$\text{Score Contribution} = 5 - \text{Scale Position}$$

**Total Composite SUS Score (0–100):**
$$\text{SUS Total} = 2.5 \times \left( \sum_{i \in \{1,3,5,7,9\}} (Q_i - 1) + \sum_{j \in \{2,4,6,8,10\}} (5 - Q_j) \right)$$

### Benchmark Interpretation:
- **$\ge 80.3$:** Grade A (Excellent / Top 10% usability)
- **$68.0\text{--}80.2$:** Grade B (Good / Above average industry benchmark)
- **$51.0\text{--}67.9$:** Grade C (Marginal / Needs improvement)
- **$< 51.0$:** Grade F (Unacceptable / Usability failure)
