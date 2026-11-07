import math
from pathlib import Path

def wilson_ci(k, n, confidence=0.95):
    if n == 0:
        return (0.0, 0.0)
    z = 1.959963984540054
    p = k / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    spread = (z * math.sqrt((p * (1 - p) / n) + (z**2 / (4 * n**2)))) / denom
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return lower * 100, upper * 100


metrics = [
    ("Accuracy", 93, 100, 93.0),
    ("Precision", 43, 43, 100.0),
    ("Recall (Observed: 43/50)", 43, 50, 86.0),
    ("Recall (User Example: 88/100)", 88, 100, 88.0),
    ("False Positive Rate (0/50)", 0, 50, 0.0),
]

output = []
output.append("=================================================================")
output.append("  AEGIS BENCHMARK METRICS: 95% CONFIDENCE INTERVALS")
output.append("=================================================================")
output.append(f"{'Metric':<35} | {'Point Est.':<16} | {'95% CI (Wilson)':<18}")
output.append("-" * 75)

for name, k, n, est in metrics:
    w_low, w_high = wilson_ci(k, n)
    output.append(f"{name:<35} | {est:>6.2f}% ({k}/{n:<3})   | [{w_low:5.1f}%, {w_high:5.1f}%]")

output.append("=================================================================")
output.append("")
output.append("Notes:")
output.append("1. Accuracy (93/100): 93.0% with 95% Wilson CI [86.3%, 96.6%].")
output.append("2. Recall (43/50): 86.0% with 95% Wilson CI [73.8%, 93.1%].")
output.append("3. Reference 88/100 Recall: 88.0% with 95% Wilson CI [80.2%, 93.0%].")
output.append("4. False Positive Rate (0/50): 0.0% with 95% Wilson CI [0.0%, 7.1%].")
output.append("5. Precision (43/43): 100.0% with 95% Wilson CI [91.8%, 100.0%].")

text = "\n".join(output)
print(text)

dest = Path("evidences/05_confidence_intervals.txt")
dest.write_text(text, encoding="utf-8")
print(f"Saved to {dest}")
