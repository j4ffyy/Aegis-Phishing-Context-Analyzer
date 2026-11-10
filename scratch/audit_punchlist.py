import sys
import re

sys.stdout.reconfigure(encoding='utf-8')  # type: ignore[union-attr]
with open(r'c:\Users\jafph\Desktop\Capstone 1 - Phishing Analyzer\Aegis-Phishing-Context-Analyzer\MO-IT200D2_S4102_Group1_Capstone2_CORRECTED.md', encoding='utf-8') as f:
    text = f.read()

checks = {
    '40/60 or 40 phishing': len(re.findall(r'40\s*(?:phishing|legitimate|/|\-)', text, re.I)),
    '96.0% or 96%': len(re.findall(r'96(?:\.0)?%', text)),
    '92.9%': len(re.findall(r'92\.9%', text)),
    '97.5%': len(re.findall(r'97\.5%', text)),
    '5.0% FPR': len(re.findall(r'5\.0%\s*(?:false|FPR)', text, re.I)),
    '0.951': len(re.findall(r'0\.951', text)),
    '1.1 s or 1.1 second': len(re.findall(r'1\.1\s*(?:s\b|second)', text, re.I)),
    'fine-tuned': len(re.findall(r'fine[- ]tuned', text, re.I)),
    'Itua': len(re.findall(r'Itua', text)),
    'Jaffyyyyyy': len(re.findall(r'Jaffyyyyyy', text)),
    '14 weeks': len(re.findall(r'14\s*weeks', text, re.I)),
    'purple span / style': len(re.findall(r'style=[\"\'][^\"\']*color:\s*(?:purple|#|rgb)', text, re.I)),
    'mermaid code blocks': len(re.findall(r'```mermaid', text)),
    'TP=39': len(re.findall(r'TP=39', text)),
    'reference 88/100': len(re.findall(r'88/100', text)),
    'full compliance with RA 10173': len(re.findall(r'full compliance with RA 10173', text, re.I)),
    'zero-licensing-cost': len(re.findall(r'zero-licensing-cost', text, re.I)),
}

print("=== AUDIT RESULTS ===")
for k, v in checks.items():
    print(f'{k}: {v} matches')
