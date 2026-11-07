import re

file_path = r'aegis-extension\overlay\overlay.js'
with open(file_path, 'rb') as f:
    raw = f.read()

# Replace UTF-8 encoded sequence for mojibake â€” (0xC3 0xA2 0xE2 0x82 0xAC 0xE2 0x80 0x9D or literal string)
text = raw.decode('utf-8', errors='replace')
count_dash = text.count('â€”')
count_arrow = text.count('â†’')
text = text.replace('â€”', '—').replace('â†’', '→')

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(text)

print(f'Replaced {count_dash} dashes and {count_arrow} arrows.')
