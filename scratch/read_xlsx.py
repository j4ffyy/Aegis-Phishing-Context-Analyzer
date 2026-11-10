import openpyxl
from pathlib import Path

wb = openpyxl.load_workbook("Aegis-Phishing-Context-Analyzer (Responses).xlsx")
sheet = wb.active
assert sheet is not None, "Workbook has no active sheet"
for r_idx, row in enumerate(sheet.iter_rows(values_only=True)):
    print(f"Row {r_idx}: {row}")
