<#
    Aegis Capstone Phishing Simulation Script
    Type: Harmless Simulated Script Execution (PowerShell)
    Purpose: Evaluates detection of dangerous script extensions (.ps1) in email attachments.
#>

Write-Host "==========================================================" -ForegroundColor Red
Write-Host " [AEGIS SIMULATION] Simulated Malicious Script Attachment" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Red
Write-Host "In a real phishing scenario, this script would attempt privilege escalation"
Write-Host "or lateral network movement. No changes were made to your system."
[System.Windows.Forms.MessageBox]::Show(
    "Aegis Phishing Analyzer Demo: Dangerous script attachment detected!", 
    "Aegis Security Alert", 
    [System.Windows.Forms.MessageBoxButtons]::OK, 
    [System.Windows.Forms.MessageBoxIcon]::Warning
)
