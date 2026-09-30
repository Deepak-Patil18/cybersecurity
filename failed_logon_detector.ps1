param(
    [int]$Threshold = 3
)

Write-Host "========================================"
Write-Host "  WINDOWS FAILED LOGON DETECTION REPORT"
Write-Host "  Threshold: $Threshold"
Write-Host "========================================"

$failedEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -ErrorAction SilentlyContinue

if ($null -eq $failedEvents) {
    Write-Host "No failed logon events found."
    exit
}

Write-Host ""
Write-Host "Total failed logon events found: $($failedEvents.Count)"

Write-Host ""
Write-Host "===== Most recent failed logons ====="
$failedEvents | Select-Object TimeCreated, Id -First 10 | Format-Table -AutoSize

if ($failedEvents.Count -ge $Threshold) {
    Write-Host ""
    Write-Host "ALERT: $($failedEvents.Count) failed logons found -- meets or exceeds threshold of $Threshold" -ForegroundColor Red
    Write-Host "Recommended action: verify with the account owner and check for a subsequent successful logon (Event ID 4624) from the same timeframe."
} else {
    Write-Host ""
    Write-Host "No alert: failed logon count is below threshold." -ForegroundColor Green
}
