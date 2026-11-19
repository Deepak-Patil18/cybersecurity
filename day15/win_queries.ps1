# Parse logon events (run in an Administrator PowerShell on Windows)
function Get-LogonEvents($Id, $Max = 20) {
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$Id} -MaxEvents $Max -ErrorAction SilentlyContinue | ForEach-Object {
    $d = @{}
    ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ Time = $_.TimeCreated; User = $d['TargetUserName']; LogonType = $d['LogonType']; SourceIP = $d['IpAddress'] }
  }
}
# Failed logons, new users, scheduled tasks
Get-LogonEvents 4625 | Format-Table -AutoSize
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} -MaxEvents 5 | Format-List TimeCreated, Message
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} -MaxEvents 5 | Format-List TimeCreated, Message
# Sysmon: process creation and DNS queries
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 5 | Format-List TimeCreated, Message
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=22} -MaxEvents 5 | Format-List TimeCreated, Message
