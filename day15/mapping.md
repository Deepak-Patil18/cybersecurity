# Alert 3001 — ATT&CK Mapping

| Time | Event | Meaning | ATT&CK tactic | ATT&CK technique |
|------|-------|---------|---------------|------------------|
| 02:10:01-02:10:31 | 4625 x11 | An outside IP guessed passwords 11 times for Administrator and admin | Credential Access | T1110 Brute Force (T1110.001 Password Guessing) |
| 02:10:36 | 4624 type 10 | The attacker logged in over Remote Desktop as Administrator | Initial Access / Lateral Movement | T1078 Valid Accounts with T1021.001 Remote Desktop Protocol |
| 02:12:08 | 4688 whoami /all | The attacker checked which account and privileges they had | Discovery | T1033 System Owner/User Discovery |
| 02:12:40 | 4688 powershell -enc | A hidden, Base64-encoded PowerShell command was run | Execution / Defense Evasion | T1059.001 PowerShell with T1027 Obfuscated Files or Information |
| 02:14:15 | 4720 | A new account called svc_helpdesk was created | Persistence | T1136.001 Create Account: Local Account |
| 02:14:30 | 4732 | svc_helpdesk was added to the Administrators group | Persistence / Privilege Escalation | T1098 Account Manipulation |
| 02:16:02 | 7045 | A service called WinUpdateSvc was installed to run upd.exe | Persistence | T1543.003 Create or Modify System Process: Windows Service |
| 02:17:20 | 4698 | A scheduled task was created to run upd.exe daily | Persistence | T1053.005 Scheduled Task/Job: Scheduled Task |
| 02:25:50 | 1102 | The Security audit log was cleared to hide the activity | Defense Evasion | T1070.001 Indicator Removal: Clear Windows Event Logs |
