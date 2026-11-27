# Unified timeline

| Time UTC | Source | What happened | Host or account |
|---|---|---|---|
| 09:02:11 | Email | Phishing email sent from 203.0.113.77. Delivered at 09:02:15. | ravi.k |
| 09:04:55 | Network | Looked up invoice-portal-update.example and opened the fake login page. | WS-022 |
| 09:05:12 | Endpoint | Salary_Revision.pdf.scr launched from Outlook. | WS-022, ravi.k |
| 09:05:30 | Network | Downloaded /upd.bin from cdn-sync-files.example. | WS-022 |
| 09:05:40 | Endpoint | Hidden, encoded PowerShell started by the .scr file. | WS-022, ravi.k |
| 09:06:10 | Endpoint | OneDriveSync scheduled task created to run AppData\Roaming\upd.exe. | WS-022, ravi.k |
| 09:06:20 | Network | First C2 beacon to 198.51.100.99:443. Ten total beacons occurred at 30-second intervals through 09:10:50. | WS-022 |
| 09:08:30 | Endpoint | Ran `net group "Domain Admins" /domain` for discovery. | WS-022, ravi.k |
| 09:15:02–09:15:10 | Endpoint | Used svc_backup credentials to access FS-01. | WS-022, ravi.k, svc_backup, FS-01 |
| 09:16:30 | Endpoint | Copied the HR share into C:\Users\Public\x with robocopy. | WS-022, svc_backup, FS-01 |
| 09:18:45 | Endpoint | Created the password-protected hr.7z archive. | WS-022, svc_backup |
| 09:29:50 | Network | POSTed 58,299 bytes to 198.51.100.99/upload. | WS-022 |
