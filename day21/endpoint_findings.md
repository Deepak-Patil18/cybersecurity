# Endpoint findings
- Account used to reach FS-01: svc_backup (used by ravi.k via explicit credentials at 09:15:02)
- Staged data: FS-01 (robocopy into C:\Users\Public\x, archive hr.7z)
- First endpoint alert: 09:05:12 (.scr launched from Outlook), about 3 minutes after the email at 09:02:11
- Open questions: how svc_backup's password was obtained; the size and later fate of hr.7z
- Note: the 7-Zip command line contains the archive password, so treat it as leaked
