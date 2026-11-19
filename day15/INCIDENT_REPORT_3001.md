# Incident Report — Ticket 3001 (WIN-SRV01)
## Executive summary (3 sentences, plain English)
___
## Severity: ___ (justify with at least 3 reasons)
## Timeline (from the events)
___
## Indicators (defanged): attacker IP, account svc_helpdesk, service WinUpdateSvc,
file C:\ProgramData\upd.exe, task \Microsoft\UpdateCheck
## Root cause: RDP exposed to the internet with a guessable Administrator password
## Recommended actions
Immediate: isolate the server; block 203.0.113.45; disable svc_helpdesk; ___
Eradication: remove the service, the task and upd.exe; reset every credential on the host; ___
Prevention: close RDP to the internet (use VPN), MFA, account lockout, alert on 4625 bursts,
alert on 4720 + 4732, alert on 1102, forward logs to a SIEM so they survive log clearing
