# Email Analysis Report — Ticket 4001
## Verdict: ___ (phishing / suspicious / benign)   Confidence: ___
## Summary (2-3 sentences, plain English)
___
## Evidence
Sender mismatch: From ___ / Return-Path ___ / Reply-To ___
Authentication: SPF ___  DKIM ___  DMARC ___
Origin IP (first hop): ___
Links (defanged): shown ___ -> real ___
Attachment: name ___  type ___  sha256 ___
## IOCs (defanged)
___
## ATT&CK mapping
___
## Scope and actions
Search mail gateway for: ___   Block: ___   Purge from mailboxes: ___
If a user clicked or opened: reset credentials, check proxy logs for ___, isolate host if ___
## Prevention
DMARC reject, external-mail banner, attachment filtering, phishing training, report-phish button
