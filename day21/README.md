# Day 21 Cybersecurity Investigation

This project documents a fictional phishing incident investigated using email, endpoint, network, and malware evidence.

## Deliverables

- `timeline.md` — unified incident timeline
- `mapping.md` — ATT&CK mapping
- `INCIDENT_REPORT_5001.md` — incident report and response plan
- `briefing_notes.md` — manager briefing
- `endpoint_findings.md`, `network_findings.md`, and `malware_findings.md` — findings by evidence source
- `rules3/`, `local3.rules`, and `dropper3.yar` — detection rules

The investigation found a phishing-led compromise, scheduled-task persistence, access to the HR share using `svc_backup`, and an upload flow to a known C2 address. The archive contents, size, and total data exposure remain unconfirmed.
