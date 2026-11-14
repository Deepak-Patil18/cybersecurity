| IOC | Type | Where seen | Tool to check | What a bad result looks like | Verdict |
|-----|------|------------|---------------|------------------------------|---------|
| 198.51.100.77 | IP | Proxy logs, every 60s | AbuseIPDB, VirusTotal | Recent abuse reports, C2 tag | Suspicious (beaconing) |
| secure-invoice-review[.]example | Domain | Email sender + link | whois, VirusTotal, urlscan | Registered days ago, phishing tag | ___ |
| files-update-center[.]example/payload.bin | URL | Second-stage download | URLhaus, urlscan | Listed as malware download | ___ |
| d16c047a...ab20d39 | SHA256 | Invoice_Q3.xlsm | VirusTotal | Many engines flag; macro/dropper label | ___ |
| 203.0.113.45 | IP | Also in Alert #1042 | Your own Day 11 logs | Same actor as the SSH compromise? | ___ |
