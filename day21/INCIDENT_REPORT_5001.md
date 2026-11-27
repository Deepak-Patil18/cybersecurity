# Incident Report — Ticket 5001

## 1. Executive summary

A phishing email sent to ravi.k led to a malicious screensaver file running on WS-022 within minutes. The file established persistence, ran hidden PowerShell, and was followed by use of the svc_backup account to access FS-01 and stage HR data. Network records show repeated connections to an attacker-controlled address and a later 58,299-byte upload to that address. The incident is critical, while the archive’s contents, size, and total amount of data taken remain unconfirmed.

## 2. Severity and status

**Severity: CRITICAL.** Evidence shows a compromised endpoint, persistence, use of a service account to access FS-01, HR data staging, and an outbound upload to a known attacker address.

**Status:** The supplied evidence supports the incident sequence. Scope and data exposure remain under investigation.

## 3. Timeline

| Time UTC | Source | Event | Host or account |
|---|---|---|---|
| 09:02:11 | Email | Phishing email sent from 203.0.113.77. Delivered at 09:02:15. | ravi.k |
| 09:04:55 | Network | Looked up invoice-portal-update.example and opened the fake login page. | WS-022 |
| 09:05:12 | Endpoint | Salary_Revision.pdf.scr launched from Outlook. | WS-022, ravi.k |
| 09:05:30 | Network | Downloaded /upd.bin from cdn-sync-files.example. | WS-022 |
| 09:05:40 | Endpoint | Hidden, encoded PowerShell started by the .scr file. | WS-022, ravi.k |
| 09:06:10 | Endpoint | Created OneDriveSync scheduled task to run AppData\Roaming\upd.exe. | WS-022, ravi.k |
| 09:06:20–09:10:50 | Network | Ten connections to 198.51.100.99:443, spaced 30 seconds apart. | WS-022 |
| 09:08:30 | Endpoint | Ran `net group "Domain Admins" /domain`. | ravi.k |
| 09:15:02–09:15:10 | Endpoint | Used svc_backup credentials to access FS-01. A network logon on FS-01 came from 10.0.2.45. | ravi.k, svc_backup, FS-01 |
| 09:16:30 | Endpoint | Copied the HR share into C:\Users\Public\x with robocopy. | svc_backup, FS-01 |
| 09:18:45 | Endpoint | Created password-protected archive hr.7z. | svc_backup |
| 09:29:50 | Network | The POST flow to 198.51.100.99/upload sent 58,299 bytes to the server. | WS-022 |

## 4. Evidence by source

- **Email:** phish3.eml records the phishing message and its sender details.
- **Endpoint:** events3.jsonl and the mini-SIEM output show the .scr launch, hidden PowerShell, scheduled task, domain group discovery, explicit-credential logon, robocopy, and 7-Zip activity. The run produced seven alerts from six rules over ten events.
- **Network:** network3.pcap produced one alert for each of the four Suricata rules. Flow records show ten 30-second connections to the C2 address and a later upload flow.
- **Malware:** dropper3.bin is an MZ executable with SHA-256 `cffe1691c599b981696d62e8fc0b5bd06f12c579c316b847718e74ad03f40086`. Its strings include the C2 indicators, scheduled task, encoded PowerShell, staging commands, download and injection APIs, and IsDebuggerPresent. Overall entropy was 6.88. The YARA rule matched the dropper.

## 5. Affected assets and accounts

- WS-022
- FS-01 and its HR share
- ravi.k
- svc_backup

## 6. Data impact

Endpoint evidence shows the HR share copied to C:\Users\Public\x and archived as hr.7z. Network evidence records 58,299 bytes sent in the upload flow to 198.51.100.99. The archive’s size, contents, and whether it was the data in that upload have not been confirmed. Verify the archive’s location and size on the relevant host before stating the total amount of data taken.

## 7. Indicators of compromise

| Indicator | Value | Confidence |
|---|---|---|
| C2 IP address | 198[.]51[.]100[.]99 | High |
| Phishing sender IP | 203[.]0[.]113[.]77 | High |
| Phishing domain | invoice-portal-update[.]example | High |
| Download domain | cdn-sync-files[.]example | High |
| Download URL | hxxp://cdn-sync-files[.]example/upd.bin | High |
| Scheduled task | OneDriveSync | High |
| Dropper SHA-256 | cffe1691c599b981696d62e8fc0b5bd06f12c579c316b847718e74ad03f40086 | High |

## 8. ATT&CK mapping

- Phishing link and attachment: Initial Access, T1566.002 and T1566.001.
- User opens the .scr file: Execution and Stealth, T1204.002 and T1036.007.
- Hidden, encoded PowerShell: Execution and Stealth, T1059.001 and T1027.
- Scheduled task: Persistence, T1053.005.
- upd.bin download: Command and Control, T1105.
- Beaconing: Command and Control, T1071.001.
- Domain group discovery: Discovery, T1069.002.
- svc_backup access to FS-01: Lateral Movement, T1021.002, with valid-account use T1078.
- HR share copy: Collection, T1039.
- Local staging and 7-Zip archive: Collection, T1074.001 and T1560.001.
- Upload to C2: Exfiltration, T1041.

## 9. Root cause and control gaps

The evidence indicates that the incident began when a user opened a phishing attachment named Salary_Revision.pdf.scr. The dropper then ran hidden PowerShell and created a scheduled task. The svc_backup account was later used to access FS-01, but the evidence does not establish how its credentials were obtained. Review attachment filtering, script execution controls, service-account use, and monitoring for repeated beaconing and outbound uploads.

## 10. Response plan

### Containment
- Isolate WS-022 while keeping it powered on for memory capture and triage.
- Block 198.51.100.99, 203.0.113.77, invoice-portal-update.example, and cdn-sync-files.example.
- Disable svc_backup and reset its credentials.
- Find and remove the phishing email from recipient mailboxes. Identify all recipients.

### Scope
- Search mail logs for the sender and subject, then search proxy, DNS, and endpoint logs for the indicators.
- Preserve and examine hr.7z and the staging folder. Confirm their host, size, and contents.
- Check other systems accessed by svc_backup.
- Check whether the archive password pattern appears elsewhere.

### Eradication
- Preserve evidence, then remove the OneDriveSync task and upd.exe.
- Reimage WS-022.
- After collecting the archive and staging folder as evidence, remove them from the host where they are found.

### Recovery and prevention
- Reset ravi.k’s credentials.
- Block .scr files and misleading double-extension attachments at the mail gateway. Set DMARC to reject.
- Stop using a shared service account for interactive logons.
- Deploy the Part 3 and Part 4 detections. Alert on large uploads and password-protected 7-Zip archives.
- Notify HR and Legal so they can assess whether personal data may be involved.

## 11. Detections added

- Endpoint rules in rules3/*.yml
- Four Suricata rules in local3.rules
- YARA rule P3_Dropper in dropper3.yar

## 12. Lessons learned

- Phishing attachments with misleading extensions can lead directly to code execution.
- Shared service accounts make it harder to limit and trace access to file servers.
- Repeated outbound connections and unusual uploads should be investigated alongside endpoint alerts.
- Preserve evidence and verify archive size and contents before concluding how much data left the network.
