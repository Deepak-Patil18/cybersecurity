# Incident Report — Case 6001 (webserver)

## Executive summary
An attacker uploaded a malicious script through a vulnerable file-upload form on our web server and used it to run a cryptocurrency miner that was using almost all of the server's processing power. The attacker also gained full administrator (root) access and left several hidden ways to get back in, so the server can no longer be trusted. We recommend isolating the server, removing every foothold or rebuilding it from a clean image, fixing the upload form, and treating all credentials that were on the server as exposed.

## Severity and impact
Severity: Critical (root-level compromise with persistence).
- Server resources: one process using about 98% CPU for hours (service slowdown and extra cost).
- Access: the attacker had root, so every file, key and password on the server is at risk.
- Data exposure: no evidence in these artifacts of data being copied out, but this is not ruled out. The server also runs a database (mysqld), so it must be checked.

## Timeline (UTC, Oct 21, 2026)
- 03:14:02 POST /upload.php from 203.0.113.45 (curl); file /var/www/html/uploads/cmd.php created (web shell)
- 03:14:20 first web-shell command (c=id)
- 03:14:41 web shell downloads the miner with wget into /tmp/.kworkerd
- 03:15:05 chmod +x on the miner; 03:15:30 miner executed
- 03:16:10 www-data uses sudo to install a root crontab (crontab -u root /tmp/c.txt)
- 03:16:55 /root/.ssh/authorized_keys modified (attacker key added)
- 03:17:02 SSH login as root with the planted key from 203.0.113.45
- 03:18:30 /etc/ld.so.preload modified (points to /tmp/libhide.so)
- 03:20:00 root .bash_history touched; attacker ran history -c to cover tracks
- Later: monitoring sees process 2310 (.kworkerd) at 97.8% CPU, connected to 198.51.100.99:4444

## Root cause
A vulnerable file-upload form (/upload.php) let an attacker place a script (cmd.php) in a folder where the web server executes scripts. Missing controls: no file-type validation, uploads stored inside the web root with execution allowed, www-data allowed to run sudo for crontab, root login over SSH permitted, and no alert on new files or cron changes.

## Persistence found (all five)
1. Web shell /var/www/html/uploads/cmd.php
2. Root cron job: */5 * * * * /tmp/.kworkerd
3. Attacker SSH key in /root/.ssh/authorized_keys (comment: attacker@kali)
4. /etc/ld.so.preload entry loading /tmp/libhide.so (hides the miner)
5. Direct root SSH access using the planted key

## IOCs (defanged)
- Attacker IP: 203[.]0[.]113[.]45
- Miner/pool connection: 198[.]51[.]100[.]99:4444 and pool.minexmr-lab[.]example:4444
- Download domain: files-update-center[.]example
- Files: /var/www/html/uploads/cmd.php, /tmp/.kworkerd, /tmp/libhide.so, /tmp/c.txt
- SSH key comment: attacker@kali
- Cron line: */5 * * * * /tmp/.kworkerd
- User agent: curl/7.81.0
- Hashes: <add the SHA256 of each file once collected from the real server>

## ATT&CK mapping
T1190 Exploit Public-Facing Application; T1505.003 Web Shell; T1059.004 Unix Shell; T1105 Ingress Tool Transfer; T1496 Resource Hijacking; T1053.003 Cron; T1098.004 SSH Authorized Keys; T1574.006 Dynamic Linker Hijacking; T1548.003 Sudo; T1036.005 Match Legitimate Name; T1070.003 Clear Command History. (Confirm IDs at attack.mitre.org.)

## Evidence handling
Collected the case files and live-triage output at <date/time UTC> by <your name>; SHA256SUMS stored at ~/cyber-bootcamp/day19/evidence_practice_<timestamp>/SHA256SUMS.txt; chain of custody recorded in chain_of_custody.md.

## Actions
Containment: block 203.0.113.45 and 198.51.100.99 at the firewall; isolate the server from the network without powering it off; capture memory and run the triage script first; take a disk image; disable the upload form.
Eradication: remove cmd.php, /tmp/.kworkerd and /tmp/libhide.so; restore /etc/ld.so.preload; delete the root cron job; remove the attacker key from authorized_keys; check for other new accounts, keys and cron jobs. Best option: rebuild the server from a known-good image.
Recovery: restore the site from a backup that predates 03:14 on Oct 21; fix the upload code (validate file type, store uploads outside the web root, block script execution in the uploads folder); reset all passwords and keys that were on the server; monitor closely afterwards.

## Lessons learned and new detections
- Fix the sudo rule that let www-data edit root's crontab; disable direct root login over SSH.
- New detections: alert on new files in the uploads folder, on cron changes, on edits to authorized_keys and ld.so.preload, on high CPU, and on outbound connections to unusual ports.
- Send logs to a central system so they survive an attacker clearing local history.
- Open question: whether any database or customer data was accessed; to be answered from the database logs and the disk image.
