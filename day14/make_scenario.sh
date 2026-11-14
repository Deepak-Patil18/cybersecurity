#!/bin/bash
# Creates the Project 2 evidence files in the current folder.
cat > proxy.log << 'LOG'
Oct 19 08:55:10 proxy 10.0.2.20 GET https://news.example/ 200 18230
Oct 19 09:02:41 proxy 10.0.2.20 GET https://mail.company.example/inbox 200 9120
Oct 19 09:10:02 proxy 10.0.2.31 GET https://secure-invoice-review.example/login/verify.php?id=8842 200 4410
Oct 19 09:11:20 proxy 10.0.2.31 GET http://files-update-center.example/payload.bin 200 351000
Oct 19 09:12:05 proxy 10.0.2.31 CONNECT 198.51.100.77:443 200 512
Oct 19 09:13:05 proxy 10.0.2.31 CONNECT 198.51.100.77:443 200 512
Oct 19 09:14:05 proxy 10.0.2.31 CONNECT 198.51.100.77:443 200 512
Oct 19 09:15:05 proxy 10.0.2.31 CONNECT 198.51.100.77:443 200 512
Oct 19 09:16:05 proxy 10.0.2.31 CONNECT 198.51.100.77:443 200 512
Oct 19 09:17:05 proxy 10.0.2.31 CONNECT 198.51.100.77:443 200 512
Oct 19 09:18:40 proxy 10.0.2.20 GET https://news.example/sports 200 22010
Oct 19 09:30:44 proxy 10.0.2.31 POST http://198.51.100.77/upload 200 48213000
Oct 19 09:41:12 proxy 10.0.2.20 GET https://mail.company.example/inbox 200 9333
LOG
cat > auth.log << 'LOG'
Oct 19 08:30:11 webserver sshd[800]: Accepted password for alice from 10.0.2.20 port 40100 ssh2
Oct 19 09:48:02 webserver sshd[1201]: Failed password for root from 203.0.113.45 port 52001 ssh2
Oct 19 09:48:05 webserver sshd[1201]: Failed password for root from 203.0.113.45 port 52003 ssh2
Oct 19 09:48:09 webserver sshd[1201]: Failed password for admin from 203.0.113.45 port 52005 ssh2
Oct 19 09:48:12 webserver sshd[1201]: Failed password for admin from 203.0.113.45 port 52007 ssh2
Oct 19 10:02:01 webserver sshd[1260]: Failed password for svc-backup from 10.0.2.31 port 44010 ssh2
Oct 19 10:02:04 webserver sshd[1260]: Failed password for svc-backup from 10.0.2.31 port 44012 ssh2
Oct 19 10:02:07 webserver sshd[1260]: Failed password for svc-backup from 10.0.2.31 port 44014 ssh2
Oct 19 10:02:10 webserver sshd[1260]: Failed password for svc-backup from 10.0.2.31 port 44016 ssh2
Oct 19 10:02:13 webserver sshd[1260]: Failed password for svc-backup from 10.0.2.31 port 44018 ssh2
Oct 19 10:02:16 webserver sshd[1260]: Failed password for svc-backup from 10.0.2.31 port 44020 ssh2
Oct 19 10:02:19 webserver sshd[1260]: Accepted password for svc-backup from 10.0.2.31 port 44022 ssh2
Oct 19 10:03:05 webserver sudo:    svc-backup : TTY=pts/1 ; PWD=/home/svc-backup ; USER=root ; COMMAND=/bin/cat /etc/shadow
Oct 19 10:04:30 webserver crontab[1290]: (svc-backup) REPLACE (svc-backup)
Oct 19 10:20:15 webserver sshd[1350]: Accepted password for alice from 10.0.2.20 port 40250 ssh2
LOG
echo "Created proxy.log and auth.log"
