#!/bin/bash
echo "========================================"
echo "   LINUX SECURITY AUDIT — $(date)"
echo "========================================"

echo ""
echo "===== Logged in as ====="
whoami
id

echo ""
echo "===== Users with UID 0 (root privileges) ====="
awk -F: '($3 == 0) {print $1}' /etc/passwd

echo ""
echo "===== SUID binaries found ====="
find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f 2>/dev/null

echo ""
echo "===== Currently running processes (top 10 by CPU) ====="
ps aux --sort=-%cpu | head -11

echo ""
echo "===== Listening network ports ====="
sudo ss -tulnp

echo ""
echo "===== Available security updates ====="
apt list --upgradable 2>/dev/null | head -10

echo ""
echo "===== Audit complete ====="

