#!/bin/bash
# Live triage collection for a Linux host, in order of volatility. Usage: ./triage_collect.sh CASE_NAME
CASE="${1:-case}"
OUT="evidence_${CASE}_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
run() {                         # run NAME COMMAND...   saves output and logs what was done
  name="$1"; shift
  if command -v "$1" >/dev/null 2>&1; then
    "$@" > "$OUT/$name.txt" 2>&1
    echo "$(date -u +%FT%TZ) collected $name: $*" >> "$OUT/collection_log.txt"
  else
    echo "$(date -u +%FT%TZ) SKIPPED $name ($1 not installed)" >> "$OUT/collection_log.txt"
  fi
}
echo "$(date -u +%FT%TZ) collection started by $(whoami) on $(hostname)" > "$OUT/collection_log.txt"
# Most volatile first
run 01_date date -u
run 02_uptime uptime
run 03_logged_in who
run 04_processes ps aux
run 05_network_connections ss -tunap
run 06_listening_ports ss -tulnp
run 07_ip_addresses ip addr
run 08_arp_cache ip neigh
run 09_routing ip route
run 10_recent_logins last -n 30
run 11_users cat /etc/passwd
run 12_cron_root crontab -l
run 13_tmp_listing ls -la /tmp
# Seal the evidence: hash every file we collected
( cd "$OUT" && sha256sum *.txt > SHA256SUMS.txt )
echo "$(date -u +%FT%TZ) hashes written to SHA256SUMS.txt" >> "$OUT/collection_log.txt"
echo "Evidence folder: $OUT"; ls "$OUT"
