#!/bin/bash
# Usage: ./win_detect.sh win_events.log [threshold]
LOG="${1:-win_events.log}"
T="${2:-5}"
echo "===== Windows detection rules ====="
 
echo "--- Rule 1: brute force followed by success ---"
awk -F'|' -v t="$T" '
  $2==4625 && $5!="-" {fails[$5]++}
  $2==4624 && $5!="-" {ok[$5]=$1 " " $3}
  END {for (ip in fails) if (fails[ip]>=t) {
         print "[ALERT] " ip " had " fails[ip] " failed logons"
         if (ip in ok) print "[CRITICAL] " ip " then logged on successfully as " ok[ip]
       }}' "$LOG"
 
echo "--- Rule 2: new account added to Administrators ---"
awk -F'|' '$2==4720 {u=$6; sub(/.*created: /,"",u); made[u]=$1}
           $2==4732 && $6 ~ /Administrators/ {split($6,a," "); if (a[1] in made) print "[CRITICAL] " a[1] " created at " made[a[1]] " and added to Administrators at " $1}' "$LOG"
 
echo "--- Rule 3: audit log cleared ---"
awk -F'|' '$2==1102 {print "[CRITICAL] " $1 " audit log cleared by " $3 " (T1070.001)"}' "$LOG"
