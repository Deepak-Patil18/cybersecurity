#!/bin/bash
# Usage: ./detect_bruteforce.sh auth_sample.log [threshold]
LOG="${1:-auth_sample.log}"
THRESHOLD="${2:-5}"
echo "===== Brute-force detection (threshold: $THRESHOLD failures) ====="
grep "Failed password" "$LOG" \
  | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
  | sort | uniq -c | sort -rn \
  | while read count ip; do
      if [ "$count" -ge "$THRESHOLD" ]; then
        echo "[ALERT] $ip had $count failed logins"
        if grep -q "Accepted password for .* from $ip " "$LOG"; then
          echo "[CRITICAL] $ip ALSO has a SUCCESSFUL login -> possible compromise"
          grep "Accepted password for .* from $ip " "$LOG"
        fi
      fi
    done

