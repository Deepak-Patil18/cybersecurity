#!/bin/bash
# Usage: ./brute_force_detector.sh <logfile> <threshold>
LOGFILE=${1:-sample_auth.log}
THRESHOLD=${2:-5}

echo "========================================"
echo "  BRUTE-FORCE DETECTION REPORT"
echo "  Log file: $LOGFILE | Threshold: $THRESHOLD"
echo "========================================"
echo ""

echo "Total failed login attempts:"
grep -c "Failed password" "$LOGFILE"
echo ""

echo "Failed attempts by IP address:"
grep "Failed password" "$LOGFILE" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr
echo ""

echo "===== ALERTS (>= $THRESHOLD failed attempts) ====="
grep "Failed password" "$LOGFILE" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | \
  awk -v t="$THRESHOLD" '$1 >= t {print "ALERT: " $2 " had " $1 " failed attempts — investigate immediately"}'
echo ""

echo "===== Checking if any alerted IP later succeeded ====="
for ip in $(grep "Failed password" "$LOGFILE" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | awk -v t="$THRESHOLD" '$1 >= t {print $2}'); do
  if grep "$ip" "$LOGFILE" | grep -qi accepted; then
    echo "CRITICAL: $ip succeeded after multiple failures — possible active compromise"
  fi
done
