#!/bin/bash
# Usage: ./extract_iocs.sh incident_notes.txt
FILE="${1:-incident_notes.txt}"
CLEAN=$(sed 's/\[\.\]/./g; s/hxxp/http/g; s/\[@\]/@/g' "$FILE")   # "refang" the text
 
echo "===== IPs (external only) ====="
echo "$CLEAN" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
  | grep -vE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)' | sort -u
 
echo "===== URLs ====="
echo "$CLEAN" | grep -oE 'https?://[^ ]+' | sort -u
 
echo "===== Domains ====="
echo "$CLEAN" | grep -oE '\b[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.(com|net|org|ru|xyz|top|example)\b' | sort -u
 
echo "===== Hashes (MD5 / SHA256) ====="
echo "$CLEAN" | grep -oE '\b([a-fA-F0-9]{32}|[a-fA-F0-9]{64})\b' | sort -u
 
echo "===== Email addresses ====="
echo "$CLEAN" | grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | sort -u
