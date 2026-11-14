#!/bin/bash
# Usage: ./attack_tagger.sh auth_sample.log
LOG="${1:-auth_sample.log}"
tag() {  # $1=pattern  $2=technique ID  $3=name  $4=tactic
  n=$(grep -cE "$1" "$LOG")
  [ "$n" -gt 0 ] && printf "%-10s %-34s %-22s %s event(s)\n" "$2" "$3" "$4" "$n"
}
echo "===== MITRE ATT&CK tagging: $LOG ====="
printf "%-10s %-34s %-22s %s\n" "ID" "Technique" "Tactic" "Matches"
tag "Failed password"         T1110.001 "Brute Force: Password Guessing" "Credential Access"
tag "Accepted password"       T1078     "Valid Accounts"                 "Initial Access"
tag "sudo:.*COMMAND"          T1548.003 "Sudo and Sudo Caching"          "Privilege Escalation"
tag "useradd.*new user"       T1136.001 "Create Account: Local Account"  "Persistence"

