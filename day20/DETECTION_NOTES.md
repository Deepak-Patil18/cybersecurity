cd ~/cyber-bootcamp/day20
cat > DETECTION_NOTES.md << 'EOF'
# Detection Notes

## Rules created: 7 (lab-001 to lab-007)

| Rule | ATT&CK technique | Data source | Severity | Known false positives | Tuning applied |
|------|------------------|-------------|----------|-----------------------|----------------|
| lab-001 Many failed logons from one source | T1110 | Security log, Event 4625 | High | Users mistyping passwords; a misconfigured service retrying an old password | Threshold of 5 failures per source IP |
| lab-002 Hidden or encoded PowerShell | T1059.001 | Process creation, Event 4688 | High | Admin scripts and software that use -enc legitimately; "-encoding" also contains "-enc" | None yet |
| lab-003 User added to Administrators group | T1098 | Security log, Event 4732 | Critical | Planned admin changes by IT | None yet (compare against change tickets) |
| lab-004 Security audit log cleared | T1070.001 | Security log, Event 1102 | Critical | Planned maintenance by IT | None yet |
| lab-005 whoami executed | T1033 | Process creation, Event 4688 | Low | svc_inventory runs whoami as part of an inventory tool | Filter on Account svc_inventory |
| lab-006 Remote Desktop logon | T1021.001 | Security log, Event 4624 type 10 | Medium | Admins using RDP all day | Restrict to external source IPs (to do) |
| lab-007 Service installed from ProgramData | T1543.003 | System log, Event 7045 | High | Some legitimate software installs services there | None yet |

## Gaps to close next
- T1136.001 Create Account (Event 4720): the attacker created svc_helpdesk, but no rule fires on account creation
- T1053.005 Scheduled Task (Event 4698): no rule for scheduled-task persistence

## Threshold decisions
Brute force: >= 5 failed logons from one source in the sample data. At 12 the rule missed the real attack (11 attempts), which I tested on purpose.
What I would check before production:
- Normal failure counts per source over several weeks (to set the threshold above normal noise)
- Whether VPN and NAT make many users share one source IP
- A second, slower rule with a longer time window for attackers who guess slowly
- A rule for a successful logon after many failures from the same source

## Tuning rules I follow
- Exclude one specific account and one specific command, never a whole rule
- Write down every exclusion and why, and review them regularly
- Test each change against known-bad data so it still fires
EOF
cat DETECTION_NOTES.md
