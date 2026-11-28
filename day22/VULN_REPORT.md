# Vulnerability Management Report — Scan of 2026-10-27 (fictional)

## Executive summary
The scan found 10 vulnerabilities across our systems. Four are urgent because they sit on internet-facing or business-critical systems and are known to be exploited by real attackers: the VPN gateway, the mail gateway, the public website and the HR file server. We recommend fixing those four within 72 hours, workarounds for the two systems with no patch, and the rest on a normal schedule.

## Top 5 actions this week, in order
1. vpn-01 (CVE-2014-0160, Heartbleed): upgrade OpenSSL and replace the certificates and keys. Owner: network team. Why first: internet-facing, critical asset, known to be exploited, leaks memory contents.
2. mail-01 (CVE-2026-0004, fictional): no patch exists, so apply a workaround today (restrict the exposed service at the firewall or take it offline) and watch for the vendor fix. Owner: messaging team. Why: internet-facing, critical, remote code execution, no fix.
3. web-01 (CVE-2021-44228, Log4Shell): update the Log4j library. Owner: web team. Why: internet-facing, CVSS 10.0, known to be exploited.
4. fs-01 (CVE-2017-0144, EternalBlue): disable SMBv1 and install the patch. Owner: server team. Why: holds HR data, known to be exploited, and the same flaw lets an attacker spread inside the network.
5. rdp-02 (CVE-2019-0708, BlueKeep): patch the admin jump host and restrict RDP to known addresses. Owner: server team. Why: an administrative host, remote code execution, known to be exploited.

## Findings with no patch (workarounds needed)
- mail-01 CVE-2026-0004 (RCE, P1): block or restrict the service at the firewall; monitor for exploitation
- hr-app CVE-2026-0001 (XSS, P3): add input filtering and a web application firewall rule until a code fix
- print-03 CVE-2026-0002 (information disclosure, P4): move the printer's web interface to a restricted network

## Exceptions (risk accepted)
Finding: kiosk-04 CVE-2026-0005 (CVSS 3.7, low-impact information leak)
Owner: facilities IT manager
Reason: low severity, no sensitive data on the device, patching needs a visit
Expires: 90 days from scan; re-evaluate then

## How findings were prioritized
Score = (CVSS, plus 2 if the flaw is known to be exploited, capped at 10) x (business criticality / 5) x (1.5 if internet-facing, otherwise 1.0).
Bands: P1 9 or higher (72 hours), P2 6 to 8.9 (7 days), P3 3 to 5.9 (30 days), P4 below 3 (90 days).
Override: any known-exploited flaw is at least P2, so dev-07 (CVE-2017-5638) is P2* despite low business value, because an attacker who reaches it could move to other systems.
Ranking by CVSS alone would have put the developer test box ahead of the VPN gateway.

## Related attack techniques
T1190 Exploit Public-Facing Application, T1210 Exploitation of Remote Services

## Verification plan
Re-scan the P1 systems within 24 hours of each fix, the P2 systems within 3 days, and everything else at the next scheduled scan on 2026-11-27. Confirm no finding reappears.
