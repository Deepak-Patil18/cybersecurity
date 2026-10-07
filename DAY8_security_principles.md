# Day 8: Security Principles Applied to Project 1 Findings

## CIA Triad Analysis
| Finding | CIA Pillar Violated | Why |
|---|---|---|
| Telnet plaintext | Confidentiality | Credentials readable in transit |
| vsftpd 2.3.4 backdoor | All three | Full system compromise possible |
| Port 1524 root shell | All three | Direct unauthenticated root access |
| Weak DB credentials | Confidentiality + Integrity | Attacker can read/modify data |

## Least Privilege Finding
[Write 2-3 sentences: does Metasploitable2 follow least privilege? What would you
recommend? Base this on what you saw in /etc/sudoers and group membership.]

## Defense in Depth Recommendations
| Finding | Layer(s) That Would Prevent It |
|---|---|
| vsftpd 2.3.4 backdoor | Host (patching) + Network (IDS) |
| Telnet plaintext | Application (use SSH) + Policy |
| Port 1524 root shell | Perimeter (firewall) + Host (disable unused services) |
| Weak DB credentials | Data (password policy) + Host (network segmentation) |

## Risk Register
| Vulnerability | Likelihood | Impact | Risk Rating |
|---|---|---|---|
| vsftpd 2.3.4 backdoor | High | High | CRITICAL |
| Port 1524 root shell | High | High | CRITICAL |
| Telnet plaintext credentials | Medium | Medium | HIGH |
| Weak DB credentials | Medium | High | HIGH |

## Conclusion
If Metasploitable2 were a real production system, the two CRITICAL findings
(vsftpd backdoor and the unauthenticated root shell on port 1524) would require
immediate remediation, since both allow instant, unauthenticated full compromise.
The HIGH findings should follow shortly after. This prioritization is based on
likelihood x impact, not just technical severity alone.
