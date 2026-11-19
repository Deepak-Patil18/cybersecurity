# Day 12 Detection Mapping

| SID | Detection | Cyber Kill Chain stage | ATT&CK tactic | ATT&CK technique |
|-----|-----------|------------------------|---------------|------------------|
| 1000001 | Phishing domain lookup | Delivery | Initial Access | [T1566.002 – Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |
| 1000002 | `payload.bin` download | Delivery / Installation | Command and Control | [T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| 1000003 | Beacon to C2 IP over web protocols | Command and Control | Command and Control | [T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |
| 1000004 | SYN port scan | Reconnaissance | Reconnaissance (`T1595.001`) or Discovery (`T1046`) | [T1595.001 – Active Scanning: Scanning IP Blocks](https://attack.mitre.org/techniques/T1595/001/) for external scanning; [T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/) for scanning within an accessed environment |
| 1000005 | Long DNS labels consistent with DNS tunneling | Command and Control | Command and Control | [T1071.004 – Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/) |

## Mapping notes

- A domain lookup alone does not prove phishing or delivery. `T1566.002` fits when evidence connects the domain to a spearphishing link sent to a victim; otherwise, describe the observed DNS or web activity and avoid asserting the phishing technique without supporting evidence.
- A payload download is mapped to `T1105` when a file is transferred into the victim environment. ATT&CK places this technique under the Command and Control tactic, even if a Cyber Kill Chain lesson groups the event under Delivery or Installation.
- For a SYN scan, use `T1595.001` when the adversary scans externally to discover targets. Use `T1046` when an adversary in an accessed environment enumerates network services. The packet pattern alone may not establish which context applies.
- Long DNS labels can be a tunneling indicator, but length alone is not proof of C2. Confirm with context such as high entropy, repeated encoded subdomains, unusual query volume, or suspicious process attribution.

