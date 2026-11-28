#!/usr/bin/env python3
"""Usage: python3 prioritize.py scan_results.csv   (risk-based prioritization)"""
import sys, csv
 
def risk(r):
    base = min(10.0, float(r["cvss"]) + (2.0 if r["kev"] == "Y" else 0.0))   # known-exploited bonus
    crit = int(r["criticality"]) / 5.0                                       # business value 0.2 - 1.0
    expo = 1.5 if r["exposure"] == "internet" else 1.0                       # reachable from the internet?
    return round(base * crit * expo, 1)
 
def band(s):
    return "P1" if s >= 9 else "P2" if s >= 6 else "P3" if s >= 3 else "P4"
 
SLA = {"P1": "fix within 72 hours", "P2": "fix within 7 days", "P3": "fix within 30 days", "P4": "fix within 90 days"}
rows = list(csv.DictReader(open(sys.argv[1])))
for r in rows:
    r["risk"] = risk(r); r["band"] = band(r["risk"])
    if r["kev"] == "Y" and r["band"] in ("P3", "P4"):
        r["band"] = "P2*"          # override: a known-exploited flaw is never left for 30-90 days
print("===== Ranked by CVSS alone =====")
for i, r in enumerate(sorted(rows, key=lambda r: -float(r["cvss"])), 1):
    print(f"{i:2}. {r['cvss']:>4}  {r['host']:9} {r['cve']}")
print("\n===== Ranked by risk (CVSS + exploited + business value + exposure) =====")
for i, r in enumerate(sorted(rows, key=lambda r: -r["risk"]), 1):
    print(f"{i:2}. {r['band']:3} risk={r['risk']:>4}  {r['host']:9} {r['cve']:15} {r['role']}")
print("\n===== Summary =====")
for b in ("P1", "P2", "P3", "P4"):
    n = sum(1 for r in rows if r["band"].startswith(b))
    print(f"{b}: {n} findings  ({SLA[b]})")
print("\n* = raised to P2 because the flaw is known to be exploited in the wild")
print("No patch available, so use a workaround:", ", ".join(r["host"] for r in rows if r["patch_available"] == "N"))
