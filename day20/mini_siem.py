#!/usr/bin/env python3
"""Usage: python3 mini_siem.py events.jsonl rules/   (a tiny Sigma-style detection engine)"""
import sys, json, glob, yaml
from collections import defaultdict
 
def matches(event, selection):
    for key, expected in selection.items():
        field, _, op = key.partition("|")
        value = str(event.get(field, ""))
        wanted = expected if isinstance(expected, list) else [expected]
        ok = False
        for w in wanted:
            w = str(w)
            if op == "contains":     ok = ok or (w.lower() in value.lower())
            elif op == "startswith": ok = ok or value.lower().startswith(w.lower())
            elif op == "endswith":   ok = ok or value.lower().endswith(w.lower())
            else:                    ok = ok or (value == w)
        if not ok:
            return False
    return True
 
events = [json.loads(l) for l in open(sys.argv[1])]
rules = [yaml.safe_load(open(p)) for p in sorted(glob.glob(sys.argv[2] + "/*.yml"))]
total = 0
for rule in rules:
    det = rule["detection"]
    cond = det["condition"]
    sel = det["selection"]
    flt = det.get("filter")
    hits = [e for e in events if matches(e, sel) and not (flt and matches(e, flt))]
    # optional aggregation:  "selection | count() by FIELD >= N"
    if "|" in cond:
        _, agg = [s.strip() for s in cond.split("|")]
        by = agg.split("by")[1].split(">=")[0].strip()
        n = int(agg.split(">=")[1])
        groups = defaultdict(list)
        for e in hits: groups[e.get(by)].append(e)
        hits = [g[0] for g in groups.values() if len(g) >= n]
        detail = lambda e: f"{by}={e.get(by)} ({len(groups[e.get(by)])} events)"
    else:
        detail = lambda e: f"account={e.get('Account')} " + " ".join(f"{k}={v}" for k, v in e.items() if k in ('CommandLine','TargetUser','ServiceName'))
    for e in hits:
        total += 1
        attack = ",".join(t.replace("attack.", "") for t in rule.get("tags", []) if t.startswith("attack.t"))
        print(f"[{rule['level'].upper():8}] {e['time'][11:19]}  {rule['title']}  [{attack}]  {detail(e)}")
print(f"\n{total} alerts from {len(rules)} rules over {len(events)} events")
