#!/usr/bin/env python3
"""Creates events.jsonl: fictional Windows events in JSON (one event per line)."""
import json
ev = []
def add(t, eid, acct="-", host="WIN-SRV01", **kw):
    e = {"time": f"2026-10-20T{t}Z", "EventID": eid, "Account": acct, "Host": host}
    e.update(kw); ev.append(e)
 
# normal activity + a known-good admin task that will cause a false positive
add("01:30:00", 4624, "jsmith", LogonType=2, SourceIP="-")
add("01:45:10", 4688, "svc_inventory", CommandLine="whoami /all", ParentImage="C:\\Tools\\inventory.exe")
add("01:50:00", 4625, "jsmith", LogonType=3, SourceIP="10.0.0.15")
# the attack
for i, u in enumerate(["Administrator"]*5 + ["admin"]*3 + ["Administrator"]*3):
    add(f"02:10:{1+i*3:02d}", 4625, u, LogonType=3, SourceIP="203.0.113.45")
add("02:10:36", 4624, "Administrator", LogonType=10, SourceIP="203.0.113.45")
add("02:12:08", 4688, "Administrator", CommandLine="whoami /all", ParentImage="C:\\Windows\\System32\\cmd.exe")
add("02:12:40", 4688, "Administrator", CommandLine="powershell -nop -w hidden -enc JABjAD0A", ParentImage="C:\\Windows\\System32\\cmd.exe")
add("02:14:15", 4720, "Administrator", TargetUser="svc_helpdesk")
add("02:14:30", 4732, "Administrator", TargetUser="svc_helpdesk", Group="Administrators")
add("02:16:02", 7045, "SYSTEM", ServiceName="WinUpdateSvc", ServicePath="C:\\ProgramData\\upd.exe")
add("02:25:50", 1102, "Administrator")
add("08:58:12", 4624, "jsmith", LogonType=2, SourceIP="-")
with open("events.jsonl", "w") as f:
    for e in sorted(ev, key=lambda x: x["time"]):
        f.write(json.dumps(e) + "\n")
print(f"Created events.jsonl with {len(ev)} events")
