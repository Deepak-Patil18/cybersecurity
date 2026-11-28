#!/usr/bin/env python3
"""Usage: python3 cloud_detect.py cloudtrail.jsonl   (simple cloud detections)"""
import sys, json
from collections import Counter
 
OFFICE_IPS = {"198.51.100.10"}                 # your organization's known egress IPs
HOME_REGIONS = {"us-east-1"}                   # regions you actually use
events = [json.loads(l) for l in open(sys.argv[1])]
alerts = []
 
def alert(level, e, why, technique):
    alerts.append((e["eventTime"][11:19], level, why, e["userIdentity"]["userName"], e["sourceIPAddress"], technique))
 
fails = Counter(e["sourceIPAddress"] for e in events if e["eventName"] == "ConsoleLogin" and e.get("errorCode"))
for e in events:
    n, p = e["eventName"], e.get("requestParameters", {})
    if n == "ConsoleLogin" and e.get("errorCode") and fails[e["sourceIPAddress"]] >= 2:
        alert("MEDIUM", e, "Repeated failed console logins", "T1110")
    if e["userIdentity"]["type"] == "Root":
        alert("HIGH", e, "Root account used", "T1078.004")
    if e["sourceIPAddress"] not in OFFICE_IPS and e["eventSource"] == "iam.amazonaws.com" and n in ("CreateUser", "CreateAccessKey", "AttachUserPolicy"):
        alert("HIGH", e, f"IAM change from unknown IP: {n}", "T1098.001")
    if n == "AttachUserPolicy" and p.get("policyArn", "").endswith("AdministratorAccess"):
        alert("CRITICAL", e, "AdministratorAccess granted", "T1098")
    if n == "AuthorizeSecurityGroupIngress" and p.get("cidrIp") == "0.0.0.0/0":
        alert("HIGH", e, f"Port {p.get('fromPort')} opened to the whole internet", "T1562.007")
    if n == "PutBucketPolicy" and "Principal:*" in p.get("policy", ""):
        alert("CRITICAL", e, f"Bucket {p.get('bucketName')} made public", "T1530")
    if n == "RunInstances" and e["awsRegion"] not in HOME_REGIONS:
        alert("HIGH", e, f"Instances launched in unused region {e['awsRegion']}", "T1496")
    if n in ("StopLogging", "DeleteTrail"):
        alert("CRITICAL", e, "CloudTrail logging disabled", "T1562.008")
 
gets = [e for e in events if e["eventName"] == "GetObject" and e["sourceIPAddress"] not in OFFICE_IPS]
if len(gets) >= 3:
    alert("HIGH", gets[0], f"{len(gets)} S3 downloads from an unknown IP", "T1530")
 
for a in sorted(alerts):
    print(f"[{a[1]:8}] {a[0]}  {a[2]}  user={a[3]} ip={a[4]}  [{a[5]}]")
print(f"\n{len(alerts)} alerts over {len(events)} events")
