#!/usr/bin/env python3
"""Creates cloudtrail.jsonl: fictional AWS CloudTrail-style events (one JSON event per line)."""
import json
ACCT = "111122223333"
events = []
def add(t, name, source, user, ip, region="us-east-1", utype="IAMUser", params=None, error=None, agent="aws-cli/2.15"):
    arn = f"arn:aws:iam::{ACCT}:root" if utype == "Root" else f"arn:aws:iam::{ACCT}:user/{user}"
    e = {"eventTime": f"2026-10-22T{t}Z", "eventSource": source, "eventName": name, "awsRegion": region,
         "sourceIPAddress": ip, "userAgent": agent,
         "userIdentity": {"type": utype, "userName": user, "arn": arn}, "requestParameters": params or {}}
    if error: e["errorCode"] = error
    events.append(e)
 
# normal activity from the office IP
add("08:30:00", "ConsoleLogin", "signin.amazonaws.com", "dev-maya", "198.51.100.10", agent="Mozilla/5.0")
add("08:41:12", "ListBuckets", "s3.amazonaws.com", "dev-maya", "198.51.100.10")
add("09:05:30", "RunInstances", "ec2.amazonaws.com", "dev-maya", "198.51.100.10", params={"instanceType": "t3.micro"})
# the attack: stolen access key for dev-maya used from an outside IP
add("02:14:01", "ConsoleLogin", "signin.amazonaws.com", "dev-maya", "203.0.113.45", error="Failed authentication", agent="Mozilla/5.0")
add("02:14:09", "ConsoleLogin", "signin.amazonaws.com", "dev-maya", "203.0.113.45", error="Failed authentication", agent="Mozilla/5.0")
add("02:20:15", "GetCallerIdentity", "sts.amazonaws.com", "dev-maya", "203.0.113.45", agent="python-requests/2.31")
add("02:20:40", "ListUsers", "iam.amazonaws.com", "dev-maya", "203.0.113.45", agent="python-requests/2.31")
add("02:21:10", "CreateUser", "iam.amazonaws.com", "dev-maya", "203.0.113.45", params={"userName": "backup-svc"}, agent="python-requests/2.31")
add("02:21:30", "AttachUserPolicy", "iam.amazonaws.com", "dev-maya", "203.0.113.45", params={"userName": "backup-svc", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, agent="python-requests/2.31")
add("02:21:50", "CreateAccessKey", "iam.amazonaws.com", "dev-maya", "203.0.113.45", params={"userName": "backup-svc"}, agent="python-requests/2.31")
add("02:25:05", "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", "backup-svc", "203.0.113.45", params={"groupId": "sg-0a1b2c", "cidrIp": "0.0.0.0/0", "fromPort": 22, "toPort": 22}, agent="python-requests/2.31")
add("02:30:00", "PutBucketPolicy", "s3.amazonaws.com", "backup-svc", "203.0.113.45", params={"bucketName": "acme-customer-exports", "policy": "Principal:* Action:s3:GetObject"}, agent="python-requests/2.31")
for i in range(5):
    add(f"02:35:{i*10:02d}", "GetObject", "s3.amazonaws.com", "backup-svc", "203.0.113.45", params={"bucketName": "acme-customer-exports", "key": f"export-{i}.csv"}, agent="python-requests/2.31")
add("02:41:00", "RunInstances", "ec2.amazonaws.com", "backup-svc", "203.0.113.45", region="ap-southeast-1", params={"instanceType": "p3.8xlarge", "minCount": 10}, agent="python-requests/2.31")
add("02:45:30", "StopLogging", "cloudtrail.amazonaws.com", "backup-svc", "203.0.113.45", params={"name": "main-trail"}, agent="python-requests/2.31")
# one more normal event
add("10:15:00", "ListBuckets", "s3.amazonaws.com", "dev-maya", "198.51.100.10")
events.sort(key=lambda e: e["eventTime"])
with open("cloudtrail.jsonl", "w") as f:
    for e in events: f.write(json.dumps(e) + "\n")
print(f"Created cloudtrail.jsonl with {len(events)} events")
