# Cloud Incident Report — Case 7001

## Executive summary
An outside attacker used a stolen access key belonging to the developer account dev-maya to take over our cloud account on Oct 22. They created their own administrator user, made a customer data bucket public and downloaded files from it, started ten very large computers in a region we never use, and then switched off the audit log to hide what they did. We recommend disabling the stolen and attacker-created identities, restoring the security settings, and finding out exactly which customer files were taken.

## Severity: Critical
- Administrator access was gained and a backdoor identity was created
- Customer data was exposed (public bucket and downloads)
- Audit logging was disabled, so part of the activity is invisible
- Cost impact from ten p3.8xlarge instances in ap-southeast-1

## Timeline (UTC, Oct 22, 2026)
- 02:14:01 and 02:14:09: two failed console logins for dev-maya from 203.0.113.45
- 02:20:15: GetCallerIdentity using dev-maya's key (the attacker checks who they are)
- 02:20:40: ListUsers (looking around)
- 02:21:10: CreateUser backup-svc
- 02:21:30: AttachUserPolicy gives backup-svc AdministratorAccess
- 02:21:50: CreateAccessKey for backup-svc (a second way back in)
- 02:25:05: security group opened to 0.0.0.0/0 on port 22 (SSH open to the world)
- 02:30:00: PutBucketPolicy makes acme-customer-exports public
- 02:35:00 to 02:35:40: five GetObject downloads from that bucket
- 02:41:00: RunInstances, ten p3.8xlarge in ap-southeast-1
- 02:45:30: StopLogging on the trail main-trail

## Identities involved
- dev-maya: legitimate developer; her access key was stolen and used from an outside IP
- backup-svc: created by the attacker with AdministratorAccess and its own access key

## Data impact
Bucket acme-customer-exports: 5 files downloaded (export-0.csv to export-4.csv); the bucket was public from 02:30. Anything accessed after logging stopped at 02:45:30 is unknown and must be checked using other sources.

## Financial impact
Ten p3.8xlarge GPU instances in ap-southeast-1, a region the company does not use, consistent with cryptocurrency mining. Cost to be confirmed from the billing console.

## IOCs (defanged)
- Source IP: 203[.]0[.]113[.]45
- User agent: python-requests/2.31 (14 of the 16 attacker calls)
- User: backup-svc and its access key
- Security group sg-0a1b2c rule: 0.0.0.0/0 on port 22
- Instances in ap-southeast-1

## ATT&CK mapping
T1078.004 Valid Accounts: Cloud Accounts; T1110 Brute Force; T1087.004 Cloud Account Discovery; T1136.003 Create Account: Cloud Account; T1098.001 Additional Cloud Credentials; T1562.007 Disable or Modify Cloud Firewall; T1530 Data from Cloud Storage; T1496 Resource Hijacking; T1562.008 Disable or Modify Cloud Logs. (Confirm IDs at attack.mitre.org.)

## Response plan
Contain: disable dev-maya's access key and rotate her credentials; disable backup-svc and delete its access key after saving the details as evidence; block 203.0.113.45 where possible; apply a deny policy to stop new changes from the stolen identity.
Restore guardrails: re-enable CloudTrail immediately; remove 0.0.0.0/0 from the security group; block public access on the bucket and restore its policy; terminate the ten instances and check every other region for more.
Scope: find where the key leaked (public code repository, laptop, ticket); review the gap after 02:45:30 using other sources (flow logs, GuardDuty, S3 server access logs); identify exactly which customer files were downloaded; look for other new users, roles, keys or functions.
Recover: remove the unauthorized users and policies; reset anything the attacker could have read; require MFA for all users; replace long-lived keys with roles; add guardrails against disabling logging; restrict unused regions; set billing alerts; notify legal about the customer data exposure.

## What we cannot see
Activity after StopLogging at 02:45:30, and where the access key leaked.

## Lessons and new detections
- Alert on: StopLogging, AdministratorAccess granted, bucket policy changes, security groups opened to 0.0.0.0/0, instances started in unused regions, and IAM changes from unknown IPs
- Keep the list of known office IPs and used regions up to date; detections depend on it
- Move to roles instead of long-lived keys, enforce MFA, and block disabling of logging at the organization level
