# Briefing notes

At 09:02, ravi.k received a phishing email with a link and a file disguised as a salary document. Within minutes, the file ran on WS-022, downloaded another program, created a scheduled task so it could run again, and started hidden PowerShell.

The activity later used svc_backup to access FS-01, copy files from the HR share, and package them into a password-protected archive. We found ten regular connections to an external server, followed by an upload flow that sent 58,299 bytes to that server.

This is a critical incident because an endpoint was compromised, a service account was used to reach a file server, and data left the network. We correlated the email, endpoint, network, and malware evidence, and prepared detections. We do not yet know the archive’s exact contents or size, or the total amount of data taken.

Our proposed actions are to isolate WS-022 while preserving memory, block the attacker indicators, disable and reset svc_backup, and investigate FS-01 and other systems for related activity. In this exercise, those response actions are recommendations, not completed work. We need approval to begin containment, IT support to preserve and reimage affected systems, and HR and Legal to assess possible exposure of personal information.
