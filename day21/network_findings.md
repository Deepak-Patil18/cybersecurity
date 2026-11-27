# Network findings
- C2 destination: 198.51.100.99
- First beacon: 09:06:20, 68 seconds after the Outlook-launched .scr alert at 09:05:12.
- Beacon pattern: 10 HTTPS connections to port 443, at 30-second intervals.
- Suspected exfiltration: one HTTP connection to port 80 at 09:29:50. Record the bytes_toserver value from the corrected command.
- Assessment: the traffic supports beaconing followed by a possible upload to the C2 server.
- Scope note: traffic bytes prove the amount transmitted from this workstation. Check hr.7z on FS-01 before claiming the archive size or total data stolen.
