# Rule translations
## lab-001 Many failed logons from one source
SPL: index=wineventlog EventCode=4625 | stats count by src_ip | where count>=5
KQL: SecurityEvent | where EventID == 4625 | summarize count() by IpAddress | where count_ >= 5
## lab-003 User added to Administrators group
SPL: index=wineventlog EventCode=4732 Group_Name="Administrators"
KQL: SecurityEvent | where EventID == 4732 and TargetUserName == "Administrators"
## lab-007 Service installed from ProgramData
SPL: index=wineventlog EventCode=7045 Service_File_Name="*\ProgramData\*"
KQL: Event | where EventID == 7045 and RenderedDescription contains "\ProgramData\"
 
Note: field names vary by data source and SIEM version. Check one raw event first.
