rule P3_Dropper
{
    strings:
        $c2   = "198.51.100.99" ascii
        $url  = "cdn-sync-files.example" ascii
        $task = "schtasks /create /tn OneDriveSync" ascii
        $ps   = "-w hidden -enc" ascii
        $api1 = "VirtualAlloc" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($c2, $url)) and
        $task and
        $ps and
        2 of ($api*)
}
