rule Lab_Suspicious_Dropper
{
    meta:
        description = "Bootcamp lab sample: downloader with persistence and shadow-copy deletion"
    strings:
        $url   = "files-update-center.example" ascii
        $c2    = "198.51.100.77" ascii
        $ps    = "-w hidden -enc" ascii
        $run   = "CurrentVersion\\Run" ascii
        $vss   = "vssadmin delete shadows" ascii
        $api1  = "VirtualAlloc" ascii
        $api2  = "WriteProcessMemory" ascii
        $api3  = "CreateRemoteThread" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($url, $c2, $ps)) and $run and $vss and 2 of ($api*)
}

