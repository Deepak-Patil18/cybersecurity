#!/usr/bin/env python3
"""Creates sample.bin: a HARMLESS, fictional 'malware-like' file for static-analysis practice.
It only contains text and random bytes. It cannot run."""
import random
random.seed(11)
 
header = b"MZ" + b"\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 46
dos_msg = b"This program cannot be run in DOS mode.\r\n$\x00\x00"
 
ascii_strings = [
    b"http://files-update-center.example/payload.bin",
    b"198.51.100.77",
    b"powershell -nop -w hidden -enc",
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"WinUpdateSvc",
    b"C:\\ProgramData\\upd.exe",
    b"cmd.exe /c whoami /all",
    b"vssadmin delete shadows /all /quiet",
    b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread",
    b"URLDownloadToFileA", b"RegSetValueExA", b"IsDebuggerPresent",
    b"KERNEL32.dll", b"WININET.dll", b"ADVAPI32.dll",
]
body = b"\x00".join(ascii_strings) + b"\x00"
wide = "Your files have been encrypted. Contact recovery@secure-invoice-review.example".encode("utf-16-le")
packed = bytes(random.getrandbits(8) for _ in range(2048))      # looks like packed/encrypted data
padding = b"\x00" * 1024
 
open("sample.bin", "wb").write(header + dos_msg + body + b"\x00\x00" + wide + b"\x00\x00" + padding + packed)
print("Created sample.bin")
