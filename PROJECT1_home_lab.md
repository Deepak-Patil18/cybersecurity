# Project 1: Home Lab Setup (Kali Linux + Metasploitable2)

## Objective
Build an isolated penetration-testing lab using VirtualBox, consisting of a Kali Linux
attacker machine and a deliberately vulnerable Metasploitable2 target, to practice
reconnaissance and vulnerability identification safely.

## Lab Architecture
- Host: Windows machine running VirtualBox
- Attacker VM: Kali Linux, IP 192.168.56.X (replace with your Kali IP)
- Target VM: Metasploitable2, IP 192.168.56.105 (replace with your actual IP)
- Network: VirtualBox Host-Only Adapter (vboxnet0) — fully isolated from the internet
  and home network, by design, since the target VM is intentionally vulnerable

## Steps Performed
1. Installed VirtualBox and verified virtualization support
2. Imported the official Kali Linux VirtualBox image and updated packages
3. Deployed Metasploitable2 from its official .vmdk disk image
4. Created an isolated Host-Only network and attached both VMs to it
5. Verified connectivity between VMs and confirmed no internet exposure for the target
6. Ran an initial Nmap service-version scan against the target

## Key Findings (Nmap -sV scan)
- Port 21 (FTP): vsftpd 2.3.4 — matches a known backdoor vulnerability, CVE-2011-2523
- Port 23 (Telnet): plaintext credential transmission, no encryption
- Port 3306 (MySQL): reachable, potential weak/default credentials
- Port 8180 (Apache Tomcat): commonly ships with default admin credentials

## Lessons Learned
- Outdated software versions (visible via banner grabbing/service detection) are
  directly tied to known CVEs — this is why asset/version inventories matter in real
  vulnerability management.
- Network isolation (Host-Only mode) is essential when working with intentionally
  vulnerable systems, to avoid any accidental exposure.
- This lab environment will be reused for deeper exploitation and web app testing
  later in this bootcamp.

## Tools Used
VirtualBox, Kali Linux, Metasploitable2, Nmap
