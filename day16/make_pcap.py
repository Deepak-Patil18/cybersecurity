#!/usr/bin/env python3
"""Builds lab.pcap: a small, fictional capture of the Day 14 incident (+ a port scan)."""
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap
import random, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)
random.seed(7)
 
pkts = []
T0 = 1792000000.0          # arbitrary start time
 
def add(p, t):
    p.time = t
    pkts.append(p)
 
def tcp_session(cip, sip, sport, dport, t, c_payload=b"", s_payload=b""):
    c_seq, s_seq = 1000, 5000
    e = lambda p: Ether()/p
    add(e(IP(src=cip, dst=sip)/TCP(sport=sport, dport=dport, flags="S", seq=c_seq)), t)
    add(e(IP(src=sip, dst=cip)/TCP(sport=dport, dport=sport, flags="SA", seq=s_seq, ack=c_seq+1)), t+0.01)
    add(e(IP(src=cip, dst=sip)/TCP(sport=sport, dport=dport, flags="A", seq=c_seq+1, ack=s_seq+1)), t+0.02)
    c_seq += 1; s_seq += 1
    if c_payload:
        add(e(IP(src=cip, dst=sip)/TCP(sport=sport, dport=dport, flags="PA", seq=c_seq, ack=s_seq)/Raw(c_payload)), t+0.03)
        c_seq += len(c_payload)
        add(e(IP(src=sip, dst=cip)/TCP(sport=dport, dport=sport, flags="A", seq=s_seq, ack=c_seq)), t+0.04)
    if s_payload:
        add(e(IP(src=sip, dst=cip)/TCP(sport=dport, dport=sport, flags="PA", seq=s_seq, ack=c_seq)/Raw(s_payload)), t+0.05)
        s_seq += len(s_payload)
        add(e(IP(src=cip, dst=sip)/TCP(sport=sport, dport=dport, flags="A", seq=c_seq, ack=s_seq)), t+0.06)
    add(e(IP(src=cip, dst=sip)/TCP(sport=sport, dport=dport, flags="FA", seq=c_seq, ack=s_seq)), t+0.07)
    add(e(IP(src=sip, dst=cip)/TCP(sport=dport, dport=sport, flags="FA", seq=s_seq, ack=c_seq+1)), t+0.08)
    add(e(IP(src=cip, dst=sip)/TCP(sport=sport, dport=dport, flags="A", seq=c_seq+1, ack=s_seq+1)), t+0.09)
 
def dns_lookup(client, qname, answer, t):
    sp = random.randint(40000, 60000)
    add(Ether()/IP(src=client, dst="10.0.2.1")/UDP(sport=sp, dport=53)/DNS(rd=1, qd=DNSQR(qname=qname)), t)
    add(Ether()/IP(src="10.0.2.1", dst=client)/UDP(sport=53, dport=sp)/DNS(id=0, qr=1, qd=DNSQR(qname=qname), an=DNSRR(rrname=qname, rdata=answer)), t+0.02)
 
WS = "10.0.2.31"
# 1) phishing page
dns_lookup(WS, "secure-invoice-review.example", "192.0.2.50", T0+10)
tcp_session(WS, "192.0.2.50", 51001, 80, T0+10.2,
  b"GET /login/verify.php?id=8842 HTTP/1.1\r\nHost: secure-invoice-review.example\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
  b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
# 2) payload download
dns_lookup(WS, "files-update-center.example", "192.0.2.60", T0+78)
tcp_session(WS, "192.0.2.60", 51002, 80, T0+78.2,
  b"GET /payload.bin HTTP/1.1\r\nHost: files-update-center.example\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
  b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nMZ\x90\x00")
# 3) beaconing to C2 every 60s
for i in range(6):
    tcp_session(WS, "198.51.100.77", 52000+i, 443, T0+120+60*i, b"\x16\x03\x01\x00\x05hello", b"\x17\x03\x03\x00\x02ok")
# 4) DNS tunnelling-style long labels
for i in range(4):
    label = "".join(random.choice("abcdef0123456789") for _ in range(40))
    dns_lookup(WS, f"{label}.tunnel-c2.example", "198.51.100.77", T0+500+i*5)
# 5) SYN scan from outside against the server
SC, SRV = "203.0.113.45", "10.0.2.40"
for k, port in enumerate(range(20, 45)):
    t = T0+700+k*0.2
    add(Ether()/IP(src=SC, dst=SRV)/TCP(sport=40000+k, dport=port, flags="S", seq=1), t)
    if port in (22, 80):
        add(Ether()/IP(src=SRV, dst=SC)/TCP(sport=port, dport=40000+k, flags="SA", seq=9, ack=2), t+0.01)
    else:
        add(Ether()/IP(src=SRV, dst=SC)/TCP(sport=port, dport=40000+k, flags="RA", seq=0, ack=2), t+0.01)
# 6) normal traffic
dns_lookup("10.0.2.20", "news.example", "192.0.2.80", T0+30)
tcp_session("10.0.2.20", "192.0.2.80", 53001, 80, T0+30.2,
  b"GET / HTTP/1.1\r\nHost: news.example\r\nUser-Agent: Mozilla/5.0\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
 
pkts.sort(key=lambda p: p.time)
wrpcap("lab.pcap", pkts)
print(f"Wrote lab.pcap with {len(pkts)} packets")
