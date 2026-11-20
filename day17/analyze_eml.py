#!/usr/bin/env python3
"""Usage: python3 analyze_eml.py phish.eml"""
import sys, re, hashlib
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from urllib.parse import urlparse
 
def domain_of(addr):
    m = re.search(r"@([A-Za-z0-9.-]+)", addr or "")
    return m.group(1).lower() if m else ""
 
class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.links = []; self._href = None; self._text = ""
    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href"); self._text = ""
    def handle_data(self, data):
        if self._href is not None: self._text += data
    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._text.strip(), self._href)); self._href = None
 
msg = BytesParser(policy=policy.default).parse(open(sys.argv[1], "rb"))
flags = []
frm, rp, rt = str(msg["From"]), str(msg["Return-Path"] or ""), str(msg["Reply-To"] or "")
print(f"===== Email analysis: {sys.argv[1]} =====")
print("From:        ", frm)
print("Return-Path: ", rp)
print("Reply-To:    ", rt or "(none)")
print("Subject:     ", msg["Subject"])
 
# 1. Sender consistency
if domain_of(rp) and domain_of(rp) != domain_of(frm):
    flags.append(f"Return-Path domain ({domain_of(rp)}) differs from From domain ({domain_of(frm)})")
if rt and domain_of(rt) != domain_of(frm):
    flags.append(f"Reply-To domain ({domain_of(rt)}) differs from From domain ({domain_of(frm)})")
 
# 2. Authentication results
auth = str(msg["Authentication-Results"] or "")
print("Auth results:", auth or "(missing)")
for check in ("spf", "dkim", "dmarc"):
    m = re.search(check + r"=(\w+)", auth)
    result = m.group(1) if m else "missing"
    if result != "pass":
        flags.append(f"{check.upper()} result is '{result}'")
 
# 3. Origin of the message (the bottom-most Received header is closest to the sender)
received = msg.get_all("Received") or []
ips = [re.findall(r"\[(\d+\.\d+\.\d+\.\d+)\]", r) for r in received]
print("Received hops (newest first):", len(received))
if received:
    print("First hop IP seen by our server:", ips[0][0] if ips[0] else "n/a")
 
# 4. Subject urgency
if re.search(r"urgent|immediately|overdue|action required|verify|suspend", str(msg["Subject"]), re.I):
    flags.append("Subject uses urgency / pressure wording")
 
# 5. Links: visible text vs real destination
body = msg.get_body(preferencelist=("html",))
if body:
    lp = LinkParser(); lp.feed(body.get_content())
    for text, href in lp.links:
        shown = urlparse(text if "://" in text else "//" + text).hostname or ""
        real = urlparse(href).hostname or ""
        print(f"Link: shown='{text}'  real='{href}'")
        if shown and shown != real:
            flags.append(f"Link text shows {shown} but goes to {real}")
 
# 6. Attachments
for part in msg.iter_attachments():
    name = part.get_filename() or "(unnamed)"
    data = part.get_content()
    if isinstance(data, str): data = data.encode()
    sha = hashlib.sha256(data).hexdigest()
    print(f"Attachment: {name}  sha256={sha}")
    if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|com)$", name, re.I):
        flags.append(f"Attachment '{name}' uses a double extension")
    elif re.search(r"\.(exe|scr|js|vbs|bat|cmd|com|iso|lnk)$", name, re.I):
        flags.append(f"Attachment '{name}' is an executable type")
 
print()
print(f"RED FLAGS ({len(flags)}):")
for f in flags: print(" -", f)
print("VERDICT:", "likely phishing - escalate" if len(flags) >= 3 else "no strong indicators" if not flags else "suspicious - investigate")
