#!/usr/bin/env python3
"""Creates two fictional emails: phish.eml and legit.eml"""
import base64
from email.message import EmailMessage
from email.utils import format_datetime
import datetime
 
def build(path, hdrs, text, html, attach=None, extra_headers=None):
    m = EmailMessage()
    for k, v in hdrs.items():
        m[k] = v
    for k, v in (extra_headers or []):
        m[k] = v
    m.set_content(text)
    m.add_alternative(html, subtype="html")
    if attach:
        name, data = attach
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    with open(path, "wb") as f:
        f.write(bytes(m))
 
# ---------- phishing email ----------
phish_hdrs = {
    "Return-Path": "<bounce@mailer-x9.example>",
    "From": '"Accounts Payable" <billing@secure-invoice-review.example>',
    "Reply-To": "payments@freemail-box.example",
    "To": "priya.sharma@company.example",
    "Subject": "URGENT: Invoice Q3 overdue - action required immediately",
    "Date": "Tue, 20 Oct 2026 08:57:55 +0000",
    "Message-ID": "<7f3a91@mailer-x9.example>",
    "Authentication-Results": "mx.company.example; spf=fail smtp.mailfrom=mailer-x9.example; dkim=none; dmarc=fail header.from=secure-invoice-review.example",
}
phish_extra = [
    ("Received", "from mail-relay.mailer-x9.example (unknown [203.0.113.45]) by mx.company.example with ESMTP; Tue, 20 Oct 2026 08:58:02 +0000"),
    ("Received", "from [10.9.8.7] (localhost) by mail-relay.mailer-x9.example with SMTP; Tue, 20 Oct 2026 08:57:55 +0000"),
]
phish_text = "Your invoice is overdue. Open the link or the attachment immediately."
phish_html = ('<html><body><p>Dear customer,</p><p>Your invoice Q3 is <b>overdue</b>. '
  '<a href="http://secure-invoice-review.example/login/verify.php?id=8842">https://portal.company.example/invoice</a></p>'
  '<p>See the attached file. Failure to act today will suspend your account.</p></body></html>')
build("phish.eml", phish_hdrs, phish_text, phish_html,
      attach=("Invoice_Q3.pdf.exe", b"MZ-FAKE-SAMPLE-bootcamp-harmless"), extra_headers=phish_extra)
 
# ---------- legitimate email ----------
legit_hdrs = {
    "Return-Path": "<alice@company.example>",
    "From": '"Alice Rao" <alice@company.example>',
    "To": "priya.sharma@company.example",
    "Subject": "Team meeting notes",
    "Date": "Tue, 20 Oct 2026 09:10:00 +0000",
    "Message-ID": "<c21@company.example>",
    "Authentication-Results": "mx.company.example; spf=pass smtp.mailfrom=company.example; dkim=pass header.d=company.example; dmarc=pass header.from=company.example",
}
legit_extra = [("Received", "from mail.company.example (mail.company.example [10.0.2.5]) by mx.company.example with ESMTP; Tue, 20 Oct 2026 09:10:02 +0000")]
build("legit.eml", legit_hdrs, "Notes from today's meeting are below.",
      '<html><body><p>Notes from today\'s meeting are below. See <a href="https://wiki.company.example/notes">https://wiki.company.example/notes</a></p></body></html>',
      extra_headers=legit_extra)
print("Created phish.eml and legit.eml")
