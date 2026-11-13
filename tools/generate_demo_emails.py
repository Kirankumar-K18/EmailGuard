"""Regenerate the Demo Mode data set (five .eml files, scenarios.json, demo_dns.json).

Run from the project root:   python tools/generate_demo_emails.py

* All domains use reserved names (.example) and all IPs use documentation
  ranges (RFC 5737), so nothing here can touch a real organisation.
* Scenarios 1, 3 and 4 carry GENUINE DKIM signatures made with throw-away RSA
  keys generated on the fly. The private keys are never written to disk - only
  the public keys, which are published in the *simulated* DNS zone file.
* Scenario 3 is signed correctly and then modified, so DKIM verification fails
  for a real cryptographic reason (body hash mismatch).
"""
from __future__ import annotations

import json
import sys
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import dkim_verifier, rsa_signature  # noqa: E402

OUT = ROOT / "sample_emails" / "demo_emails"
RECIPIENT = "student@campus-demo.example"


def new_message(headers: list[tuple[str, str]], body: str, html: str | None = None) -> EmailMessage:
    msg = EmailMessage(policy=SMTP)
    for name, value in headers:
        msg[name] = value
    msg.set_content(body, cte="7bit")
    if html:
        msg.add_alternative(html, subtype="html", cte="7bit")
    return msg


def make_key(domain: str, selector: str):
    key = rsa_signature.generate_keypair(2048)
    return rsa_signature.private_key_to_pem(key), dkim_verifier.make_key_record(key.public_key())


def received(frm: str, ip: str, by: str, when: str, ident: str) -> tuple[str, str]:
    return ("Received", f"from {frm} ({frm} [{ip}]) by {by} with ESMTPS id {ident} for <{RECIPIENT}>; {when}")


def build() -> tuple[list[dict], dict]:
    zone: dict[str, dict] = {}
    scenarios: list[dict] = []

    # ---- Scenario 1: legitimate, fully authenticated ---------------------
    d1, sel1 = "northwind-demo.example", "sel2026"
    priv, rec = make_key(d1, sel1)
    zone[d1] = {"TXT": ["v=spf1 ip4:203.0.113.0/24 include:_spf.mailhost-demo.example -all"], "MX": ["mail.northwind-demo.example"]}
    zone["_spf.mailhost-demo.example"] = {"TXT": ["v=spf1 ip4:198.51.100.0/24 ~all"]}
    zone[f"{sel1}._domainkey.{d1}"] = {"TXT": [rec]}
    zone[f"_dmarc.{d1}"] = {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc-reports@northwind-demo.example; pct=100; adkim=r; aspf=r"]}
    msg = new_message(
        [("Return-Path", "<priya.sharma@northwind-demo.example>"),
         received("mail.northwind-demo.example", "203.0.113.25", "mx.campus-demo.example", "Thu, 12 Nov 2026 09:14:30 +0530", "A1B2C3"),
         ("Authentication-Results", "mx.campus-demo.example; spf=pass smtp.mailfrom=northwind-demo.example; dkim=pass header.d=northwind-demo.example; dmarc=pass header.from=northwind-demo.example"),
         ("From", "Priya Sharma <priya.sharma@northwind-demo.example>"), ("To", RECIPIENT),
         ("Subject", "Project review meeting - Friday 10:00"), ("Date", "Thu, 12 Nov 2026 09:14:22 +0530"),
         ("Message-ID", "<20261112091422.7F3A@northwind-demo.example>")],
        "Hello,\n\nThe project review meeting is scheduled for Friday at 10:00 in Room 204.\n"
        "The agenda and slides are available on the team portal:\nhttps://northwind-demo.example/portal/review\n\nRegards,\nPriya Sharma\nNorthwind Demo Ltd\n")
    signed = dkim_verifier.sign_for_demo(msg.as_bytes(), d1, sel1, priv)
    (OUT / "01_legitimate_authenticated.eml").write_bytes(signed)
    scenarios.append({
        "id": 1, "title": "Legitimate authenticated email", "file": "01_legitimate_authenticated.eml", "sending_ip": "203.0.113.25",
        "description": "A normal internal-style message. The sending IP is listed in the domain's SPF record, the message carries a valid DKIM signature and the domain publishes a DMARC reject policy.",
        "expected": {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS", "classification": "AUTHENTICATED"},
        "learning_points": ["SPF passes because 203.0.113.25 is inside ip4:203.0.113.0/24.",
                            "DKIM is verified cryptographically against the public key in the simulated DNS zone.",
                            "DMARC passes because SPF and DKIM are both aligned with the From domain."],
    })

    # ---- Scenario 2: SPF failure ----------------------------------------
    d2 = "globalbank-demo.example"
    zone[d2] = {"TXT": ["v=spf1 ip4:192.0.2.0/25 mx -all"], "MX": ["mail.globalbank-demo.example"]}
    zone["mail.globalbank-demo.example"] = {"A": ["192.0.2.10"]}
    zone[f"_dmarc.{d2}"] = {"TXT": ["v=DMARC1; p=quarantine; rua=mailto:dmarc@globalbank-demo.example; pct=100"]}
    msg = new_message(
        [("Return-Path", "<accounts@globalbank-demo.example>"),
         received("unknown-host.example", "198.51.100.77", "mx.campus-demo.example", "Thu, 12 Nov 2026 11:02:51 +0530", "D4E5F6"),
         ("Authentication-Results", "mx.campus-demo.example; spf=fail smtp.mailfrom=globalbank-demo.example; dkim=none; dmarc=fail header.from=globalbank-demo.example"),
         ("From", "GlobalBank Accounts <accounts@globalbank-demo.example>"), ("To", RECIPIENT),
         ("Subject", "Your monthly statement is ready"), ("Date", "Thu, 12 Nov 2026 11:02:40 +0530"),
         ("Message-ID", "<stmt-88120@globalbank-demo.example>")],
        "Dear customer,\n\nYour statement for October is now available in online banking:\nhttps://globalbank-demo.example/statements\n\nGlobalBank Demo\n")
    (OUT / "02_spf_failure.eml").write_bytes(msg.as_bytes())
    scenarios.append({
        "id": 2, "title": "Email with SPF failure", "file": "02_spf_failure.eml", "sending_ip": "198.51.100.77",
        "description": "The message claims to come from globalbank-demo.example but was delivered from 198.51.100.77, which is not authorised by that domain's SPF record (-all). There is no DKIM signature to fall back on.",
        "expected": {"spf": "FAIL", "dkim": "NONE", "dmarc": "FAIL", "classification": "FAILED AUTHENTICATION"},
        "learning_points": ["SPF checks the *connecting IP*, not what the From header says.",
                            "With no DKIM signature, DMARC has no aligned pass to rely on and fails.",
                            "The domain's p=quarantine policy would send this message to spam."],
    })

    # ---- Scenario 3: DKIM failure (modified in transit) -------------------
    d3, sel3 = "cloudmart-demo.example", "mail1"
    priv, rec = make_key(d3, sel3)
    zone[d3] = {"TXT": ["v=spf1 ip4:203.0.113.128/25 -all"]}
    zone[f"{sel3}._domainkey.{d3}"] = {"TXT": [rec]}
    zone[f"_dmarc.{d3}"] = {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@cloudmart-demo.example; pct=100"]}
    zone["lists-demo.example"] = {"TXT": ["v=spf1 ip4:192.0.2.60 -all"]}
    original = new_message(
        [("From", "CloudMart Orders <orders@cloudmart-demo.example>"), ("To", RECIPIENT),
         ("Subject", "Your order #48213 has shipped"), ("Date", "Wed, 11 Nov 2026 16:40:05 +0530"),
         ("Message-ID", "<ord-48213@cloudmart-demo.example>")],
        "Hi,\n\nYour order #48213 has shipped.\nEstimated delivery: 14 Nov 2026.\n\nThank you for shopping with CloudMart.\n")
    signed = dkim_verifier.sign_for_demo(original.as_bytes(), d3, sel3, priv)
    tampered = signed.replace(b"Estimated delivery: 14 Nov 2026.",
                              b"Estimated delivery: 14 Nov 2026.\r\nPlease update your payment details at https://cloudmart-demo.example/billing")
    tampered += b"\r\n--\r\nYou are receiving this via lists-demo.example\r\n"
    assert tampered != signed
    hdr = (b"Return-Path: <bounce-7391@lists-demo.example>\r\n"
           + (b"Received: from relay.lists-demo.example (relay.lists-demo.example [192.0.2.60]) by mx.campus-demo.example with ESMTPS id G7H8I9 "
              b"for <student@campus-demo.example>; Wed, 11 Nov 2026 16:41:12 +0530\r\n")
           + b"Authentication-Results: mx.campus-demo.example; spf=pass smtp.mailfrom=lists-demo.example; "
             b"dkim=fail (body hash did not verify) header.d=cloudmart-demo.example; dmarc=fail header.from=cloudmart-demo.example\r\n")
    (OUT / "03_dkim_failure.eml").write_bytes(hdr + tampered)
    scenarios.append({
        "id": 3, "title": "Email with DKIM signature failure", "file": "03_dkim_failure.eml", "sending_ip": "192.0.2.60",
        "description": "A genuinely DKIM-signed message that was modified after signing (a mailing-list footer and an extra sentence were added). The body hash no longer matches, so the signature fails. SPF passes only for the list's own domain, which is not aligned with the From domain.",
        "expected": {"spf": "PASS", "dkim": "FAIL", "dmarc": "FAIL", "classification": "FAILED AUTHENTICATION"},
        "learning_points": ["DKIM protects the message CONTENT: changing even one character of the signed body breaks it.",
                            "SPF passed for lists-demo.example, but DMARC needs the SPF domain to align with the From domain - it does not.",
                            "This is why mailing lists and forwarders often break DKIM and DMARC."],
    })

    # ---- Scenario 4: Reply-To mismatch (authenticated but suspicious) ----
    d4, sel4 = "acmetech-demo.example", "dkim2026"
    priv, rec = make_key(d4, sel4)
    zone[d4] = {"TXT": ["v=spf1 ip4:203.0.113.64/26 -all"]}
    zone[f"{sel4}._domainkey.{d4}"] = {"TXT": [rec]}
    zone[f"_dmarc.{d4}"] = {"TXT": ["v=DMARC1; p=quarantine; rua=mailto:dmarc@acmetech-demo.example; pct=100"]}
    msg = new_message(
        [("Return-Path", "<rahul.mehta@acmetech-demo.example>"),
         received("mail.acmetech-demo.example", "203.0.113.80", "mx.campus-demo.example", "Tue, 10 Nov 2026 14:22:10 +0530", "J1K2L3"),
         ("Authentication-Results", "mx.campus-demo.example; spf=pass smtp.mailfrom=acmetech-demo.example; dkim=pass header.d=acmetech-demo.example; dmarc=pass header.from=acmetech-demo.example"),
         ("From", "Rahul Mehta (CFO) <rahul.mehta@acmetech-demo.example>"), ("To", RECIPIENT),
         ("Reply-To", "Rahul Mehta <rahul.mehta.cfo@gmail.com>"),
         ("Subject", "Urgent: change of vendor bank details"), ("Date", "Tue, 10 Nov 2026 14:22:01 +0530"),
         ("Message-ID", "<20261110142201.55A1@acmetech-demo.example>")],
        "Hi,\n\nPlease update the bank details for Zenith Supplies before today's payment run.\n"
        "The new account information will follow from my personal address - reply there only,\nas I am travelling and cannot take calls.\n"
        "This is urgent, please process it immediately.\n\nRahul\n")
    signed = dkim_verifier.sign_for_demo(msg.as_bytes(), d4, sel4, priv)
    (OUT / "04_reply_to_mismatch.eml").write_bytes(signed)
    scenarios.append({
        "id": 4, "title": "Email with From / Reply-To mismatch", "file": "04_reply_to_mismatch.eml", "sending_ip": "203.0.113.80",
        "description": "A business-email-compromise pattern: the message passes SPF, DKIM and DMARC (it really was sent through the company's mail system, for example from a compromised account), but replies are redirected to a free-mail address and the text pressures the recipient to change bank details.",
        "expected": {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS", "classification": "SUSPICIOUS"},
        "learning_points": ["Authentication proves WHO sent the message, not that it is trustworthy.",
                            "Reply-To pointing to a different domain is a classic BEC warning sign.",
                            "Heuristics add context where cryptographic checks pass."],
    })

    # ---- Scenario 5: multiple indicators ----------------------------------
    zone["paypal-demo-note.example"] = {"TXT": ["(Scenario 5 domains intentionally publish no SPF/DMARC records.)"]}
    del zone["paypal-demo-note.example"]
    msg = new_message(
        [("Return-Path", "<bounce@mailer-xj3.example>"),
         received("localhost", "192.0.2.201", "relay8.example", "Mon, 09 Nov 2026 02:55:00 +0000", "R8"),
         received("relay7.example", "192.0.2.207", "relay8.example", "Mon, 09 Nov 2026 02:50:00 +0000", "R7"),
         received("relay6.example", "192.0.2.206", "relay7.example", "Mon, 09 Nov 2026 03:00:00 +0000", "R6"),
         received("relay5.example", "192.0.2.205", "relay6.example", "Mon, 09 Nov 2026 02:49:00 +0000", "R5"),
         received("relay4.example", "192.0.2.204", "relay5.example", "Mon, 09 Nov 2026 02:48:00 +0000", "R4"),
         received("relay3.example", "198.51.100.200", "relay4.example", "Mon, 09 Nov 2026 02:47:00 +0000", "R3"),
         received("relay2.example", "192.0.2.202", "relay3.example", "Mon, 09 Nov 2026 02:46:00 +0000", "R2"),
         received("relay1.example", "192.0.2.201", "relay2.example", "Mon, 09 Nov 2026 02:45:00 +0000", "R1"),
         ("Authentication-Results", "mx.campus-demo.example; spf=pass smtp.mailfrom=paypa1-support.example; dkim=pass header.d=paypa1-support.example; dmarc=pass header.from=paypa1-support.example"),
         ("From", "PayPal Support <service@paypa1-support.example>"), ("To", RECIPIENT),
         ("Reply-To", "security.paypal.help@gmail.com"),
         ("Subject", "URGENT: Your account has been suspended - verify your account immediately"),
         ("Date", "Mon, 09 Nov 2026 02:44:10 +0000"), ("Message-ID", "<9f2c1d@mailer-xj3.example>")],
        "Dear customer,\n\nUnusual activity was detected and your account has been suspended.\n"
        "You must verify your account immediately - act now or it will be closed.\n"
        "Log in here: http://paypal.com@secure-verify-login.example/account\n"
        "Or use: http://203.0.113.200/paypal/login  or  https://bit.ly/demo-3xQ9\n\nPayPal Security Team\n",
        html='<html><body><p>Your account has been suspended. <a href="http://203.0.113.200/paypal/login">www.paypal.com/secure-login</a></p>'
             '<p>Short link: <a href="https://bit.ly/demo-3xQ9">Verify your account now</a></p></body></html>')
    msg.add_attachment(b"DEMO PLACEHOLDER - harmless text, not an executable.\n", maintype="application", subtype="octet-stream", filename="PayPal_Statement.pdf.exe")
    msg.add_attachment(b"<html><body>demo placeholder</body></html>\n", maintype="text", subtype="html", filename="details.html")
    (OUT / "05_multiple_indicators.eml").write_bytes(msg.as_bytes())
    scenarios.append({
        "id": 5, "title": "Suspicious email with multiple indicators", "file": "05_multiple_indicators.eml", "sending_ip": "198.51.100.200",
        "description": "A textbook phishing message: a look-alike domain (paypa1), a brand display name, a free-mail Reply-To, a mismatched Return-Path, links to a raw IP / URL shortener / '@' trick, a double-extension attachment, out-of-order Received hops - and a FORGED Authentication-Results header claiming everything passed.",
        "expected": {"spf": "NONE", "dkim": "NONE", "dmarc": "NONE", "classification": "SUSPICIOUS"},
        "learning_points": ["Never trust an Authentication-Results header inside the message: EmailGuard re-checks and finds the claims are false.",
                            "No single indicator is conclusive, but many together drive the score to HIGH.",
                            "The attacker's own domains publish no SPF/DKIM/DMARC, so authentication cannot help - heuristics must."],
    })
    return scenarios, zone


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    scenarios, zone = build()
    (OUT / "scenarios.json").write_text(json.dumps({
        "notice": "DEMONSTRATION DATA - fictional messages, reserved .example domains, documentation IP ranges.",
        "scenarios": scenarios}, indent=2), encoding="utf-8")
    (OUT / "demo_dns.json").write_text(json.dumps({
        "notice": "SIMULATED DNS ZONE used by Demo Mode. Contains public keys only; the matching private keys were discarded at generation time.",
        "zone": zone}, indent=2), encoding="utf-8")
    print(f"Wrote {len(scenarios)} scenarios to {OUT}")


if __name__ == "__main__":
    main()
