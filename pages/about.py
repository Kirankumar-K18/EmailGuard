"""PAGE 9 - About the project."""
from __future__ import annotations

import streamlit as st

import config
from database import db
from ui.components import banner, esc, html, page_header
from ui.theme import show_table

DEV_FIELDS = [
    ("dev.name", "Student name", "[Your Name]"),
    ("dev.roll", "Roll number / Registration no.", "[Roll Number]"),
    ("dev.course", "Course and year", "B.Tech - Cryptography and Network Security (CNS)"),
    ("dev.institution", "Institution", "[College / University Name]"),
    ("dev.guide", "Faculty / Guide", "[Faculty Name]"),
    ("dev.team", "Team members (if any)", "[Team Members]"),
]

SYLLABUS = [
    ("Symmetric vs. asymmetric cryptography", "Digital Signature Lab > Concepts tab; RSA key pair generation", "modules/rsa_signature.py"),
    ("Public-key cryptosystem: RSA", "RSA-2048 key generation, key serialisation (PKCS#8 / SPKI PEM), fingerprints", "modules/rsa_signature.py"),
    ("Cryptographic hash functions: SHA-256", "Hashing, integrity verification, avalanche-effect demonstration", "modules/hashing.py"),
    ("Digital signatures (RSA-PSS)", "Sign, verify, tamper, fail workflow; non-repudiation discussion", "pages/digital_signature.py"),
    ("Message authentication and integrity", "DKIM header/body hash verification; SHA-256 digest comparison", "modules/dkim_verifier.py"),
    ("Key distribution and public-key infrastructure ideas", "DKIM public keys distributed through DNS TXT records", "modules/dkim_verifier.py, modules/dns_utils.py"),
    ("E-mail security", "SPF, DKIM, DMARC analysis; spoofing and phishing indicators", "modules/spf_checker.py, dmarc_checker.py, spoofing_detector.py"),
    ("Network attacks and threats", "Spoofing, display-name impersonation, look-alike domains, header forgery, BEC patterns", "modules/spoofing_detector.py"),
    ("Network security applications and protocols", "DNS-based authentication, SMTP header analysis (Received chain)", "modules/email_parser.py"),
]

CONCEPTS = [
    ("Authentication", "Proving who sent a message: SPF (server IP), DKIM (domain signature), DMARC (alignment with From)."),
    ("Integrity", "Detecting modification: SHA-256 digests, DKIM body hash, RSA-PSS verification failing after tampering."),
    ("Non-repudiation", "A valid RSA signature can only come from the private-key holder (shown in the lab)."),
    ("Confidentiality (contrast)", "Not provided by SPF/DKIM/DMARC or signatures - requires encryption such as TLS or S/MIME; explained for comparison."),
    ("Defence in depth", "Cryptographic checks, DNS policy checks and heuristics are combined and always labelled by method."),
    ("Secure software practice", "Parameterised SQL, HTML-escaping of untrusted e-mail content, input size limits, no secrets stored."),
]


def render() -> None:
    page_header("About EmailGuard", config.APP_FULL_NAME, "info")
    html(f'<div class="eg-card"><h4>Project description</h4><p style="color:#E6EDF7">EmailGuard is a Streamlit application that analyses e-mail authentication. '
         'It parses raw messages, retrieves and evaluates SPF and DMARC records from DNS, verifies DKIM signatures cryptographically, scores spoofing indicators with a transparent '
         'rule set, stores every analysis in SQLite and produces PDF reports. A Digital Signature Lab demonstrates RSA-2048, SHA-256 and RSA-PSS interactively. '
         'Every result states how it was produced, and anything that could not be verified is reported as NOT EVALUATED rather than assumed.</p></div>')
    c1, c2 = st.columns(2)
    with c1:
        html('<div class="eg-card"><h4>Problem statement</h4><p>E-mail was designed without sender authentication, so the From address can be forged trivially. '
             'Spoofed and phishing messages exploit this to steal credentials and redirect payments. Users and administrators need a way to check, with cryptographic and DNS evidence, '
             'whether a message really came from the domain it claims, and to see which signals make it suspicious - without over-claiming certainty.</p></div>')
    with c2:
        html('<div class="eg-card"><h4>Objectives</h4>'
             '<p>&bull; Implement RSA-2048 key generation, SHA-256 hashing and RSA-PSS signing and verification using a vetted library.</p>'
             '<p>&bull; Perform genuine SPF (DNS), DKIM (cryptographic) and DMARC (policy and alignment) analysis.</p>'
             '<p>&bull; Detect spoofing indicators with an explainable 0-100 risk score.</p>'
             '<p>&bull; Persist and review analyses, and export professional PDF reports.</p>'
             '<p>&bull; Teach the concepts through guided demo scenarios.</p></div>')

    st.markdown("##### Technologies used")
    show_table([
        {"Layer": "Language", "Technology": "Python 3.11+", "Purpose": "Application and analysis logic"},
        {"Layer": "UI", "Technology": "Streamlit, custom CSS, Plotly", "Purpose": "SOC-style dashboard and interactive charts"},
        {"Layer": "Cryptography", "Technology": "cryptography (OpenSSL), hashlib", "Purpose": "RSA-2048, RSA-PSS, SHA-256"},
        {"Layer": "E-mail", "Technology": "Python email package, re", "Purpose": "RFC 5322 parsing, header and URL extraction"},
        {"Layer": "DNS", "Technology": "dnspython", "Purpose": "TXT / A / AAAA / MX lookups for SPF, DKIM keys and DMARC"},
        {"Layer": "DKIM", "Technology": "dkimpy", "Purpose": "RFC 6376 canonicalisation and signature verification"},
        {"Layer": "Storage", "Technology": "SQLite (sqlite3)", "Purpose": "Analysis history, events, settings"},
        {"Layer": "Reports", "Technology": "ReportLab", "Purpose": "PDF analysis reports"},
    ])

    st.markdown("##### CNS syllabus mapping")
    st.caption("The mapping uses the standard topics of an undergraduate Cryptography and Network Security course. Adjust the topic names to match your prescribed syllabus and unit numbers.")
    show_table([{"CNS topic": a, "Where it appears in EmailGuard": b, "Source file": c} for a, b, c in SYLLABUS])

    st.markdown("##### Security concepts implemented")
    html('<div class="eg-card">' + "".join(f"<p><b style='color:#E6EDF7'>{esc(k)}</b> - {esc(v)}</p>" for k, v in CONCEPTS) + "</div>")

    st.markdown("##### Developer information")
    st.caption("Editable placeholders. Values are saved in the local SQLite database (application_settings table).")
    try:
        saved = db.get_settings("dev.")
    except db.DatabaseError as exc:
        st.error(str(exc))
        saved = {}
    with st.form("dev_form"):
        values = {}
        cols = st.columns(2)
        for i, (key, label, default) in enumerate(DEV_FIELDS):
            values[key] = cols[i % 2].text_input(label, value=saved.get(key, default), max_chars=120)
        if st.form_submit_button("Save developer information", type="primary"):
            try:
                for k, v in values.items():
                    db.set_setting(k, v.strip())
                st.success("Saved.")
            except db.DatabaseError as exc:
                st.error(str(exc))
    banner("EmailGuard is an educational project. Its results are indicative and must not be used as the sole basis for security decisions.", "warn")
