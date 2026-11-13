"""PAGE 2 - Email analyzer: headers, full message, .eml upload, or manual sender information."""
from __future__ import annotations

import streamlit as st

from modules.analysis_engine import build_email_from_fields
from modules.email_parser import EmailParseError, parse_email
from ui.common import dns_choice_help, read_upload, run_analysis, safe_save
from ui.components import banner, page_header
from ui.report_view import render_report

SAMPLE_HEADERS = """Return-Path: <info@example.org>
Received: from mail.example.org (mail.example.org [203.0.113.10]) by mx.example.net with ESMTPS id X1; Thu, 12 Nov 2026 10:00:05 +0000
From: Example Org <info@example.org>
To: you@example.net
Subject: Sample headers
Date: Thu, 12 Nov 2026 10:00:00 +0000
Message-ID: <abc123@example.org>
"""


def render() -> None:
    page_header("Email Analyzer", "Parse a message, run SPF / DKIM / DMARC checks and a heuristic spoofing assessment.", "mail")
    banner("Every result is labelled by how it was produced: CRYPTOGRAPHIC (signature really verified), DNS (record fetched and evaluated), "
           "HEADER CLAIM (stated by the message, not verified) or HEURISTIC (rule-based). Missing information is reported as NOT EVALUATED, never as a pass.", "info")

    mode = st.radio("Input method", ["Paste raw email / headers", "Upload .eml file", "Enter sender information"], horizontal=True, key="an_mode")
    raw: bytes | None = None
    input_mode = "full_message"

    if mode == "Paste raw email / headers":
        kind = st.radio("What are you pasting?", ["Complete raw email (headers + body)", "Headers only"], horizontal=True, key="an_kind")
        text = st.text_area("Raw content", height=260, key="an_text", placeholder=SAMPLE_HEADERS,
                            help="In Gmail use 'Show original'; in Outlook open message properties. Paste exactly as shown.")
        if text.strip():
            raw = text.encode("utf-8", errors="replace")
        input_mode = "headers_only" if kind == "Headers only" else "full_message"
        if input_mode == "full_message":
            st.caption("Pasted text can differ from the original bytes (line endings, whitespace), which may break DKIM. Upload the .eml for exact verification.")
    elif mode == "Upload .eml file":
        up = st.file_uploader("Select an .eml file", type=["eml", "txt"], key="an_upload")
        raw = read_upload(up)
    else:
        c1, c2 = st.columns(2)
        disp = c1.text_input("Display name", key="an_disp", placeholder="Support Team")
        addr = c2.text_input("Sender address (From)", key="an_addr", placeholder="user@example.com")
        reply = c1.text_input("Reply-To (optional)", key="an_reply")
        rpath = c2.text_input("Return-Path / envelope sender (optional)", key="an_rpath")
        subject = c1.text_input("Subject", key="an_subj")
        attach = c2.text_input("Attachment file names (comma separated, optional)", key="an_att", placeholder="invoice.pdf.exe")
        body = st.text_area("Body text (optional)", height=140, key="an_body")
        st.caption("Manual entry builds a synthetic message containing only what you typed, so DKIM cannot be verified and header-based authentication claims are unavailable.")
        if addr.strip():
            try:
                raw = build_email_from_fields(disp, addr, reply, rpath, subject, body, [a for a in attach.split(",")])
            except ValueError as exc:
                st.error(str(exc))
        input_mode = "manual"

    st.markdown("##### Authentication checks")
    c1, c2, c3 = st.columns([1.4, 1.4, 1])
    dns_label = c1.selectbox("DNS lookups", ["Live DNS (real queries)", "Off (no DNS)"], key="an_dns", help=dns_choice_help())
    ip = c2.text_input("Sending server IP (for SPF)", key="an_ip", placeholder="203.0.113.10",
                       help="The IP address of the server that delivered the message to you, normally the first external hop in the Received headers.")
    timeout = c3.number_input("DNS timeout (s)", min_value=1.0, max_value=30.0, value=5.0, step=1.0, key="an_to")
    envelope = st.text_input("Envelope sender override (optional)", key="an_env", placeholder="bounce@example.com",
                             help="Domain used for SPF. Defaults to the Return-Path, then the From domain.")

    if raw is not None and input_mode != "manual":
        try:
            preview = parse_email(raw)
            if preview.received_ips and not ip:
                ext = [r for r in preview.received_ips if not r["is_private"]]
                if ext:
                    st.info("IP addresses found in Received headers (oldest hop last): " + ", ".join(r["ip"] for r in ext[:6])
                            + ". Copy the one that delivered the message to your server into the field above to enable SPF.")
        except EmailParseError:
            pass

    if st.button("Analyze email", type="primary", disabled=raw is None, key="an_go"):
        with st.spinner("Analysing..."):
            result = run_analysis(
                raw, input_mode=input_mode, dns_mode="live" if dns_label.startswith("Live") else "off",
                sending_ip=ip, envelope_from=envelope or None, dns_timeout=float(timeout), source="analyzer")
            if result is not None:
                safe_save(result)
                st.session_state["an_result"] = result
    if raw is None:
        st.caption("Provide input above to enable analysis.")

    result = st.session_state.get("an_result")
    if result:
        st.divider()
        render_report(result, key="analyzer")
