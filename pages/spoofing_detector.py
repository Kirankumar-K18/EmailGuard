"""PAGE 7 - Rule-based e-mail spoofing detector with a 0-100 heuristic risk score."""
from __future__ import annotations

import streamlit as st

from modules.analysis_engine import build_email_from_fields
from modules.spoofing_detector import DISCLAIMER, RULES
from ui.common import read_upload, run_analysis, safe_save
from ui.components import banner, page_header
from ui.report_view import render_report, render_risk_panel
from ui.theme import show_table

CLAIM_OPTIONS = ["not provided", "pass", "fail", "softfail", "none"]


def render() -> None:
    page_header("Email Spoofing Detector", "Rule-based heuristic risk score from sender, header, link and attachment indicators.", "alert")
    banner(DISCLAIMER, "warn")

    mode = st.radio("Input", ["Enter details manually", "Analyse a raw email / .eml"], horizontal=True, key="sp_mode")
    raw: bytes | None = None
    input_mode = "full_message"

    if mode == "Enter details manually":
        c1, c2 = st.columns(2)
        disp = c1.text_input("Sender display name", key="sp_disp", placeholder="PayPal Support")
        addr = c2.text_input("Sender address (From)", key="sp_addr", placeholder="service@paypa1-support.example")
        reply = c1.text_input("Reply-To address (optional)", key="sp_reply")
        rpath = c2.text_input("Return-Path (optional)", key="sp_rpath")
        subject = st.text_input("Subject", key="sp_subj")
        body = st.text_area("Message body", height=130, key="sp_body", placeholder="Paste the message text. Links in the text are analysed.")
        links = st.text_area("Additional links (one per line, optional)", height=80, key="sp_links")
        attach = st.text_input("Attachment file names (comma separated, optional)", key="sp_att", placeholder="invoice.pdf.exe, details.html")
        st.markdown("**Authentication results reported by the message headers** (optional - treated as unverified claims)")
        a, b, c = st.columns(3)
        claims = {"spf": a.selectbox("SPF", CLAIM_OPTIONS, key="sp_c_spf"), "dkim": b.selectbox("DKIM", CLAIM_OPTIONS, key="sp_c_dkim"),
                  "dmarc": c.selectbox("DMARC", CLAIM_OPTIONS, key="sp_c_dmarc")}
        if addr.strip():
            try:
                full_body = (body or "") + ("\n" + links if links.strip() else "")
                raw = build_email_from_fields(disp, addr, reply, rpath, subject, full_body, attach.split(","), claims)
            except ValueError as exc:
                st.error(str(exc))
        input_mode = "manual"
    else:
        kind = st.radio("Source", ["Upload .eml", "Paste raw email"], horizontal=True, key="sp_src")
        if kind == "Upload .eml":
            raw = read_upload(st.file_uploader("Select an .eml file", type=["eml", "txt"], key="sp_up"))
        else:
            t = st.text_area("Raw email", height=240, key="sp_text")
            raw = t.encode("utf-8", errors="replace") if t.strip() else None

    if st.button("Calculate risk score", type="primary", disabled=raw is None, key="sp_go"):
        with st.spinner("Applying detection rules..."):
            result = run_analysis(raw, input_mode=input_mode, dns_mode="off", source="spoofing_detector")
            if result is not None:
                safe_save(result)
                st.session_state["sp_result"] = result
    if raw is None:
        st.caption("Enter a sender address (manual mode) or provide an email to enable scoring.")

    result = st.session_state.get("sp_result")
    if result:
        st.divider()
        render_risk_panel(result, key="spoof")
        with st.expander("Full analysis report and PDF download"):
            st.caption("DNS lookups are off on this page, so SPF/DKIM/DMARC show NOT EVALUATED unless the header claims are used. Use Email Analyzer for live DNS checks.")
            render_report(result, key="spoof_full")

    with st.expander("Scoring rules and point values"):
        st.caption("Every rule adds a fixed number of points; totals are capped at 100.")
        show_table([{"Rule": k, "Points": v} for k, v in sorted(RULES.items(), key=lambda kv: -kv[1])])
