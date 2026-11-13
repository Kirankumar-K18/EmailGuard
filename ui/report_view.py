"""Shared renderer for an analysis result (Analyzer, Demo Mode, Spoofing Detector, History)."""
from __future__ import annotations

import json

import plotly.graph_objects as go
import streamlit as st

from modules.analysis_engine import METHOD_LEGEND
from modules.report_generator import generate_pdf_report
from ui.components import banner, demo_banner, esc, html, method_chip, status_badge
from ui.theme import plotly_layout, rename_columns, show_chart, show_table


def risk_gauge(score: int, level: str, key: str) -> None:
    color = {"LOW": "#22C55E", "MEDIUM": "#F59E0B", "HIGH": "#EF4444"}.get(level, "#22D3EE")
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score, number=dict(font=dict(size=44, color="#E6EDF7"), suffix=""),
        gauge=dict(axis=dict(range=[0, 100], tickcolor="#8A9BB8", tickwidth=1), bar=dict(color=color, thickness=0.28),
                   bgcolor="rgba(0,0,0,0)", borderwidth=0,
                   steps=[dict(range=[0, 29.5], color="rgba(34,197,94,.18)"), dict(range=[29.5, 59.5], color="rgba(245,158,11,.18)"),
                          dict(range=[59.5, 100], color="rgba(239,68,68,.18)")]),
    ))
    plotly_layout(fig, height=210, legend=False)
    fig.update_layout(margin=dict(l=20, r=20, t=18, b=22))
    show_chart(fig, key=f"gauge_{key}")


def _auth_card(entry: dict) -> str:
    detail = entry.get("explanation", "")
    short = detail if len(detail) <= 150 else detail[:147] + "..."
    domain = entry.get("domain") or "-"
    return (f'<div class="eg-card" style="height:100%"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.45rem">'
            f'<b style="font-size:1rem">{esc(entry["mechanism"])}</b>{status_badge(entry.get("status", "-"))}</div>'
            f'<div style="margin-bottom:.4rem">{method_chip(entry.get("method", ""))}'
            f'<span style="color:#8A9BB8;font-size:.76rem">{esc(domain)}</span></div>'
            f'<p>{esc(short)}</p></div>')


def _claims_table(result: dict) -> None:
    claims = result["authentication"].get("header_claims") or {}
    rows = []
    for key in ("spf", "dkim", "dmarc"):
        ours = result["authentication"][key]["status"]
        claim = claims.get(key, "not stated")
        if claim == "not stated" or ours in ("NOT EVALUATED", "TEMPERROR"):
            verdict = "not comparable"
        elif claim == "pass" and ours == "PASS" or claim != "pass" and ours != "PASS":
            verdict = "consistent"
        else:
            verdict = "INCONSISTENT"
        rows.append({"Mechanism": key.upper(), "Claimed in headers (unverified)": claim, "EmailGuard result": ours, "Comparison": verdict})
    show_table(rows)


def _render_auth_details(result: dict, key: str) -> None:
    auth = result["authentication"]
    st.markdown("##### Header claims vs. EmailGuard's own checks")
    st.caption("Authentication-Results and Received-SPF headers are written by whichever server handled the message - an attacker can forge them. EmailGuard never treats them as verified.")
    _claims_table(result)

    spf, dkim, dmarc = auth["spf"], auth["dkim"], auth["dmarc"]
    with st.expander(f"SPF - {spf['status']}", expanded=spf["status"] not in ("NOT EVALUATED",)):
        html(f'{method_chip(spf["method"])}<span style="color:#8A9BB8;font-size:.78rem">source: {esc(spf["data_source"])}</span>')
        st.write(spf["explanation"])
        d = spf.get("details", {})
        if d.get("record"):
            st.markdown(f"**SPF record for `{spf['domain']}`**")
            st.code(d["record"], language="text", wrap_lines=True)
            st.caption(f"Identity checked: {result.get('spf_basis', '')} - IP {d.get('ip', '')} - DNS lookups used: {d.get('lookups', 0)} of 10")
        if d.get("mechanisms"):
            show_table(rename_columns(d["mechanisms"], {"qualifier": "Q", "mechanism": "Mechanism", "value": "Value", "meaning": "Meaning"}))
        if d.get("trace"):
            with st.expander("Evaluation trace"):
                st.code("\n".join(d["trace"]), language="text")

    with st.expander(f"DKIM - {dkim['status']}", expanded=dkim["status"] not in ("NOT EVALUATED",)):
        html(f'{method_chip(dkim["method"])}<span style="color:#8A9BB8;font-size:.78rem">key source: {esc(dkim["data_source"])}</span>')
        st.write(dkim["explanation"])
        sigs = dkim.get("details", {}).get("signatures", [])
        if sigs:
            rows = [{"d=": s.get("domain", ""), "s=": s.get("selector", ""), "Result": s.get("status", ""),
                     "Algorithm": s.get("algorithm", ""), "Canonicalization": s.get("canonicalization", ""),
                     "Key bits": s.get("key_bits") or "", "Reason": s.get("reason", "")} for s in sigs]
            show_table(rows)
            for s in sigs:
                if s.get("explanation"):
                    st.caption(f"{s.get('domain', '')} / {s.get('selector', '')}: {s['explanation']}")

    with st.expander(f"DMARC - {dmarc['status']}", expanded=dmarc["status"] not in ("NOT EVALUATED",)):
        html(f'{method_chip(dmarc["method"])}<span style="color:#8A9BB8;font-size:.78rem">source: {esc(dmarc["data_source"])}</span>')
        st.write(dmarc["explanation"])
        d = dmarc.get("details", {})
        if d.get("record"):
            st.code(d["record"], language="text", wrap_lines=True)
            st.caption(f"Policy p={d.get('policy')} - subdomain policy sp={d.get('subdomain_policy') or 'inherits p'} - pct={d.get('pct')} - "
                       f"SPF aligned: {d.get('spf_aligned')} - DKIM aligned: {d.get('dkim_aligned')}")
        for w in d.get("warnings", []):
            st.caption(f"Note: {w}")


def _render_indicators(result: dict, key: str) -> None:
    spoof = result["spoofing"]
    inds = spoof["indicators"]
    if not inds:
        st.success("No suspicious indicators were triggered by the rule set.")
    else:
        left, right = st.columns([3, 2])
        with left:
            for i in inds:
                ev = "".join(f'<div class="ev">{esc(e)}</div>' for e in i.get("evidence", []))
                html(f'<div class="eg-ind {esc(i["severity"])}"><span class="pts">+{i["points"]} pts</span>'
                     f'<div class="t">{esc(i["title"])} <span style="color:#8A9BB8;font-weight:400;font-size:.76rem">&middot; {esc(i["category"])}</span></div>'
                     f'<div class="d">{esc(i["detail"])}</div>{ev}</div>')
        with right:
            cats = spoof.get("category_scores", {})
            fig = go.Figure(go.Bar(x=list(cats.values()), y=list(cats.keys()), orientation="h", marker_color="#3B82F6"))
            plotly_layout(fig, height=60 + 36 * max(len(cats), 1), legend=False)
            fig.update_layout(title=dict(text="Points by category", font=dict(size=13)), yaxis=dict(autorange="reversed"))
            show_chart(fig, key=f"cat_{key}")
            st.caption(f"Raw total {spoof.get('raw_total', spoof['score'])} points, capped at 100. Bands: 0-29 LOW, 30-59 MEDIUM, 60-100 HIGH.")
    banner(spoof["disclaimer"], "warn")


def _render_email_details(result: dict) -> None:
    e = result["email"]
    rows = [("From", e.get("from")), ("To", e.get("to")), ("Reply-To", e.get("reply_to")), ("Return-Path", e.get("return_path")),
            ("Subject", e.get("subject")), ("Date", e.get("date")), ("Message-ID", e.get("message_id"))]
    show_table([{"Field": k, "Value": v or "(not present)"} for k, v in rows])
    if e.get("missing_headers"):
        st.warning("Missing headers: " + ", ".join(e["missing_headers"]))
    if e.get("received"):
        with st.expander(f"Received headers ({len(e['received'])} hops, newest first)"):
            st.code("\n\n".join(e["received"]), language="text", wrap_lines=True)
    if e.get("authentication_results"):
        with st.expander("Authentication-Results headers (claims, unverified)"):
            st.code("\n\n".join(e["authentication_results"]), language="text", wrap_lines=True)
    if e.get("dkim_signature"):
        with st.expander("DKIM-Signature headers"):
            st.code("\n\n".join(e["dkim_signature"]), language="text", wrap_lines=True)
    if e.get("urls"):
        with st.expander(f"URLs found ({len(e['urls'])})"):
            show_table(rename_columns(e["urls"], {"url": "URL", "text": "Link text", "source": "Found in"}))
    if e.get("attachments"):
        with st.expander(f"Attachments ({len(e['attachments'])})"):
            show_table(e["attachments"])
    if e.get("received_ips"):
        with st.expander("IP addresses seen in Received headers (candidates for the SPF check)"):
            show_table(e["received_ips"])
    if e.get("body_preview"):
        with st.expander("Body preview (first 600 characters, shown as plain text)"):
            st.text(e["body_preview"])


def _render_steps(result: dict) -> None:
    out = []
    for s in result["steps"]:
        out.append(f'<div class="eg-step"><div class="eg-step-n">{s["step"]}</div><div class="eg-step-body">'
                   f'<div><b>{esc(s["title"])}</b> &nbsp;{method_chip(s["method"])}{status_badge(s["status"])}</div>'
                   f'<div class="d">{esc(s["detail"])}</div></div></div>')
    html("".join(out))


def render_risk_panel(result: dict, key: str = "risk") -> None:
    """Focused view used by the Spoofing Detector: gauge, band, contributing indicators."""
    spoof = result["spoofing"]
    left, right = st.columns([2, 3])
    with left:
        html('<div style="color:#8A9BB8;font-size:.74rem;letter-spacing:.07em;font-weight:600;margin-bottom:-.4rem">HEURISTIC RISK SCORE (0-100)</div>')
        risk_gauge(spoof["score"], spoof["level"], key)
        html(f'<div style="text-align:center;margin-bottom:.6rem">{status_badge(spoof["level"] + " RISK", True)}</div>')
    with right:
        n = len(spoof["indicators"])
        html(f'<div class="eg-card"><h4>How the score was reached</h4>'
             f'<p style="color:#E6EDF7">{n} indicator(s) triggered, totalling {spoof.get("raw_total", spoof["score"])} points (capped at 100). '
             f'Bands: 0-29 LOW &middot; 30-59 MEDIUM &middot; 60-100 HIGH.</p>'
             f'<p>{spoof.get("rules_available", 0)} rules are evaluated; only those listed below contributed.</p></div>')
    _render_indicators(result, key)


def render_report(result: dict, key: str = "report") -> None:
    """Render the full report for ``result``."""
    if result.get("is_demo"):
        demo_banner()
    health = result.get("dns_health") or {}
    if health.get("checked") and not health.get("healthy"):
        banner("DNS health check failed: " + health.get("message", "") + " Any 'NONE' or 'no record' result below may be wrong.", "danger")
    verdict = result["verdict"]
    spoof = result["spoofing"]

    left, right = st.columns([3, 2])
    with left:
        saved = f" &middot; saved as #{result['analysis_id']}" if result.get("analysis_id") else ""
        html(f'<div class="eg-card eg-verdict"><div style="color:#8A9BB8;font-size:.74rem;letter-spacing:.07em;font-weight:600">FINAL SECURITY VERDICT</div>'
             f'<div class="eg-v-title">{status_badge(verdict["classification"], True)}</div>'
             f'<div style="color:#E6EDF7;font-size:.92rem">{esc(verdict["headline"])}</div>'
             f'<div style="color:#8A9BB8;font-size:.78rem">{esc(result.get("timestamp", ""))} &middot; DNS source: {esc(result.get("dns_source", ""))}{saved}</div></div>')
    with right:
        html('<div style="color:#8A9BB8;font-size:.74rem;letter-spacing:.07em;font-weight:600;margin-bottom:-.4rem">HEURISTIC RISK SCORE</div>')
        risk_gauge(spoof["score"], spoof["level"], key)
        html(f'<div style="text-align:center;margin-bottom:.6rem">{status_badge(spoof["level"] + " RISK", True)}</div>')

    cols = st.columns(3)
    for col, mech in zip(cols, ("spf", "dkim", "dmarc")):
        with col:
            html(_auth_card(result["authentication"][mech]))

    ds = result.get("digital_signature", {})
    html(f'<div class="eg-card"><b>Digital signature status</b> &nbsp;{status_badge(ds.get("status", "-"))} '
         f'<span style="color:#8A9BB8;font-size:.84rem">{esc(ds.get("note", ""))}</span></div>')

    tabs = st.tabs(["Authentication", "Indicators", "Email details", "Analysis process", "Method legend & limitations"])
    with tabs[0]:
        _render_auth_details(result, key)
    with tabs[1]:
        _render_indicators(result, key)
    with tabs[2]:
        _render_email_details(result)
    with tabs[3]:
        _render_steps(result)
    with tabs[4]:
        st.markdown("##### How to read each result")
        html("".join(f'<p>{method_chip(k)} {esc(v)}</p>' for k, v in METHOD_LEGEND.items()))
        st.markdown("##### Limitations of this analysis")
        for lim in result.get("limitations", []):
            st.markdown(f"- {lim}")

    c1, c2, _ = st.columns([1, 1, 3])
    try:
        pdf = generate_pdf_report(result)
        c1.download_button("Download PDF report", pdf, file_name=f"emailguard_report_{result.get('analysis_id') or 'new'}.pdf",
                           mime="application/pdf", key=f"pdf_{key}", type="primary")
    except Exception as exc:  # report generation must never break the page
        c1.error(f"PDF could not be generated: {exc}")
    c2.download_button("Download JSON", json.dumps(result, indent=2, default=str), file_name=f"emailguard_analysis_{result.get('analysis_id') or 'new'}.json",
                       mime="application/json", key=f"json_{key}")
