"""PAGE 3 - SPF verification (real DNS lookups via dnspython)."""
from __future__ import annotations

import streamlit as st

from modules import demo_data
from modules.dns_utils import LiveResolver
from ui.common import dns_health_warning
from modules.spf_checker import SPF_LIMITATIONS, check_spf
from ui.components import banner, card, demo_banner, esc, html, kv_list, method_chip, page_header, status_badge
from ui.theme import rename_columns, show_table

STATUS_HELP = {
    "PASS": "The IP is authorised by the domain's SPF record.",
    "FAIL": "The IP is explicitly not authorised (-all).",
    "SOFTFAIL": "The IP is probably not authorised (~all).",
    "NEUTRAL": "The record makes no statement about the IP (?all or no match).",
    "NONE": "The domain publishes no SPF record.",
    "PERMERROR": "The record is invalid or exceeds RFC limits.",
    "TEMPERROR": "A temporary DNS problem prevented evaluation.",
    "NOT EVALUATED": "EmailGuard stopped because the record uses a feature it does not support.",
}


def render() -> None:
    page_header("SPF Verification", "Retrieve a domain's SPF record from DNS and test whether an IP address is authorised to send for it.", "globe")
    banner("SPF authenticates the connecting server's IP against the domain in the envelope sender (MAIL FROM). It does not verify the visible From address "
           "and does not protect message content.", "info")

    source = st.radio("DNS source", ["Live DNS (real lookup)", "Demonstration zone (offline, simulated)"], horizontal=True, key="spf_src")
    demo = source.startswith("Demonstration")
    zone_domains: list[str] = []
    if demo:
        zone = demo_data.load_zone()
        zone_domains = sorted(d for d, v in zone.items() if any(t.startswith("v=spf1") for t in v.get("TXT", [])))
        demo_banner("DEMONSTRATION DATA - this lookup uses the bundled simulated DNS zone, not the real Internet.")

    c1, c2 = st.columns(2)
    if demo:
        domain = c1.selectbox("Sender domain", zone_domains, key="spf_dom_demo")
        defaults = {"northwind-demo.example": "203.0.113.25", "globalbank-demo.example": "198.51.100.77", "cloudmart-demo.example": "203.0.113.200",
                    "acmetech-demo.example": "203.0.113.80", "lists-demo.example": "192.0.2.60", "_spf.mailhost-demo.example": "198.51.100.5"}
        ip = c2.text_input("Sending IP address", value=defaults.get(domain, "203.0.113.25"), key=f"spf_ip_demo_{domain}")
    else:
        domain = c1.text_input("Sender domain", key="spf_dom", placeholder="example.com")
        ip = c2.text_input("Sending IP address", key="spf_ip", placeholder="203.0.113.10")

    if st.button("Check SPF", type="primary", key="spf_go"):
        if not (domain or "").strip() or not ip.strip():
            st.error("Enter both a domain and an IP address.")
        else:
            try:
                with st.spinner("Querying DNS..." if not demo else "Evaluating..."):
                    resolver = demo_data.demo_resolver() if demo else LiveResolver()
                    st.session_state["spf_result"] = check_spf(domain, ip, resolver)
                    st.session_state["spf_demo"] = demo
            except ValueError as exc:
                st.error(str(exc))
                st.session_state.pop("spf_result", None)
            except Exception as exc:
                st.error(f"Unexpected error: {type(exc).__name__}: {exc}")
                st.session_state.pop("spf_result", None)

    res = st.session_state.get("spf_result")
    if not res:
        return
    st.divider()
    if st.session_state.get("spf_demo"):
        demo_banner("DEMONSTRATION DATA - simulated DNS zone.")
    elif res.status in ("NONE", "TEMPERROR"):
        dns_health_warning()
    left, right = st.columns([2, 3])
    with left:
        html(f'<div class="eg-card"><div style="color:#8A9BB8;font-size:.74rem;letter-spacing:.07em;font-weight:600">SPF RESULT</div>'
             f'<div style="margin:.4rem 0">{status_badge(res.status, True)}</div>{method_chip("DNS")}'
             f'<p style="margin-top:.6rem">{esc(STATUS_HELP.get(res.status, ""))}</p></div>')
        html('<div class="eg-card">' + kv_list([("Domain", res.domain), ("IP address", res.ip), ("Matched term", res.matched or "none"),
                                                ("DNS lookups used", f"{res.lookups} of 10"), ("Data source", res.data_source)]) + "</div>")
    with right:
        html(f'<div class="eg-card"><h4>Explanation</h4><p style="color:#E6EDF7">{esc(res.explanation)}</p></div>')
        if res.record:
            st.markdown("**Retrieved SPF record**")
            st.code(res.record, language="text", wrap_lines=True)
    if res.mechanisms:
        st.markdown("##### Parsed mechanisms (evaluated left to right)")
        show_table(rename_columns(res.mechanisms, {"qualifier": "Qualifier", "mechanism": "Mechanism", "value": "Value", "meaning": "Meaning"}))
    with st.expander("Evaluation trace"):
        st.code("\n".join(res.trace) or "(no steps)", language="text")
    with st.expander("Limitations of this SPF implementation"):
        for lim in SPF_LIMITATIONS:
            st.markdown(f"- {lim}")
