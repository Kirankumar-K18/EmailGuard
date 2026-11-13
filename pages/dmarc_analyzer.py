"""PAGE 5 - DMARC analyzer: policy lookup plus an explicit, honest evaluation."""
from __future__ import annotations

import streamlit as st

from modules import demo_data
from modules.dmarc_checker import TAG_DESCRIPTIONS, evaluate_dmarc, lookup_dmarc
from modules.dns_utils import LiveResolver
from ui.common import dns_health_warning
from ui.components import banner, demo_banner, esc, html, method_chip, page_header, status_badge
from ui.theme import show_table

AVAIL = ["Not available", "PASS", "FAIL"]


def render() -> None:
    page_header("DMARC Analyzer", "Look up a domain's DMARC policy and understand what it requires.", "shield")
    banner("A DMARC record alone cannot produce a PASS or FAIL. DMARC passes only if SPF or DKIM passed AND the domain they authenticated aligns with the visible From domain. "
           "Without real SPF/DKIM outcomes for a specific message, the result is NOT EVALUATED.", "info")

    source = st.radio("DNS source", ["Live DNS (real lookup)", "Demonstration zone (offline, simulated)"], horizontal=True, key="dm_src")
    demo = source.startswith("Demonstration")
    if demo:
        zone = demo_data.load_zone()
        doms = sorted(d[len("_dmarc."):] for d in zone if d.startswith("_dmarc."))
        demo_banner("DEMONSTRATION DATA - the policy below comes from the bundled simulated DNS zone.")
        domain = st.selectbox("Domain", doms, key="dm_dom_demo")
    else:
        domain = st.text_input("Domain", key="dm_dom", placeholder="example.com")

    if st.button("Look up DMARC policy", type="primary", key="dm_go"):
        if not (domain or "").strip():
            st.error("Enter a domain.")
        else:
            with st.spinner("Querying DNS..."):
                try:
                    st.session_state["dm_result"] = lookup_dmarc(domain, demo_data.demo_resolver() if demo else LiveResolver())
                    st.session_state["dm_demo"] = demo
                except Exception as exc:
                    st.session_state.pop("dm_result", None)
                    st.error(f"Lookup failed: {type(exc).__name__}: {exc}")

    rec = st.session_state.get("dm_result")
    if not rec:
        return
    st.divider()
    if st.session_state.get("dm_demo"):
        demo_banner("DEMONSTRATION DATA - simulated DNS zone.")
    elif rec.status in ("NONE", "TEMPERROR"):
        dns_health_warning()

    lookup_badge = {"FOUND": "PASS", "NONE": "NONE", "TEMPERROR": "TEMPERROR", "INVALID": "FAIL"}[rec.status]
    left, right = st.columns([2, 3])
    with left:
        label = {"FOUND": "POLICY FOUND", "NONE": "NO POLICY", "TEMPERROR": "LOOKUP ERROR", "INVALID": "INVALID RECORD"}[rec.status]
        html(f'<div class="eg-card"><div style="color:#8A9BB8;font-size:.74rem;letter-spacing:.07em;font-weight:600">DNS LOOKUP</div>'
             f'<div style="margin:.4rem 0">{status_badge(lookup_badge, True).replace(esc(lookup_badge), label)}</div>{method_chip("DNS")}'
             f'<p style="margin-top:.6rem">Queried: {esc(", ".join(rec.queried))}</p>'
             f'<p>Source: {esc(rec.data_source)}</p></div>')
    with right:
        body = "".join(f"<p style='color:#E6EDF7'>{esc(line)}</p>" for line in rec.explanation)
        html(f'<div class="eg-card"><h4>Policy explanation</h4>{body}</div>')

    for err in rec.errors:
        st.error(err)
    if rec.raw:
        st.markdown("**Retrieved record**")
        st.code(rec.raw, language="text", wrap_lines=True)
        order = ["v", "p", "sp", "rua", "ruf", "pct", "adkim", "aspf"]
        rows = []
        for tag in order + [t for t in rec.tags if t not in order]:
            value = rec.tags.get(tag)
            default = {"pct": "100 (default)", "adkim": "r (default)", "aspf": "r (default)", "sp": "same as p (default)"}.get(tag, "not set")
            rows.append({"Tag": tag, "Value": value if value is not None else default, "Meaning": TAG_DESCRIPTIONS.get(tag, "Additional tag")})
        show_table(rows)
        for w in rec.warnings:
            st.warning(w)

    st.markdown("##### Evaluate DMARC for a specific message")
    st.caption("Supply the real SPF and DKIM outcomes and the domains they authenticated. DMARC is then evaluated honestly: if either outcome is unknown the answer stays NOT EVALUATED.")
    c1, c2 = st.columns(2)
    spf_in = c1.selectbox("SPF result for the message", AVAIL, key="dm_spf")
    spf_dom = c1.text_input("SPF-authenticated domain (envelope sender domain)", key="dm_spf_dom", disabled=spf_in != "PASS")
    dkim_in = c2.selectbox("DKIM result for the message", AVAIL, key="dm_dkim")
    dkim_dom = c2.text_input("DKIM-signing domain (d=)", key="dm_dkim_dom", disabled=dkim_in != "PASS")
    from_dom = st.text_input("Visible From domain", value=rec.domain, key="dm_from")
    if st.button("Evaluate alignment", key="dm_eval"):
        spf_status = "NOT EVALUATED" if spf_in == "Not available" else spf_in
        dkim_status = "NOT EVALUATED" if dkim_in == "Not available" else dkim_in
        ev = evaluate_dmarc(from_dom, rec, spf_status, spf_dom, dkim_status, [{"status": dkim_status, "domain": dkim_dom}])
        html(f'<div class="eg-card"><div style="margin-bottom:.5rem">{status_badge(ev["status"], True)}</div>'
             f'<p style="color:#E6EDF7">{esc(ev["explanation"])}</p>'
             f'<p>SPF aligned: {esc(ev["spf_aligned"])} &middot; DKIM aligned: {esc(ev["dkim_aligned"])}</p></div>')

    with st.expander("How DMARC alignment works"):
        st.markdown(
            "- **SPF alignment**: the domain SPF authenticated (envelope sender) must match the From domain - exactly if `aspf=s`, same organisational domain if `aspf=r`.\n"
            "- **DKIM alignment**: the signing domain `d=` must match the From domain in the same way (`adkim`).\n"
            "- DMARC **passes** if at least one of the two is *both passing and aligned*.\n"
            "- On failure, the receiver applies the policy `p` (none / quarantine / reject), subject to `pct`.\n"
            "- EmailGuard approximates the organisational domain without the full Public Suffix List.")
