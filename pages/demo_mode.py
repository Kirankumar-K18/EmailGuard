"""Demo Mode - five predefined scenarios analysed by the real engine against a simulated DNS zone."""
from __future__ import annotations

import time

import streamlit as st

from modules import demo_data
from ui.common import run_analysis, safe_save
from ui.components import banner, demo_banner, esc, html, page_header, status_badge
from ui.report_view import render_report


def _expected_vs_actual(result: dict, expected: dict) -> None:
    a = result["authentication"]
    got = {"spf": a["spf"]["status"], "dkim": a["dkim"]["status"], "dmarc": a["dmarc"]["status"], "classification": result["verdict"]["classification"]}
    rows = "".join(
        f'<tr><td style="padding:.25rem .8rem .25rem 0;color:#8A9BB8">{esc(k.upper())}</td><td style="padding:.25rem 1rem .25rem 0">{status_badge(got[k])}</td>'
        f'<td style="color:#8A9BB8;font-size:.8rem">{"matches the scenario design" if got[k] == expected[k] else "differs from the design: " + esc(expected[k])}</td></tr>'
        for k in ("spf", "dkim", "dmarc", "classification"))
    html(f'<div class="eg-card"><h4>Scenario outcome</h4><table style="border-collapse:collapse">{rows}</table></div>')


def render() -> None:
    page_header("Demo Mode", "Five guided scenarios for demonstrating authentication and spoofing analysis without needing real e-mails or Internet access.", "flask")
    demo_banner("DEMONSTRATION DATA - fictional messages from reserved .example domains, evaluated against a simulated DNS zone. "
                "The SPF, DKIM and DMARC logic and the DKIM signature verification are real; only the DNS answers and the e-mails are simulated.")

    try:
        scenarios = demo_data.load_scenarios()
    except (OSError, ValueError, KeyError) as exc:
        st.error(f"Demo data could not be loaded: {exc}")
        return

    titles = {s["id"]: f"Scenario {s['id']}: {s['title']}" for s in scenarios}
    sid = st.radio("Choose a scenario", list(titles), format_func=titles.get, key="demo_sid")
    sc = next(s for s in scenarios if s["id"] == sid)

    html(f'<div class="eg-card"><h4>{esc(sc["title"])}</h4><p style="color:#E6EDF7">{esc(sc["description"])}</p>'
         f'<p>Sending IP used for SPF: <code>{esc(sc["sending_ip"])}</code> (documentation range)</p></div>')

    raw = demo_data.read_scenario_email(sc)
    with st.expander("Sample email (raw headers and body)", expanded=False):
        st.code(raw.decode("utf-8", "replace"), language="text", wrap_lines=True)
        st.download_button("Download this .eml", raw, file_name=sc["file"], mime="message/rfc822", key=f"demo_dl_{sid}")
    with st.expander("Simulated DNS zone used in the demonstration"):
        zone = demo_data.load_zone()
        st.json({k: v for k, v in zone.items() if any(k.endswith(d) for d in ("example",))})

    c1, c2 = st.columns([1, 1])
    save = c2.checkbox("Save result to Analysis History (flagged as demo)", value=True, key="demo_save")
    if c1.button("Run analysis", type="primary", key="demo_go"):
        with st.status("Analysing scenario...", expanded=True) as status:
            result = run_analysis(raw, dns_mode="simulated", resolver=demo_data.demo_resolver(), sending_ip=sc["sending_ip"],
                                  is_demo=True, scenario=sc["title"], source="demo_scenario")
            if result is None:
                status.update(label="Analysis failed", state="error")
            else:
                result["scenario_info"] = {k: sc[k] for k in ("id", "title", "description", "expected", "learning_points")}
                for s in result["steps"]:
                    st.write(f"**{s['step']}. {s['title']}** - {s['method']} - {s['status']}")
                    time.sleep(0.15)
                if save:
                    safe_save(result)
                st.session_state["demo_result"] = result
                status.update(label="Analysis complete", state="complete", expanded=False)

    result = st.session_state.get("demo_result")
    if result and result.get("scenario_info", {}).get("id") == sid:
        st.divider()
        info = result["scenario_info"]
        _expected_vs_actual(result, info["expected"])
        html('<div class="eg-card"><h4>What this scenario teaches</h4>' + "".join(f"<p>&bull; {esc(p)}</p>" for p in info["learning_points"]) + "</div>")
        render_report(result, key=f"demo_{sid}")
    elif result:
        banner("A different scenario was analysed last. Press 'Run analysis' to analyse this one.", "info")
