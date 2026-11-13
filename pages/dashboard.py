"""PAGE 1 - Security dashboard. Every figure comes from SQLite."""
from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from database import db
from modules import demo_data
from ui.components import empty_state, esc, html, kpi_card, page_header, status_badge
from ui.theme import plotly_layout, show_chart, show_table

CLASS_COLORS = {"AUTHENTICATED": "#22C55E", "SUSPICIOUS": "#F59E0B", "FAILED AUTHENTICATION": "#EF4444", "UNVERIFIED": "#8A9BB8"}
STATUS_COLORS = {"PASS": "#22C55E", "FAIL": "#EF4444", "SOFTFAIL": "#F59E0B", "NEUTRAL": "#F59E0B", "NONE": "#8A9BB8",
                 "NOT EVALUATED": "#4B5B7A", "PERMERROR": "#B91C1C", "TEMPERROR": "#D97706"}


def render() -> None:
    page_header("Security Dashboard", "Live overview of analysed e-mails, authentication outcomes and threat indicators.", "activity")

    top_l, top_r = st.columns([3, 2])
    with top_l:
        include_demo = st.toggle("Include demonstration data", value=True,
                                 help="Demo rows are simulated sample records so the dashboard is not empty on first run. They are always flagged as demo data.")
    with top_r:
        a, b = st.columns(2)
        try:
            n_demo = db.count_demo_rows()
        except db.DatabaseError as exc:
            st.error(str(exc))
            return
        if a.button("Load demo data", disabled=n_demo > 0, help="Adds 36 simulated analyses spread over the last 14 days."):
            with st.spinner("Analysing demo scenarios..."):
                n = demo_data.seed_demo_data(36)
            st.toast(f"Added {n} demonstration records.")
            st.rerun()
        if b.button("Remove demo data", disabled=n_demo == 0):
            removed = demo_data.remove_demo_data()
            st.toast(f"Removed {removed} demonstration records.")
            st.rerun()

    try:
        stats = db.dashboard_stats(include_demo=include_demo)
    except db.DatabaseError as exc:
        st.error(f"Could not read statistics: {exc}")
        return

    if include_demo and n_demo:
        html(f'<div class="eg-banner demo"><b>DEMONSTRATION DATA</b> &nbsp;{n_demo} simulated record(s) are included in these statistics. '
             "They are sample data, not real e-mail analyses. Use the toggle above to see real analyses only.</div>")

    if stats["total"] == 0:
        empty_state("No analyses yet. Open Email Analyzer or Demo Mode to analyse a message, or press 'Load demo data'.")
        return

    cols = st.columns(5)
    cards = [
        ("Total analysed", stats["total"], "all stored analyses", "#22D3EE", "mail"),
        ("Authenticated", stats["authenticated"], "at least one pass, low risk", "#22C55E", "check"),
        ("Suspicious", stats["suspicious"], "no hard failure, risky signals", "#F59E0B", "alert"),
        ("Auth failures", stats["failed"], "failed authentication attempts", "#EF4444", "x"),
        ("Success rate", f"{stats['success_rate']}%", "authenticated / total", "#8B5CF6", "percent"),
    ]
    for col, (label, value, sub, accent, ic) in zip(cols, cards):
        with col:
            html(kpi_card(label, value, sub, accent, ic))

    st.write("")
    c1, c2 = st.columns([3, 2])
    with c1:
        days = list(stats["activity"].keys())
        fig = go.Figure()
        for cls in ("AUTHENTICATED", "SUSPICIOUS", "FAILED AUTHENTICATION", "UNVERIFIED"):
            fig.add_bar(x=days, y=[stats["activity"][d].get(cls, 0) for d in days], name=cls.title(), marker_color=CLASS_COLORS[cls])
        fig.update_layout(barmode="stack", title=dict(text="Email analysis activity (last 14 days)", font=dict(size=14)))
        plotly_layout(fig, height=330)
        fig.update_xaxes(tickformat="%d %b", type="date")
        show_chart(fig, "activity")
    with c2:
        labels = [k for k, v in stats["by_classification"].items() if v]
        fig = go.Figure(go.Pie(labels=[l.title() for l in labels], values=[stats["by_classification"][l] for l in labels], hole=0.62,
                               marker=dict(colors=[CLASS_COLORS.get(l, "#3B82F6") for l in labels], line=dict(color="#070B14", width=2)),
                               textinfo="percent", sort=False))
        fig.update_layout(title=dict(text="Authentication results", font=dict(size=14)))
        plotly_layout(fig, height=320)
        show_chart(fig, "pie")

    c3, c4 = st.columns([3, 2])
    with c3:
        fig = go.Figure()
        statuses = sorted({s for m in stats["auth"].values() for s in m}, key=lambda s: ["PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "NOT EVALUATED"].index(s) if s in ["PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "NOT EVALUATED"] else 9)
        for s in statuses:
            fig.add_bar(x=["SPF", "DKIM", "DMARC"], y=[stats["auth"].get(m, {}).get(s, 0) for m in ("SPF", "DKIM", "DMARC")],
                        name=s, marker_color=STATUS_COLORS.get(s, "#3B82F6"))
        fig.update_layout(barmode="group", title=dict(text="SPF / DKIM / DMARC outcomes", font=dict(size=14)))
        plotly_layout(fig, height=300)
        show_chart(fig, "auth")
    with c4:
        if stats["threats"]:
            fig = go.Figure(go.Bar(x=[n for _, n in stats["threats"]], y=[t for t, _ in stats["threats"]], orientation="h",
                                   marker=dict(color=[n for _, n in stats["threats"]], colorscale=[[0, "#3B82F6"], [1, "#8B5CF6"]])))
            fig.update_layout(title=dict(text="Threat indicator distribution", font=dict(size=14)), yaxis=dict(autorange="reversed"))
            plotly_layout(fig, height=300, legend=False)
            show_chart(fig, "threats")
        else:
            empty_state("No threat indicators recorded.")

    c5, c6 = st.columns([3, 2])
    with c5:
        st.markdown("##### Recent email analysis history")
        rows = db.list_analyses(include_demo=include_demo, limit=8)
        table_rows = [{
            "ID": r["id"], "Time (UTC)": r["created_at"].replace("T", " ").rstrip("Z"), "Sender": r["sender"], "Subject": r["subject"],
            "SPF": r["spf_status"], "DKIM": r["dkim_status"], "DMARC": r["dmarc_status"], "Risk": r["risk_score"],
            "Result": r["classification"].title(), "Data": "Demo" if r["is_demo"] else "Real"} for r in rows]
        show_table(table_rows)
    with c6:
        st.markdown("##### Security alerts")
        if not stats["alerts"]:
            empty_state("No high or medium alerts.")
        else:
            items = []
            for a in stats["alerts"][:7]:
                color = "#EF4444" if a["severity"] == "high" else "#F59E0B"
                tag = ' <span class="eg-badge warn">DEMO</span>' if a["is_demo"] else ""
                items.append(f'<div class="eg-alert"><span class="dot" style="background:{color}"></span><div><div>{esc(a["title"])}{tag}</div>'
                             f'<div class="meta">#{a["analysis_id"]} &middot; {esc(a["sender"])[:42]} &middot; {esc(a["created_at"].replace("T", " ").rstrip("Z"))}</div></div></div>')
            html(f'<div class="eg-card">{"".join(items)}</div>')
