"""PAGE 8 - Analysis history: search, filter, sort, detail view, CSV export, delete."""
from __future__ import annotations

import csv
import io
import streamlit as st

from database import db
from ui.components import banner, empty_state, page_header
from ui.report_view import render_report
from ui.theme import show_table

CLASSES = ["AUTHENTICATED", "SUSPICIOUS", "FAILED AUTHENTICATION", "UNVERIFIED"]
STATUSES = ["PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "NOT EVALUATED", "PERMERROR", "TEMPERROR"]
SORTS = {"Date": "created_at", "ID": "id", "Sender": "sender", "Subject": "subject", "Risk score": "risk_score",
         "Classification": "classification", "SPF": "spf_status", "DKIM": "dkim_status", "DMARC": "dmarc_status"}


def render() -> None:
    page_header("Analysis History", "Every analysis stored in the local SQLite database.", "database")

    f1, f2, f3 = st.columns([3, 2, 2])
    search = f1.text_input("Search sender, subject, message-ID or analysis ID", key="h_search")
    sort_label = f2.selectbox("Sort by", list(SORTS), key="h_sort")
    order = f3.radio("Order", ["Descending", "Ascending"], horizontal=True, key="h_order")
    with st.expander("Filters"):
        g1, g2, g3 = st.columns(3)
        classes = g1.multiselect("Classification", CLASSES, key="h_class")
        levels = g2.multiselect("Risk level", ["LOW", "MEDIUM", "HIGH"], key="h_level")
        data_kind = g3.selectbox("Data", ["All", "Real analyses only", "Demonstration data only"], key="h_data")
        h1, h2, h3 = st.columns(3)
        spf = h1.multiselect("SPF status", STATUSES, key="h_spf")
        dkim = h2.multiselect("DKIM status", STATUSES, key="h_dkim")
        dmarc = h3.multiselect("DMARC status", STATUSES, key="h_dmarc")

    try:
        rows = db.list_analyses(search=search, classifications=classes, risk_levels=levels, spf=spf, dkim=dkim, dmarc=dmarc,
                                include_demo=data_kind != "Real analyses only", sort_by=SORTS[sort_label], descending=order == "Descending")
    except db.DatabaseError as exc:
        st.error(f"Could not read history: {exc}")
        return
    if data_kind == "Demonstration data only":
        rows = [r for r in rows if r["is_demo"]]

    total = db.count_analyses()
    if total == 0:
        empty_state("History is empty. Analyse an email or open Demo Mode.")
        return

    table_rows = [{
        "ID": r["id"], "Date (UTC)": r["created_at"].replace("T", " ").rstrip("Z"), "Sender": r["sender"], "Subject": r["subject"],
        "SPF": r["spf_status"], "DKIM": r["dkim_status"], "DMARC": r["dmarc_status"], "Risk score": r["risk_score"],
        "Risk level": r["risk_level"], "Classification": r["classification"], "Data": "Demo" if r["is_demo"] else "Real"} for r in rows]
    st.caption(f"Showing {len(table_rows)} of {total} stored analyses.")
    if not table_rows:
        empty_state("No analyses match the current search and filters.")
    else:
        show_table(table_rows)
        csv_buffer = io.StringIO()
        writer = csv.DictWriter(csv_buffer, fieldnames=list(table_rows[0].keys()))
        writer.writeheader()
        writer.writerows(table_rows)
        st.download_button("Export CSV", csv_buffer.getvalue().encode("utf-8-sig"), file_name="emailguard_history.csv", mime="text/csv", key="h_csv")

        st.markdown("##### Detailed report")
        ids = [row["ID"] for row in table_rows]
        subjects = {row["ID"]: row["Subject"] for row in table_rows}
        chosen = st.selectbox("Select an analysis", ids, format_func=lambda i: f"#{i} - {subjects.get(i) or '(no subject)'}"[:90], key="h_pick")
        try:
            result = db.get_analysis(int(chosen))
        except db.DatabaseError as exc:
            st.error(str(exc))
            result = None
        if result:
            render_report(result, key=f"hist_{chosen}")
            if st.button("Delete this analysis", key=f"h_del_{chosen}"):
                db.delete_analysis(int(chosen))
                st.toast(f"Deleted analysis #{chosen}.")
                st.rerun()

    st.divider()
    st.markdown("##### Delete history")
    banner("Deletion is permanent. Exported CSV files are not affected.", "warn")
    d1, d2, d3 = st.columns(3)
    for col, label, demo_only, key in ((d1, "Delete demonstration data", True, "demo"), (d2, "Delete real analyses", False, "real"), (d3, "Delete everything", None, "all")):
        with col:
            confirm = st.checkbox(f"Confirm: {label.lower()}", key=f"h_conf_{key}")
            if st.button(label, disabled=not confirm, key=f"h_delbtn_{key}"):
                n = db.delete_all(demo_only=demo_only)
                st.toast(f"Deleted {n} record(s).")
                st.rerun()
