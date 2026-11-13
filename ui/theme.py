"""Theme helpers: CSS injection, Plotly styling and Streamlit version compatibility."""
from __future__ import annotations

import streamlit as st
from html import escape

import config

try:
    _ST_VERSION = tuple(int(p) for p in st.__version__.split(".")[:2])
except ValueError:  # pragma: no cover
    _ST_VERSION = (1, 40)
NEW_WIDTH_API = _ST_VERSION >= (1, 50)


def stretch() -> dict:
    """Keyword arguments that make charts/tables/buttons fill their container on any supported Streamlit."""
    return {"width": "stretch"} if NEW_WIDTH_API else {"use_container_width": True}


def inject_css() -> None:
    try:
        css = config.CSS_PATH.read_text(encoding="utf-8")
    except OSError:
        css = ""
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def plotly_layout(fig, height: int = 300, legend: bool = True):
    """Apply the dark SOC look to a Plotly figure."""
    c = config.COLORS
    fig.update_layout(
        height=height,
        margin=dict(l=8, r=8, t=40, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#C7D2E5", family="Inter, Segoe UI, system-ui, sans-serif", size=12),
        colorway=[c["cyan"], c["blue"], c["purple"], c["green"], c["orange"], c["red"]],
        legend=dict(orientation="h", yanchor="top", y=-0.22, xanchor="left", x=0, font=dict(size=11)) if legend else dict(),
        showlegend=legend,
        title=dict(x=0, xanchor="left", font=dict(size=14)),
        hoverlabel=dict(bgcolor="#152038", bordercolor="#1F2C47", font=dict(color="#E6EDF7")),
    )
    fig.update_xaxes(gridcolor="#1A2540", zerolinecolor="#1A2540", linecolor="#1F2C47")
    fig.update_yaxes(gridcolor="#1A2540", zerolinecolor="#1A2540", linecolor="#1F2C47")
    return fig


def show_chart(fig, key: str | None = None) -> None:
    st.plotly_chart(fig, config={"displayModeBar": False}, key=key, **stretch())


def rename_columns(rows: list[dict], mapping: dict[str, str]) -> list[dict]:
    """Rename dictionary keys without requiring pandas."""
    return [{mapping.get(key, key): value for key, value in row.items()} for row in rows]


def show_table(data, **kwargs) -> None:
    """Render a lightweight HTML table without Streamlit's Arrow/pandas conversion."""
    if data is None:
        st.caption("No data to display.")
        return

    # Accept a list of dictionaries (the project's standard table format).
    if isinstance(data, list):
        if not data:
            st.caption("No data to display.")
            return
        if isinstance(data[0], dict):
            columns = list(data[0].keys())
            rows = data
        else:
            st.error("Unsupported table data format.")
            return
    else:
        # Avoid silently invoking Streamlit's Arrow-backed dataframe renderer.
        st.error("Unsupported table data format. Expected a list of records.")
        return

    header = "".join(f"<th>{escape(str(col))}</th>" for col in columns)
    body_rows = []
    for row in rows:
        cells = "".join(
            f"<td>{escape('' if row.get(col) is None else str(row.get(col)))}</td>"
            for col in columns
        )
        body_rows.append(f"<tr>{cells}</tr>")

    table_html = f"""
    <div style="overflow-x:auto; width:100%;">
      <table style="width:100%; border-collapse:collapse; font-size:0.85rem;">
        <thead><tr>{header}</tr></thead>
        <tbody>{''.join(body_rows)}</tbody>
      </table>
    </div>
    <style>
      table th {{ text-align:left; color:#9FB2D0; background:#111B30; padding:10px 12px;
                  border-bottom:1px solid #263653; white-space:nowrap; }}
      table td {{ color:#DCE6F5; padding:10px 12px; border-bottom:1px solid #1F2C47;
                  vertical-align:top; }}
      table tr:hover td {{ background:#152038; }}
    </style>
    """
    st.markdown(table_html, unsafe_allow_html=True)
