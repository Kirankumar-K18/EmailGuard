"""Reusable HTML components.

SECURITY: e-mail content is untrusted. Every value that originates from a
message is passed through :func:`esc` before it is placed in HTML that is
rendered with ``unsafe_allow_html=True``.
"""
from __future__ import annotations

from html import escape

import streamlit as st

_ICONS = {
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "mail": '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>',
    "check": '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    "alert": '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "x": '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    "activity": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    "percent": '<line x1="19" y1="5" x2="5" y2="19"/><circle cx="6.5" cy="6.5" r="2.5"/><circle cx="17.5" cy="17.5" r="2.5"/>',
    "lock": '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "key": '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
    "info": '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    "search": '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    "database": '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    "file": '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/>',
    "flask": '<path d="M9 3h6"/><path d="M10 3v6L4.5 19a1.5 1.5 0 0 0 1.3 2.2h12.4a1.5 1.5 0 0 0 1.3-2.2L14 9V3"/>',
}

_STATUS_CLASS = {
    "PASS": "pass", "AUTHENTICATED": "pass", "VERIFIED": "pass", "LOW": "pass", "SIMULATED": "warn",
    "FAIL": "fail", "PERMERROR": "fail", "FAILED AUTHENTICATION": "fail", "HIGH": "fail", "INVALID": "fail",
    "SOFTFAIL": "warn", "TEMPERROR": "warn", "NEUTRAL": "warn", "SUSPICIOUS": "warn", "MEDIUM": "warn", "WARNING": "warn",
    "high": "fail", "medium": "warn", "low": "muted",
}

_METHOD_CLASS = {
    "CRYPTOGRAPHIC": "m-crypto", "DNS": "m-dns", "HEURISTIC": "m-heur", "HEADER CLAIM": "m-claim",
    "DEMONSTRATION": "m-demo", "NOT PERFORMED": "m-none", "PARSING": "m-none",
}


def esc(value) -> str:
    """HTML-escape any value (None becomes an empty string)."""
    return escape("" if value is None else str(value), quote=True)


def icon(name: str, size: int = 18) -> str:
    body = _ICONS.get(name, _ICONS["info"])
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{body}</svg>')


def html(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def page_header(title: str, subtitle: str, icon_name: str = "shield") -> None:
    html(f'<div class="eg-head"><div class="eg-head-icon">{icon(icon_name, 22)}</div>'
         f'<div><h1>{esc(title)}</h1><div class="eg-sub">{esc(subtitle)}</div></div></div>')


def status_badge(status: str, large: bool = False) -> str:
    cls = _STATUS_CLASS.get(status, "muted")
    return f'<span class="eg-badge {cls}{" lg" if large else ""}">{esc(status)}</span>'


def method_chip(method: str) -> str:
    return f'<span class="eg-chip {_METHOD_CLASS.get(method, "m-none")}">{esc(method)}</span>'


def banner(text: str, kind: str = "info") -> None:
    html(f'<div class="eg-banner {kind}">{esc(text)}</div>')


def demo_banner(text: str = "DEMONSTRATION DATA - fictional e-mail evaluated against a simulated DNS zone. Not a real-world result.") -> None:
    html(f'<div class="eg-banner demo"><b>DEMONSTRATION DATA</b> &nbsp;{esc(text.replace("DEMONSTRATION DATA - ", ""))}</div>')


def kpi_card(label: str, value, sub: str = "", accent: str = "#22D3EE", icon_name: str = "activity") -> str:
    return (f'<div class="eg-kpi" style="--accent:{esc(accent)}"><div class="eg-kpi-top"><span>{esc(label)}</span>'
            f'<span class="eg-kpi-icon">{icon(icon_name, 18)}</span></div><div class="eg-kpi-value">{esc(value)}</div>'
            f'<div class="eg-kpi-sub">{esc(sub)}</div></div>')


def card(title: str, body_html: str) -> None:
    """Render a card. ``body_html`` must already be safe HTML (built with esc())."""
    html(f'<div class="eg-card"><h4>{esc(title)}</h4>{body_html}</div>')


def kv_list(rows: list[tuple[str, str]]) -> str:
    items = "".join(f"<dt>{esc(k)}</dt><dd>{esc(v) if v not in (None, '') else '-'}</dd>" for k, v in rows)
    return f'<dl class="eg-kv">{items}</dl>'


def empty_state(message: str) -> None:
    html(f'<div class="eg-empty">{esc(message)}</div>')


def sidebar_footer(version: str) -> None:
    st.sidebar.markdown(
        f'<div class="eg-side-foot"><b></b> '
        ,
        unsafe_allow_html=True,
    )
