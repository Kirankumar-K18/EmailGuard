"""EmailGuard - entry point.   Run with:  streamlit run app.py

Each module in ``pages/`` exposes a ``render()`` function; this file registers
them with ``st.navigation`` (the ``pages/`` folder is therefore not scanned by
Streamlit's legacy multipage mode).
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

import config  # noqa: E402
from database import db  # noqa: E402
from ui import theme  # noqa: E402
from ui.components import sidebar_footer  # noqa: E402

st.set_page_config(
    page_title="EmailGuard - Secure. Authenticate. Protect.",
    page_icon=str(config.ICON_PATH) if config.ICON_PATH.exists() else None,
    layout="wide",
    initial_sidebar_state="expanded",
)
theme.inject_css()

# (module, sidebar title, url slug, is default page)
PAGES = [
    ("dashboard", "Security Dashboard", "dashboard", True),
    ("email_analyzer", "Email Analyzer", "email-analyzer", False),
    ("spf_verification", "SPF Verification", "spf", False),
    ("dkim_verification", "DKIM Verification", "dkim", False),
    ("dmarc_analyzer", "DMARC Analyzer", "dmarc", False),
    ("digital_signature", "Digital Signature Lab", "signature-lab", False),
    ("spoofing_detector", "Spoofing Detector", "spoofing", False),
    ("demo_mode", "Demo Mode", "demo", False),
    ("analysis_history", "Analysis History", "history", False),
    ("about", "About Project", "about", False),
]

if config.LOGO_PATH.exists():
    try:
        st.logo(str(config.LOGO_PATH), icon_image=str(config.ICON_PATH) if config.ICON_PATH.exists() else None, size="large")
    except Exception:  # older Streamlit without the icon_image / size arguments
        st.sidebar.image(str(config.LOGO_PATH))

if not st.session_state.get("_db_ready"):
    try:
        db.init_db()
        st.session_state["_db_ready"] = True
    except db.DatabaseError as exc:
        st.error(f"Database problem: {exc}. History and the dashboard will be unavailable until this is fixed.")


def _page(module_name: str, title: str, slug: str, default: bool) -> "st.Page":
    module = importlib.import_module(f"pages.{module_name}")
    return st.Page(module.render, title=title, url_path=slug, default=default)


navigation = st.navigation([_page(*entry) for entry in PAGES])
sidebar_footer(config.APP_VERSION)
navigation.run()
