"""Helpers shared by the page modules: input reading, DB access with friendly errors."""
from __future__ import annotations

import streamlit as st

import config
from database import db
from modules.analysis_engine import analyze_email
from modules.dns_utils import LiveResolver, check_dns_health
from modules.email_parser import EmailParseError


def read_upload(uploaded) -> bytes | None:
    """Validate an uploaded .eml/.txt file and return its bytes (or show an error and return None)."""
    if uploaded is None:
        return None
    name = (uploaded.name or "").lower()
    if not name.endswith((".eml", ".txt", ".msg.txt", ".mbox")):
        st.error(f"'{uploaded.name}' is not a supported file type. Upload a text-based .eml (or .txt) file.")
        return None
    data = uploaded.getvalue()
    if len(data) > config.MAX_EMAIL_BYTES:
        st.error(f"The file is larger than {config.MAX_EMAIL_BYTES // (1024 * 1024)} MB.")
        return None
    if not data.strip():
        st.error("The uploaded file is empty.")
        return None
    return data


def safe_save(result: dict) -> int | None:
    """Save a result, reporting database problems in the UI instead of raising."""
    try:
        return db.save_analysis(result)
    except db.DatabaseError as exc:
        st.error(f"The analysis was completed but could not be saved to history: {exc}")
        return None


def run_analysis(raw: bytes | str, **kwargs) -> dict | None:
    """Run the engine and turn expected failures into user-facing messages."""
    try:
        return analyze_email(raw, **kwargs)
    except EmailParseError as exc:
        st.error(str(exc))
    except ValueError as exc:
        st.error(str(exc))
    except Exception as exc:  # last-resort guard so a malformed message never crashes the app
        st.error(f"Unexpected error while analysing the message: {type(exc).__name__}: {exc}")
    return None


def dns_choice_help() -> str:
    return ("Live DNS sends real queries from this computer to your DNS resolver. Choose 'Off' to analyse offline: "
            "SPF, DKIM and DMARC will then be reported as NOT EVALUATED rather than guessed.")


def dns_health_warning() -> None:
    """Warn when the live resolver looks broken, so a 'no record' result is not over-trusted.

    The probe result is cached for a minute to avoid repeating the canary queries on every rerun.
    """
    import time

    cached = st.session_state.get("_dns_health")
    if not cached or time.time() - cached[0] > 60:
        try:
            cached = (time.time(), *check_dns_health(LiveResolver(timeout=3)))
        except Exception as exc:  # the probe itself must never break a page
            cached = (time.time(), False, f"The DNS health check could not run: {exc}")
        st.session_state["_dns_health"] = cached
    if not cached[1]:
        st.warning(f"DNS health check: {cached[2]}")
