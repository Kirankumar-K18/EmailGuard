"""EmailGuard central configuration.

All tunable constants live here so the rest of the code base stays free of
magic numbers. Nothing in this file is secret; no credentials are stored.
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

APP_NAME = "EmailGuard"
APP_TAGLINE = "Secure. Authenticate. Protect."
APP_FULL_NAME = "EmailGuard - Intelligent Email Authentication and Spoofing Detection System Using Cryptographic Techniques"
APP_VERSION = "1.0.0"

# --- Paths -----------------------------------------------------------------
# The database path can be overridden (used by the unit tests).
DB_PATH = Path(os.environ.get("EMAILGUARD_DB", BASE_DIR / "database" / "emailguard.db"))
SCHEMA_PATH = BASE_DIR / "database" / "schema.sql"
ASSETS_DIR = BASE_DIR / "assets"
CSS_PATH = ASSETS_DIR / "styles.css"
LOGO_PATH = ASSETS_DIR / "logo.png"
ICON_PATH = ASSETS_DIR / "icon.png"
DEMO_DIR = BASE_DIR / "sample_emails" / "demo_emails"
DEMO_SCENARIOS_PATH = DEMO_DIR / "scenarios.json"
DEMO_DNS_PATH = DEMO_DIR / "demo_dns.json"

# --- Input limits ----------------------------------------------------------
MAX_EMAIL_BYTES = 5 * 1024 * 1024  # 5 MB per analysed message
MAX_HISTORY_ROWS = 5000

# --- DNS -------------------------------------------------------------------
DNS_TIMEOUT_SECONDS = 5.0
SPF_MAX_DNS_LOOKUPS = 10   # RFC 7208 section 4.6.4
SPF_MAX_VOID_LOOKUPS = 2   # RFC 7208 section 4.6.4

# --- Risk scoring ----------------------------------------------------------
RISK_LOW_MAX = 29      # 0-29   LOW RISK
RISK_MEDIUM_MAX = 59   # 30-59  MEDIUM RISK, 60-100 HIGH RISK

# --- RSA -------------------------------------------------------------------
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
RSA_PSS_SALT_LENGTH = 32  # equals the SHA-256 digest length

# --- Status vocabulary -----------------------------------------------------
STATUS_PASS_LIKE = {"PASS"}
STATUS_FAIL_LIKE = {"FAIL", "PERMERROR"}
STATUS_WARN_LIKE = {"SOFTFAIL", "TEMPERROR", "NEUTRAL"}
STATUS_MUTED = {"NONE", "NOT EVALUATED"}

# --- Palette (kept in sync with assets/styles.css) --------------------------
COLORS = {
    "bg": "#070B14",
    "surface": "#0D1424",
    "card": "#111A2E",
    "border": "#1F2C47",
    "text": "#E6EDF7",
    "muted": "#8A9BB8",
    "cyan": "#22D3EE",
    "blue": "#3B82F6",
    "purple": "#8B5CF6",
    "green": "#22C55E",
    "red": "#EF4444",
    "orange": "#F59E0B",
}
