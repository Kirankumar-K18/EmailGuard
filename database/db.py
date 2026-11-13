"""SQLite access layer.

* Every query is parameterised - user text is never concatenated into SQL.
  The only dynamic SQL fragments (ORDER BY column/direction) come from fixed
  whitelists.
* Failures are re-raised as :class:`DatabaseError` with a readable message so
  the UI can show them instead of crashing.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Sequence

import config

_TS = "%Y-%m-%dT%H:%M:%SZ"

SORTABLE = {
    "id": "e.id",
    "created_at": "e.created_at",
    "sender": "e.sender",
    "subject": "e.subject",
    "risk_score": "e.risk_score",
    "classification": "e.classification",
    "spf_status": "spf_status",
    "dkim_status": "dkim_status",
    "dmarc_status": "dmarc_status",
}


class DatabaseError(Exception):
    """A database operation failed."""


def _path(db_path: str | Path | None) -> Path:
    return Path(db_path) if db_path else Path(config.DB_PATH)


@contextmanager
def get_connection(db_path: str | Path | None = None) -> Iterator[sqlite3.Connection]:
    path = _path(db_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, timeout=10)
    except (sqlite3.Error, OSError) as exc:
        raise DatabaseError(f"Cannot open the database at {path}: {exc}") from exc
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        raise DatabaseError(f"Database error: {exc}") from exc
    finally:
        conn.close()


def init_db(db_path: str | Path | None = None) -> None:
    """Create tables and indexes if they do not exist (safe to call repeatedly)."""
    try:
        schema = Path(config.SCHEMA_PATH).read_text(encoding="utf-8")
    except OSError as exc:
        raise DatabaseError(f"Cannot read schema file: {exc}") from exc
    with get_connection(db_path) as conn:
        conn.executescript(schema)


def _now() -> str:
    return datetime.now(timezone.utc).strftime(_TS)


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
def save_analysis(result: dict, db_path: str | Path | None = None, created_at: str | None = None) -> int:
    """Persist an analysis result (plus its auth rows and security events).

    Returns the new analysis id and stores it in ``result['analysis_id']``.
    """
    email = result.get("email", {})
    verdict = result.get("verdict", {})
    auth = result.get("authentication", {})
    spoof = result.get("spoofing", {})
    stamp = created_at or _now()
    is_demo = 1 if result.get("is_demo") else 0
    try:
        payload = json.dumps(result, default=str)
    except (TypeError, ValueError) as exc:
        raise DatabaseError(f"The analysis result could not be serialised: {exc}") from exc

    with get_connection(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO email_analysis
               (created_at, source, is_demo, scenario, sender, from_domain, recipient, subject, email_date, message_id,
                risk_score, risk_level, classification, report_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (stamp, result.get("source", "analyzer"), is_demo, result.get("scenario"),
             email.get("from") or email.get("from_addr") or "(unknown sender)", email.get("from_domain", ""),
             email.get("to", ""), email.get("subject", ""), email.get("date", ""), email.get("message_id", ""),
             int(verdict.get("risk_score", spoof.get("score", 0))), verdict.get("risk_level", spoof.get("level", "LOW")),
             verdict.get("classification", "UNVERIFIED"), payload),
        )
        analysis_id = int(cur.lastrowid)
        for mech in ("spf", "dkim", "dmarc"):
            entry = auth.get(mech)
            if not entry:
                continue
            conn.execute(
                """INSERT INTO authentication_results (analysis_id, mechanism, status, method, domain, details, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (analysis_id, mech.upper(), entry.get("status", "NOT EVALUATED"), entry.get("method", "NOT PERFORMED"),
                 entry.get("domain", ""), (entry.get("explanation") or "")[:1000], stamp),
            )
        for ind in spoof.get("indicators", []):
            conn.execute(
                """INSERT INTO security_events (analysis_id, created_at, severity, event_type, title, message, is_demo)
                   VALUES (?,?,?,?,?,?,?)""",
                (analysis_id, stamp, ind.get("severity", "low"), ind.get("category", "Other"), ind.get("title", ""),
                 (ind.get("detail") or "")[:500], is_demo),
            )
    result["analysis_id"] = analysis_id
    return analysis_id


def delete_analysis(analysis_id: int, db_path: str | Path | None = None) -> bool:
    with get_connection(db_path) as conn:
        cur = conn.execute("DELETE FROM email_analysis WHERE id = ?", (int(analysis_id),))
        return cur.rowcount > 0


def delete_many(ids: Sequence[int], db_path: str | Path | None = None) -> int:
    ids = [int(i) for i in ids]
    if not ids:
        return 0
    with get_connection(db_path) as conn:
        marks = ",".join("?" * len(ids))
        return conn.execute(f"DELETE FROM email_analysis WHERE id IN ({marks})", ids).rowcount  # nosec - placeholders only


def delete_all(demo_only: bool | None = None, db_path: str | Path | None = None) -> int:
    """Delete history. ``demo_only=True`` removes only demo rows, ``False`` only real ones, ``None`` everything."""
    with get_connection(db_path) as conn:
        if demo_only is None:
            return conn.execute("DELETE FROM email_analysis").rowcount
        return conn.execute("DELETE FROM email_analysis WHERE is_demo = ?", (1 if demo_only else 0,)).rowcount


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
def get_analysis(analysis_id: int, db_path: str | Path | None = None) -> dict | None:
    """Return the stored result dictionary for an analysis (with ``analysis_id`` filled in)."""
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT report_json, created_at FROM email_analysis WHERE id = ?", (int(analysis_id),)).fetchone()
    if row is None:
        return None
    try:
        result = json.loads(row["report_json"])
    except json.JSONDecodeError as exc:
        raise DatabaseError(f"Stored report #{analysis_id} is corrupted: {exc}") from exc
    result["analysis_id"] = int(analysis_id)
    result.setdefault("saved_at", row["created_at"])
    return result


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def list_analyses(
    search: str = "",
    classifications: Sequence[str] | None = None,
    risk_levels: Sequence[str] | None = None,
    spf: Sequence[str] | None = None,
    dkim: Sequence[str] | None = None,
    dmarc: Sequence[str] | None = None,
    include_demo: bool = True,
    sort_by: str = "created_at",
    descending: bool = True,
    limit: int = 500,
    db_path: str | Path | None = None,
) -> list[dict]:
    where, params, having = ["1=1"], [], []
    if not include_demo:
        where.append("e.is_demo = 0")
    if search.strip():
        term = _like(search.strip())
        where.append("(e.sender LIKE ? ESCAPE '\\' OR e.subject LIKE ? ESCAPE '\\' OR e.message_id LIKE ? ESCAPE '\\' OR CAST(e.id AS TEXT) = ?)")
        params += [term, term, term, search.strip()]
    if classifications:
        where.append(f"e.classification IN ({','.join('?' * len(classifications))})")
        params += list(classifications)
    if risk_levels:
        where.append(f"e.risk_level IN ({','.join('?' * len(risk_levels))})")
        params += list(risk_levels)
    having_params: list[str] = []
    for alias, values in (("spf_status", spf), ("dkim_status", dkim), ("dmarc_status", dmarc)):
        if values:
            having.append(f"{alias} IN ({','.join('?' * len(values))})")
            having_params += list(values)
    order_col = SORTABLE.get(sort_by, "e.created_at")
    direction = "DESC" if descending else "ASC"
    sql = f"""
        SELECT e.id, e.created_at, e.sender, e.subject, e.email_date, e.risk_score, e.risk_level, e.classification,
               e.is_demo, e.source, e.scenario,
               MAX(CASE WHEN a.mechanism='SPF'   THEN a.status END) AS spf_status,
               MAX(CASE WHEN a.mechanism='DKIM'  THEN a.status END) AS dkim_status,
               MAX(CASE WHEN a.mechanism='DMARC' THEN a.status END) AS dmarc_status
        FROM email_analysis e
        LEFT JOIN authentication_results a ON a.analysis_id = e.id
        WHERE {' AND '.join(where)}
        GROUP BY e.id
        {('HAVING ' + ' AND '.join(having)) if having else ''}
        ORDER BY {order_col} {direction}, e.id DESC
        LIMIT ?"""  # nosec - only whitelisted identifiers are interpolated
    with get_connection(db_path) as conn:
        rows = conn.execute(sql, params + having_params + [min(int(limit), config.MAX_HISTORY_ROWS)]).fetchall()
    return [dict(r) for r in rows]


def count_analyses(include_demo: bool = True, db_path: str | Path | None = None) -> int:
    with get_connection(db_path) as conn:
        sql = "SELECT COUNT(*) FROM email_analysis" + ("" if include_demo else " WHERE is_demo = 0")
        return int(conn.execute(sql).fetchone()[0])


def count_demo_rows(db_path: str | Path | None = None) -> int:
    with get_connection(db_path) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM email_analysis WHERE is_demo = 1").fetchone()[0])


def dashboard_stats(include_demo: bool = True, days: int = 14, db_path: str | Path | None = None) -> dict:
    """Aggregate everything the dashboard needs, directly from SQLite."""
    demo_clause = "" if include_demo else " AND e.is_demo = 0"
    with get_connection(db_path) as conn:
        by_class = {r["classification"]: r["n"] for r in conn.execute(
            f"SELECT e.classification, COUNT(*) AS n FROM email_analysis e WHERE 1=1{demo_clause} GROUP BY e.classification")}
        by_risk = {r["risk_level"]: r["n"] for r in conn.execute(
            f"SELECT e.risk_level, COUNT(*) AS n FROM email_analysis e WHERE 1=1{demo_clause} GROUP BY e.risk_level")}
        auth_rows = conn.execute(
            f"""SELECT a.mechanism, a.status, COUNT(*) AS n FROM authentication_results a
                JOIN email_analysis e ON e.id = a.analysis_id WHERE 1=1{demo_clause}
                GROUP BY a.mechanism, a.status""").fetchall()
        since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).strftime("%Y-%m-%d")
        act_rows = conn.execute(
            f"""SELECT substr(e.created_at,1,10) AS day, e.classification, COUNT(*) AS n FROM email_analysis e
                WHERE substr(e.created_at,1,10) >= ?{demo_clause} GROUP BY day, e.classification""", (since,)).fetchall()
        threat_rows = conn.execute(
            f"""SELECT s.event_type, COUNT(*) AS n FROM security_events s
                JOIN email_analysis e ON e.id = s.analysis_id WHERE 1=1{demo_clause}
                GROUP BY s.event_type ORDER BY n DESC""").fetchall()
        alert_rows = conn.execute(
            f"""SELECT s.created_at, s.severity, s.event_type, s.title, e.id AS analysis_id, e.sender, e.is_demo
                FROM security_events s JOIN email_analysis e ON e.id = s.analysis_id
                WHERE s.severity IN ('high','medium'){demo_clause}
                ORDER BY s.created_at DESC, CASE s.severity WHEN 'high' THEN 0 ELSE 1 END, s.id DESC LIMIT 10""").fetchall()

    total = sum(by_class.values())
    auth: dict[str, dict[str, int]] = {"SPF": {}, "DKIM": {}, "DMARC": {}}
    for r in auth_rows:
        auth.setdefault(r["mechanism"], {})[r["status"]] = r["n"]
    day_index = [(datetime.now(timezone.utc) - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d") for i in range(days)]
    activity = {d: {"AUTHENTICATED": 0, "SUSPICIOUS": 0, "FAILED AUTHENTICATION": 0, "UNVERIFIED": 0} for d in day_index}
    for r in act_rows:
        if r["day"] in activity:
            activity[r["day"]][r["classification"]] = r["n"]
    authenticated = by_class.get("AUTHENTICATED", 0)
    return {
        "total": total,
        "authenticated": authenticated,
        "suspicious": by_class.get("SUSPICIOUS", 0),
        "failed": by_class.get("FAILED AUTHENTICATION", 0),
        "unverified": by_class.get("UNVERIFIED", 0),
        "success_rate": round(100.0 * authenticated / total, 1) if total else 0.0,
        "by_classification": by_class,
        "by_risk": by_risk,
        "auth": auth,
        "activity": activity,
        "threats": [(r["event_type"], r["n"]) for r in threat_rows],
        "alerts": [dict(r) for r in alert_rows],
    }


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
def get_setting(key: str, default: str = "", db_path: str | Path | None = None) -> str:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT value FROM application_settings WHERE key = ?", (key,)).fetchone()
    return default if row is None or row["value"] is None else row["value"]


def set_setting(key: str, value: str, db_path: str | Path | None = None) -> None:
    with get_connection(db_path) as conn:
        conn.execute(
            """INSERT INTO application_settings (key, value, updated_at) VALUES (?,?,?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
            (key, value, _now()),
        )


def get_settings(prefix: str = "", db_path: str | Path | None = None) -> dict[str, str]:
    """Return all settings whose key starts with ``prefix``."""
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM application_settings WHERE key LIKE ? ESCAPE '\\'", (escaped + "%",)).fetchall()
    return {r["key"]: r["value"] for r in rows}
