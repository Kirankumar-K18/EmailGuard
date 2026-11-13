import json
import sqlite3

import pytest

from database import db
from modules import demo_data
from modules.analysis_engine import analyze_email, classify
from modules.dns_utils import DictResolver
from modules.email_parser import EmailParseError
from modules.report_generator import generate_pdf_report


@pytest.fixture(scope="module")
def scenario_results():
    return {s["id"]: demo_data.run_scenario(s) for s in demo_data.load_scenarios()}


def test_all_five_demo_scenarios_produce_designed_outcomes(scenario_results):
    assert len(scenario_results) == 5
    for sid, res in scenario_results.items():
        exp = res["scenario_info"]["expected"]
        a = res["authentication"]
        assert (a["spf"]["status"], a["dkim"]["status"], a["dmarc"]["status"], res["verdict"]["classification"]) == (
            exp["spf"], exp["dkim"], exp["dmarc"], exp["classification"]), f"scenario {sid}"
        assert res["is_demo"] is True


def test_scenario_5_forged_claims_are_caught(scenario_results):
    res = scenario_results[5]
    assert res["email"]["header_claims"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}  # what the message CLAIMS
    assert res["authentication"]["spf"]["status"] == "NONE"  # what EmailGuard FOUND
    assert "CLAIM_MISMATCH" in {i["id"] for i in res["spoofing"]["indicators"]} and res["spoofing"]["level"] == "HIGH"


def test_scenario_1_is_clean_and_scenario_4_authenticated_but_suspicious(scenario_results):
    assert scenario_results[1]["spoofing"]["score"] == 0
    assert scenario_results[4]["verdict"]["classification"] == "SUSPICIOUS" and scenario_results[4]["authentication"]["dmarc"]["status"] == "PASS"


def test_no_dns_means_not_evaluated_never_pass(simple_email):
    res = analyze_email(simple_email, dns_mode="off")
    assert res["authentication"]["spf"]["status"] == "NOT EVALUATED" and res["authentication"]["dmarc"]["status"] == "NOT EVALUATED"
    assert res["authentication"]["dkim"]["status"] == "NONE"  # no DKIM-Signature header exists: a fact about the message
    assert res["authentication"]["spf"]["method"] == "NOT PERFORMED"
    signed = "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=x; h=from; bh=a; b=b\r\n" + simple_email
    assert analyze_email(signed, dns_mode="off")["authentication"]["dkim"]["status"] == "NOT EVALUATED"  # signature present, key unfetched
    assert res["email"]["header_claims"]["spf"] == "pass"  # reported, but as an unverified claim
    assert res["verdict"]["classification"] == "UNVERIFIED"


def test_spf_not_evaluated_without_sending_ip(simple_email):
    res = analyze_email(simple_email, dns_mode="simulated", resolver=DictResolver({}))
    assert res["authentication"]["spf"]["status"] == "NOT EVALUATED" and "IP" in res["authentication"]["spf"]["explanation"]


def test_headers_only_never_claims_dkim_result():
    res = analyze_email("From: a@example.com\nTo: b@example.net\nDKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=x; h=from; bh=a; b=b\n",
                        input_mode="headers_only", dns_mode="simulated", resolver=DictResolver({}))
    assert res["authentication"]["dkim"]["status"] == "NOT EVALUATED"


def test_invalid_input_raises_parse_error():
    with pytest.raises(EmailParseError):
        analyze_email("this is not an email", dns_mode="off")


def test_classification_logic():
    assert classify("FAIL", "NONE", "FAIL", "LOW")[0] == "FAILED AUTHENTICATION"
    assert classify("PASS", "PASS", "PASS", "HIGH")[0] == "SUSPICIOUS"
    assert classify("PASS", "NONE", "NONE", "LOW")[0] == "AUTHENTICATED"
    assert classify("NOT EVALUATED", "NOT EVALUATED", "NOT EVALUATED", "LOW")[0] == "UNVERIFIED"


# ------------------------------------------------------------------ database
def test_init_is_idempotent_and_creates_required_tables(tmp_db):
    db.init_db(tmp_db)
    with sqlite3.connect(tmp_db) as c:
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"email_analysis", "authentication_results", "security_events", "application_settings"} <= tables


def test_save_and_retrieve_roundtrip(tmp_db, scenario_results):
    res = json.loads(json.dumps(scenario_results[3], default=str))
    aid = db.save_analysis(res, tmp_db)
    assert res["analysis_id"] == aid
    loaded = db.get_analysis(aid, tmp_db)
    assert loaded["verdict"]["classification"] == "FAILED AUTHENTICATION" and loaded["analysis_id"] == aid
    row = db.list_analyses(db_path=tmp_db)[0]
    assert (row["spf_status"], row["dkim_status"], row["dmarc_status"]) == ("PASS", "FAIL", "FAIL")
    with sqlite3.connect(tmp_db) as c:
        assert c.execute("SELECT COUNT(*) FROM authentication_results").fetchone()[0] == 3
        assert c.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == len(res["spoofing"]["indicators"])


def test_search_filter_sort_and_pagination(tmp_db, scenario_results):
    for sid in (1, 2, 3, 4, 5):
        db.save_analysis(json.loads(json.dumps(scenario_results[sid], default=str)), tmp_db)
    assert len(db.list_analyses(db_path=tmp_db)) == 5
    assert len(db.list_analyses(search="statement", db_path=tmp_db)) == 1
    assert [r["classification"] for r in db.list_analyses(classifications=["AUTHENTICATED"], db_path=tmp_db)] == ["AUTHENTICATED"]
    assert len(db.list_analyses(spf=["FAIL"], db_path=tmp_db)) == 1
    scores = [r["risk_score"] for r in db.list_analyses(sort_by="risk_score", descending=True, db_path=tmp_db)]
    assert scores == sorted(scores, reverse=True)
    assert len(db.list_analyses(limit=2, db_path=tmp_db)) == 2
    assert db.list_analyses(sort_by="id; DROP TABLE email_analysis", db_path=tmp_db)  # unknown sort key falls back safely


def test_sql_injection_attempts_are_inert(tmp_db, scenario_results):
    db.save_analysis(json.loads(json.dumps(scenario_results[1], default=str)), tmp_db)
    for evil in ("'; DROP TABLE email_analysis; --", "' OR '1'='1", "%", "_", "\\"):
        db.list_analyses(search=evil, db_path=tmp_db)
    assert db.count_analyses(db_path=tmp_db) == 1
    assert db.list_analyses(search="%", db_path=tmp_db) == []  # '%' is matched literally, not as a wildcard


def test_delete_variants_and_cascade(tmp_db, scenario_results):
    ids = [db.save_analysis(json.loads(json.dumps(scenario_results[i], default=str)), tmp_db) for i in (1, 2, 3)]
    assert db.delete_analysis(ids[0], tmp_db) and not db.delete_analysis(99999, tmp_db)
    with sqlite3.connect(tmp_db) as c:
        assert c.execute("SELECT COUNT(*) FROM authentication_results WHERE analysis_id=?", (ids[0],)).fetchone()[0] == 0
    real = json.loads(json.dumps(scenario_results[1], default=str)); real["is_demo"] = False
    db.save_analysis(real, tmp_db)
    assert db.delete_all(demo_only=True, db_path=tmp_db) == 2 and db.count_analyses(db_path=tmp_db) == 1
    assert db.delete_all(db_path=tmp_db) == 1 and db.count_analyses(db_path=tmp_db) == 0
    assert db.get_analysis(ids[1], tmp_db) is None


def test_dashboard_stats_are_computed_from_database(tmp_db, scenario_results):
    for sid in (1, 1, 2, 3, 4, 5):
        db.save_analysis(json.loads(json.dumps(scenario_results[sid], default=str)), tmp_db)
    s = db.dashboard_stats(db_path=tmp_db)
    assert s["total"] == 6 and s["authenticated"] == 2 and s["failed"] == 2 and s["suspicious"] == 2
    assert s["success_rate"] == 33.3 and s["auth"]["SPF"]["PASS"] == 4 and s["threats"] and s["alerts"]
    assert sum(sum(d.values()) for d in s["activity"].values()) == 6
    assert db.dashboard_stats(include_demo=False, db_path=tmp_db)["total"] == 0


def test_settings_roundtrip_and_prefix(tmp_db):
    db.set_setting("dev.name", "A", tmp_db); db.set_setting("dev.name", "B", tmp_db); db.set_setting("other", "x", tmp_db)
    assert db.get_setting("dev.name", db_path=tmp_db) == "B" and db.get_setting("missing", "dflt", tmp_db) == "dflt"
    assert db.get_settings("dev.", tmp_db) == {"dev.name": "B"}


def test_database_errors_are_wrapped(tmp_path):
    with pytest.raises(db.DatabaseError):
        db.count_analyses(db_path=tmp_path)  # a directory is not a database file
    bad = tmp_path / "garbage.db"
    bad.write_bytes(b"this is not sqlite" * 50)
    with pytest.raises(db.DatabaseError):
        db.init_db(bad)


def test_corrupted_report_json_reports_error(tmp_db):
    with sqlite3.connect(tmp_db) as c:
        c.execute("INSERT INTO email_analysis (report_json) VALUES ('{not json')")
    with pytest.raises(db.DatabaseError):
        db.get_analysis(1, tmp_db)


def test_seed_and_remove_demo_data(tmp_db, monkeypatch):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_db)
    assert demo_data.seed_demo_data(12) == 12 and db.count_demo_rows() == 12
    assert demo_data.remove_demo_data() == 12 and db.count_analyses() == 0


# --------------------------------------------------------------------- PDF
def test_pdf_report_is_valid_for_every_scenario(scenario_results):
    for sid, res in scenario_results.items():
        pdf = generate_pdf_report(res)
        assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF") and len(pdf) > 3000, f"scenario {sid}"


def test_pdf_contains_required_sections_and_demo_label(scenario_results, monkeypatch):
    from reportlab import rl_config

    monkeypatch.setattr(rl_config, "pageCompression", 0)  # plain-text content streams so the text can be checked
    pdf = generate_pdf_report(scenario_results[5])
    text = pdf.decode("latin-1")
    for required in ("Email information", "Sender details", "Authentication results", "SPF verification", "DKIM verification",
                     "DMARC verification", "Digital signature status", "Suspicious indicators", "Risk score and verdict",
                     "FINAL SECURITY VERDICT", "DEMONSTRATION DATA", "paypa1-support.example", "heuristic risk assessment"):
        assert required in text, f"PDF is missing: {required}"
    real = generate_pdf_report(analyze_email(open(demo_data.config.DEMO_DIR / "01_legitimate_authenticated.eml", "rb").read(), dns_mode="off"))
    assert b"DEMONSTRATION DATA" not in real  # only demo results carry the banner


def test_pdf_handles_hostile_text_without_crashing(scenario_results):
    res = json.loads(json.dumps(scenario_results[5], default=str))
    res["email"]["subject"] = "<b>bold</b> & <script>alert(1)</script> ‮\u0000 \U0001F600 " + "x" * 3000
    res["email"]["from"] = "<<<>>> & '\""
    assert generate_pdf_report(res).startswith(b"%PDF-")


def test_pdf_for_minimal_result(simple_email):
    assert generate_pdf_report(analyze_email(simple_email, dns_mode="off")).startswith(b"%PDF-")
