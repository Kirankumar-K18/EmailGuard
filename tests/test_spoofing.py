import pytest

from modules.analysis_engine import build_email_from_fields
from modules.email_parser import parse_email
from modules.spoofing_detector import RULES, analyze_spoofing, levenshtein, lookalike_brand, risk_level

CLEAN = ("From: Priya <priya@northwind.example>\nTo: you@example.net\nSubject: Meeting notes\nDate: Thu, 12 Nov 2026 10:00:00 +0000\n"
         "Message-ID: <1@northwind.example>\nReturn-Path: <priya@northwind.example>\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
         "Notes are at https://northwind.example/notes\n")


def ids(result):
    return {i["id"] for i in result["indicators"]}


def test_risk_bands():
    assert [risk_level(s) for s in (0, 29, 30, 59, 60, 100)] == ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH"]


def test_clean_message_scores_low_with_no_indicators():
    r = analyze_spoofing(parse_email(CLEAN), {})
    assert r["level"] == "LOW" and r["score"] == 0 and r["indicators"] == []
    assert "heuristic" in r["disclaimer"].lower() and "not a definitive" in r["disclaimer"].lower()


def test_reply_to_mismatch_and_freemail():
    p = parse_email(CLEAN.replace("Subject:", "Reply-To: boss@gmail.com\nSubject:"))
    r = analyze_spoofing(p, {})
    assert {"REPLYTO_MISMATCH", "REPLYTO_FREEMAIL"} <= ids(r)


def test_reply_to_same_organisation_not_flagged():
    p = parse_email(CLEAN.replace("Subject:", "Reply-To: other@mail.northwind.example\nSubject:"))
    assert "REPLYTO_MISMATCH" not in ids(analyze_spoofing(p, {}))


def test_display_name_with_embedded_foreign_address():
    p = parse_email('From: "ceo@bigcorp.example" <x@evil.example>\nTo: a@b.example\n\nhi')
    assert "DISPLAY_EMAIL" in ids(analyze_spoofing(p, {}))


def test_display_name_brand_impersonation():
    p = parse_email("From: PayPal Support <help@random-domain.example>\nTo: a@b.example\n\nhi")
    assert "DISPLAY_BRAND" in ids(analyze_spoofing(p, {}))


def test_genuine_brand_domain_not_flagged():
    p = parse_email("From: PayPal <service@paypal.com>\nTo: a@b.example\nDate: Thu, 12 Nov 2026 10:00:00 +0000\nMessage-ID: <x@paypal.com>\n\nhi")
    got = ids(analyze_spoofing(p, {"spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}))
    assert "DISPLAY_BRAND" not in got and "LOOKALIKE" not in got


@pytest.mark.parametrize("domain", ["paypa1.com", "paypal-support.example", "micros0ft.com", "paypall.com", "secure-amazon.net", "g00gle.com", "login.paypal.evil.example"])
def test_lookalike_domains_detected(domain):
    assert lookalike_brand(domain) is not None


@pytest.mark.parametrize("domain", ["paypal.com", "mail.google.com", "microsoft.com", "northwind.example", "amazon.co.uk", "example.org", "applepie-bakery.example"])
def test_legitimate_domains_not_flagged(domain):
    assert lookalike_brand(domain) is None


def test_levenshtein():
    assert levenshtein("paypal", "paypa1") == 1 and levenshtein("", "abc") == 3 and levenshtein("same", "same") == 0


def test_authentication_failures_score_points():
    r = analyze_spoofing(parse_email(CLEAN), {"spf": {"status": "FAIL"}, "dkim": {"status": "FAIL"}, "dmarc": {"status": "FAIL"}})
    assert {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"} <= ids(r)
    assert r["score"] >= RULES["SPF_FAIL"] + RULES["DKIM_FAIL"] + RULES["DMARC_FAIL"] - 0


def test_not_evaluated_is_not_treated_as_failure():
    r = analyze_spoofing(parse_email(CLEAN.replace("Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n", "")),
                         {"spf": {"status": "NOT EVALUATED"}, "dkim": {"status": "NOT EVALUATED"}, "dmarc": {"status": "NOT EVALUATED"}})
    assert not ({"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"} & ids(r))
    assert "NO_AUTH_INFO" in ids(r)  # unverifiable origin is noted, but not as a failure


def test_header_claim_that_contradicts_verification_is_flagged():
    r = analyze_spoofing(parse_email(CLEAN), {"spf": {"status": "FAIL"}, "dkim": {"status": "NONE"}, "dmarc": {"status": "NONE"}})
    assert "CLAIM_MISMATCH" in ids(r)


def test_suspicious_links():
    body = ("go to http://203.0.113.9/login or https://bit.ly/abc or http://paypal.com@evil.example/x or https://xn--pple-43d.example/\n")
    r = analyze_spoofing(parse_email(f"From: a@example.com\nTo: b@example.net\n\n{body}"), {})
    assert {"URL_IP", "URL_SHORT", "URL_AT", "URL_PUNY"} <= ids(r)


def test_html_link_text_mismatch():
    raw = ("From: a@example.com\nTo: b@example.net\nMIME-Version: 1.0\nContent-Type: text/html\n\n"
           '<a href="http://evil.example/p">www.mybank.example/login</a>')
    assert "URL_MISMATCH" in ids(analyze_spoofing(parse_email(raw), {}))


@pytest.mark.parametrize("name, rule", [("invoice.pdf.exe", "ATT_DANGEROUS"), ("invoice.pdf.exe", "ATT_DOUBLE"), ("report.docm", "ATT_MACRO"),
                                        ("login.html", "ATT_HTML"), ("files.zip", "ATT_ARCHIVE")])
def test_attachment_rules(name, rule):
    raw = build_email_from_fields("", "a@example.com", attachment_names=[name])
    assert rule in ids(analyze_spoofing(parse_email(raw), {}, manual=True))


def test_plain_pdf_attachment_not_flagged():
    raw = build_email_from_fields("", "a@example.com", attachment_names=["report.pdf"])
    assert not any(i.startswith("ATT_") for i in ids(analyze_spoofing(parse_email(raw), {}, manual=True)))


def test_language_rules():
    raw = "From: a@example.com\nTo: b@example.net\nSubject: URGENT\n\nVerify your account immediately. Please update the bank details for the wire transfer."
    assert {"LANG_URGENT", "LANG_CRED", "LANG_PAYMENT"} <= ids(analyze_spoofing(parse_email(raw), {}))


def test_header_consistency_rules():
    assert {"MISSING_DATE", "MISSING_MSGID"} <= ids(analyze_spoofing(parse_email("From: a@example.com\nTo: b@example.net\n\nx"), {}))
    assert "MULTI_FROM" in ids(analyze_spoofing(parse_email("From: a@example.com\nFrom: b@example.org\n\nx"), {}))
    hops = "".join(f"Received: from h{i}.example (h{i}.example [192.0.2.{i + 1}]) by x; Thu, 12 Nov 2026 10:0{i}:00 +0000\n" for i in range(9))
    assert "MANY_HOPS" in ids(analyze_spoofing(parse_email(hops + "From: a@example.com\n\nx"), {}))
    out_of_order = ("Received: from a (a [192.0.2.1]) by x; Thu, 12 Nov 2026 10:00:00 +0000\nReceived: from b (b [192.0.2.2]) by y; Thu, 12 Nov 2026 12:00:00 +0000\n"
                    "From: a@example.com\n\nx")
    assert "HOP_ORDER" in ids(analyze_spoofing(parse_email(out_of_order), {}))


def test_manual_mode_does_not_penalise_absent_headers():
    raw = build_email_from_fields("", "alice@example.com", subject="Hi", body="hello")
    r = analyze_spoofing(parse_email(raw), {"dkim": {"status": "NOT EVALUATED"}}, manual=True)
    assert r["score"] == 0 and r["indicators"] == []


def test_score_is_capped_and_sorted_and_explained():
    raw = build_email_from_fields("PayPal Support", "service@paypa1-support.example", reply_to="help@gmail.com", return_path="x@other.example",
                                  subject="URGENT", body="verify your account immediately http://203.0.113.5/x https://bit.ly/q",
                                  attachment_names=["invoice.pdf.exe"], claims={"spf": "fail"})
    r = analyze_spoofing(parse_email(raw), {}, manual=True)
    assert r["score"] == 100 and r["raw_total"] > 100 and r["level"] == "HIGH"
    pts = [i["points"] for i in r["indicators"]]
    assert pts == sorted(pts, reverse=True)
    assert all(i["title"] and i["detail"] and i["category"] for i in r["indicators"])
    assert sum(r["category_scores"].values()) == r["raw_total"]


def test_every_rule_has_positive_points():
    assert all(isinstance(v, int) and v > 0 for v in RULES.values())


def test_build_email_rejects_missing_from_and_sanitises_newlines():
    with pytest.raises(ValueError):
        build_email_from_fields("", "")
    raw = build_email_from_fields("Evil\r\nBcc: victim@example.com", "a@example.com", subject="x\r\nInjected: yes")
    p = parse_email(raw)
    assert not p.get_all("bcc") and not p.get_all("injected")  # header injection neutralised
