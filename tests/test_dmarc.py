import pytest

from modules.dmarc_checker import domains_aligned, evaluate_dmarc, lookup_dmarc, parse_dmarc_record
from modules.dns_utils import DictResolver

REC = "v=DMARC1; p=reject; sp=quarantine; rua=mailto:r@example.com; ruf=mailto:f@example.com; pct=50; adkim=s; aspf=r"


def resolver(txt, name="_dmarc.example.com"):
    return DictResolver({name: {"TXT": txt}})


def test_parse_all_tags():
    p = parse_dmarc_record(REC)
    assert (p["policy"], p["subdomain_policy"], p["pct"], p["adkim"], p["aspf"]) == ("reject", "quarantine", 50, "s", "r")
    assert p["rua"] == ["mailto:r@example.com"] and p["ruf"] == ["mailto:f@example.com"] and not p["errors"]
    assert any("pct=50" in w for w in p["warnings"])


def test_defaults_and_warnings():
    p = parse_dmarc_record("v=DMARC1; p=none")
    assert (p["pct"], p["adkim"], p["aspf"], p["subdomain_policy"]) == (100, "r", "r", "")
    assert any("p=none" in w for w in p["warnings"]) and any("rua" in w for w in p["warnings"])


@pytest.mark.parametrize("bad", ["v=DMARC2; p=none", "p=none; v=DMARC1", "v=DMARC1", "v=DMARC1; p=bogus", "v=DMARC1; p=none; pct=abc", "v=DMARC1; p=none; adkim=x"])
def test_invalid_records_report_errors(bad):
    assert parse_dmarc_record(bad)["errors"]


def test_lookup_found_none_and_error():
    found = lookup_dmarc("example.com", resolver([REC]))
    assert found.status == "FOUND" and found.policy == "reject" and found.record_domain == "example.com" and found.explanation
    none = lookup_dmarc("example.com", DictResolver({}))
    assert none.status == "NONE" and "No DMARC record" in none.explanation[0]
    err = lookup_dmarc("example.com", DictResolver({"_dmarc.example.com": {"__timeout__": True}}))
    assert err.status == "TEMPERROR" and err.errors


def test_subdomain_falls_back_to_organisational_domain():
    r = lookup_dmarc("mail.example.com", resolver([REC]))
    assert r.status == "FOUND" and r.used_org_fallback and r.record_domain == "example.com"


def test_multiple_records_invalid_and_non_dmarc_txt_ignored():
    assert lookup_dmarc("example.com", resolver([REC, REC])).status == "INVALID"
    assert lookup_dmarc("example.com", resolver(["some other txt", REC])).status == "FOUND"


def test_alignment_rules():
    assert domains_aligned("mail.example.com", "example.com", "r")
    assert not domains_aligned("mail.example.com", "example.com", "s")
    assert domains_aligned("example.com", "example.com", "s")
    assert not domains_aligned("example.org", "example.com", "r")
    assert domains_aligned("a.example.co.uk", "b.example.co.uk", "r") and not domains_aligned("a.co.uk", "b.co.uk", "r")
    assert not domains_aligned("", "example.com")


def lk(txt=REC):
    return lookup_dmarc("example.com", resolver([txt]))


def test_pass_requires_aligned_pass():
    ev = evaluate_dmarc("example.com", lk(), "PASS", "example.com", "NONE", [])
    assert ev["status"] == "PASS" and ev["spf_aligned"] is True
    ev = evaluate_dmarc("example.com", lk(), "FAIL", "", "PASS", [{"status": "PASS", "domain": "example.com"}])
    assert ev["status"] == "PASS" and ev["dkim_aligned"] is True


def test_fail_when_both_evaluated_and_unaligned():
    ev = evaluate_dmarc("example.com", lk(), "PASS", "bulkmailer.example", "PASS", [{"status": "PASS", "domain": "other.example"}])
    assert ev["status"] == "FAIL" and ev["applied_policy"] == "reject" and "not aligned" in ev["explanation"]


def test_strict_dkim_alignment_rejects_subdomain_signer():
    ev = evaluate_dmarc("example.com", lk(), "FAIL", "", "PASS", [{"status": "PASS", "domain": "mail.example.com"}])
    assert ev["status"] == "FAIL"  # adkim=s in REC


def test_not_evaluated_when_information_missing_never_a_pass_or_fail():
    ev = evaluate_dmarc("example.com", lk(), "NOT EVALUATED", "", "NOT EVALUATED", [])
    assert ev["status"] == "NOT EVALUATED"
    ev = evaluate_dmarc("example.com", lk(), "NOT EVALUATED", "", "FAIL", [])
    assert ev["status"] == "NOT EVALUATED" and "NOT a failure" in ev["explanation"]
    assert evaluate_dmarc("example.com", None, "PASS", "example.com", "PASS", [])["status"] == "NOT EVALUATED"
    err = lookup_dmarc("example.com", DictResolver({"_dmarc.example.com": {"__timeout__": True}}))
    assert evaluate_dmarc("example.com", err, "PASS", "example.com", "PASS", [])["status"] == "NOT EVALUATED"


def test_no_policy_is_none_and_subdomain_policy_applied():
    assert evaluate_dmarc("example.com", lookup_dmarc("example.com", DictResolver({})), "PASS", "example.com", "NONE", [])["status"] == "NONE"
    ev = evaluate_dmarc("shop.example.com", lookup_dmarc("shop.example.com", resolver([REC])), "FAIL", "", "NONE", [])
    assert ev["status"] == "FAIL" and ev["applied_policy"] == "quarantine"  # sp= applies to subdomain
