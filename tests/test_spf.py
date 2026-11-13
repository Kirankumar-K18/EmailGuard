import pytest

from modules.dns_utils import DictResolver
from modules.spf_checker import SPFSyntaxError, check_spf, parse_spf_record


def zone(**records):
    return DictResolver({k.replace("_", "."): v for k, v in records.items()})


def z(mapping):
    return DictResolver(mapping)


BASE = {
    "example.com": {"TXT": ["v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 include:_spf.vendor.example a mx -all"], "A": ["198.51.100.5"], "MX": ["mx.example.com"]},
    "_spf.vendor.example": {"TXT": ["v=spf1 ip4:192.0.2.0/28 ~all"]},
    "mx.example.com": {"A": ["198.51.100.99"]},
}


@pytest.mark.parametrize("ip, status", [
    ("203.0.113.77", "PASS"),        # ip4 range
    ("2001:db8::1", "PASS"),         # ip6 range
    ("192.0.2.5", "PASS"),           # via include
    ("198.51.100.5", "PASS"),        # via a
    ("198.51.100.99", "PASS"),       # via mx
    ("8.8.8.8", "FAIL"),             # -all
])
def test_basic_evaluation(ip, status):
    assert check_spf("example.com", ip, z(BASE)).status == status


def test_softfail_neutral_and_qualifiers():
    assert check_spf("a.example", "1.2.3.4", z({"a.example": {"TXT": ["v=spf1 ip4:10.0.0.0/8 ~all"]}})).status == "SOFTFAIL"
    assert check_spf("a.example", "1.2.3.4", z({"a.example": {"TXT": ["v=spf1 ip4:10.0.0.0/8 ?all"]}})).status == "NEUTRAL"
    assert check_spf("a.example", "1.2.3.4", z({"a.example": {"TXT": ["v=spf1 -ip4:1.2.3.4 +all"]}})).status == "FAIL"
    assert check_spf("a.example", "1.2.3.4", z({"a.example": {"TXT": ["v=spf1 ip4:10.0.0.0/8"]}})).status == "NEUTRAL"  # nothing matched


def test_none_when_no_record_or_domain_missing():
    assert check_spf("nospf.example", "1.2.3.4", z({"nospf.example": {"TXT": ["google-site-verification=abc"]}})).status == "NONE"
    assert check_spf("missing.example", "1.2.3.4", z({})).status == "NONE"
    assert check_spf("not a domain", "1.2.3.4", z({})).status == "NONE"


def test_temperror_on_dns_timeout():
    r = check_spf("slow.example", "1.2.3.4", z({"slow.example": {"__timeout__": True}}))
    assert r.status == "TEMPERROR" and "timeout" in r.explanation.lower()


def test_multiple_spf_records_is_permerror():
    r = check_spf("two.example", "1.2.3.4", z({"two.example": {"TXT": ["v=spf1 -all", "v=spf1 +all"]}}))
    assert r.status == "PERMERROR" and "2 SPF records" in r.explanation


def test_syntax_error_is_permerror():
    assert check_spf("bad.example", "1.2.3.4", z({"bad.example": {"TXT": ["v=spf1 ip4:not-an-ip -all"]}})).status == "PERMERROR"
    assert check_spf("bad.example", "1.2.3.4", z({"bad.example": {"TXT": ["v=spf1 bogus:x -all"]}})).status == "PERMERROR"


def test_include_loop_hits_lookup_limit():
    r = check_spf("loop.example", "1.2.3.4", z({"loop.example": {"TXT": ["v=spf1 include:loop.example -all"]}}))
    assert r.status == "PERMERROR" and "10" in r.explanation


def test_include_of_domain_without_spf_is_permerror():
    r = check_spf("a.example", "1.2.3.4", z({"a.example": {"TXT": ["v=spf1 include:nothing.example -all"]}}))
    assert r.status == "PERMERROR"


def test_include_fail_inside_does_not_match():
    m = {"a.example": {"TXT": ["v=spf1 include:b.example ~all"]}, "b.example": {"TXT": ["v=spf1 -ip4:1.2.3.4 +all"]}}
    assert check_spf("a.example", "1.2.3.4", z(m)).status == "SOFTFAIL"  # inner FAIL -> include does not match


def test_redirect_modifier():
    m = {"a.example": {"TXT": ["v=spf1 redirect=b.example"]}, "b.example": {"TXT": ["v=spf1 ip4:1.2.3.4 -all"]}}
    assert check_spf("a.example", "1.2.3.4", z(m)).status == "PASS"
    assert check_spf("a.example", "9.9.9.9", z(m)).status == "FAIL"


def test_cidr_on_a_and_mx():
    m = {"a.example": {"TXT": ["v=spf1 a:h.example/24 -all"]}, "h.example": {"A": ["198.51.100.10"]}}
    assert check_spf("a.example", "198.51.100.200", z(m)).status == "PASS"
    assert check_spf("a.example", "198.51.101.1", z(m)).status == "FAIL"


def test_exists_mechanism():
    m = {"a.example": {"TXT": ["v=spf1 exists:allow.example -all"]}, "allow.example": {"A": ["127.0.0.2"]}}
    assert check_spf("a.example", "1.2.3.4", z(m)).status == "PASS"


def test_macros_and_ptr_are_not_evaluated_never_guessed():
    r = check_spf("a.example", "1.2.3.4", z({"a.example": {"TXT": ["v=spf1 exists:%{i}._spf.a.example -all"]}}))
    assert r.status == "NOT EVALUATED" and "macro" in r.explanation.lower()
    r = check_spf("a.example", "1.2.3.4", z({"a.example": {"TXT": ["v=spf1 ptr -all"]}}))
    assert r.status == "NOT EVALUATED"


def test_void_lookup_limit():
    m = {"a.example": {"TXT": ["v=spf1 a:n1.example a:n2.example a:n3.example -all"]}}
    assert check_spf("a.example", "1.2.3.4", z(m)).status == "PERMERROR"


def test_ipv4_mapped_ipv6_and_invalid_ip():
    assert check_spf("example.com", "::ffff:203.0.113.5", z(BASE)).status == "PASS"
    with pytest.raises(ValueError):
        check_spf("example.com", "999.1.1.1", z(BASE))


def test_result_metadata_and_trace():
    r = check_spf("example.com", "203.0.113.77", z(BASE))
    assert r.record.startswith("v=spf1") and "ip4:203.0.113.0/24" in r.matched
    assert any("MATCH" in line for line in r.trace) and r.limitations and r.mechanisms
    assert "simulated" in r.data_source


def test_parser_details():
    rec = parse_spf_record("v=spf1 +a:mail.example.com/24//64 -mx ~include:x.example redirect=y.example exp=e.example foo=bar")
    assert [(m.qualifier, m.name) for m in rec.mechanisms] == [("+", "a"), ("-", "mx"), ("~", "include")]
    assert rec.mechanisms[0].cidr4 == 24 and rec.mechanisms[0].cidr6 == 64
    assert rec.redirect == "y.example" and rec.unknown_modifiers == ["foo=bar"]
    with pytest.raises(SPFSyntaxError):
        parse_spf_record("v=spf2 -all")
    with pytest.raises(SPFSyntaxError):
        parse_spf_record("v=spf1 ip4:2001:db8::/32 -all")
    with pytest.raises(SPFSyntaxError):
        parse_spf_record("v=spf1 all:extra")
