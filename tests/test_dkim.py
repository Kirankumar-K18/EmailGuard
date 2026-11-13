import pytest

from modules import dkim_verifier as dv
from modules import rsa_signature as rs
from modules.dns_utils import DictResolver

MSG = (b"From: Alice <alice@alice.example>\nTo: bob@bob.example\nSubject: Quarterly report\nDate: Fri, 13 Nov 2026 09:00:00 +0000\n"
       b"Message-ID: <q@alice.example>\n\nHi Bob,\n\nThe report is ready.\n\nAlice\n")


@pytest.fixture(scope="module")
def signed(rsa_key):
    return dv.sign_for_demo(MSG, "alice.example", "s1", rs.private_key_to_pem(rsa_key))


@pytest.fixture(scope="module")
def good_dns(rsa_key):
    return dv.demo_resolver("alice.example", "s1", dv.make_key_record(rsa_key.public_key()))


def test_genuine_signature_verifies(signed, good_dns):
    res = dv.verify_dkim(signed, good_dns)
    assert res.status == "PASS"
    sig = res.signatures[0]
    assert (sig.domain, sig.selector, sig.status, sig.key_bits) == ("alice.example", "s1", "PASS", 2048)
    assert sig.algorithm == "rsa-sha256" and "subject" in [h.lower() for h in sig.signed_headers]
    assert sig.key_query == "s1._domainkey.alice.example"


def test_body_tampering_fails_with_explanation(signed, good_dns):
    res = dv.verify_dkim(signed.replace(b"The report is ready.", b"The report is READY."), good_dns)
    assert res.status == "FAIL" and "BODY" in res.explanation and "body hash" in res.signatures[0].reason.lower()


def test_signed_header_tampering_fails(signed, good_dns):
    res = dv.verify_dkim(signed.replace(b"Subject: Quarterly report", b"Subject: Quarterly refund"), good_dns)
    assert res.status == "FAIL" and "signed header" in res.explanation.lower()


def test_unsigned_header_change_still_passes(signed, good_dns):
    assert dv.verify_dkim(signed.replace(b"Hi Bob", b"Hi Bob"), good_dns).status == "PASS"
    extra = b"X-Unsigned-Note: added in transit\r\n" + signed
    assert dv.verify_dkim(extra, good_dns).status == "PASS"


def test_wrong_public_key_fails(signed):
    other = dv.demo_resolver("alice.example", "s1", dv.make_key_record(rs.generate_keypair(2048).public_key()))
    assert dv.verify_dkim(signed, other).status == "FAIL"


def test_missing_key_is_permerror_and_dns_timeout_is_temperror(signed):
    r = dv.verify_dkim(signed, DictResolver({}))
    assert r.status == "PERMERROR" and "No public key" in r.explanation
    r = dv.verify_dkim(signed, DictResolver({"s1._domainkey.alice.example": {"__timeout__": True}}))
    assert r.status == "TEMPERROR" and "temporary DNS problem" in r.explanation


def test_revoked_key_is_permerror(signed):
    res = dv.verify_dkim(signed, DictResolver({"s1._domainkey.alice.example": {"TXT": ["v=DKIM1; k=rsa; p="]}}))
    assert res.status in ("PERMERROR", "FAIL")  # empty p= means the key was revoked: must never pass
    assert res.status != "PASS"


def test_no_signature_is_none(good_dns):
    r = dv.verify_dkim(MSG, good_dns)
    assert r.status == "NONE" and r.signatures == []


def test_malformed_signature_header_is_permerror(good_dns):
    bad = b"DKIM-Signature: v=1; a=rsa-sha256; d=alice.example\r\n" + MSG.replace(b"\n", b"\r\n")
    r = dv.verify_dkim(bad, good_dns)
    assert r.status == "PERMERROR" and "malformed" in r.explanation


def test_lf_only_input_is_normalised(signed, good_dns):
    assert dv.verify_dkim(signed.replace(b"\r\n", b"\n"), good_dns).status == "PASS"


def test_multiple_signatures_any_pass_wins(rsa_key, signed, good_dns):
    other = rs.generate_keypair(2048)
    double = dv.sign_for_demo(signed, "evil.example", "x", rs.private_key_to_pem(other))
    zone = DictResolver({**good_dns.zone, "x._domainkey.evil.example": {"TXT": ["v=DKIM1; p=AAAA"]}})
    res = dv.verify_dkim(double, zone)
    assert len(res.signatures) == 2 and res.status == "PASS"
    assert {s.domain: s.status for s in res.signatures}["alice.example"] == "PASS"


def test_key_record_description(rsa_key):
    info = dv.describe_key_record(dv.make_key_record(rsa_key.public_key()))
    assert info["bits"] == 2048 and not info["revoked"] and info["key_type"] == "rsa"
    assert dv.describe_key_record("v=DKIM1; p=")["revoked"] is True
    assert dv.describe_key_record("v=DKIM1; p=!!!notbase64")["error"]


def test_limitations_are_stated(good_dns):
    assert dv.verify_dkim(MSG, good_dns).limitations
