import pytest

from modules.email_parser import (EmailParseError, extract_received_ips, extract_urls, parse_authentication_results,
                                  parse_email)


def test_extracts_core_headers(simple_email):
    p = parse_email(simple_email)
    assert p.from_addr == "sender@example.com" and p.from_display == "Sender Name" and p.from_domain == "example.com"
    assert p.subject == "Hello there" and p.message_id == "<abc@example.com>"
    assert p.return_path_domain == "example.com"
    assert p.to == "Receiver <receiver@example.net>"
    assert p.date_parsed is not None and p.date_parsed.year == 2026
    assert len(p.received) == 1 and p.received_ips[0]["ip"] == "203.0.113.7"
    assert p.missing_headers == []


def test_reply_to_and_encoded_subject():
    raw = "From: a@example.com\nReply-To: Help <help@other.example>\nSubject: =?utf-8?B?SGVsbG8gV29ybGQ=?=\nTo: b@example.net\n\nbody"
    p = parse_email(raw)
    assert p.reply_to_addr == "help@other.example" and p.reply_to_domain == "other.example"
    assert p.subject == "Hello World"


def test_missing_headers_are_reported_not_fatal():
    p = parse_email("From: a@example.com\nSubject: only these\n\nhi")
    assert set(p.missing_headers) == {"to", "date", "message-id"}
    assert any("Missing headers" in w for w in p.warnings)
    assert any("No Authentication-Results" in w for w in p.warnings)


def test_headers_only_input_is_accepted():
    p = parse_email("From: a@example.com\nTo: b@example.net\nSubject: x\n")
    assert p.from_addr == "a@example.com" and not p.has_body


@pytest.mark.parametrize("bad", ["", "   \n\n ", "just some random text without headers", "<html><body>hi</body></html>"])
def test_invalid_input_raises_clear_error(bad):
    with pytest.raises(EmailParseError):
        parse_email(bad)


def test_binary_and_none_rejected():
    with pytest.raises(EmailParseError):
        parse_email(b"\x00\x01\x02\x03PK\x03\x04" + b"\x00" * 100)
    with pytest.raises(EmailParseError):
        parse_email(None)  # type: ignore[arg-type]


def test_oversized_input_rejected(monkeypatch):
    import config

    monkeypatch.setattr(config, "MAX_EMAIL_BYTES", 100)
    with pytest.raises(EmailParseError):
        parse_email("From: a@example.com\n" + "X-Pad: " + "a" * 500 + "\n\nbody")


def test_multiple_received_headers_keep_order():
    raw = ("Received: from a.example (a [93.184.216.34]) by b; Thu, 12 Nov 2026 10:00:00 +0000\n"
           "Received: from c.example (c [192.168.1.5]) by d; Thu, 12 Nov 2026 09:00:00 +0000\n"
           "From: x@example.com\n\nbody")
    p = parse_email(raw)
    ips = extract_received_ips(p.received)
    assert [i["ip"] for i in ips] == ["93.184.216.34", "192.168.1.5"]
    assert ips[1]["is_private"] is True and ips[0]["is_private"] is False


def test_authentication_results_parsing_and_claims():
    parsed = parse_authentication_results(["mx.example; spf=pass smtp.mailfrom=a.example; dkim=fail header.d=b.example; dmarc=none"])
    by = {r["method"]: r for r in parsed["results"]}
    assert by["spf"]["result"] == "pass" and by["spf"]["properties"]["smtp.mailfrom"] == "a.example"
    assert by["dkim"]["result"] == "fail" and by["dmarc"]["result"] == "none"
    p = parse_email("Authentication-Results: mx.example; spf=softfail; dkim=pass\nReceived-SPF: fail (x)\nFrom: a@example.com\n\nb")
    assert p.header_claims["spf"] == "softfail" and p.header_claims["dkim"] == "pass"


def test_received_spf_used_when_no_authentication_results():
    p = parse_email("Received-SPF: Pass (domain designates 1.2.3.4)\nFrom: a@example.com\n\nb")
    assert p.header_claims == {"spf": "pass"}


def test_url_extraction_text_and_html_anchor_mismatch():
    urls = extract_urls("see https://a.example/x, and http://b.example/y.", '<a href="http://evil.example/login">www.bank.example</a>')
    found = {u["url"]: u for u in urls}
    assert "https://a.example/x" in found and "http://b.example/y" in found
    assert found["http://evil.example/login"]["text"] == "www.bank.example"


def test_attachment_extraction():
    raw = ("From: a@example.com\nTo: b@example.net\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=XX\n\n"
           "--XX\nContent-Type: text/plain\n\nhello\n--XX\nContent-Type: application/octet-stream\n"
           'Content-Disposition: attachment; filename="invoice.pdf.exe"\nContent-Transfer-Encoding: base64\n\nSGVsbG8=\n--XX--\n')
    p = parse_email(raw)
    assert p.attachments[0]["filename"] == "invoice.pdf.exe" and p.attachments[0]["size"] == 5
    assert len(p.attachments[0]["sha256"]) == 64 and "hello" in p.body_text


def test_multiple_from_headers_counted():
    assert parse_email("From: a@example.com\nFrom: b@example.org\n\nx").from_count == 2


def test_dkim_signature_summary():
    p = parse_email("DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1; c=relaxed/relaxed; h=from; bh=x; b=y\nFrom: a@example.com\n\nb")
    assert p.dkim_summary() == [{"d": "example.com", "s": "sel1", "a": "rsa-sha256", "c": "relaxed/relaxed"}]


def test_lf_and_crlf_inputs_parse_identically(simple_email):
    assert parse_email(simple_email).subject == parse_email(simple_email.replace("\r\n", "\n")).subject
