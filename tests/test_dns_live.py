"""Tests the LiveResolver (real dnspython code path, real DNS wire format) against a loopback DNS server.

No Internet access is needed: a tiny UDP DNS server runs on 127.0.0.1 and answers from a dictionary.
This proves that TXT/A/MX parsing, NXDOMAIN handling, SERVFAIL and timeouts are mapped correctly,
which a simulated resolver cannot show.
"""
from __future__ import annotations

import socket
import threading

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from modules import dkim_verifier as dv
from modules import rsa_signature as rs
from modules.dmarc_checker import lookup_dmarc
from modules.dns_utils import DNSTemporaryError, LiveResolver
from modules.spf_checker import check_spf

LONG_TXT = ["v=DKIM1; k=rsa; p=" + "A" * 200, "B" * 200]  # one record made of two strings (each <= 255 bytes, as DNS requires)


class LoopbackDNS:
    def __init__(self, zone: dict[tuple[str, str], list], servfail: set[str] = frozenset(), silent: set[str] = frozenset()):
        self.zone, self.servfail, self.silent = zone, set(servfail), set(silent)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.thread.join(timeout=2)
        self.sock.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            query = dns.message.from_wire(data)
            q = query.question[0]
            name = q.name.to_text().rstrip(".").lower()
            rtype = dns.rdatatype.to_text(q.rdtype)
            if name in self.silent:
                continue  # never answer: simulates a timeout
            reply = dns.message.make_response(query)
            reply.flags |= dns.flags.AA
            if name in self.servfail:
                reply.set_rcode(dns.rcode.SERVFAIL)
            else:
                values = self.zone.get((name, rtype))
                known_name = any(n == name for n, _ in self.zone)
                if values is not None:
                    rdclass = q.rdclass
                    if rtype == "TXT":
                        rdata = [dns.rdata.from_text(rdclass, q.rdtype, " ".join(f'"{s}"' for s in (v if isinstance(v, list) else [v]))) for v in values]
                    else:
                        rdata = [dns.rdata.from_text(rdclass, q.rdtype, v) for v in values]
                    reply.answer.append(dns.rrset.from_rdata_list(q.name, 60, rdata))
                elif not known_name:
                    reply.set_rcode(dns.rcode.NXDOMAIN)
            self.sock.sendto(reply.to_wire(), addr)


def resolver(server: LoopbackDNS, timeout: float = 1.5) -> LiveResolver:
    return LiveResolver(timeout=timeout, nameservers=["127.0.0.1"], port=server.port)


ZONE = {
    ("example.test", "TXT"): [["v=spf1 ip4:203.0.113.0/24 include:_spf.vendor.test -all"], ["google-site-verification=xyz"]],
    ("_spf.vendor.test", "TXT"): [["v=spf1 ip4:198.51.100.0/24 -all"]],
    ("_dmarc.example.test", "TXT"): [["v=DMARC1; p=reject; rua=mailto:r@example.test"]],
    ("example.test", "MX"): ["20 mx2.example.test.", "10 mx1.example.test."],
    ("mx1.example.test", "A"): ["203.0.113.50"],
    ("mx1.example.test", "AAAA"): ["2001:db8::50"],
    ("long.example.test", "TXT"): [LONG_TXT],
}


def test_txt_a_aaaa_mx_and_multi_string_txt():
    with LoopbackDNS(ZONE) as srv:
        r = resolver(srv)
        assert "v=spf1 ip4:203.0.113.0/24 include:_spf.vendor.test -all" in r.txt("example.test")
        assert r.mx("example.test") == ["mx1.example.test", "mx2.example.test"]  # sorted by preference
        assert r.a("mx1.example.test") == ["203.0.113.50"] and r.aaaa("mx1.example.test") == ["2001:db8::50"]
        assert r.txt("long.example.test") == ["".join(LONG_TXT)]  # strings are joined, as RFC 6376 requires
        assert any(line.startswith("TXT ") for line in r.query_log)


def test_nxdomain_and_nodata_return_empty_not_error():
    with LoopbackDNS(ZONE) as srv:
        r = resolver(srv)
        assert r.txt("does-not-exist.test") == []
        assert r.aaaa("example.test") == []  # name exists, type does not


def test_servfail_and_timeout_raise_temporary_error():
    with LoopbackDNS(ZONE, servfail={"broken.test"}, silent={"slow.test"}) as srv:
        r = resolver(srv, timeout=0.8)
        with pytest.raises(DNSTemporaryError):
            r.txt("broken.test")
        with pytest.raises(DNSTemporaryError) as exc:
            r.txt("slow.test")
        assert "timeout" in str(exc.value).lower()


def test_dns_failure_is_never_reported_as_no_record():
    with LoopbackDNS(ZONE, servfail={"broken.test", "_dmarc.broken.test"}) as srv:
        assert check_spf("broken.test", "1.2.3.4", resolver(srv)).status == "TEMPERROR"
        assert lookup_dmarc("broken.test", resolver(srv)).status == "TEMPERROR"


def test_spf_and_dmarc_end_to_end_over_real_dns_protocol():
    with LoopbackDNS(ZONE) as srv:
        r = resolver(srv)
        assert check_spf("example.test", "203.0.113.9", r).status == "PASS"
        assert check_spf("example.test", "198.51.100.9", r).status == "PASS"  # through include
        assert check_spf("example.test", "192.0.2.9", r).status == "FAIL"
        assert check_spf("nothing.test", "192.0.2.9", r).status == "NONE"
        d = lookup_dmarc("example.test", r)
        assert d.status == "FOUND" and d.policy == "reject" and "live DNS" in d.data_source


def test_dkim_end_to_end_over_real_dns_protocol(rsa_key):
    msg = b"From: a@dk.test\nTo: b@example.net\nSubject: hi\nDate: Fri, 13 Nov 2026 09:00:00 +0000\nMessage-ID: <1@dk.test>\n\nbody text\n"
    signed = dv.sign_for_demo(msg, "dk.test", "sel", rs.private_key_to_pem(rsa_key))
    record = dv.make_key_record(rsa_key.public_key())
    chunks = [record[i:i + 200] for i in range(0, len(record), 200)]  # published as several TXT strings
    with LoopbackDNS({("sel._domainkey.dk.test", "TXT"): [chunks]}) as srv:
        assert dv.verify_dkim(signed, resolver(srv)).status == "PASS"
        assert dv.verify_dkim(signed.replace(b"body text", b"body TEXT"), resolver(srv)).status == "FAIL"
    with LoopbackDNS({}, silent={"sel._domainkey.dk.test"}) as srv:
        assert dv.verify_dkim(signed, resolver(srv, timeout=0.8)).status == "TEMPERROR"
