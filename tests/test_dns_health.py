"""DNS health check: a 'no record' answer must not be trusted when the resolver cannot resolve anything."""
from __future__ import annotations

import pytest

from modules import analysis_engine
from modules.dns_utils import BaseResolver, DictResolver, DNSTemporaryError, check_dns_health


class _Resolver(BaseResolver):
    source_label = "test resolver"

    def __init__(self, a_answers=None, raises=False):
        super().__init__()
        self.a_answers, self.raises = a_answers or {}, raises

    def a(self, name):
        if self.raises:
            raise DNSTemporaryError("simulated outage")
        return self.a_answers.get(name, [])

    def txt(self, name):
        return []

    aaaa = mx = txt


def test_simulated_zone_is_always_healthy():
    ok, msg = check_dns_health(DictResolver({}))
    assert ok and "Simulated" in msg


def test_resolver_that_resolves_a_canary_is_healthy():
    ok, msg = check_dns_health(_Resolver({"cloudflare.com": ["104.16.0.1"]}))
    assert ok and "cloudflare.com" in msg


def test_nxdomain_for_every_canary_is_unhealthy():
    ok, msg = check_dns_health(_Resolver())
    assert not ok and "well-known domains" in msg


def test_outage_is_unhealthy():
    ok, msg = check_dns_health(_Resolver(raises=True))
    assert not ok and "simulated outage" in msg


EML = b"From: a@example.com\r\nTo: b@example.net\r\nSubject: Hi\r\nDate: Thu, 12 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nbody\r\n"


def test_engine_records_unhealthy_dns_in_live_mode(monkeypatch):
    monkeypatch.setattr(analysis_engine, "LiveResolver", lambda timeout=None: _Resolver())
    result = analysis_engine.analyze_email(EML, dns_mode="live", sending_ip="203.0.113.5")
    assert result["dns_health"]["checked"] and not result["dns_health"]["healthy"]
    assert any(s["title"] == "DNS health check" and s["status"] == "WARNING" for s in result["steps"])
    assert any("DNS health check failed" in lim for lim in result["limitations"])


def test_engine_marks_healthy_dns(monkeypatch):
    monkeypatch.setattr(analysis_engine, "LiveResolver", lambda timeout=None: _Resolver({"google.com": ["142.250.0.1"]}))
    result = analysis_engine.analyze_email(EML, dns_mode="live", sending_ip="203.0.113.5")
    assert result["dns_health"] == {"checked": True, "healthy": True, "message": "DNS is working: google.com resolved normally."}


@pytest.mark.parametrize("mode", ["off", "simulated"])
def test_engine_skips_probe_when_not_live(mode):
    kwargs = {"resolver": DictResolver({})} if mode == "simulated" else {}
    result = analysis_engine.analyze_email(EML, dns_mode=mode, **kwargs)
    assert result["dns_health"]["checked"] is False
