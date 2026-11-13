"""DNS access layer.

Every module that needs DNS (SPF, DKIM, DMARC) talks to a *resolver object*
with four methods: ``txt``, ``a``, ``aaaa`` and ``mx``. Two implementations are
provided:

* :class:`LiveResolver`  - real queries through dnspython (needs Internet).
* :class:`DictResolver`  - answers from an in-memory zone. Used by the demo
  scenarios and the unit tests so everything works offline.

Conventions: a name that does not exist (NXDOMAIN) or has no data of the
requested type returns an empty list; a *temporary* problem (timeout, SERVFAIL,
no resolver configured) raises :class:`DNSTemporaryError`.
"""
from __future__ import annotations

from typing import Iterable

import config
from modules.utils import to_ascii_domain


class DNSTemporaryError(Exception):
    """A DNS lookup could not be completed (timeout, SERVFAIL, no network)."""


class BaseResolver:
    """Interface plus a query log (useful for the UI's evaluation trace)."""

    source_label = "unknown"

    def __init__(self) -> None:
        self.query_log: list[str] = []

    def _record(self, rtype: str, name: str) -> None:
        self.query_log.append(f"{rtype} {name}")

    def txt(self, name: str) -> list[str]:  # pragma: no cover - interface
        raise NotImplementedError

    def a(self, name: str) -> list[str]:  # pragma: no cover - interface
        raise NotImplementedError

    def aaaa(self, name: str) -> list[str]:  # pragma: no cover - interface
        raise NotImplementedError

    def mx(self, name: str) -> list[str]:  # pragma: no cover - interface
        raise NotImplementedError


class LiveResolver(BaseResolver):
    """Real DNS resolver backed by dnspython."""

    source_label = "live DNS"

    def __init__(self, timeout: float | None = None, nameservers: Iterable[str] | None = None, port: int | None = None) -> None:
        super().__init__()
        import dns.resolver

        self.timeout = float(timeout or config.DNS_TIMEOUT_SECONDS)
        try:
            self._resolver = dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration:
            # Fall back to well-known public resolvers if the OS has none configured.
            self._resolver = dns.resolver.Resolver(configure=False)
            self._resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        if port:  # non-standard port: used by the unit tests' loopback DNS server
            self._resolver.port = int(port)
        self._resolver.lifetime = self.timeout
        self._resolver.timeout = min(self.timeout, 3.0)

    def _query(self, name: str, rtype: str):
        import dns.exception
        import dns.resolver

        qname = to_ascii_domain(name)
        self._record(rtype, qname)
        try:
            answer = self._resolver.resolve(qname, rtype, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.Timeout as exc:
            raise DNSTemporaryError(f"DNS timeout while querying {rtype} {qname}") from exc
        except dns.resolver.NoNameservers as exc:
            raise DNSTemporaryError(f"No DNS server could answer {rtype} {qname} (SERVFAIL or no network)") from exc
        except dns.resolver.NoResolverConfiguration as exc:
            raise DNSTemporaryError("No DNS resolver is configured on this machine") from exc
        except dns.exception.SyntaxError:
            return []  # invalid name syntax: treat as "no such name"
        except dns.exception.DNSException as exc:
            raise DNSTemporaryError(f"DNS error while querying {rtype} {qname}: {exc}") from exc
        except OSError as exc:  # network unreachable, etc.
            raise DNSTemporaryError(f"Network error while querying {rtype} {qname}: {exc}") from exc
        return list(answer) if answer.rrset is not None else []

    def txt(self, name: str) -> list[str]:
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self._query(name, "TXT")]

    def a(self, name: str) -> list[str]:
        return [r.address for r in self._query(name, "A")]

    def aaaa(self, name: str) -> list[str]:
        return [r.address for r in self._query(name, "AAAA")]

    def mx(self, name: str) -> list[str]:
        records = sorted(self._query(name, "MX"), key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".").lower() for r in records]


class DictResolver(BaseResolver):
    """Offline resolver answering from a dictionary.

    ``zone`` maps a domain name to ``{"TXT": [...], "A": [...], "AAAA": [...],
    "MX": [...]}``. A zone entry may contain ``"__timeout__": True`` to
    simulate a DNS timeout for that name.
    """

    source_label = "simulated DNS (demonstration zone)"

    def __init__(self, zone: dict[str, dict] | None = None) -> None:
        super().__init__()
        self.zone = {k.lower().rstrip("."): v for k, v in (zone or {}).items()}

    def _lookup(self, name: str, rtype: str) -> list[str]:
        key = name.lower().rstrip(".")
        self._record(rtype, key)
        entry = self.zone.get(key)
        if entry is None:
            return []
        if entry.get("__timeout__"):
            raise DNSTemporaryError(f"Simulated DNS timeout while querying {rtype} {key}")
        return list(entry.get(rtype, []))

    def txt(self, name: str) -> list[str]:
        return self._lookup(name, "TXT")

    def a(self, name: str) -> list[str]:
        return self._lookup(name, "A")

    def aaaa(self, name: str) -> list[str]:
        return self._lookup(name, "AAAA")

    def mx(self, name: str) -> list[str]:
        return [str(x).lower().rstrip(".") for x in self._lookup(name, "MX")]


# Names that certainly exist on the public Internet. If a resolver cannot resolve
# any of them, "no record found" answers for other domains cannot be trusted.
CANARY_NAMES = ("google.com", "cloudflare.com", "microsoft.com")


def check_dns_health(resolver: BaseResolver) -> tuple[bool, str]:
    """Return ``(healthy, message)``.

    ``healthy`` is False when lookups fail outright, or when the resolver claims
    that every well-known domain does not exist (typical for offline machines,
    captive portals and filtering resolvers). Simulated resolvers are always
    considered healthy because their answers are intentional.
    """
    if isinstance(resolver, DictResolver):
        return True, "Simulated DNS zone (no network involved)."
    for name in CANARY_NAMES:
        try:
            if resolver.a(name):
                return True, f"DNS is working: {name} resolved normally."
        except DNSTemporaryError as exc:
            return False, f"DNS lookups are failing ({exc}). Check your Internet connection or DNS settings."
    return False, (
        "This computer's DNS resolver reported that well-known domains such as google.com do not exist. "
        "It is probably offline, blocked or filtered, so 'no record found' results may be wrong."
    )
