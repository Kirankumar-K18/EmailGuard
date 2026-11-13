"""SPF (Sender Policy Framework) evaluation using DNS TXT lookups.

This is a practical *subset* of RFC 7208, written so that its behaviour is
predictable and its limits are explicit (see ``SPF_LIMITATIONS``).

Supported:   all, include, a, mx, ip4, ip6, exists (no macros), redirect=,
             qualifiers (+ - ~ ?), CIDR lengths, the 10-lookup limit, the
             2-void-lookup limit, multiple-record detection.
Unsupported: macro expansion (``%{i}`` etc.), the ``ptr`` mechanism, ``exp=``
             explanation strings, HELO identity checks. If evaluation reaches
             one of these, the result is ``NOT EVALUATED`` - never a guess.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field

import config
from modules.dns_utils import BaseResolver, DNSTemporaryError, LiveResolver
from modules.utils import is_valid_domain, normalize_domain, to_ascii_domain

QUALIFIER_RESULT = {"+": "PASS", "-": "FAIL", "~": "SOFTFAIL", "?": "NEUTRAL"}

SPF_LIMITATIONS = [
    "SPF macros (e.g. %{i}, %{d}) are not expanded; records that need them yield NOT EVALUATED.",
    "The 'ptr' mechanism is not implemented (RFC 7208 discourages it); reaching it yields NOT EVALUATED.",
    "The 'exp=' explanation modifier is ignored and HELO/EHLO identity checks are not performed.",
    "Only the A/AAAA/MX/TXT queries needed for evaluation are made; DNS responses are not DNSSEC-validated.",
    "Results depend on the DNS data visible *now*; they may differ from what the receiving server saw when the message arrived.",
]


class SPFSyntaxError(ValueError):
    """The SPF record could not be parsed."""


class _SPFAbort(Exception):
    """Internal control flow: evaluation ends with a specific status."""

    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class SPFMechanism:
    qualifier: str
    name: str
    value: str = ""
    cidr4: int = 32
    cidr6: int = 128
    raw: str = ""

    @property
    def result_if_match(self) -> str:
        return QUALIFIER_RESULT[self.qualifier]

    def describe(self) -> str:
        verb = {
            "PASS": "authorises",
            "FAIL": "rejects",
            "SOFTFAIL": "soft-rejects (suspicious)",
            "NEUTRAL": "makes no statement about",
        }[self.result_if_match]
        target = {
            "all": "every other sender",
            "include": f"whatever the SPF record of {self.value} authorises",
            "a": f"the A/AAAA addresses of {self.value or 'the domain itself'}",
            "mx": f"the mail servers (MX) of {self.value or 'the domain itself'}",
            "ip4": f"IPv4 range {self.value}",
            "ip6": f"IPv6 range {self.value}",
            "exists": f"senders when {self.value} resolves to an A record",
            "ptr": "hosts found via reverse DNS (not supported by EmailGuard)",
        }[self.name]
        return f"{verb} {target}"


@dataclass
class SPFRecord:
    raw: str
    mechanisms: list[SPFMechanism] = field(default_factory=list)
    redirect: str = ""
    exp: str = ""
    unknown_modifiers: list[str] = field(default_factory=list)


def parse_spf_record(raw: str) -> SPFRecord:
    """Parse a ``v=spf1 ...`` record. Raises :class:`SPFSyntaxError` on bad syntax."""
    text = (raw or "").strip()
    if not re.match(r"^v=spf1(\s|$)", text, re.I):
        raise SPFSyntaxError("Record does not start with 'v=spf1'.")
    record = SPFRecord(raw=text)
    for term in text.split()[1:]:
        mod = re.match(r"^([A-Za-z][A-Za-z0-9_.-]*)=(.*)$", term)
        if mod:
            name, value = mod.group(1).lower(), mod.group(2)
            if name == "redirect":
                if record.redirect:
                    raise SPFSyntaxError("Duplicate redirect= modifier.")
                record.redirect = normalize_domain(value)
            elif name == "exp":
                record.exp = value
            else:
                record.unknown_modifiers.append(term)
            continue
        m = re.match(r"^([+\-~?])?([A-Za-z0-9]+)(.*)$", term)
        if not m:
            raise SPFSyntaxError(f"Cannot parse term '{term}'.")
        qualifier, name, rest = m.group(1) or "+", m.group(2).lower(), m.group(3)
        mech = SPFMechanism(qualifier=qualifier, name=name, raw=term)
        if name == "all":
            if rest:
                raise SPFSyntaxError(f"'all' takes no arguments: '{term}'.")
        elif name in ("ip4", "ip6"):
            if not rest.startswith(":") or len(rest) < 2:
                raise SPFSyntaxError(f"'{name}' needs a network: '{term}'.")
            value = rest[1:]
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise SPFSyntaxError(f"Invalid {name} network '{value}': {exc}") from exc
            if (name == "ip4" and net.version != 4) or (name == "ip6" and net.version != 6):
                raise SPFSyntaxError(f"'{value}' is not an {name.upper()} network.")
            mech.value = value
        elif name in ("a", "mx"):
            body = rest[1:] if rest.startswith(":") else rest
            m2 = re.match(r"^(?P<dom>[^/]*)(?:/(?P<c4>\d{1,2}))?(?://(?P<c6>\d{1,3}))?$", body)
            if not m2:
                raise SPFSyntaxError(f"Invalid '{name}' term '{term}'.")
            mech.value = normalize_domain(m2.group("dom"))
            mech.cidr4 = int(m2.group("c4")) if m2.group("c4") else 32
            mech.cidr6 = int(m2.group("c6")) if m2.group("c6") else 128
            if mech.cidr4 > 32 or mech.cidr6 > 128:
                raise SPFSyntaxError(f"CIDR length out of range in '{term}'.")
        elif name in ("include", "exists"):
            if not rest.startswith(":") or len(rest) < 2:
                raise SPFSyntaxError(f"'{name}' needs a domain: '{term}'.")
            mech.value = normalize_domain(rest[1:])
        elif name == "ptr":
            mech.value = normalize_domain(rest[1:]) if rest.startswith(":") else ""
        else:
            raise SPFSyntaxError(f"Unknown mechanism '{name}' in '{term}'.")
        record.mechanisms.append(mech)
    return record


@dataclass
class SPFResult:
    status: str
    domain: str
    ip: str
    explanation: str
    record: str = ""
    matched: str = ""
    lookups: int = 0
    trace: list[str] = field(default_factory=list)
    mechanisms: list[dict] = field(default_factory=list)
    data_source: str = "live DNS"
    limitations: list[str] = field(default_factory=lambda: list(SPF_LIMITATIONS))

    def to_dict(self) -> dict:
        return asdict(self)


class _Context:
    def __init__(self, ip: ipaddress._BaseAddress, resolver: BaseResolver) -> None:
        self.ip = ip
        self.resolver = resolver
        self.lookups = 0
        self.voids = 0
        self.trace: list[str] = []
        self.matched = ""

    def count_lookup(self, what: str) -> None:
        self.lookups += 1
        if self.lookups > config.SPF_MAX_DNS_LOOKUPS:
            raise _SPFAbort(
                "PERMERROR",
                f"The record needs more than {config.SPF_MAX_DNS_LOOKUPS} DNS lookups (RFC 7208 limit) while processing {what}.",
            )

    def count_void(self, what: str) -> None:
        self.voids += 1
        if self.voids > config.SPF_MAX_VOID_LOOKUPS:
            raise _SPFAbort(
                "PERMERROR",
                f"More than {config.SPF_MAX_VOID_LOOKUPS} DNS lookups returned no data (RFC 7208 void-lookup limit), last: {what}.",
            )


def _normalise_ip(ip: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _reject_macros(spec: str, mechanism: str) -> None:
    if "%" in spec:
        raise _SPFAbort(
            "NOT EVALUATED",
            f"The '{mechanism}' term uses SPF macros ('{spec}'), which EmailGuard does not expand.",
        )


def _fetch_spf(ctx: _Context, domain: str) -> SPFRecord | None:
    ctx.trace.append(f"TXT lookup: {domain}")
    try:
        texts = ctx.resolver.txt(domain)
    except DNSTemporaryError as exc:
        raise _SPFAbort("TEMPERROR", str(exc)) from exc
    candidates = [t for t in texts if re.match(r"^v=spf1(\s|$)", t.strip(), re.I)]
    if not candidates:
        ctx.trace.append(f"  no SPF record at {domain}")
        return None
    if len(candidates) > 1:
        raise _SPFAbort("PERMERROR", f"{domain} publishes {len(candidates)} SPF records; exactly one is allowed.")
    ctx.trace.append(f"  found: {candidates[0].strip()}")
    try:
        return parse_spf_record(candidates[0])
    except SPFSyntaxError as exc:
        raise _SPFAbort("PERMERROR", f"SPF record of {domain} has a syntax error: {exc}") from exc


def _addresses(ctx: _Context, host: str) -> list[str]:
    try:
        addrs = ctx.resolver.aaaa(host) if ctx.ip.version == 6 else ctx.resolver.a(host)
    except DNSTemporaryError as exc:
        raise _SPFAbort("TEMPERROR", str(exc)) from exc
    if not addrs:
        ctx.count_void(host)
    return addrs


def _in_network(ctx: _Context, address: str, cidr4: int, cidr6: int) -> bool:
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return False
    if addr.version != ctx.ip.version:
        return False
    prefix = cidr4 if addr.version == 4 else cidr6
    return ctx.ip in ipaddress.ip_network(f"{addr}/{prefix}", strict=False)


def _matches(ctx: _Context, mech: SPFMechanism, domain: str, depth: int) -> bool:
    name = mech.name
    if name == "all":
        return True
    if name in ("ip4", "ip6"):
        net = ipaddress.ip_network(mech.value, strict=False)
        return net.version == ctx.ip.version and ctx.ip in net
    if name == "include":
        _reject_macros(mech.value, "include")
        ctx.count_lookup(f"include:{mech.value}")
        ctx.trace.append(f"include -> evaluating {mech.value}")
        inner = _check_host(ctx, mech.value, depth + 1)
        if inner == "NONE":
            raise _SPFAbort("PERMERROR", f"include:{mech.value} points to a domain without an SPF record.")
        ctx.trace.append(f"include:{mech.value} returned {inner}")
        return inner == "PASS"
    if name in ("a", "mx"):
        target = mech.value or domain
        _reject_macros(target, name)
        ctx.count_lookup(f"{name}:{target}")
        if name == "a":
            return any(_in_network(ctx, a, mech.cidr4, mech.cidr6) for a in _addresses(ctx, target))
        try:
            hosts = ctx.resolver.mx(target)
        except DNSTemporaryError as exc:
            raise _SPFAbort("TEMPERROR", str(exc)) from exc
        if not hosts:
            ctx.count_void(target)
        if len(hosts) > 10:
            raise _SPFAbort("PERMERROR", f"{target} has more than 10 MX hosts (RFC 7208 limit).")
        return any(
            _in_network(ctx, a, mech.cidr4, mech.cidr6) for host in hosts for a in _addresses(ctx, host)
        )
    if name == "exists":
        _reject_macros(mech.value, "exists")
        ctx.count_lookup(f"exists:{mech.value}")
        try:
            found = ctx.resolver.a(mech.value)
        except DNSTemporaryError as exc:
            raise _SPFAbort("TEMPERROR", str(exc)) from exc
        if not found:
            ctx.count_void(mech.value)
        return bool(found)
    if name == "ptr":
        raise _SPFAbort("NOT EVALUATED", "The 'ptr' mechanism is not supported by EmailGuard.")
    raise _SPFAbort("PERMERROR", f"Unknown mechanism '{name}'.")  # pragma: no cover


def _check_host(ctx: _Context, domain: str, depth: int = 0) -> str:
    record = _fetch_spf(ctx, domain)
    if record is None:
        return "NONE"
    if depth == 0:
        ctx.top_record = record  # type: ignore[attr-defined]
    for mech in record.mechanisms:
        if _matches(ctx, mech, domain, depth):
            result = mech.result_if_match
            if depth == 0 or not ctx.matched:
                ctx.matched = f"{mech.raw or mech.name} (in {domain})"
            ctx.trace.append(f"MATCH {mech.raw} in {domain} -> {result}")
            return result
        ctx.trace.append(f"no match: {mech.raw}")
    if record.redirect:
        _reject_macros(record.redirect, "redirect")
        ctx.count_lookup(f"redirect={record.redirect}")
        ctx.trace.append(f"redirect -> {record.redirect}")
        inner = _check_host(ctx, record.redirect, depth + 1)
        if inner == "NONE":
            raise _SPFAbort("PERMERROR", f"redirect={record.redirect} points to a domain without an SPF record.")
        return inner
    ctx.trace.append("no mechanism matched and no redirect: default result NEUTRAL")
    return "NEUTRAL"


def _explain(status: str, domain: str, ip: str, matched: str, detail: str) -> str:
    return {
        "PASS": f"{ip} is authorised to send mail for {domain}; it matched '{matched}'.",
        "FAIL": f"{ip} is explicitly NOT authorised to send mail for {domain} (matched '{matched}'). The domain owner asks receivers to reject such mail.",
        "SOFTFAIL": f"{ip} is probably NOT authorised to send mail for {domain} (matched '{matched}'). The '~' qualifier means 'suspicious, but do not reject outright'.",
        "NEUTRAL": f"{domain}'s SPF record makes no statement about {ip} ('{matched or 'no mechanism matched'}'). SPF provides no assurance either way.",
        "NONE": f"{domain} does not publish an SPF record, so SPF cannot authenticate this sender.",
        "PERMERROR": f"The SPF record cannot be evaluated: {detail}",
        "TEMPERROR": f"A temporary DNS problem prevented evaluation: {detail}",
        "NOT EVALUATED": f"EmailGuard stopped without a verdict: {detail}",
    }[status]


def check_spf(domain: str, ip: str, resolver: BaseResolver | None = None) -> SPFResult:
    """Evaluate SPF for ``ip`` sending as ``domain``.

    Raises ``ValueError`` only for an unparsable IP address; every DNS or
    record problem is reported through the returned status.
    """
    try:
        client_ip = _normalise_ip(ipaddress.ip_address((ip or "").strip()))
    except ValueError as exc:
        raise ValueError(f"'{ip}' is not a valid IPv4 or IPv6 address.") from exc
    domain = to_ascii_domain(domain)
    resolver = resolver or LiveResolver()
    source = getattr(resolver, "source_label", "DNS")

    if not is_valid_domain(domain):
        return SPFResult(
            status="NONE", domain=domain, ip=str(client_ip), data_source=source,
            explanation=f"'{domain}' is not a valid domain name, so no SPF record can exist.",
        )

    ctx = _Context(client_ip, resolver)
    ctx.top_record = None  # type: ignore[attr-defined]
    detail = ""
    try:
        status = _check_host(ctx, domain)
    except _SPFAbort as abort:
        status, detail = abort.status, abort.message
        ctx.trace.append(f"ABORT {status}: {detail}")

    top: SPFRecord | None = ctx.top_record  # type: ignore[attr-defined]
    return SPFResult(
        status=status,
        domain=domain,
        ip=str(client_ip),
        explanation=_explain(status, domain, str(client_ip), ctx.matched, detail),
        record=top.raw if top else "",
        matched=ctx.matched,
        lookups=ctx.lookups,
        trace=ctx.trace,
        mechanisms=[
            {"qualifier": m.qualifier, "mechanism": m.name, "value": m.value or "-", "meaning": m.describe()}
            for m in (top.mechanisms if top else [])
        ] + ([{"qualifier": "", "mechanism": "redirect", "value": top.redirect, "meaning": f"continue evaluation at {top.redirect}"}] if top and top.redirect else []),
        data_source=source,
    )
