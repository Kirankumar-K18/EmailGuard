"""DMARC record lookup, parsing and (conditional) alignment evaluation.

A DNS record alone cannot produce a DMARC *result*. DMARC passes only if at
least one of SPF or DKIM both (1) passed and (2) is *aligned* with the visible
From domain. :func:`lookup_dmarc` therefore only explains the published
policy, while :func:`evaluate_dmarc` needs real SPF/DKIM outcomes and returns
``NOT EVALUATED`` when they are unavailable.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from modules.dns_utils import BaseResolver, DNSTemporaryError
from modules.utils import is_subdomain_of, normalize_domain, parse_tag_list, registered_domain, to_ascii_domain

VALID_POLICIES = ("none", "quarantine", "reject")

POLICY_MEANING = {
    "none": "Monitoring only: receivers should not act on failures, but the domain owner receives reports.",
    "quarantine": "Messages that fail DMARC should be treated as suspicious (typically delivered to spam/junk).",
    "reject": "Messages that fail DMARC should be rejected during SMTP delivery. This is the strongest setting.",
}

TAG_DESCRIPTIONS = {
    "v": "Protocol version (must be DMARC1)",
    "p": "Policy for the organisational domain",
    "sp": "Policy for subdomains (defaults to p)",
    "rua": "Aggregate report destination(s)",
    "ruf": "Forensic (failure) report destination(s)",
    "pct": "Percentage of failing mail the policy applies to",
    "adkim": "DKIM alignment mode (r = relaxed, s = strict)",
    "aspf": "SPF alignment mode (r = relaxed, s = strict)",
    "fo": "Failure-reporting options",
    "ri": "Aggregate report interval in seconds",
    "rf": "Failure report format",
}


@dataclass
class DMARCLookup:
    domain: str
    status: str  # FOUND, NONE, TEMPERROR, INVALID
    record_domain: str = ""
    raw: str = ""
    tags: dict = field(default_factory=dict)
    policy: str = ""
    subdomain_policy: str = ""
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
    used_org_fallback: bool = False
    data_source: str = "live DNS"
    queried: list[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return self.status == "FOUND"

    def to_dict(self) -> dict:
        return asdict(self)


def parse_dmarc_record(raw: str) -> dict:
    """Parse and validate a DMARC TXT record. Never raises."""
    tags = parse_tag_list(raw)
    errors: list[str] = []
    warnings: list[str] = []
    first_tag = next(iter(tags), "")
    if first_tag != "v" or tags.get("v", "").upper() != "DMARC1":
        errors.append("The record must begin with 'v=DMARC1'.")
    policy = tags.get("p", "").lower()
    if not policy:
        errors.append("Required tag 'p' (policy) is missing.")
    elif policy not in VALID_POLICIES:
        errors.append(f"Invalid policy p={policy!r}; expected none, quarantine or reject.")
    sub = tags.get("sp", "").lower()
    if sub and sub not in VALID_POLICIES:
        errors.append(f"Invalid subdomain policy sp={sub!r}.")
    pct = 100
    if "pct" in tags:
        try:
            pct = int(tags["pct"])
            if not 0 <= pct <= 100:
                raise ValueError
        except ValueError:
            errors.append(f"pct={tags['pct']!r} must be an integer from 0 to 100.")
            pct = 100
    adkim = tags.get("adkim", "r").lower()
    aspf = tags.get("aspf", "r").lower()
    for name, val in (("adkim", adkim), ("aspf", aspf)):
        if val not in ("r", "s"):
            errors.append(f"{name}={val!r} must be 'r' (relaxed) or 's' (strict).")
    rua = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    ruf = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]
    for uri in rua + ruf:
        if not re.match(r"^(mailto:|https?://)", uri, re.I):
            warnings.append(f"Report URI {uri!r} is not a mailto: or https: URI.")
    if policy == "none":
        warnings.append("p=none gives no protection against spoofing; consider moving to quarantine or reject once reports look clean.")
    if pct < 100 and policy in ("quarantine", "reject"):
        warnings.append(f"pct={pct}: the policy is enforced on only {pct}% of failing messages.")
    if not rua:
        warnings.append("No 'rua' tag: the domain owner does not receive aggregate reports.")
    return {
        "tags": tags,
        "policy": policy if policy in VALID_POLICIES else "",
        "subdomain_policy": sub if sub in VALID_POLICIES else "",
        "pct": pct,
        "adkim": adkim if adkim in ("r", "s") else "r",
        "aspf": aspf if aspf in ("r", "s") else "r",
        "rua": rua,
        "ruf": ruf,
        "errors": errors,
        "warnings": warnings,
    }


def lookup_dmarc(domain: str, resolver: BaseResolver) -> DMARCLookup:
    """Fetch the ``_dmarc`` TXT record for ``domain`` (falling back to the
    organisational domain, as RFC 7489 requires) and parse it."""
    domain = to_ascii_domain(domain)
    source = getattr(resolver, "source_label", "DNS")
    result = DMARCLookup(domain=domain, status="NONE", data_source=source)
    if not domain or "." not in domain:
        result.explanation.append("A valid domain name is required.")
        return result

    candidates = [domain]
    org = registered_domain(domain)
    if org and org != domain:
        candidates.append(org)

    for candidate in candidates:
        name = f"_dmarc.{candidate}"
        result.queried.append(name)
        try:
            texts = resolver.txt(name)
        except DNSTemporaryError as exc:
            result.status = "TEMPERROR"
            result.errors.append(str(exc))
            result.explanation.append("A DNS problem prevented the lookup, so the policy is unknown.")
            return result
        records = [t for t in texts if re.match(r"^\s*v\s*=\s*DMARC1\s*(;|$)", t, re.I)]
        if len(records) > 1:
            result.status = "INVALID"
            result.record_domain = candidate
            result.errors.append(f"{name} publishes {len(records)} DMARC records; receivers must ignore all of them.")
            return result
        if records:
            parsed = parse_dmarc_record(records[0])
            result.record_domain = candidate
            result.used_org_fallback = candidate != domain
            result.raw = records[0].strip()
            result.tags = parsed["tags"]
            result.policy = parsed["policy"]
            result.subdomain_policy = parsed["subdomain_policy"]
            result.pct = parsed["pct"]
            result.adkim = parsed["adkim"]
            result.aspf = parsed["aspf"]
            result.rua = parsed["rua"]
            result.ruf = parsed["ruf"]
            result.errors = parsed["errors"]
            result.warnings = parsed["warnings"]
            result.status = "INVALID" if parsed["errors"] and not parsed["policy"] else "FOUND"
            result.explanation = _explain_policy(result)
            return result

    result.explanation = [
        f"No DMARC record was found at {' or '.join(result.queried)}.",
        "Without a DMARC policy, receivers apply their own rules and the domain owner gets no failure reports.",
    ]
    return result


def _explain_policy(rec: DMARCLookup) -> list[str]:
    lines = []
    if rec.used_org_fallback:
        lines.append(
            f"No record exists at _dmarc.{rec.domain}; the organisational domain's policy ({rec.record_domain}) applies."
        )
    if rec.policy:
        lines.append(f"Policy p={rec.policy}: {POLICY_MEANING[rec.policy]}")
    if rec.subdomain_policy:
        lines.append(f"Subdomain policy sp={rec.subdomain_policy}: {POLICY_MEANING[rec.subdomain_policy]}")
    elif rec.policy:
        lines.append("No 'sp' tag, so subdomains inherit the main policy.")
    lines.append(
        f"Alignment: DKIM is {'strict (exact domain match)' if rec.adkim == 's' else 'relaxed (same organisational domain)'}; "
        f"SPF is {'strict' if rec.aspf == 's' else 'relaxed'}."
    )
    if rec.pct < 100:
        lines.append(f"Only {rec.pct}% of failing messages are subject to the policy (pct={rec.pct}).")
    lines.append(
        "A DMARC *result* is not derivable from this record alone: it also needs the SPF and DKIM outcomes of a specific message "
        "and whether their domains align with the From domain."
    )
    return lines


def domains_aligned(authenticated_domain: str, from_domain: str, mode: str = "r") -> bool:
    """DMARC identifier alignment: strict = exact match, relaxed = same organisational domain."""
    a, b = normalize_domain(authenticated_domain), normalize_domain(from_domain)
    if not a or not b:
        return False
    if mode == "s":
        return a == b
    return registered_domain(a) == registered_domain(b)


_EVALUATED = {"PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "PERMERROR"}


def evaluate_dmarc(
    from_domain: str,
    lookup: DMARCLookup | None,
    spf_status: str,
    spf_domain: str,
    dkim_status: str,
    dkim_signatures: list[dict] | None = None,
) -> dict:
    """Evaluate DMARC given *real* SPF and DKIM outcomes.

    ``dkim_signatures`` is a list of ``{"status": ..., "domain": ...}``.
    Returns ``status`` of PASS, FAIL, NONE (no policy published) or NOT EVALUATED.
    """
    from_domain = normalize_domain(from_domain)
    out = {
        "status": "NOT EVALUATED",
        "spf_aligned": None,
        "dkim_aligned": None,
        "applied_policy": "",
        "policy_action": "",
        "explanation": "",
    }
    if lookup is None or lookup.status == "TEMPERROR":
        out["explanation"] = "The DMARC policy could not be retrieved, so alignment cannot be evaluated."
        return out
    if lookup.status == "INVALID":
        out["explanation"] = "The domain's DMARC record is invalid; receivers ignore it, so no DMARC result exists."
        return out
    if lookup.status == "NONE":
        out["status"] = "NONE"
        out["explanation"] = "No DMARC policy is published for the From domain, so DMARC cannot pass or fail."
        return out

    adkim, aspf = lookup.adkim, lookup.aspf
    spf_ok = spf_status == "PASS"
    out["spf_aligned"] = spf_ok and domains_aligned(spf_domain, from_domain, aspf) if spf_status in _EVALUATED else None
    dkim_pass = [s for s in (dkim_signatures or []) if s.get("status") == "PASS"]
    if dkim_status in _EVALUATED:
        out["dkim_aligned"] = any(domains_aligned(s.get("domain", ""), from_domain, adkim) for s in dkim_pass)

    if out["spf_aligned"] or out["dkim_aligned"]:
        which = " and ".join(n for n, ok in (("SPF", out["spf_aligned"]), ("DKIM", out["dkim_aligned"])) if ok)
        out["status"] = "PASS"
        out["explanation"] = f"DMARC passes: {which} passed and is aligned with the From domain ({from_domain}). One aligned mechanism is enough."
        return out

    if out["spf_aligned"] is None or out["dkim_aligned"] is None:
        missing = [n for n, v in (("SPF", out["spf_aligned"]), ("DKIM", out["dkim_aligned"])) if v is None]
        out["explanation"] = (
            f"DMARC cannot be concluded: {' and '.join(missing)} was not evaluated, and the evaluated mechanism did not produce an aligned pass. "
            "This is NOT a failure - it means information is missing."
        )
        return out

    policy = lookup.policy
    if lookup.record_domain and is_subdomain_of(from_domain, lookup.record_domain) and lookup.subdomain_policy:
        policy = lookup.subdomain_policy
    out["status"] = "FAIL"
    out["applied_policy"] = policy
    out["policy_action"] = POLICY_MEANING.get(policy, "")
    reasons = []
    reasons.append("SPF did not pass" if spf_status != "PASS" else f"SPF passed for {spf_domain} but that domain is not aligned with {from_domain}")
    reasons.append("no valid DKIM signature" if not dkim_pass else f"DKIM passed for {', '.join(s.get('domain', '?') for s in dkim_pass)} but not aligned with {from_domain}")
    out["explanation"] = (
        f"DMARC fails: {'; '.join(reasons)}. The published policy is p={policy}: {POLICY_MEANING.get(policy, '')}"
        + (f" (applies to {lookup.pct}% of failing mail)" if lookup.pct < 100 else "")
    )
    return out
