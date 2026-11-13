"""Small shared helpers: tag-list parsing and domain utilities."""
from __future__ import annotations

import ipaddress
import re

# A deliberately small list of multi-label public suffixes. EmailGuard does not
# bundle the full Public Suffix List, so organisational-domain detection is an
# approximation (documented as a limitation).
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "co.in", "net.in", "org.in", "ac.in", "edu.in", "gov.in", "res.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.br", "com.mx", "com.ar", "com.cn", "com.hk", "com.sg", "com.my",
    "co.za", "co.kr", "com.tr", "com.pk", "com.bd", "com.ng",
}

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def parse_tag_list(value: str, lowercase_names: bool = True) -> dict[str, str]:
    """Parse ``tag=value; tag=value`` lists (used by DMARC and DKIM).

    The first occurrence of a tag wins. Whitespace around names and values is
    trimmed. Folding (CR/LF) is removed first.
    """
    tags: dict[str, str] = {}
    flat = (value or "").replace("\r", "").replace("\n", "")
    for part in flat.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, val = part.partition("=")
        name = name.strip()
        if lowercase_names:
            name = name.lower()
        if name and name not in tags:
            tags[name] = val.strip()
    return tags


def normalize_domain(value: str | None) -> str:
    """Lower-case a domain and strip whitespace, brackets and trailing dots."""
    if not value:
        return ""
    return value.strip().strip("<>").strip().strip(".").lower()


def to_ascii_domain(domain: str) -> str:
    """Return the IDNA (punycode) form of a domain, or the input if invalid."""
    domain = normalize_domain(domain)
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return domain


def is_valid_domain(domain: str) -> bool:
    """Check basic DNS name syntax (underscore labels such as _dmarc allowed)."""
    domain = to_ascii_domain(domain)
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    return all(_LABEL_RE.match(label) for label in domain.split("."))


def extract_domain(address: str | None) -> str:
    """Return the domain part of an e-mail address (empty string if none)."""
    if not address or "@" not in address:
        return ""
    return normalize_domain(address.rsplit("@", 1)[1])


def registered_domain(domain: str | None) -> str:
    """Approximate the organisational (registrable) domain."""
    domain = normalize_domain(domain)
    labels = domain.split(".") if domain else []
    if len(labels) <= 2:
        return domain
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def is_subdomain_of(child: str, parent: str) -> bool:
    child, parent = normalize_domain(child), normalize_domain(parent)
    return bool(child and parent) and child != parent and child.endswith("." + parent)


def is_ip(value: str | None) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def truncate(text: str, length: int = 80) -> str:
    text = text or ""
    return text if len(text) <= length else text[: length - 1] + "…"
