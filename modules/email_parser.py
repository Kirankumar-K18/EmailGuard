"""Raw e-mail / header parsing built on Python's :mod:`email` library.

The parser is deliberately lenient: real-world messages are messy, so missing
headers and odd encodings are reported as warnings instead of exceptions. The
only hard failure is input that does not look like an e-mail at all.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import message_from_bytes, policy
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

import config
from modules.utils import extract_domain, normalize_domain, parse_tag_list


class EmailParseError(ValueError):
    """Raised when the input cannot be interpreted as an e-mail message."""


_HEADER_LINE_RE = re.compile(rb"^[A-Za-z][A-Za-z0-9-]*:[ \t]?", re.M)
_URL_RE = re.compile(r"https?://[^\s<>\"'\]\[)}{]+", re.I)
_IPV4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
_IPV6_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:]{3,})\]")

REQUIRED_HEADERS = ("from", "to", "date", "message-id", "subject")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def unfold(value: str) -> str:
    """Remove RFC 5322 header folding."""
    return re.sub(r"\r?\n[ \t]+", " ", value or "").strip()


def decode_mime_words(value: str) -> str:
    """Decode RFC 2047 encoded words ("=?utf-8?B?...?=")."""
    value = unfold(value)
    try:
        return str(make_header(decode_header(value)))
    except Exception:  # malformed encoded-word: fall back to the raw text
        return value


def to_crlf(data: bytes) -> bytes:
    """Normalise bare LF line endings to CRLF (needed for DKIM verification)."""
    return re.sub(rb"(?<!\r)\n", b"\r\n", data)


def _to_bytes(raw: str | bytes) -> bytes:
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="surrogateescape" if "\udc80" <= max(raw or " ") <= "\udcff" else "strict")
    return bytes(raw)


class _AnchorParser(HTMLParser):
    """Collects <a href> targets together with their visible text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.links.append({"url": self._href.strip(), "text": " ".join("".join(self._text).split())})
            self._href = None


def extract_urls(text: str = "", html: str = "") -> list[dict]:
    """Return unique URLs as ``{"url", "text", "source"}`` dictionaries.

    ``text`` is the anchor text for HTML links (used to detect link/label
    mismatches); ``source`` is ``"text"`` or ``"html"``.
    """
    seen: dict[str, dict] = {}
    if html:
        parser = _AnchorParser()
        try:
            parser.feed(html)
            parser.close()
        except Exception:
            pass
        for link in parser.links:
            if link["url"].lower().startswith(("http://", "https://")):
                seen.setdefault(link["url"], {"url": link["url"], "text": link["text"], "source": "html"})
        for m in _URL_RE.finditer(html):
            url = m.group(0).rstrip(".,;:!?")
            seen.setdefault(url, {"url": url, "text": "", "source": "html"})
    for m in _URL_RE.finditer(text or ""):
        url = m.group(0).rstrip(".,;:!?")
        seen.setdefault(url, {"url": url, "text": "", "source": "text"})
    return list(seen.values())


def parse_authentication_results(values: list[str]) -> dict:
    """Parse ``Authentication-Results`` headers (RFC 8601) into method results.

    These values are *claims made by whichever server added the header*.
    EmailGuard reports them but never treats them as verified.
    """
    parsed: list[dict] = []
    for value in values:
        flat = re.sub(r"\s+", " ", unfold(value))
        parts = [p.strip() for p in flat.split(";") if p.strip()]
        if not parts:
            continue
        authserv = parts[0].split()[0] if "=" not in parts[0].split()[0] else ""
        for segment in parts[1:] if authserv else parts:
            m = re.match(r"^([A-Za-z0-9-]+)\s*=\s*([A-Za-z]+)", segment)
            if not m:
                continue
            props = dict(re.findall(r"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\s*=\s*([^\s;()]+)", segment))
            parsed.append(
                {
                    "method": m.group(1).lower(),
                    "result": m.group(2).lower(),
                    "properties": props,
                    "authserv_id": authserv,
                }
            )
    return {"results": parsed}


def summarize_header_claims(auth_results: list[str], received_spf: list[str]) -> dict:
    """Condense header-claimed results into ``{"spf": "pass", "dkim": ..., "dmarc": ...}``."""
    claims: dict[str, str] = {}
    for item in parse_authentication_results(auth_results)["results"]:
        if item["method"] in ("spf", "dkim", "dmarc") and item["method"] not in claims:
            claims[item["method"]] = item["result"]
    if "spf" not in claims:
        for value in received_spf:
            m = re.match(r"^\s*([A-Za-z]+)", unfold(value))
            if m:
                claims["spf"] = m.group(1).lower()
                break
    return claims


def extract_received_ips(received: list[str]) -> list[dict]:
    """Extract IP addresses mentioned in Received headers (topmost hop first)."""
    found: list[dict] = []
    seen: set[str] = set()
    for hop, header in enumerate(received):
        flat = unfold(header)
        candidates = _IPV4_RE.findall(flat) + _IPV6_RE.findall(flat)
        for cand in candidates:
            try:
                ip = ipaddress.ip_address(cand)
            except ValueError:
                continue
            if cand in seen:
                continue
            seen.add(cand)
            found.append(
                {
                    "hop": hop,
                    "ip": cand,
                    "is_private": bool(ip.is_private or ip.is_loopback or ip.is_link_local),
                }
            )
    return found


def parse_received_time(header: str) -> datetime | None:
    """Return the timestamp at the end of a Received header, if parseable."""
    if ";" not in header:
        return None
    try:
        dt = parsedate_to_datetime(unfold(header).rsplit(";", 1)[1].strip())
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------
@dataclass
class ParsedEmail:
    raw: bytes
    headers: list[tuple[str, str]] = field(default_factory=list)
    has_body: bool = False
    from_display: str = ""
    from_addr: str = ""
    from_domain: str = ""
    from_count: int = 0
    to: str = ""
    reply_to: str = ""
    reply_to_addr: str = ""
    reply_to_domain: str = ""
    return_path: str = ""
    return_path_addr: str = ""
    return_path_domain: str = ""
    subject: str = ""
    date_raw: str = ""
    date_parsed: datetime | None = None
    message_id: str = ""
    message_id_domain: str = ""
    received: list[str] = field(default_factory=list)
    authentication_results: list[str] = field(default_factory=list)
    received_spf: list[str] = field(default_factory=list)
    dkim_signatures: list[str] = field(default_factory=list)
    header_claims: dict = field(default_factory=dict)
    received_ips: list[dict] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    urls: list[dict] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)
    missing_headers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    def dkim_summary(self) -> list[dict]:
        out = []
        for sig in self.dkim_signatures:
            tags = parse_tag_list(sig)
            out.append({"d": tags.get("d", ""), "s": tags.get("s", ""), "a": tags.get("a", ""), "c": tags.get("c", "")})
        return out

    def to_dict(self) -> dict:
        """JSON-serialisable summary (raw bytes and full body are not included)."""
        return {
            "from": f"{self.from_display} <{self.from_addr}>" if self.from_display else self.from_addr,
            "from_display": self.from_display,
            "from_addr": self.from_addr,
            "from_domain": self.from_domain,
            "to": self.to,
            "reply_to": self.reply_to,
            "reply_to_domain": self.reply_to_domain,
            "return_path": self.return_path,
            "return_path_domain": self.return_path_domain,
            "subject": self.subject,
            "date": self.date_raw,
            "message_id": self.message_id,
            "received": self.received,
            "authentication_results": self.authentication_results,
            "received_spf": self.received_spf,
            "dkim_signature": self.dkim_signatures,
            "dkim_summary": self.dkim_summary(),
            "header_claims": self.header_claims,
            "received_ips": self.received_ips,
            "urls": self.urls,
            "attachments": self.attachments,
            "missing_headers": self.missing_headers,
            "warnings": self.warnings,
            "has_body": self.has_body,
            "body_preview": (self.body_text or self.body_html)[:600],
            "header_count": len(self.headers),
        }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def _decode_payload(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def parse_email(raw: str | bytes) -> ParsedEmail:
    """Parse raw headers or a complete RFC 5322 message.

    Raises :class:`EmailParseError` for empty, oversized or non-email input.
    """
    if raw is None:
        raise EmailParseError("No input was provided.")
    data = _to_bytes(raw).lstrip(b"\r\n \t")
    if not data.strip():
        raise EmailParseError("The input is empty. Paste e-mail headers or upload an .eml file.")
    if len(data) > config.MAX_EMAIL_BYTES:
        raise EmailParseError(f"The input exceeds the {config.MAX_EMAIL_BYTES // (1024 * 1024)} MB limit.")
    if b"\x00" in data[:2048]:
        raise EmailParseError("The input looks like a binary file, not an e-mail. Upload a text-based .eml file.")
    if not _HEADER_LINE_RE.search(data[:65536]):
        raise EmailParseError("No RFC 5322 header lines ('Name: value') were found, so this does not look like an e-mail.")

    msg = message_from_bytes(data, policy=policy.compat32)
    result = ParsedEmail(raw=data)

    for name, value in msg.raw_items():
        result.headers.append((name, str(value)))
    if not result.headers:
        raise EmailParseError("No headers could be parsed from the input.")

    # --- identity headers -------------------------------------------------
    from_values = result.get_all("from")
    result.from_count = len(from_values)
    if from_values:
        display, addr = parseaddr(decode_mime_words(from_values[0]))
        result.from_display, result.from_addr = display.strip(), addr.strip().lower()
        result.from_domain = extract_domain(result.from_addr)
    to_values = result.get_all("to")
    result.to = decode_mime_words(", ".join(to_values)) if to_values else ""

    reply = result.get_all("reply-to")
    if reply:
        result.reply_to = decode_mime_words(reply[0])
        result.reply_to_addr = parseaddr(result.reply_to)[1].lower()
        result.reply_to_domain = extract_domain(result.reply_to_addr)

    rpath = result.get_all("return-path")
    if rpath:
        result.return_path = unfold(rpath[0])
        result.return_path_addr = parseaddr(result.return_path)[1].lower() or result.return_path.strip("<> ").lower()
        result.return_path_domain = extract_domain(result.return_path_addr)

    subject = result.get_all("subject")
    result.subject = decode_mime_words(subject[0]) if subject else ""

    date = result.get_all("date")
    if date:
        result.date_raw = unfold(date[0])
        try:
            parsed_date = parsedate_to_datetime(result.date_raw)
            result.date_parsed = parsed_date if parsed_date.tzinfo else parsed_date.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            result.warnings.append("The Date header could not be parsed.")

    mid = result.get_all("message-id")
    if mid:
        result.message_id = unfold(mid[0])
        result.message_id_domain = extract_domain(result.message_id.strip("<> "))

    result.received = [unfold(v) for v in result.get_all("received")]
    result.authentication_results = [unfold(v) for v in result.get_all("authentication-results")]
    result.received_spf = [unfold(v) for v in result.get_all("received-spf")]
    result.dkim_signatures = [unfold(v) for v in result.get_all("dkim-signature")]
    result.header_claims = summarize_header_claims(result.authentication_results, result.received_spf)
    result.received_ips = extract_received_ips(result.received)

    result.missing_headers = [h for h in REQUIRED_HEADERS if not result.get_all(h)]
    if result.missing_headers:
        result.warnings.append("Missing headers: " + ", ".join(h.title() for h in result.missing_headers))
    if not result.authentication_results and not result.received_spf:
        result.warnings.append("No Authentication-Results or Received-SPF header is present.")

    # --- body and attachments ---------------------------------------------
    text_parts: list[str] = []
    html_parts: list[str] = []
    try:
        for part in msg.walk():
            if part.is_multipart():
                continue
            filename = part.get_filename()
            disposition = (part.get("Content-Disposition") or "").lower()
            ctype = part.get_content_type()
            if filename or disposition.startswith("attachment"):
                name = decode_mime_words(filename) if filename else "(unnamed)"
                payload = part.get_payload(decode=True) or b""
                result.attachments.append(
                    {
                        "filename": name,
                        "content_type": ctype,
                        "size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
            elif ctype == "text/plain":
                text_parts.append(_decode_payload(part))
            elif ctype == "text/html":
                html_parts.append(_decode_payload(part))
    except Exception as exc:  # pragma: no cover - defensive; malformed MIME
        result.warnings.append(f"The MIME structure could not be fully parsed: {exc}")

    result.body_text = "\n".join(text_parts).strip()
    result.body_html = "\n".join(html_parts).strip()
    result.has_body = bool(result.body_text or result.body_html or result.attachments)
    result.urls = extract_urls(result.body_text, result.body_html)

    if not result.from_addr:
        result.warnings.append("No usable From address was found.")
    return result


def build_domain_summary(parsed: ParsedEmail) -> dict:
    """Return the sender-related domains side by side (used by reports)."""
    return {
        "from": normalize_domain(parsed.from_domain),
        "reply_to": normalize_domain(parsed.reply_to_domain),
        "return_path": normalize_domain(parsed.return_path_domain),
        "message_id": normalize_domain(parsed.message_id_domain),
    }
