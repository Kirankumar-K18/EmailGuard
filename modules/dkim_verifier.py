"""DKIM signature verification (RFC 6376) using the maintained ``dkimpy`` library.

EmailGuard does **not** re-implement DKIM canonicalisation or hashing: it
extracts the DKIM-Signature header(s), fetches the public key from DNS
(``<selector>._domainkey.<domain>`` TXT) and delegates the cryptographic check
to ``dkimpy``. Signatures are RSASSA-PKCS1-v1_5 over a canonicalised
header/body hash - this is *not* RSA-PSS (used in the Digital Signature Lab).

Pasted messages: browsers normalise line endings and sometimes whitespace, so a
genuine signature can fail after copy/paste. Prefer uploading the original .eml.
"""
from __future__ import annotations

import base64
import binascii
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email import message_from_bytes, policy

import dkim as dkimpy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from modules.dns_utils import BaseResolver, DictResolver, DNSTemporaryError, LiveResolver
from modules.email_parser import to_crlf, unfold
from modules.utils import parse_tag_list

DKIM_LIMITATIONS = [
    "Verification is delegated to the 'dkimpy' library; EmailGuard adds DNS retrieval and explanations only.",
    "Only rsa-sha256 / rsa-sha1 signatures are verified (Ed25519 requires the optional PyNaCl package).",
    "Pasted text may differ from the original bytes (line endings, whitespace, folding), which can cause false failures. Upload the .eml for best accuracy.",
    "Key records are fetched from DNS as seen now; a rotated or removed key makes older signatures fail.",
    "The tool does not evaluate ARC chains or the legacy DomainKeys (DK) mechanism.",
]


@dataclass
class DKIMSignatureResult:
    index: int
    status: str  # PASS, FAIL, PERMERROR, TEMPERROR
    domain: str
    selector: str
    explanation: str
    algorithm: str = ""
    canonicalization: str = ""
    signed_headers: list[str] = field(default_factory=list)
    identity: str = ""
    timestamp: str = ""
    expiry: str = ""
    key_query: str = ""
    key_record: str = ""
    key_bits: int = 0
    key_flags: str = ""
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DKIMResult:
    status: str  # PASS, FAIL, NONE, PERMERROR, TEMPERROR
    explanation: str
    signatures: list[DKIMSignatureResult] = field(default_factory=list)
    data_source: str = "live DNS"
    limitations: list[str] = field(default_factory=lambda: list(DKIM_LIMITATIONS))

    def to_dict(self) -> dict:
        out = asdict(self)
        out["signatures"] = [s.to_dict() for s in self.signatures]
        return out

    def passing_signatures(self) -> list[dict]:
        return [{"status": s.status, "domain": s.domain} for s in self.signatures]


# ---------------------------------------------------------------------------
# Header extraction
# ---------------------------------------------------------------------------
def extract_dkim_headers(raw: bytes) -> list[str]:
    """Return the unfolded value of every DKIM-Signature header (top to bottom)."""
    msg = message_from_bytes(raw, policy=policy.compat32)
    return [unfold(str(v)) for k, v in msg.raw_items() if k.lower() == "dkim-signature"]


def parse_signature_tags(header_value: str) -> dict:
    """Parse the tag list of a DKIM-Signature header and compute helper fields."""
    tags = parse_tag_list(header_value)
    for k in ("b", "bh"):
        if k in tags:
            tags[k] = "".join(tags[k].split())
    return tags


def _fmt_ts(value: str) -> str:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OverflowError, OSError):
        return ""


def describe_key_record(record: str) -> dict:
    """Parse a DKIM public-key TXT record: bits, key type, flags, revoked state."""
    tags = parse_tag_list(record)
    info = {"version": tags.get("v", ""), "key_type": tags.get("k", "rsa"), "flags": tags.get("t", ""), "bits": 0, "revoked": False, "error": ""}
    p = "".join(tags.get("p", "").split())
    if not p:
        info["revoked"] = True
        return info
    try:
        key = serialization.load_der_public_key(base64.b64decode(p, validate=False))
        if isinstance(key, rsa.RSAPublicKey):
            info["bits"] = key.key_size
    except (ValueError, binascii.Error, TypeError) as exc:
        info["error"] = f"Public key could not be decoded: {exc}"
    return info


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


FAILURE_HINTS = (
    ("body hash mismatch", "The message BODY was changed after signing (the body hash bh= no longer matches). Typical causes: a mailing-list footer, an antivirus banner, forwarding software, deliberate tampering - or whitespace changes from copy/paste."),
    ("signature verification failed", "The signature does not match the signed headers. A signed header (From, Subject, Date...) was altered, or the signature was made with a different private key than the published public key."),
    ("signature has expired", "The signature carries an expiry time (x=) that has passed."),
    ("missing public key", "No public key is published at the selector's DNS name, so the signature cannot be checked."),
    ("key", "The public key published in DNS is malformed, revoked or too short to be accepted."),
    ("rsa-sha1", "The signature uses the deprecated rsa-sha1 algorithm."),
)


def _hint_for(reason: str, default: str) -> str:
    low = reason.lower()
    for needle, hint in FAILURE_HINTS:
        if needle in low:
            return hint
    return default


def _verify_one(raw: bytes, index: int, header_value: str, resolver: BaseResolver, min_key_bits: int) -> DKIMSignatureResult:
    tags = parse_signature_tags(header_value)
    domain, selector = tags.get("d", "").lower(), tags.get("s", "")
    result = DKIMSignatureResult(
        index=index,
        status="PERMERROR",
        domain=domain,
        selector=selector,
        explanation="",
        algorithm=tags.get("a", ""),
        canonicalization=tags.get("c", "simple/simple"),
        signed_headers=[h.strip() for h in tags.get("h", "").split(":") if h.strip()],
        identity=tags.get("i", ""),
        timestamp=_fmt_ts(tags.get("t", "")),
        expiry=_fmt_ts(tags.get("x", "")),
        key_query=f"{selector}._domainkey.{domain}" if domain and selector else "",
    )
    missing = [t for t in ("v", "a", "b", "bh", "d", "h", "s") if not tags.get(t)]
    if missing:
        result.explanation = f"The DKIM-Signature header is malformed: required tag(s) missing: {', '.join(missing)}."
        result.reason = "malformed signature header"
        return result

    captured: dict[str, str] = {}

    def dns_hook(name, timeout=5):  # signature required by dkimpy
        try:
            texts = resolver.txt(name.decode() if isinstance(name, bytes) else name)
        except DNSTemporaryError as exc:
            raise dkimpy.DnsTimeoutError(str(exc)) from exc
        if not texts:
            return None
        record = next((t for t in texts if "p=" in t.replace(" ", "")), texts[0])
        captured["record"] = record
        return record.encode("utf-8")

    handler = _ListHandler()
    logger = logging.getLogger(f"emailguard.dkim.{id(handler)}")
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    logger.addHandler(handler)

    status, reason = "FAIL", ""
    try:
        verifier = dkimpy.DKIM(raw, logger=logger, minkey=min_key_bits)
        ok = verifier.verify(idx=index, dnsfunc=dns_hook)
        if ok:
            status = "PASS"
        else:
            reason = "; ".join(handler.messages)
            if "DnsTimeoutError" in reason:
                status = "TEMPERROR"
            elif "record" not in captured:
                status, reason = "PERMERROR", "missing public key" + (f" ({reason})" if reason else "")
            elif not reason:
                status, reason = "FAIL", "signature verification failed"
            elif any(w in reason.lower() for w in ("keyformat", "unparsable", "key")) and "verification failed" not in reason.lower():
                status = "PERMERROR"
    except dkimpy.DnsTimeoutError as exc:
        status, reason = "TEMPERROR", str(exc)
    except dkimpy.ValidationError as exc:
        status, reason = "FAIL", str(exc)
    except (dkimpy.MessageFormatError, dkimpy.ParameterError, dkimpy.KeyFormatError, dkimpy.UnparsableKeyError) as exc:
        status, reason = "PERMERROR", str(exc)
    except dkimpy.DKIMException as exc:
        status, reason = "FAIL", str(exc)
    except Exception as exc:  # defensive: never crash the UI on odd input
        status, reason = "PERMERROR", f"{type(exc).__name__}: {exc}"
    finally:
        logger.removeHandler(handler)

    result.status = status
    result.reason = reason
    record = captured.get("record", "")
    if record:
        info = describe_key_record(record)
        result.key_record = record
        result.key_bits = info["bits"]
        result.key_flags = info["flags"]

    if status == "PASS":
        result.explanation = (
            f"Valid signature by {domain} (selector {selector}). The headers listed in h= and the message body are exactly as signed, "
            "and the signature was produced by the private key matching the public key published in DNS."
        )
    elif status == "TEMPERROR":
        result.explanation = f"The public key could not be retrieved because of a temporary DNS problem ({reason}). Try again or check connectivity."
    elif status == "PERMERROR":
        result.explanation = _hint_for(reason, f"The signature or key is invalid ({reason or 'unspecified error'}).")
    else:
        result.explanation = _hint_for(reason, f"Verification failed ({reason or 'no detail provided by the library'}).")
    return result


def verify_dkim(raw: bytes | str, resolver: BaseResolver | None = None, min_key_bits: int = 1024) -> DKIMResult:
    """Verify every DKIM-Signature in a complete message.

    Overall status: PASS if any signature passes; otherwise FAIL > PERMERROR >
    TEMPERROR in that order of severity; NONE when no signature is present.
    """
    data = to_crlf(raw.encode("utf-8") if isinstance(raw, str) else raw)
    resolver = resolver or LiveResolver()
    source = getattr(resolver, "source_label", "DNS")
    headers = extract_dkim_headers(data)
    if not headers:
        return DKIMResult(status="NONE", explanation="The message contains no DKIM-Signature header, so there is nothing to verify.", data_source=source)

    results = [_verify_one(data, i, h, resolver, min_key_bits) for i, h in enumerate(headers)]
    statuses = [r.status for r in results]
    if "PASS" in statuses:
        overall = "PASS"
        good = results[statuses.index("PASS")]
        explanation = f"At least one signature verified cryptographically: d={good.domain}, s={good.selector}."
    else:
        for candidate in ("FAIL", "PERMERROR", "TEMPERROR"):
            if candidate in statuses:
                overall = candidate
                break
        else:  # pragma: no cover
            overall = "PERMERROR"
        explanation = next(r.explanation for r in results if r.status == overall)
    return DKIMResult(status=overall, explanation=explanation, signatures=results, data_source=source)


# ---------------------------------------------------------------------------
# Educational demonstration helpers (local key + simulated DNS)
# ---------------------------------------------------------------------------
def make_key_record(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode("ascii")


def sign_for_demo(message: bytes, domain: str, selector: str, private_pem: bytes) -> bytes:
    """Return ``message`` with a genuine DKIM-Signature header prepended.

    Uses ``dkimpy`` with relaxed/relaxed canonicalisation. For demonstration
    only: the key lives in memory and the matching public key is published in a
    simulated DNS zone, not real DNS.
    """
    message = to_crlf(message)
    header = dkimpy.sign(
        message,
        selector.encode(),
        domain.encode(),
        private_pem,
        canonicalize=(b"relaxed", b"relaxed"),
        include_headers=[b"from", b"to", b"subject", b"date", b"message-id"],
    )
    return header + message


def demo_resolver(domain: str, selector: str, key_record: str) -> DictResolver:
    return DictResolver({f"{selector}._domainkey.{domain}": {"TXT": [key_record]}})
