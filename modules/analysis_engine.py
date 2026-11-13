"""Orchestrates parsing, SPF, DKIM, DMARC and spoofing analysis.

The engine produces one JSON-serialisable *result dictionary* that is stored in
SQLite, rendered by the UI and turned into a PDF. Every authentication entry
carries a ``method`` so the origin of each statement is always explicit:

* ``CRYPTOGRAPHIC``  - a signature was really verified (DKIM via dkimpy).
* ``DNS``            - a DNS record was fetched and evaluated (SPF, DMARC).
* ``HEADER CLAIM``   - the message itself says so; NOT verified by EmailGuard.
* ``HEURISTIC``      - rule-based scoring of header/content patterns.
* ``NOT PERFORMED``  - the check could not run (missing input or DNS disabled).

When ``is_demo`` is true the DNS answers came from a simulated zone and the
result is labelled DEMONSTRATION DATA.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP

import config
from modules import dkim_verifier, dmarc_checker, spf_checker, spoofing_detector
from modules.dns_utils import BaseResolver, LiveResolver, check_dns_health
from modules.email_parser import EmailParseError, ParsedEmail, parse_email
from modules.utils import is_ip, normalize_domain, registered_domain

METHOD_LEGEND = {
    "CRYPTOGRAPHIC": "A digital signature was mathematically verified against a public key.",
    "DNS": "A DNS record was retrieved and evaluated against the message data.",
    "HEADER CLAIM": "The message itself states this result. EmailGuard did NOT verify it.",
    "HEURISTIC": "Rule-based pattern analysis. Indicative only - not proof.",
    "DEMONSTRATION": "Simulated data used for teaching; not a real-world result.",
    "NOT PERFORMED": "The check could not be run with the information available.",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _entry(mechanism: str, status: str, method: str, source: str, domain: str, explanation: str, details: dict | None = None) -> dict:
    return {
        "mechanism": mechanism,
        "status": status,
        "method": method,
        "data_source": source,
        "domain": domain,
        "explanation": explanation,
        "details": details or {},
    }


def classify(spf: str, dkim: str, dmarc: str, risk_level: str) -> tuple[str, str]:
    """Return ``(classification, headline)``."""
    failed = [n for n, s in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)) if s == "FAIL"]
    if failed:
        return "FAILED AUTHENTICATION", f"{' and '.join(failed)} verification failed."
    if risk_level in ("MEDIUM", "HIGH") or spf == "SOFTFAIL":
        return "SUSPICIOUS", f"No hard authentication failure, but the heuristic risk level is {risk_level}."
    if "PASS" in (spf, dkim, dmarc):
        return "AUTHENTICATED", "At least one authentication mechanism passed and no suspicious indicators outweighed it."
    return "UNVERIFIED", "No authentication result could be established, so the sender is unconfirmed."


def build_email_from_fields(
    from_display: str = "",
    from_addr: str = "",
    reply_to: str = "",
    return_path: str = "",
    subject: str = "",
    body: str = "",
    attachment_names: list[str] | None = None,
    claims: dict[str, str] | None = None,
) -> bytes:
    """Assemble a synthetic message from form fields (used by the spoofing detector's manual mode)."""

    def clean(value: str) -> str:
        return (value or "").replace("\r", " ").replace("\n", " ").strip()

    msg = EmailMessage(policy=SMTP)
    from_addr = clean(from_addr)
    if not from_addr:
        raise ValueError("A From address is required.")
    display = clean(from_display)
    msg["From"] = f'"{display}" <{from_addr}>' if display else from_addr
    msg["To"] = "recipient@example.invalid"
    if clean(reply_to):
        msg["Reply-To"] = clean(reply_to)
    if clean(return_path):
        msg["Return-Path"] = f"<{clean(return_path).strip('<>')}>"
    msg["Subject"] = clean(subject)
    claims = {k: v for k, v in (claims or {}).items() if v and v != "not provided"}
    if claims:
        msg["Authentication-Results"] = "mx.example.invalid; " + "; ".join(f"{k}={v}" for k, v in claims.items())
    msg.set_content(body or "")
    for name in attachment_names or []:
        name = clean(name)
        if name:
            msg.add_attachment(b"", maintype="application", subtype="octet-stream", filename=name)
    return msg.as_bytes()


def analyze_email(
    raw: str | bytes,
    *,
    input_mode: str = "full_message",
    dns_mode: str = "off",
    resolver: BaseResolver | None = None,
    sending_ip: str | None = None,
    envelope_from: str | None = None,
    dns_timeout: float = config.DNS_TIMEOUT_SECONDS,
    is_demo: bool = False,
    scenario: str | None = None,
    source: str = "analyzer",
) -> dict:
    """Analyse a message and return the full result dictionary.

    ``dns_mode``: ``"off"`` (no lookups), ``"live"`` (real DNS) or ``"simulated"``
    (use the ``resolver`` argument, e.g. the demo zone).
    Raises :class:`EmailParseError` if the input is not an e-mail.
    """
    steps: list[dict] = []
    limitations: list[str] = []

    def step(title: str, method: str, status: str, detail: str) -> None:
        steps.append({"step": len(steps) + 1, "title": title, "method": method, "status": status, "detail": detail})

    # 1. Parse -------------------------------------------------------------
    parsed: ParsedEmail = parse_email(raw)
    headers_only = input_mode == "headers_only"
    manual = input_mode == "manual"
    step("Parse message", "PARSING", "DONE",
         f"{len(parsed.headers)} header fields, {len(parsed.received)} Received hops, {len(parsed.urls)} URLs, {len(parsed.attachments)} attachments extracted."
         + (" Input declared as headers only." if headers_only else ""))
    for w in parsed.warnings:
        if manual and ("Missing headers" in w or "Authentication-Results" in w):
            continue  # expected for a form-built message
        step("Parser warning", "PARSING", "WARNING", w)

    resolver_obj: BaseResolver | None = None
    if dns_mode == "live":
        resolver_obj = LiveResolver(timeout=dns_timeout)
    elif dns_mode == "simulated":
        resolver_obj = resolver
        if resolver_obj is None:
            raise ValueError("dns_mode='simulated' requires a resolver.")
    data_source = resolver_obj.source_label if resolver_obj else "none (DNS disabled)"
    dns_health = {"checked": False, "healthy": True, "message": ""}
    if dns_mode == "live" and resolver_obj is not None:
        healthy, message = check_dns_health(resolver_obj)
        dns_health = {"checked": True, "healthy": healthy, "message": message}
        if not healthy:
            step("DNS health check", "DNS", "WARNING", message + " Results below that say NONE or 'no record' may be unreliable.")
            limitations.append("DNS health check failed: " + message)

    claims = parsed.header_claims
    step("Read header-claimed results", "HEADER CLAIM", "DONE",
         ("Authentication-Results/Received-SPF claim: " + ", ".join(f"{k}={v}" for k, v in claims.items()) + ". These are NOT verified by EmailGuard.")
         if claims else "No Authentication-Results or Received-SPF header present.")

    # 2. SPF ---------------------------------------------------------------
    spf_domain = normalize_domain(envelope_from.rsplit("@", 1)[-1]) if envelope_from else (parsed.return_path_domain or "")
    spf_basis = "envelope sender (MAIL FROM / Return-Path)"
    if not spf_domain:
        spf_domain, spf_basis = parsed.from_domain, "From header domain (no usable Return-Path; RFC 7208 would use the HELO identity)"
    ip_text = (sending_ip or "").strip()
    if resolver_obj is None:
        spf = _entry("SPF", "NOT EVALUATED", "NOT PERFORMED", data_source, spf_domain,
                     "DNS lookups are disabled, so SPF was not evaluated.")
    elif not ip_text:
        spf = _entry("SPF", "NOT EVALUATED", "NOT PERFORMED", data_source, spf_domain,
                     "SPF needs the IP address of the server that delivered the message, and none was supplied. "
                     "Header claims are not a substitute.")
    elif not is_ip(ip_text):
        spf = _entry("SPF", "NOT EVALUATED", "NOT PERFORMED", data_source, spf_domain, f"'{ip_text}' is not a valid IP address.")
    elif not spf_domain:
        spf = _entry("SPF", "NOT EVALUATED", "NOT PERFORMED", data_source, "", "No sender domain could be determined.")
    else:
        res = spf_checker.check_spf(spf_domain, ip_text, resolver_obj)
        spf = _entry("SPF", res.status, "DNS", res.data_source, spf_domain, res.explanation,
                     {"record": res.record, "matched": res.matched, "lookups": res.lookups, "ip": res.ip, "basis": spf_basis,
                      "trace": res.trace, "mechanisms": res.mechanisms})
        limitations += res.limitations
    step("SPF evaluation", spf["method"], spf["status"], spf["explanation"])

    # 3. DKIM --------------------------------------------------------------
    dkim_sigs_header = [dkim_verifier.parse_signature_tags(h) for h in parsed.dkim_signatures]
    if manual:
        dkim = _entry("DKIM", "NOT EVALUATED", "NOT PERFORMED", data_source, "",
                      "The message was assembled from form fields, so it has no genuine DKIM signature to verify. Use a real .eml for DKIM.",
                      {"signatures": []})
    elif headers_only:
        dkim = _entry("DKIM", "NOT EVALUATED", "NOT PERFORMED", data_source, "",
                      "The input contains headers only. A DKIM signature covers the message body hash, so verification needs the complete message.",
                      {"signatures": [{"domain": t.get("d", ""), "selector": t.get("s", ""), "status": "NOT EVALUATED"} for t in dkim_sigs_header]})
    elif not parsed.dkim_signatures:
        dkim = _entry("DKIM", "NONE", "CRYPTOGRAPHIC", data_source, "", "The message contains no DKIM-Signature header, so there is nothing to verify.", {"signatures": []})
    elif resolver_obj is None:
        dkim = _entry("DKIM", "NOT EVALUATED", "NOT PERFORMED", data_source, dkim_sigs_header[0].get("d", ""),
                      "A DKIM-Signature is present but DNS lookups are disabled, so the public key could not be fetched and the signature was not verified.",
                      {"signatures": [{"domain": t.get("d", ""), "selector": t.get("s", ""), "status": "NOT EVALUATED"} for t in dkim_sigs_header]})
    else:
        dres = dkim_verifier.verify_dkim(parsed.raw, resolver_obj)
        dkim = _entry("DKIM", dres.status, "CRYPTOGRAPHIC", dres.data_source,
                      dres.signatures[0].domain if dres.signatures else "", dres.explanation,
                      {"signatures": [s.to_dict() for s in dres.signatures]})
        limitations += dres.limitations
    step("DKIM verification", dkim["method"], dkim["status"], dkim["explanation"])

    # 4. DMARC -------------------------------------------------------------
    lookup = None
    if resolver_obj is None:
        dmarc = _entry("DMARC", "NOT EVALUATED", "NOT PERFORMED", data_source, parsed.from_domain,
                       "DNS lookups are disabled, so the DMARC policy could not be retrieved.")
    elif not parsed.from_domain:
        dmarc = _entry("DMARC", "NOT EVALUATED", "NOT PERFORMED", data_source, "", "No From domain is available.")
    else:
        lookup = dmarc_checker.lookup_dmarc(parsed.from_domain, resolver_obj)
        ev = dmarc_checker.evaluate_dmarc(
            parsed.from_domain, lookup, spf["status"], spf_domain, dkim["status"],
            [{"status": s.get("status"), "domain": s.get("domain", "")} for s in dkim["details"].get("signatures", [])],
        )
        dmarc = _entry("DMARC", ev["status"], "DNS", lookup.data_source, parsed.from_domain, ev["explanation"],
                       {"record": lookup.raw, "record_domain": lookup.record_domain, "policy": lookup.policy,
                        "subdomain_policy": lookup.subdomain_policy, "pct": lookup.pct, "adkim": lookup.adkim, "aspf": lookup.aspf,
                        "rua": lookup.rua, "spf_aligned": ev["spf_aligned"], "dkim_aligned": ev["dkim_aligned"],
                        "applied_policy": ev["applied_policy"], "lookup_status": lookup.status,
                        "warnings": lookup.warnings, "errors": lookup.errors})
    step("DMARC evaluation", dmarc["method"], dmarc["status"], dmarc["explanation"])

    # 5. Heuristics --------------------------------------------------------
    auth = {"spf": spf, "dkim": dkim, "dmarc": dmarc}
    spoof = spoofing_detector.analyze_spoofing(parsed, auth, manual=manual)
    step("Heuristic spoofing analysis", "HEURISTIC", spoof["level"],
         f"Risk score {spoof['score']}/100 from {len(spoof['indicators'])} indicator(s).")

    # 6. Verdict -----------------------------------------------------------
    classification, headline = classify(spf["status"], dkim["status"], dmarc["status"], spoof["level"])
    reasons = [f"{a['mechanism']}: {a['status']} ({a['method']})" for a in (spf, dkim, dmarc)]
    reasons += [i["title"] for i in spoof["indicators"][:4]]
    step("Final verdict", "HEURISTIC", classification, headline)

    sig_verified = dkim["status"] == "PASS"
    digital_signature = {
        "status": "VERIFIED" if sig_verified else ("INVALID" if dkim["status"] in ("FAIL", "PERMERROR") else
                  ("NO SIGNATURE" if dkim["status"] == "NONE" else "NOT VERIFIED")),
        "note": ("The DKIM (RSASSA-PKCS1-v1_5) signature was cryptographically verified. "
                 if sig_verified else "No DKIM signature was successfully verified. ")
                + "The RSA-PSS Digital Signature Lab is a separate educational demonstration and is not part of e-mail analysis.",
    }

    if is_demo:
        limitations.insert(0, "DEMONSTRATION DATA: DNS answers came from a simulated zone and IP addresses use documentation ranges; the e-mail is fictional.")
    limitations.append("Header-claimed results (Authentication-Results, Received-SPF) are reported but never treated as verified.")
    limitations.append("The organisational domain is approximated without the full Public Suffix List.")
    limitations = list(dict.fromkeys(limitations))

    email_info = parsed.to_dict()
    return {
        "analysis_id": None,
        "timestamp": _now(),
        "source": source,
        "is_demo": is_demo,
        "scenario": scenario,
        "input_mode": input_mode,
        "dns_mode": dns_mode,
        "dns_source": data_source,
        "dns_health": dns_health,
        "sending_ip": ip_text,
        "spf_basis": spf_basis,
        "email": email_info,
        "authentication": {"spf": spf, "dkim": dkim, "dmarc": dmarc, "header_claims": claims},
        "spoofing": spoof,
        "verdict": {"classification": classification, "headline": headline, "reasons": reasons,
                    "risk_score": spoof["score"], "risk_level": spoof["level"]},
        "digital_signature": digital_signature,
        "steps": steps,
        "limitations": limitations,
        "method_legend": METHOD_LEGEND,
    }


__all__ = ["analyze_email", "build_email_from_fields", "classify", "EmailParseError", "METHOD_LEGEND"]
