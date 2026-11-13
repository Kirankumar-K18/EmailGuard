"""Rule-based e-mail spoofing / phishing risk scoring.

This is a *heuristic* risk assessment. Every rule adds a fixed number of points
(see ``RULES`` below and docs/project_documentation.md); the total is capped at
100 and mapped to LOW (0-29), MEDIUM (30-59) or HIGH (60-100). A high score
means "several suspicious indicators were observed", not "this e-mail is
malicious"; a low score does not prove an e-mail is genuine.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import config
from modules.email_parser import ParsedEmail, parse_received_time
from modules.utils import is_subdomain_of, normalize_domain, registered_domain

DISCLAIMER = (
    "This score is a rule-based heuristic risk assessment. It is not a definitive determination that an e-mail is "
    "malicious or legitimate: genuine messages can trigger rules, and a skilled attacker can avoid them."
)

# Official registrable domains of frequently impersonated brands (illustrative, not exhaustive).
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com", "office365.com", "microsoftonline.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googlemail.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "hdfcbank": {"hdfcbank.com", "hdfcbank.net"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "sbi": {"sbi.co.in", "onlinesbi.com"},
    "paytm": {"paytm.com"},
    "irs": {"irs.gov"},
    "bankofamerica": {"bankofamerica.com"},
    "wellsfargo": {"wellsfargo.com"},
    "chase": {"chase.com", "jpmorgan.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "github": {"github.com"},
    "zoom": {"zoom.us"},
}

BRAND_ALIASES = {
    "bank of america": "bankofamerica",
    "wells fargo": "wellsfargo",
    "hdfc bank": "hdfcbank",
    "icici bank": "icicibank",
    "axis bank": "axisbank",
    "state bank of india": "sbi",
    "office 365": "microsoft",
    "apple id": "apple",
    "google drive": "google",
    "amazon prime": "amazon",
}

BRAND_KEYWORDS = {
    "secure", "support", "login", "verify", "verification", "account", "accounts", "service", "services", "update",
    "alert", "alerts", "billing", "help", "official", "team", "center", "customer", "care", "mail", "online",
    "portal", "security", "notify", "notification", "id", "pay", "payment", "payments", "wallet", "web", "app",
}

FREE_MAIL = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "live.com", "aol.com", "proton.me",
    "protonmail.com", "icloud.com", "gmx.com", "mail.com", "yandex.com", "rediffmail.com", "zoho.com",
}

ROLE_TERMS = (
    "support", "security team", "helpdesk", "help desk", "it department", "admin", "administrator", "accounts payable",
    "billing", "hr department", "payroll", "ceo", "cfo", "director", "customer service",
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "tiny.cc",
    "shorturl.at", "rb.gy", "lnkd.in",
}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "gq", "tk", "ml", "cf", "ga", "work", "country", "kim", "loan"}

DANGEROUS_EXT = {
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf", "jar", "msi", "ps1", "lnk", "hta",
    "iso", "img", "dll", "reg",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab"}
HTML_EXT = {"html", "htm", "svg", "xhtml"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "csv"}

URGENCY = ("urgent", "immediately", "asap", "within 24 hours", "act now", "final notice", "last warning",
           "expires today", "will be suspended", "has been suspended", "will be closed", "limited time")
CREDENTIAL = ("verify your account", "confirm your password", "reset your password", "update your password",
              "log in to", "sign in to", "update your payment", "security alert", "unusual activity",
              "confirm your identity", "account has been locked", "account will be")
PAYMENT = ("wire transfer", "bank details", "change of bank", "new bank account", "gift card", "payment instructions",
           "remittance", "update vendor", "change of vendor", "bank account details")

CONFUSABLES = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "$": "s", "@": "a", "|": "l", "!": "i"})

# Points per rule - the single source of truth for scoring.
RULES = {
    "SPF_FAIL": 20, "SPF_SOFTFAIL": 10, "DKIM_FAIL": 20, "DMARC_FAIL": 20,
    "CLAIM_FAIL": 12, "CLAIM_MISMATCH": 15, "NO_AUTH_INFO": 8, "NO_DKIM": 5, "NO_DMARC": 4,
    "REPLYTO_MISMATCH": 15, "REPLYTO_FREEMAIL": 5, "RETURNPATH_MISMATCH": 10, "DISPLAY_BRAND": 20,
    "DISPLAY_EMAIL": 25, "DISPLAY_ROLE_FREEMAIL": 8, "LOOKALIKE": 25, "PUNYCODE": 15, "MSGID_MISMATCH": 5,
    "MISSING_FROM": 30, "MULTI_FROM": 15, "MISSING_DATE": 5, "MISSING_MSGID": 5, "FUTURE_DATE": 5,
    "MANY_HOPS": 5, "HOP_ORDER": 5, "HOP_UNKNOWN": 3,
    "URL_IP": 12, "URL_SHORT": 6, "URL_PUNY": 10, "URL_AT": 12, "URL_MISMATCH": 15, "URL_TLD": 6, "URL_DEEP": 4,
    "LANG_URGENT": 6, "LANG_CRED": 8, "LANG_PAYMENT": 10,
    "ATT_DANGEROUS": 20, "ATT_DOUBLE": 10, "ATT_MACRO": 10, "ATT_HTML": 8, "ATT_ARCHIVE": 5,
}


def risk_level(score: int) -> str:
    if score <= config.RISK_LOW_MAX:
        return "LOW"
    if score <= config.RISK_MEDIUM_MAX:
        return "MEDIUM"
    return "HIGH"


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _decode_punycode(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    return label


def lookalike_brand(domain: str) -> tuple[str, str] | None:
    """Return ``(brand, reason)`` if ``domain`` imitates a known brand's domain."""
    domain = normalize_domain(domain)
    reg = registered_domain(domain)
    if not reg or "." not in reg:
        return None
    label = _decode_punycode(reg.split(".")[0])
    norm = label.translate(CONFUSABLES)
    compact = re.sub(r"[-_]", "", norm)
    tokens = [t for t in re.split(r"[-_]", norm) if t]
    substituted = norm != label
    sub_labels = domain[: -len(reg)].rstrip(".").split(".") if domain != reg else []
    for brand, official in BRANDS.items():
        if reg in official:
            continue
        if compact == brand and not substituted:
            return brand, f"'{reg}' uses the brand name '{brand}' but is not one of its official domains"
        if brand in sub_labels:
            return brand, f"the brand name '{brand}' appears as a subdomain of unrelated domain '{reg}'"
        rest = [t for t in tokens if t != brand]
        if brand in tokens and all(t in BRAND_KEYWORDS or t.isdigit() for t in rest):
            how = f" (character substitution: '{label}' reads as '{norm}')" if substituted else ""
            return brand, f"'{reg}' combines the brand name '{brand}' with generic words{how}"
        stripped = compact
        for kw in sorted(BRAND_KEYWORDS, key=len, reverse=True):
            stripped = stripped.replace(kw, "")
        if len(brand) >= 4 and stripped == brand and compact != brand:
            return brand, f"'{reg}' is the brand name '{brand}' plus generic words"
        if substituted and compact == brand:
            return brand, f"'{reg}' imitates '{brand}' using look-alike characters ('{label}' vs '{brand}')"
        limit = 1 if len(brand) < 8 else 2
        if len(brand) >= 5 and 0 < levenshtein(compact, brand) <= limit:
            return brand, f"'{reg}' is within {levenshtein(compact, brand)} character(s) of '{brand}' (possible typosquat)"
    return None


def _indicator(id_: str, category: str, severity: str, title: str, detail: str, evidence: list[str] | None = None, points: int | None = None) -> dict:
    return {
        "id": id_,
        "category": category,
        "severity": severity,
        "points": RULES[id_] if points is None else points,
        "title": title,
        "detail": detail,
        "evidence": evidence or [],
    }


def _url_host(url: str) -> tuple[str, str, bool]:
    """Return (host, userinfo, has_at) for a URL."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except ValueError:  # malformed URL such as an unbalanced IPv6 bracket
        return "", "", False
    has_at = "@" in parsed.netloc
    userinfo = parsed.netloc.rsplit("@", 1)[0] if has_at else ""
    return host, userinfo, has_at


def _check_authentication(parsed: ParsedEmail, auth: dict, out: list[dict], manual: bool = False) -> None:
    claims = parsed.header_claims
    evaluated_any = False
    for key, label in (("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")):
        status = (auth.get(key) or {}).get("status", "NOT EVALUATED")
        if status not in ("NOT EVALUATED", "TEMPERROR"):
            evaluated_any = True
        if key == "spf" and status == "FAIL":
            out.append(_indicator("SPF_FAIL", "Authentication", "high", "SPF check failed", (auth["spf"].get("explanation") or "The sending IP is not authorised by the domain's SPF policy.")))
        elif key == "spf" and status == "SOFTFAIL":
            out.append(_indicator("SPF_SOFTFAIL", "Authentication", "medium", "SPF soft-fail", "The sending IP is probably not authorised (~all). Treat with suspicion."))
        elif key == "dkim" and status == "FAIL":
            out.append(_indicator("DKIM_FAIL", "Authentication", "high", "DKIM signature verification failed", auth["dkim"].get("explanation", "")))
        elif key == "dmarc" and status == "FAIL":
            out.append(_indicator("DMARC_FAIL", "Authentication", "high", "DMARC evaluation failed", auth["dmarc"].get("explanation", "")))
        elif status == "NOT EVALUATED" and claims.get(key) in ("fail", "softfail", "permerror", "temperror"):
            out.append(_indicator("CLAIM_FAIL", "Authentication", "medium", f"Headers report {label} {claims[key]}",
                                  f"The Authentication-Results/Received-SPF header says {key}={claims[key]}. EmailGuard did not verify this itself (header claim).",
                                  [f"{key}={claims[key]}"]))
    if not evaluated_any and not claims and not manual:
        out.append(_indicator("NO_AUTH_INFO", "Authentication", "medium", "No authentication results available",
                              "The message carries no Authentication-Results or Received-SPF header and nothing could be verified, so its origin is unconfirmed."))
    if (auth.get("dkim") or {}).get("status") == "NONE" and not manual:
        out.append(_indicator("NO_DKIM", "Authentication", "low", "No DKIM signature", "The message is not signed with DKIM, so its integrity and domain cannot be cryptographically confirmed."))
    if (auth.get("dmarc") or {}).get("status") == "NONE":
        out.append(_indicator("NO_DMARC", "Authentication", "low", "No DMARC policy published", "The From domain publishes no DMARC policy, so receivers cannot be told how to treat spoofed mail."))

    # Header claims that the independent evaluation contradicts definitively.
    contradictions = []
    for key in ("spf", "dkim", "dmarc"):
        ours = (auth.get(key) or {}).get("status", "NOT EVALUATED")
        if claims.get(key) == "pass" and ours in ("FAIL", "SOFTFAIL", "NONE"):
            contradictions.append(f"{key.upper()}: header says pass, EmailGuard result is {ours}")
    if contradictions:
        out.append(_indicator(
            "CLAIM_MISMATCH", "Authentication", "high", "Authentication-Results header contradicts EmailGuard's own checks",
            "A header claims a pass that independent verification did not confirm. Attackers sometimes insert fake Authentication-Results headers; "
            "it can also be caused by different DNS data or modified text.", contradictions))


def _check_identity(parsed: ParsedEmail, out: list[dict]) -> None:
    from_dom = parsed.from_domain
    from_reg = registered_domain(from_dom)
    if parsed.reply_to_domain and registered_domain(parsed.reply_to_domain) != from_reg:
        out.append(_indicator("REPLYTO_MISMATCH", "Identity", "medium", "From and Reply-To domains differ",
                              "Replies would go to a different organisation than the apparent sender, a common phishing and business-e-mail-compromise pattern.",
                              [f"From: {parsed.from_addr}", f"Reply-To: {parsed.reply_to_addr}"]))
        if parsed.reply_to_domain in FREE_MAIL and from_dom not in FREE_MAIL:
            out.append(_indicator("REPLYTO_FREEMAIL", "Identity", "medium", "Reply-To points to a free-mail provider",
                                  "A corporate-looking sender asks for replies at a free consumer mailbox.", [parsed.reply_to_addr]))
    if parsed.return_path_domain and from_dom and registered_domain(parsed.return_path_domain) != from_reg:
        out.append(_indicator("RETURNPATH_MISMATCH", "Identity", "medium", "Return-Path (envelope sender) domain differs from From domain",
                              "The bounce address belongs to a different domain. Legitimate for mailing services and forwarders, but also seen in spoofed mail; SPF then authenticates the wrong domain for DMARC.",
                              [f"From: {from_dom}", f"Return-Path: {parsed.return_path_domain}"]))
    if parsed.message_id_domain and from_dom and registered_domain(parsed.message_id_domain) != from_reg:
        out.append(_indicator("MSGID_MISMATCH", "Identity", "low", "Message-ID domain differs from From domain",
                              "Weak signal: the message was generated by a system outside the From domain.",
                              [f"Message-ID domain: {parsed.message_id_domain}"]))

    display = (parsed.from_display or "").strip()
    low = display.lower()
    if display:
        emb = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", display)
        if emb and registered_domain(emb.group(1)) != from_reg:
            out.append(_indicator("DISPLAY_EMAIL", "Identity", "high", "Display name contains a different e-mail address",
                                  "Mail clients often show only the display name; this one embeds another address to look trustworthy.",
                                  [f"Display name: {display}", f"Actual address: {parsed.from_addr}"]))
        else:
            brand_hit = None
            for alias, brand in BRAND_ALIASES.items():
                if alias in low:
                    brand_hit = brand
            for brand in BRANDS:
                if re.search(rf"\b{re.escape(brand)}\b", low):
                    brand_hit = brand
            if brand_hit and from_reg not in BRANDS[brand_hit]:
                out.append(_indicator("DISPLAY_BRAND", "Identity", "high", f"Display name claims '{brand_hit}' but the domain is unrelated",
                                      f"The sender name suggests {brand_hit}, but the address belongs to {from_reg or 'an unknown domain'}.",
                                      [f"Display name: {display}", f"Sender domain: {from_dom}"]))
            elif from_dom in FREE_MAIL and any(t in low for t in ROLE_TERMS):
                out.append(_indicator("DISPLAY_ROLE_FREEMAIL", "Identity", "medium", "Authority/role display name on a free-mail address",
                                      "Names like 'Support' or 'CEO' sent from a consumer mailbox are a common impersonation pattern.",
                                      [f"Display name: {display}", f"Address: {parsed.from_addr}"]))

    if from_dom:
        if "xn--" in from_dom or any(ord(c) > 127 for c in from_dom):
            out.append(_indicator("PUNYCODE", "Identity", "medium", "Sender domain uses internationalised (punycode) characters",
                                  "Visually identical Unicode letters can disguise a different domain (homograph attack).", [from_dom]))
        hit = lookalike_brand(from_dom)
        if hit:
            out.append(_indicator("LOOKALIKE", "Identity", "high", f"Sender domain imitates '{hit[0]}'", hit[1].capitalize() + ".", [from_dom]))


def _check_headers(parsed: ParsedEmail, out: list[dict], manual: bool = False) -> None:
    if manual:
        # A form-built message has no Date/Message-ID/Received headers by construction, so these
        # checks would only measure the form, not the e-mail. Only the From checks apply.
        if not parsed.from_addr:
            out.append(_indicator("MISSING_FROM", "Header consistency", "high", "No valid From address", "A message without a usable From header is malformed."))
        return
    if not parsed.from_addr:
        out.append(_indicator("MISSING_FROM", "Header consistency", "high", "No valid From address", "A message without a usable From header is malformed."))
    if parsed.from_count > 1:
        out.append(_indicator("MULTI_FROM", "Header consistency", "high", "Multiple From headers", f"{parsed.from_count} From headers were found; this is invalid and used to confuse mail clients."))
    if "date" in parsed.missing_headers:
        out.append(_indicator("MISSING_DATE", "Header consistency", "low", "Missing Date header", "Every legitimate MTA adds a Date header."))
    if "message-id" in parsed.missing_headers:
        out.append(_indicator("MISSING_MSGID", "Header consistency", "low", "Missing Message-ID header", "Mail servers normally generate a Message-ID."))
    if parsed.date_parsed and parsed.date_parsed > datetime.now(timezone.utc) + timedelta(days=1):
        out.append(_indicator("FUTURE_DATE", "Header consistency", "low", "Date header is in the future", f"Date: {parsed.date_raw}"))
    if len(parsed.received) >= 8:
        out.append(_indicator("MANY_HOPS", "Header consistency", "low", f"Unusually long relay chain ({len(parsed.received)} Received headers)",
                              "Long chains can indicate repeated forwarding or relay abuse."))
    times = [parse_received_time(r) for r in parsed.received]
    pairs = [(a, b) for a, b in zip(times, times[1:]) if a and b]
    if any(a < b - timedelta(minutes=5) for a, b in pairs):
        out.append(_indicator("HOP_ORDER", "Header consistency", "low", "Received timestamps are out of order",
                              "Each relay adds its header on top, so times should not decrease towards the top. Inconsistency suggests forged or edited headers (or badly skewed clocks)."))
    weird = [r for r in parsed.received if re.search(r"\bfrom\s+(localhost|unknown)(?![\w.-])", r, re.I)]
    if weird:
        out.append(_indicator("HOP_UNKNOWN", "Header consistency", "low", "Relay hop with unknown or localhost host name",
                              "A hop identifies itself as 'localhost' or 'unknown'; common for direct-to-MX bulk senders.", weird[:2]))


def _check_urls(parsed: ParsedEmail, out: list[dict]) -> None:
    buckets: dict[str, list[str]] = {k: [] for k in ("ip", "short", "puny", "at", "mismatch", "tld", "deep")}
    for link in parsed.urls:
        url = link["url"]
        host, _userinfo, has_at = _url_host(url)
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
            buckets["ip"].append(url)
        except ValueError:
            pass
        if registered_domain(host) in SHORTENERS or host in SHORTENERS:
            buckets["short"].append(url)
        if "xn--" in host:
            buckets["puny"].append(url)
        if has_at:
            buckets["at"].append(url)
        tld = host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            buckets["tld"].append(url)
        if host.count(".") >= 4:
            buckets["deep"].append(url)
        shown = link.get("text", "")
        m = re.search(r"((?:[a-z0-9-]+\.)+[a-z]{2,})", shown.lower())
        if m and link["source"] == "html" and registered_domain(m.group(1)) != registered_domain(host):
            buckets["mismatch"].append(f"text '{shown}' -> {url}")
    spec = (
        ("ip", "URL_IP", "high", "Link points to a raw IP address", "Legitimate services almost always use domain names."),
        ("short", "URL_SHORT", "low", "URL shortener used", "Shortened links hide the real destination."),
        ("puny", "URL_PUNY", "medium", "Link host uses punycode (xn--)", "May disguise a look-alike domain."),
        ("at", "URL_AT", "high", "Link contains '@' before the host", "Text before '@' is ignored by browsers, which then go to the part after it - a classic disguise."),
        ("mismatch", "URL_MISMATCH", "high", "Link text shows a different domain than its target", "The visible text and the real destination disagree."),
        ("tld", "URL_TLD", "low", "Link uses a TLD frequently abused for phishing", "Weak signal on its own."),
        ("deep", "URL_DEEP", "low", "Link host has many subdomain levels", "Long host names can hide the true registered domain."),
    )
    for key, rid, sev, title, detail in spec:
        if buckets[key]:
            out.append(_indicator(rid, "Links", sev, title, detail, buckets[key][:5]))


def _check_language(parsed: ParsedEmail, out: list[dict]) -> None:
    text = f"{parsed.subject}\n{parsed.body_text}\n{re.sub(r'<[^>]+>', ' ', parsed.body_html)}".lower()
    for phrases, rid, title in (
        (URGENCY, "LANG_URGENT", "Urgency / pressure language"),
        (CREDENTIAL, "LANG_CRED", "Credential or account-verification language"),
        (PAYMENT, "LANG_PAYMENT", "Payment-redirection language"),
    ):
        hits = [p for p in phrases if p in text]
        if hits:
            out.append(_indicator(rid, "Content", "medium" if rid != "LANG_URGENT" else "low", title,
                                  "Keyword heuristic: genuine messages can also contain these phrases, so this is weak evidence on its own.", hits[:5]))


def _check_attachments(parsed: ParsedEmail, out: list[dict]) -> None:
    dangerous, double, macro, html, archive = [], [], [], [], []
    for att in parsed.attachments:
        name = att["filename"].lower().strip()
        parts = name.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if ext in DANGEROUS_EXT:
            dangerous.append(att["filename"])
        if len(parts) > 2 and parts[-2] in DOC_EXT and ext in (DANGEROUS_EXT | ARCHIVE_EXT | HTML_EXT):
            double.append(att["filename"])
        if ext in MACRO_EXT:
            macro.append(att["filename"])
        if ext in HTML_EXT:
            html.append(att["filename"])
        if ext in ARCHIVE_EXT:
            archive.append(att["filename"])
    for items, rid, sev, title, detail in (
        (dangerous, "ATT_DANGEROUS", "high", "Executable or script attachment", "Executable file types are rarely sent legitimately by e-mail."),
        (double, "ATT_DOUBLE", "high", "Double file extension", "A name such as 'invoice.pdf.exe' disguises an executable as a document."),
        (macro, "ATT_MACRO", "medium", "Macro-enabled Office attachment", "Macros are a common malware delivery route."),
        (html, "ATT_HTML", "medium", "HTML attachment", "HTML attachments are widely used for credential-harvesting pages."),
        (archive, "ATT_ARCHIVE", "low", "Archive attachment", "Archives can hide malicious content from scanners."),
    ):
        if items:
            out.append(_indicator(rid, "Attachments", sev, title, detail, items))


def analyze_spoofing(parsed: ParsedEmail, auth: dict | None = None, manual: bool = False) -> dict:
    """Score ``parsed`` and return the indicators that contributed.

    ``auth`` maps ``spf``/``dkim``/``dmarc`` to dictionaries with a ``status``
    (and optional ``explanation``); omit it to use header claims only.
    ``manual=True`` marks a message assembled from form fields: rules that
    penalise absent headers are skipped because the absence is not evidence.
    """
    auth = auth or {}
    indicators: list[dict] = []
    _check_authentication(parsed, auth, indicators, manual)
    _check_identity(parsed, indicators)
    _check_headers(parsed, indicators, manual)
    _check_urls(parsed, indicators)
    _check_language(parsed, indicators)
    _check_attachments(parsed, indicators)

    indicators.sort(key=lambda i: (-i["points"], i["category"]))
    raw_total = sum(i["points"] for i in indicators)
    score = min(100, raw_total)
    categories: dict[str, int] = {}
    for ind in indicators:
        categories[ind["category"]] = categories.get(ind["category"], 0) + ind["points"]
    return {
        "score": score,
        "raw_total": raw_total,
        "level": risk_level(score),
        "indicators": indicators,
        "category_scores": categories,
        "rules_available": len(RULES),
        "disclaimer": DISCLAIMER,
    }
