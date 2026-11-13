# EmailGuard - Project Documentation

**Intelligent Email Authentication and Spoofing Detection System Using Cryptographic Techniques**
Cryptography and Network Security (CNS) mini-project - version 1.0.0

Developer: `[Your Name]` &nbsp; Roll no.: `[Roll Number]` &nbsp; Institution: `[College / University Name]` &nbsp; Guide: `[Faculty Name]`
(editable in the application under *About Project*)

---

## 1. Introduction and problem statement

E-mail was designed without sender authentication: the visible *From* address is just text and can be forged. Spoofed and
phishing messages exploit this to steal credentials and redirect payments. Three DNS-based standards were added to restore
trust - **SPF**, **DKIM** and **DMARC** - but their results are hard to interpret from raw headers, and headers inside a
message (`Authentication-Results`) can themselves be forged. EmailGuard re-checks authentication independently, scores
spoofing indicators transparently and explains every result.

## 2. Objectives

1. Implement RSA-2048 key generation, SHA-256 hashing and RSA-PSS signing/verification with a vetted library.
2. Perform genuine SPF (DNS), DKIM (cryptographic) and DMARC (policy + alignment) analysis.
3. Detect spoofing indicators with an explainable 0-100 score.
4. Persist analyses in SQLite and export professional PDF reports.
5. Teach the concepts through reproducible demo scenarios that work offline.

## 3. Evidence labels (how results are classified)

| Label | Meaning | Used for |
|---|---|---|
| `CRYPTOGRAPHIC` | A digital signature was mathematically verified against a public key | DKIM, RSA-PSS lab |
| `DNS` | A DNS record was retrieved and evaluated against message data | SPF, DMARC |
| `HEADER CLAIM` | The message states this result; EmailGuard did **not** verify it | Authentication-Results, Received-SPF |
| `HEURISTIC` | Rule-based pattern analysis; indicative only | Spoofing score, verdict |
| `DEMONSTRATION` | Simulated data for teaching | Demo Mode, demo seed data |
| `NOT PERFORMED` | The check could not run with the information available | DNS off, no sending IP, headers only |

Rules that follow from this: SPF needs a supplied sending IP; DKIM needs the full message (the body hash is signed);
DMARC needs real SPF/DKIM outcomes; with DNS off, a signature that is present is `NOT EVALUATED`, while a message with no
signature is `NONE`. A DNS timeout is `TEMPERROR`, never "no record".

## 4. Architecture

Layered design; the logic in `modules/` has no Streamlit dependency and is fully unit-tested.

```
Browser -> Streamlit pages (pages/*.py) -> ui/ (theme, components, report_view)
                                       -> modules/analysis_engine.py
                                            |-- email_parser.py
                                            |-- spf_checker.py   --\
                                            |-- dkim_verifier.py ---+--> dns_utils.py (LiveResolver | DictResolver)
                                            |-- dmarc_checker.py --/
                                            |-- spoofing_detector.py
                                       -> database/db.py (SQLite)  -> modules/report_generator.py (PDF)
```

`dns_utils` defines one resolver interface (`txt`, `a`, `aaaa`, `mx`). `LiveResolver` queries real DNS through dnspython;
`DictResolver` answers from a dictionary. Demo Mode and most tests use `DictResolver`, so the **same** SPF/DKIM/DMARC code
runs in both worlds. The live path is additionally tested against a loopback DNS server speaking the real DNS protocol.

## 5. Cryptographic implementation

| Item | Implementation |
|---|---|
| RSA key generation | `cryptography` `rsa.generate_private_key(public_exponent=65537, key_size=2048)` |
| SHA-256 | `hashlib.sha256`; known-answer tests (FIPS 180-4 vectors) |
| Signature | RSA-PSS, MGF1(SHA-256), 32-byte salt, hash SHA-256 (`cryptography` / OpenSSL) |
| Verification | `public_key.verify(...)`; any failure is returned as an explained result, never an exception to the UI |
| Key storage | In memory only; downloads are generated on request. Private key export supports a passphrase (PKCS#8, `BestAvailableEncryption`) |
| Integrity demo | Editing one character changes the digest (avalanche effect shown in bits) and verification fails |

Nothing cryptographic is hand-written. **RSA-PSS is not DKIM**: DKIM signs a canonicalised hash of selected headers plus
the body hash with RSASSA-PKCS1-v1_5 (RFC 6376). EmailGuard delegates real DKIM verification to `dkimpy`.

Concept comparison: *symmetric* (one shared key, fast, bulk data) vs *asymmetric* (key pair, key exchange and signatures);
*hashing* (one-way, keyless, integrity) vs *encryption* (two-way, keyed, confidentiality); a *digital signature* is a hash
transformed with the private key giving integrity, authenticity and non-repudiation.

## 6. SPF, DKIM and DMARC

**SPF (RFC 7208, subset).** Fetch the domain's TXT `v=spf1` record; evaluate terms left to right; first match returns the
qualifier's result (`+` PASS, `-` FAIL, `~` SOFTFAIL, `?` NEUTRAL); no match gives NEUTRAL. Supported: `all, ip4, ip6, a, mx, include,
exists, redirect`, CIDR lengths, 10-lookup and 2-void-lookup limits, multiple-record detection. Unsupported (reports
`NOT EVALUATED`): macros, `ptr`, `exp=`, HELO checks.

**DKIM (RFC 6376 via dkimpy).** Extract every `DKIM-Signature`; read `d=`, `s=`; query `<s>._domainkey.<d>` TXT; dkimpy canonicalises,
hashes and verifies. Results: PASS, FAIL (body hash or signature mismatch), PERMERROR (missing/revoked/invalid key, malformed
signature), TEMPERROR (DNS problem), NONE (no signature). Each failure comes with a plain-language explanation.

**DMARC (RFC 7489, conditional).** Query `_dmarc.<from-domain>` (falling back to the organisational domain). DMARC passes if SPF **or** DKIM
passed **and** the authenticated domain aligns with the From domain (strict = exact, relaxed = same organisational domain). With missing
inputs the result is `NOT EVALUATED`; with no published policy it is `NONE`.

## 7. Spoofing detector - rules and points

Each triggered rule adds its points; the total is capped at 100. Bands: **0-29 LOW, 30-59 MEDIUM, 60-100 HIGH**.
The score is a heuristic, not proof. Rules that penalise *absent* headers are skipped for messages built from form
fields, because the absence reflects the form and not the e-mail.

| Rule id | Points | Triggered when |
|---|---|---|
| `MISSING_FROM` | 30 | No usable From address |
| `DISPLAY_EMAIL` | 25 | Display name embeds a different e-mail address |
| `LOOKALIKE` | 25 | Sender domain imitates a known brand (typo, digit substitution, brand + generic word) |
| `ATT_DANGEROUS` | 20 | Executable/script attachment extension |
| `DISPLAY_BRAND` | 20 | Display name names a known brand but the domain is not that brand's |
| `DKIM_FAIL` | 20 | DKIM signature present but verification failed |
| `DMARC_FAIL` | 20 | DMARC evaluation failed (no aligned SPF/DKIM pass) |
| `SPF_FAIL` | 20 | SPF evaluation returned FAIL (real DNS evaluation) |
| `CLAIM_MISMATCH` | 15 | Headers claim 'pass' but EmailGuard's own result is FAIL/SOFTFAIL/NONE (possible forged header) |
| `MULTI_FROM` | 15 | More than one From header |
| `PUNYCODE` | 15 | Sender domain uses punycode / non-ASCII characters |
| `REPLYTO_MISMATCH` | 15 | Reply-To organisational domain differs from From |
| `URL_MISMATCH` | 15 | HTML link text shows a different domain than the real target |
| `CLAIM_FAIL` | 12 | Headers claim a failure but EmailGuard could not verify it itself |
| `URL_AT` | 12 | '@' in the link's authority part |
| `URL_IP` | 12 | Link points to a raw IP address |
| `ATT_DOUBLE` | 10 | Double extension such as .pdf.exe |
| `ATT_MACRO` | 10 | Macro-enabled Office file |
| `LANG_PAYMENT` | 10 | Payment-redirection phrases |
| `RETURNPATH_MISMATCH` | 10 | Return-Path domain differs from From domain |
| `SPF_SOFTFAIL` | 10 | SPF evaluation returned SOFTFAIL |
| `URL_PUNY` | 10 | Link host uses punycode |
| `ATT_HTML` | 8 | HTML/SVG attachment |
| `DISPLAY_ROLE_FREEMAIL` | 8 | Role/authority display name (Support, CEO...) on a free-mail address |
| `LANG_CRED` | 8 | Credential / account-verification phrases |
| `NO_AUTH_INFO` | 8 | No authentication results anywhere and nothing verifiable |
| `LANG_URGENT` | 6 | Urgency / pressure phrases |
| `URL_SHORT` | 6 | URL shortener used |
| `URL_TLD` | 6 | Link uses a TLD frequently abused for phishing |
| `ATT_ARCHIVE` | 5 | Archive attachment |
| `FUTURE_DATE` | 5 | Date is more than a day in the future |
| `HOP_ORDER` | 5 | Received timestamps out of order by more than 5 minutes |
| `MANY_HOPS` | 5 | 8 or more Received headers |
| `MISSING_DATE` | 5 | No Date header |
| `MISSING_MSGID` | 5 | No Message-ID header |
| `MSGID_MISMATCH` | 5 | Message-ID domain differs from From domain |
| `NO_DKIM` | 5 | No DKIM signature |
| `REPLYTO_FREEMAIL` | 5 | Reply-To is a free-mail address while From is not |
| `NO_DMARC` | 4 | From domain publishes no DMARC policy |
| `URL_DEEP` | 4 | Link host has 4+ dots |
| `HOP_UNKNOWN` | 3 | A hop identifies itself as localhost/unknown |

The brand list and keyword lists are illustrative, not exhaustive.

## 8. Database design (SQLite)

Tables: `email_analysis` (one row per analysis, full JSON report), `authentication_results` (SPF/DKIM/DMARC rows), `security_events`
(one row per indicator, feeds dashboard alerts and threat chart), `application_settings` (key/value, e.g. developer details).
Schema is applied automatically at start-up; all queries are parameterised (sort columns come from a whitelist);
deleting an analysis cascades to its child rows.

```sql
-- EmailGuard SQLite schema. Executed automatically at start-up (idempotent).

CREATE TABLE IF NOT EXISTS email_analysis (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    source          TEXT    NOT NULL DEFAULT 'analyzer',      -- analyzer | spoofing_detector | demo_scenario | demo_seed
    is_demo         INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1)),
    scenario        TEXT,
    sender          TEXT,
    from_domain     TEXT,
    recipient       TEXT,
    subject         TEXT,
    email_date      TEXT,
    message_id      TEXT,
    risk_score      INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      TEXT    NOT NULL DEFAULT 'LOW' CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    classification  TEXT    NOT NULL DEFAULT 'UNVERIFIED',
    report_json     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS authentication_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES email_analysis(id) ON DELETE CASCADE,
    mechanism   TEXT    NOT NULL CHECK (mechanism IN ('SPF', 'DKIM', 'DMARC')),
    status      TEXT    NOT NULL,
    method      TEXT    NOT NULL,                             -- DNS | CRYPTOGRAPHIC | NOT PERFORMED
    domain      TEXT,
    details     TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER REFERENCES email_analysis(id) ON DELETE CASCADE,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    severity    TEXT    NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    event_type  TEXT    NOT NULL,                             -- indicator category
    title       TEXT    NOT NULL,
    message     TEXT,
    is_demo     INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1))
);

CREATE TABLE IF NOT EXISTS application_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_analysis_created ON email_analysis(created_at);
CREATE INDEX IF NOT EXISTS idx_analysis_class   ON email_analysis(classification);
CREATE INDEX IF NOT EXISTS idx_auth_analysis    ON authentication_results(analysis_id);
CREATE INDEX IF NOT EXISTS idx_events_analysis  ON security_events(analysis_id);
CREATE INDEX IF NOT EXISTS idx_events_created   ON security_events(created_at);
```

## 9. Testing

Run `python -m pytest -q` from the project root.

| Test file | Covers |
|---|---|
| `test_hashing.py` | SHA-256 known-answer vectors, streaming, integrity check, avalanche effect |
| `test_rsa_signature.py` | RSA-2048 keys, PSS sign/verify, tamper detection, wrong key, probabilistic signatures, PEM/passphrase, Base64 |
| `test_email_parser.py` | Header extraction, MIME words, missing headers, invalid/binary/oversized input, Received IPs, auth-results parsing, URLs, attachments |
| `test_spoofing.py` | Every rule family, look-alike domain detection (positive and negative cases), score capping, manual-mode behaviour, header-injection safety |
| `test_spf.py` | Mechanisms, qualifiers, include/redirect, limits, errors, macros/ptr -> NOT EVALUATED |
| `test_dmarc.py` | Tag parsing, fallback, alignment, evaluation honesty |
| `test_dkim.py` | Genuine signatures, body/header tampering, wrong key, missing key, DNS timeout, multiple signatures |
| `test_dns_live.py` | `LiveResolver` against a loopback DNS server: TXT multi-string, MX order, NXDOMAIN, SERVFAIL, timeout, end-to-end SPF/DMARC/DKIM |
| `test_database_and_reports.py` | Demo scenarios, honesty rules, DB CRUD/filters/stats/injection attempts/errors, PDF generation |

## 10. Known limitations

See the README (section 8). In short: live DNS needs Internet access; SPF is a documented subset; pasted text can break DKIM;
the organisational-domain logic is approximate; header-claimed results are never trusted; the risk score is heuristic.

## 11. Viva preparation - likely questions

1. **Why PSS and not PKCS#1 v1.5?** PSS is randomised with a security proof; v1.5 signing is deterministic. (DKIM itself still uses v1.5 for compatibility.)
2. **Why is hashing done before signing?** RSA can only process data smaller than the modulus and is slow; the fixed-size digest is signed instead, and it binds the whole message.
3. **SPF vs DKIM vs DMARC?** SPF authenticates the sending server's IP; DKIM authenticates content/domain with a signature; DMARC requires one of them to align with the visible From and sets policy.
4. **Why can a forwarded message fail SPF but pass DKIM?** Forwarding changes the connecting IP (SPF breaks) but not the signed content (DKIM survives).
5. **Why can mailing lists break DKIM?** Footers or subject tags change the signed body/headers.
6. **Can an attacker forge `Authentication-Results`?** Yes if it is not stripped by the receiving server - hence EmailGuard re-verifies and labels header values as unverified claims.
7. **Is a high risk score proof of phishing?** No - it is heuristic and explainable; false positives and negatives exist.
8. **Where is the private key stored?** In memory for the session; only written if the user downloads it, optionally encrypted with a passphrase.
9. **What does NOT EVALUATED mean?** The information required for a defensible result was not available; EmailGuard refuses to guess.
10. **How do you prevent SQL injection / XSS?** Parameterised SQL with a whitelist for ORDER BY; HTML-escaping of all message-derived text before rendering.
