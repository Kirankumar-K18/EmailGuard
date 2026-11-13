"""PAGE 4 - DKIM verification (real, via dkimpy) plus a clearly separate educational demonstration."""
from __future__ import annotations

import streamlit as st

from modules import dkim_verifier as dv
from modules import rsa_signature
from modules.dns_utils import DictResolver, LiveResolver
from modules.email_parser import EmailParseError, parse_email
from ui.common import read_upload
from ui.components import banner, demo_banner, esc, html, method_chip, page_header, status_badge
from ui.theme import rename_columns, show_table

DEMO_MESSAGE = (
    "From: Alice <alice@alice-demo.example>\r\nTo: Bob <bob@bob-demo.example>\r\nSubject: Quarterly report\r\n"
    "Date: Fri, 13 Nov 2026 09:00:00 +0000\r\nMessage-ID: <q3-report@alice-demo.example>\r\n\r\n"
    "Hi Bob,\r\n\r\nThe quarterly report is attached to the shared drive.\r\n\r\nAlice\r\n"
)


def _show_result(res: dv.DKIMResult, demo: bool) -> None:
    if demo:
        demo_banner("DEMONSTRATION DATA - signed with a throw-away key held in memory; the public key sits in a simulated DNS zone.")
    c1, c2 = st.columns([1, 3])
    with c1:
        html(f'<div class="eg-card"><div style="color:#8A9BB8;font-size:.74rem;letter-spacing:.07em;font-weight:600">DKIM RESULT</div>'
             f'<div style="margin:.4rem 0">{status_badge(res.status, True)}</div>{method_chip("CRYPTOGRAPHIC")}'
             f'<div style="color:#8A9BB8;font-size:.76rem;margin-top:.5rem">key source: {esc(res.data_source)}</div></div>')
    with c2:
        html(f'<div class="eg-card"><h4>Explanation</h4><p style="color:#E6EDF7">{esc(res.explanation)}</p></div>')
    for sig in res.signatures:
        with st.expander(f"Signature {sig.index + 1}: d={sig.domain or '?'} s={sig.selector or '?'} - {sig.status}", expanded=True):
            st.write(sig.explanation)
            show_table([
                {"Field": "Domain (d=)", "Value": sig.domain}, {"Field": "Selector (s=)", "Value": sig.selector},
                {"Field": "Public-key DNS name", "Value": sig.key_query}, {"Field": "Algorithm (a=)", "Value": sig.algorithm},
                {"Field": "Canonicalization (c=)", "Value": sig.canonicalization}, {"Field": "Signed headers (h=)", "Value": ", ".join(sig.signed_headers)},
                {"Field": "Signing identity (i=)", "Value": sig.identity}, {"Field": "Signed at (t=)", "Value": sig.timestamp},
                {"Field": "Expires (x=)", "Value": sig.expiry}, {"Field": "Public key size", "Value": f"{sig.key_bits} bits" if sig.key_bits else ""},
                {"Field": "Library detail", "Value": sig.reason},
            ])
            if sig.key_record:
                st.markdown("**Public-key DNS record**")
                st.code(sig.key_record, language="text", wrap_lines=True)


def render() -> None:
    page_header("DKIM Verification", "Verify DomainKeys Identified Mail signatures against the public key published in DNS.", "key")
    banner("DKIM signatures use RSASSA-PKCS1-v1_5 over a canonicalised hash of selected headers and the body, as defined in RFC 6376. "
           "They are NOT RSA-PSS signatures (those are demonstrated in the Digital Signature Lab). Verification is performed by the maintained 'dkimpy' library.", "info")
    tab_real, tab_demo = st.tabs(["Verify a real message", "Educational demonstration"])

    with tab_real:
        mode = st.radio("Input", ["Upload .eml file", "Paste raw email"], horizontal=True, key="dk_mode")
        raw: bytes | None = None
        if mode == "Upload .eml file":
            raw = read_upload(st.file_uploader("Select an .eml file", type=["eml", "txt"], key="dk_up"))
        else:
            text = st.text_area("Complete raw email (headers and body)", height=240, key="dk_text")
            raw = text.encode("utf-8", errors="replace") if text.strip() else None
            st.caption("Copy-and-paste can change line endings or whitespace and break a genuine signature. Prefer uploading the original .eml.")
        if raw is not None:
            try:
                p = parse_email(raw)
                sums = p.dkim_summary()
                if sums:
                    st.markdown("**DKIM-Signature headers found**")
                    show_table(rename_columns(sums, {"d": "Domain (d=)", "s": "Selector (s=)", "a": "Algorithm (a=)", "c": "Canonicalization (c=)"}))
                else:
                    st.warning("This message has no DKIM-Signature header.")
            except EmailParseError as exc:
                st.error(str(exc))
                raw = None
        c1, c2 = st.columns([1, 3])
        timeout = c1.number_input("DNS timeout (s)", 1.0, 30.0, 5.0, 1.0, key="dk_to")
        if st.button("Verify DKIM signature", type="primary", disabled=raw is None, key="dk_go"):
            with st.spinner("Fetching public key and verifying..."):
                try:
                    st.session_state["dk_result"] = dv.verify_dkim(raw, LiveResolver(timeout=float(timeout)))
                except Exception as exc:
                    st.session_state.pop("dk_result", None)
                    st.error(f"Verification could not be completed: {type(exc).__name__}: {exc}")
        if st.session_state.get("dk_result"):
            _show_result(st.session_state["dk_result"], demo=False)
            with st.expander("Limitations"):
                for lim in dv.DKIM_LIMITATIONS:
                    st.markdown(f"- {lim}")

    with tab_demo:
        demo_banner("DEMONSTRATION DATA - nothing on this tab touches real DNS or a real domain.")
        st.write("Because most test messages have no signature you can check offline, this demonstration creates a genuine DKIM signature with a freshly generated RSA-2048 key "
                 "(using dkimpy), publishes the matching public key in a *simulated* DNS zone, and verifies it. Then you can tamper with the message and watch verification fail.")
        msg_text = st.text_area("Message to sign", value=DEMO_MESSAGE.replace("\r\n", "\n"), height=190, key="dk_demo_msg")
        c1, c2, c3 = st.columns(3)
        domain = c1.text_input("Signing domain (d=)", value="alice-demo.example", key="dk_demo_dom")
        selector = c2.text_input("Selector (s=)", value="demo2026", key="dk_demo_sel")
        if c3.button("Generate key and sign", type="primary", key="dk_demo_sign"):
            try:
                with st.spinner("Generating RSA-2048 key..."):
                    key = rsa_signature.generate_keypair()
                    signed = dv.sign_for_demo(msg_text.encode(), domain.strip(), selector.strip(), rsa_signature.private_key_to_pem(key))
                    st.session_state["dk_demo"] = {"signed": signed.decode("utf-8", "replace"), "record": dv.make_key_record(key.public_key()),
                                                   "domain": domain.strip(), "selector": selector.strip()}
            except Exception as exc:
                st.error(f"Signing failed: {type(exc).__name__}: {exc}")
        demo = st.session_state.get("dk_demo")
        if demo:
            st.markdown("**Signed message (editable - change a character in the body or the Subject to break the signature)**")
            edited = st.text_area("Signed message", value=demo["signed"], height=280, key="dk_demo_edit", label_visibility="collapsed")
            st.markdown("**Simulated DNS TXT record**")
            st.code(f"{demo['selector']}._domainkey.{demo['domain']}  TXT  \"{demo['record'][:90]}...\"", language="text")
            if st.button("Verify (offline, simulated DNS)", key="dk_demo_verify"):
                resolver = DictResolver({f"{demo['selector']}._domainkey.{demo['domain']}": {"TXT": [demo["record"]]}})
                st.session_state["dk_demo_res"] = dv.verify_dkim(edited.encode("utf-8"), resolver)
                st.session_state["dk_demo_verified_text"] = edited
            if st.session_state.get("dk_demo_res"):
                if st.session_state.get("dk_demo_verified_text") != edited:
                    st.info("The message was edited after the last verification. Press 'Verify' again to check the current text.")
                else:
                    _show_result(st.session_state["dk_demo_res"], demo=True)
