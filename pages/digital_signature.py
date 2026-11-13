"""PAGE 6 - Digital Signature Lab: RSA-2048, SHA-256 and RSA-PSS, interactively."""
from __future__ import annotations

import streamlit as st

from modules import hashing, rsa_signature as rs
from ui.components import banner, esc, html, method_chip, page_header, status_badge

DEFAULT_MESSAGE = ("From: finance@example.org\nTo: payroll@example.org\nSubject: Salary run approved\n\n"
                   "Please release the October salary run of INR 4,25,000 to the approved account list.\n")


def _state() -> dict:
    return st.session_state.setdefault("sig", {"key": None, "signed_message": None, "signature": None})


def _verification_box(valid: bool, reason: str) -> None:
    html(f'<div class="eg-card"><div style="margin-bottom:.4rem">{status_badge("VERIFIED" if valid else "INVALID", True)} '
         f'{method_chip("CRYPTOGRAPHIC")}</div><p style="color:#E6EDF7">{esc(reason)}</p></div>')


def _tab_lab() -> None:
    s = _state()
    st.markdown("##### Step 1 - Generate an RSA-2048 key pair")
    c1, c2 = st.columns([1, 3])
    if c1.button("Generate new key pair", type="primary", key="sig_gen"):
        with st.spinner("Generating RSA-2048 key (a few seconds)..."):
            s.update(key=rs.generate_keypair(2048), signed_message=None, signature=None)
    key = s["key"]
    if key is None:
        c2.info("No key yet. Generate one to begin. The private key stays in this browser session's memory only; it is never written to disk by the app.")
        return
    pub_pem = rs.public_key_to_pem(key).decode()
    c2.success(f"Key pair ready - {key.key_size}-bit RSA, public exponent {key.public_key().public_numbers().e}. Fingerprint (SHA-256 of public key): {rs.key_fingerprint(key)[:47]}...")
    with st.expander("Public key (PEM)"):
        st.code(pub_pem, language="text")

    st.markdown("##### Step 2 - Enter the e-mail message and hash it (SHA-256)")
    message = st.text_area("Original message", value=DEFAULT_MESSAGE, height=170, key="sig_msg")
    digest = hashing.sha256_hex(message)
    st.markdown("**SHA-256 digest of the message** (64 hex characters = 256 bits)")
    st.code(digest, language="text")

    st.markdown("##### Step 3 - Sign with the private key (RSA-PSS)")
    st.caption("The message is hashed with SHA-256, then the digest is padded with PSS (MGF1-SHA256, 32-byte random salt) and transformed with the private exponent. "
               "PSS is probabilistic: signing the same message twice produces different - but equally valid - signatures.")
    if st.button("Sign message", key="sig_sign"):
        s["signed_message"] = message
        s["signature"] = rs.sign_message(key, message)
        s["sign_n"] = s.get("sign_n", 0) + 1  # new widget key so the tamper box resets to the newly signed text
    sig: bytes | None = s["signature"]
    if sig is None:
        st.info("Press 'Sign message' to create a signature.")
        return
    b64 = rs.signature_to_b64(sig)
    st.markdown(f"**Digital signature** ({len(sig) * 8} bits, Base64)")
    st.code(b64, language="text", wrap_lines=True)
    signed_message = s["signed_message"]

    st.markdown("##### Step 4 - Verify with the public key")
    res = rs.verify_signature(key.public_key(), signed_message, sig)
    st.caption("Verifying the original, unmodified message that was signed:")
    _verification_box(res.valid, res.reason)

    st.markdown("##### Step 5 - Tamper with the message and verify again")
    tampered = st.text_area("Received message (edit it - change any character - then see the result)", value=signed_message, height=150, key=f"sig_msg_edit_{s.get('sign_n', 0)}")
    t_digest = hashing.sha256_hex(tampered)
    t_res = rs.verify_signature(key.public_key(), tampered, sig)
    changed = tampered != signed_message
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**SHA-256 of received message**")
        st.code(t_digest, language="text")
    with c2:
        if changed:
            diff, total = hashing.bit_difference(hashing.sha256_hex(signed_message), t_digest)
            st.metric("Avalanche effect: output bits changed", f"{diff} / {total}", f"{100 * diff / total:.0f}% (about 50% expected)")
        else:
            st.metric("Avalanche effect: output bits changed", "0 / 256", "message identical")
    _verification_box(t_res.valid, t_res.reason if changed else "The message is unchanged, so the signature verifies. Edit the text above to see it fail.")
    if changed and not t_res.valid:
        st.error("Integrity violation detected: the signature no longer matches this message. Even a one-character change makes the SHA-256 digest completely different.")

    st.markdown("##### Step 6 - Tamper with the signature")
    if st.button("Flip one bit of the signature and verify", key="sig_flip"):
        broken = bytearray(sig)
        broken[10] ^= 0x01
        r = rs.verify_signature(key.public_key(), signed_message, bytes(broken))
        _verification_box(r.valid, r.reason)

    st.markdown("##### Download keys (educational use only)")
    banner("These are demonstration keys. Never use them to protect real communications, never upload them anywhere and delete the files when finished. "
           "Anyone holding the private key can forge signatures in your name.", "danger")
    passphrase = st.text_input("Optional passphrase to encrypt the private-key file", type="password", key="sig_pass",
                               help="With a passphrase the PEM is encrypted (PKCS#8, best available algorithm). Strongly recommended.")
    d1, d2 = st.columns(2)
    d1.download_button("Download public key (.pem)", pub_pem, file_name="emailguard_demo_public.pem", mime="application/x-pem-file", key="sig_dl_pub")
    priv_pem = rs.private_key_to_pem(key, passphrase or None)
    d2.download_button("Download private key (.pem)" + (" - encrypted" if passphrase else " - UNENCRYPTED"), priv_pem,
                       file_name="emailguard_demo_private.pem", mime="application/x-pem-file", key="sig_dl_priv")
    if not passphrase:
        st.caption("The private key will be downloaded without encryption. Enter a passphrase above to protect it.")


def _tab_verify_external() -> None:
    st.write("Verify a signature produced elsewhere (for example by the lab above in a previous session) using a public key PEM, the exact message and the Base64 signature.")
    pub = st.text_area("Public key (PEM)", height=130, key="sig_ext_pub")
    msg = st.text_area("Message (exact text)", height=110, key="sig_ext_msg")
    sig = st.text_area("Signature (Base64)", height=90, key="sig_ext_sig")
    if st.button("Verify signature", key="sig_ext_go"):
        try:
            public_key = rs.load_public_key(pub.encode())
            signature = rs.b64_to_signature(sig)
        except Exception as exc:
            st.error(f"Input could not be read: {exc}")
            return
        r = rs.verify_signature(public_key, msg, signature)
        _verification_box(r.valid, r.reason)


def _tab_concepts() -> None:
    st.markdown("##### Cryptographic concepts used in EmailGuard")
    c1, c2 = st.columns(2)
    with c1:
        html('<div class="eg-card"><h4>Symmetric vs asymmetric encryption</h4>'
             '<p><b>Symmetric</b> (AES, ChaCha20): one shared secret key encrypts and decrypts. Fast, suited to bulk data, but the key must be shared securely.</p>'
             '<p><b>Asymmetric</b> (RSA, ECC): a public key and a private key. Anyone can encrypt with the public key; only the private-key holder decrypts. '
             'Slower, so it is used for key exchange and signatures, not for bulk data.</p>'
             '<p>Hybrid designs (TLS, S/MIME, PGP) use asymmetric crypto to exchange a symmetric session key.</p></div>')
        html('<div class="eg-card"><h4>Hashing vs encryption</h4>'
             '<p><b>Hashing</b> (SHA-256) is one-way and keyless: it maps any input to a fixed 256-bit fingerprint. It cannot be reversed and detects changes (integrity).</p>'
             '<p><b>Encryption</b> is two-way and keyed: ciphertext can be turned back into the plaintext by the right key (confidentiality).</p></div>')
        html('<div class="eg-card"><h4>Digital signatures</h4>'
             '<p>Hash the message, then transform the digest with the <b>private</b> key. Anyone can check it with the <b>public</b> key. '
             'It provides <b>integrity</b>, <b>authenticity</b> and <b>non-repudiation</b>, but not confidentiality. '
             'RSA-PSS adds randomised padding, with a security proof that older PKCS#1 v1.5 padding lacks.</p></div>')
    with c2:
        html('<div class="eg-card"><h4>SPF - Sender Policy Framework</h4>'
             '<p>DNS lists which <b>IP addresses</b> may send mail for a domain. Receivers compare the connecting IP with the envelope sender\'s record. '
             'Authenticates the <i>server</i>; breaks on forwarding; no cryptography.</p></div>')
        html('<div class="eg-card"><h4>DKIM - DomainKeys Identified Mail</h4>'
             '<p>The sending domain <b>signs</b> chosen headers and the body hash with an RSA private key; the public key is in DNS (<code>selector._domainkey.domain</code>). '
             'Proves the message was authorised by that domain and not altered. Uses RSASSA-PKCS1-v1_5 with canonicalisation (not PSS).</p></div>')
        html('<div class="eg-card"><h4>DMARC</h4>'
             '<p>Ties SPF and DKIM to the visible <b>From</b> domain through <b>alignment</b>, publishes a policy (none / quarantine / reject) and requests reports. '
             'It adds no new cryptography: it decides what receivers do when alignment fails.</p></div>')


def render() -> None:
    page_header("Digital Signature Lab", "RSA-2048 key generation, SHA-256 hashing and RSA-PSS signatures - sign, verify, tamper, fail.", "lock")
    banner("This lab is an educational demonstration of RSA-PSS. It is separate from DKIM, which uses its own canonicalisation and RSASSA-PKCS1-v1_5 signatures. "
           "All primitives come from the 'cryptography' library (OpenSSL); nothing is implemented by hand.", "info")
    t1, t2, t3 = st.tabs(["Signature lab", "Verify external signature", "Concepts"])
    with t1:
        _tab_lab()
    with t2:
        _tab_verify_external()
    with t3:
        _tab_concepts()
