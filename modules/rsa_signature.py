"""RSA key generation and RSA-PSS (SHA-256) digital signatures.

All primitives come from the ``cryptography`` library (OpenSSL backend);
nothing is implemented by hand.

Important: RSA-PSS is used by the *Digital Signature Lab*. It is **not** what
DKIM uses - DKIM signs with RSASSA-PKCS1-v1_5 over a canonicalised header/body
hash (see ``dkim_verifier.py``).
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import config
from modules.hashing import to_bytes

ALLOWED_KEY_SIZES = (2048, 3072, 4096)


@dataclass
class VerificationResult:
    valid: bool
    reason: str


def generate_keypair(key_size: int = config.RSA_KEY_SIZE) -> rsa.RSAPrivateKey:
    """Generate an RSA private key (public exponent 65537)."""
    if key_size not in ALLOWED_KEY_SIZES:
        raise ValueError(f"key_size must be one of {ALLOWED_KEY_SIZES}")
    return rsa.generate_private_key(public_exponent=config.RSA_PUBLIC_EXPONENT, key_size=key_size)


def private_key_to_pem(private_key: rsa.RSAPrivateKey, passphrase: str | None = None) -> bytes:
    """Serialise to PKCS#8 PEM. With a passphrase the key is encrypted at rest."""
    if passphrase:
        encryption: serialization.KeySerializationEncryption = serialization.BestAvailableEncryption(
            passphrase.encode("utf-8")
        )
    else:
        encryption = serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def public_key_to_pem(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> bytes:
    """Serialise the public key (SubjectPublicKeyInfo PEM)."""
    public_key = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes, passphrase: str | None = None) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem, password=passphrase.encode() if passphrase else None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Not an RSA private key")
    return key


def load_public_key(pem: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Not an RSA public key")
    return key


def key_fingerprint(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> str:
    """SHA-256 fingerprint of the DER SubjectPublicKeyInfo, as colon-separated hex."""
    public_key = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=config.RSA_PSS_SALT_LENGTH)


def sign_message(private_key: rsa.RSAPrivateKey, message: str | bytes) -> bytes:
    """Sign ``message``: SHA-256 hash, then RSA-PSS (MGF1-SHA256, 32-byte salt).

    PSS is probabilistic: signing the same message twice yields different
    (but both valid) signatures.
    """
    return private_key.sign(to_bytes(message), _pss(), hashes.SHA256())


def verify_signature(public_key: rsa.RSAPublicKey, message: str | bytes, signature: bytes) -> VerificationResult:
    """Verify an RSA-PSS signature. Never raises for a bad signature."""
    if not signature:
        return VerificationResult(False, "No signature supplied.")
    try:
        public_key.verify(signature, to_bytes(message), _pss(), hashes.SHA256())
    except InvalidSignature:
        return VerificationResult(
            False,
            "Signature is INVALID: the message or the signature was altered, or a different key was used.",
        )
    except (ValueError, TypeError) as exc:
        return VerificationResult(False, f"Signature could not be processed: {exc}")
    return VerificationResult(True, "Signature is VALID: the message is unchanged and was signed by the matching private key.")


def signature_to_b64(signature: bytes) -> str:
    return base64.b64encode(signature).decode("ascii")


def b64_to_signature(text: str) -> bytes:
    return base64.b64decode(text.strip().encode("ascii"), validate=True)
