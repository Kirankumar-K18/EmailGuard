"""SHA-256 hashing helpers (thin wrappers around :mod:`hashlib`).

EmailGuard never implements SHA-256 itself; it uses the standard library.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import BinaryIO

SHA256_BITS = 256


def to_bytes(data: str | bytes | bytearray) -> bytes:
    """Return ``data`` as bytes (strings are UTF-8 encoded)."""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8")
    raise TypeError(f"Expected str or bytes, got {type(data).__name__}")


def sha256_bytes(data: str | bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest."""
    return hashlib.sha256(to_bytes(data)).digest()


def sha256_hex(data: str | bytes) -> str:
    """Return the SHA-256 digest as a 64-character lowercase hex string."""
    return hashlib.sha256(to_bytes(data)).hexdigest()


def sha256_stream(stream: BinaryIO, chunk_size: int = 1024 * 1024) -> str:
    """Hash a binary file-like object without loading it fully in memory."""
    h = hashlib.sha256()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


def verify_sha256(data: str | bytes, expected_hex: str) -> bool:
    """Integrity check: does ``data`` hash to ``expected_hex``? (constant time)."""
    actual = sha256_hex(data)
    return hmac.compare_digest(actual, (expected_hex or "").strip().lower())


def bit_difference(hex_a: str, hex_b: str) -> tuple[int, int]:
    """Count differing bits between two equal-length hex digests.

    Returns ``(differing_bits, total_bits)``. Used to demonstrate the avalanche
    effect: a one-character change flips roughly half of the 256 output bits.
    """
    if len(hex_a) != len(hex_b):
        raise ValueError("Digests must have the same length")
    a, b = int(hex_a, 16), int(hex_b, 16)
    return bin(a ^ b).count("1"), len(hex_a) * 4
