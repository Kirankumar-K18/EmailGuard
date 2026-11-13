import io

import pytest

from modules import hashing


def test_known_sha256_vectors():
    # FIPS 180-4 / NIST test vectors
    assert hashing.sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert hashing.sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert hashing.sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") == (
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")


def test_str_and_bytes_agree_and_digest_length():
    assert hashing.sha256_hex("héllo") == hashing.sha256_hex("héllo".encode("utf-8"))
    assert len(hashing.sha256_bytes("x")) == 32
    assert len(hashing.sha256_hex("x")) == 64


def test_rejects_wrong_type():
    with pytest.raises(TypeError):
        hashing.sha256_hex(123)  # type: ignore[arg-type]


def test_stream_matches_in_memory():
    data = b"A" * 3_000_000
    assert hashing.sha256_stream(io.BytesIO(data), chunk_size=65536) == hashing.sha256_hex(data)


def test_verify_sha256_detects_change():
    digest = hashing.sha256_hex("message")
    assert hashing.verify_sha256("message", digest)
    assert hashing.verify_sha256("message", digest.upper())
    assert not hashing.verify_sha256("Message", digest)
    assert not hashing.verify_sha256("message", "")


def test_avalanche_effect_is_roughly_half():
    a, b = hashing.sha256_hex("The quick brown fox"), hashing.sha256_hex("The quick brown fax")
    diff, total = hashing.bit_difference(a, b)
    assert total == 256
    assert 90 <= diff <= 166  # overwhelmingly likely; deterministic for these inputs


def test_bit_difference_validates_length():
    assert hashing.bit_difference("ff", "00") == (8, 8)
    with pytest.raises(ValueError):
        hashing.bit_difference("ff", "f")
