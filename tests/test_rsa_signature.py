import pytest

from modules import rsa_signature as rs

MESSAGE = "Pay INR 1,000 to account 1234"


def test_key_is_rsa_2048_with_standard_exponent(rsa_key):
    assert rsa_key.key_size == 2048
    assert rsa_key.public_key().public_numbers().e == 65537


def test_unsupported_key_size_rejected():
    with pytest.raises(ValueError):
        rs.generate_keypair(512)


def test_sign_and_verify_roundtrip(rsa_key):
    sig = rs.sign_message(rsa_key, MESSAGE)
    assert len(sig) == 256  # 2048-bit modulus
    res = rs.verify_signature(rsa_key.public_key(), MESSAGE, sig)
    assert res.valid and "VALID" in res.reason


def test_modified_message_fails(rsa_key):
    sig = rs.sign_message(rsa_key, MESSAGE)
    res = rs.verify_signature(rsa_key.public_key(), MESSAGE + " ", sig)
    assert not res.valid and "INVALID" in res.reason


def test_single_character_change_fails(rsa_key):
    sig = rs.sign_message(rsa_key, MESSAGE)
    assert not rs.verify_signature(rsa_key.public_key(), MESSAGE.replace("1,000", "9,000"), sig).valid


def test_modified_signature_fails(rsa_key):
    sig = bytearray(rs.sign_message(rsa_key, MESSAGE))
    sig[5] ^= 0x01
    assert not rs.verify_signature(rsa_key.public_key(), MESSAGE, bytes(sig)).valid


def test_wrong_key_fails(rsa_key):
    other = rs.generate_keypair(2048)
    sig = rs.sign_message(rsa_key, MESSAGE)
    assert not rs.verify_signature(other.public_key(), MESSAGE, sig).valid


def test_pss_is_probabilistic_but_both_valid(rsa_key):
    s1, s2 = rs.sign_message(rsa_key, MESSAGE), rs.sign_message(rsa_key, MESSAGE)
    assert s1 != s2  # random salt
    assert rs.verify_signature(rsa_key.public_key(), MESSAGE, s1).valid
    assert rs.verify_signature(rsa_key.public_key(), MESSAGE, s2).valid


def test_empty_and_truncated_signatures_do_not_raise(rsa_key):
    pub = rsa_key.public_key()
    assert not rs.verify_signature(pub, MESSAGE, b"").valid
    assert not rs.verify_signature(pub, MESSAGE, b"\x00" * 10).valid


def test_bytes_and_str_messages_equivalent(rsa_key):
    sig = rs.sign_message(rsa_key, MESSAGE.encode())
    assert rs.verify_signature(rsa_key.public_key(), MESSAGE, sig).valid


def test_pem_roundtrip_plain_and_encrypted(rsa_key):
    pub_pem = rs.public_key_to_pem(rsa_key)
    assert pub_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    plain = rs.private_key_to_pem(rsa_key)
    assert b"BEGIN PRIVATE KEY" in plain and b"ENCRYPTED" not in plain
    enc = rs.private_key_to_pem(rsa_key, "correct horse")
    assert b"ENCRYPTED" in enc
    sig = rs.sign_message(rsa_key, MESSAGE)
    reloaded = rs.load_private_key(enc, "correct horse")
    assert rs.verify_signature(rs.load_public_key(pub_pem), MESSAGE, sig).valid
    assert reloaded.private_numbers() == rsa_key.private_numbers()
    with pytest.raises(Exception):
        rs.load_private_key(enc, "wrong passphrase")
    with pytest.raises(Exception):
        rs.load_private_key(enc)  # passphrase required


def test_base64_signature_roundtrip(rsa_key):
    sig = rs.sign_message(rsa_key, MESSAGE)
    assert rs.b64_to_signature(rs.signature_to_b64(sig)) == sig
    with pytest.raises(Exception):
        rs.b64_to_signature("not base64 !!!")


def test_fingerprint_format(rsa_key):
    fp = rs.key_fingerprint(rsa_key)
    assert len(fp.split(":")) == 32
    assert fp == rs.key_fingerprint(rsa_key.public_key())
