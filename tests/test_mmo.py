"""AES-MMO-128 / HMAC-AES-MMO-128 / install-code CRC tests (Zigbee R23 Annex B.4, C.5).

Expected digests:
* C.5 single-byte, 16-byte and 8191-byte vectors are the published spec values.
* For 8192, 8201 and 8202 bytes (long padding form) the digests are cross-checked
  against ``_reference_mmo`` below, an independent bit-level implementation written
  from the R23 B.4 padding text, and pinned. They are not copied from the spec.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from vicare_direct.zigbee_direct.mmo import (
    hmac_aes_mmo,
    install_code_crc16,
    mmo_hash,
    mmo_pad,
)

_N = 16  # R23 B.4: n = block size in bits / 8


def _reference_mmo(message: bytes) -> bytes:
    """Bit-string implementation of R23 Annex B.4, independent of ``mmo_pad``."""
    bits = "".join(f"{b:08b}" for b in message)
    length = len(bits)
    if length < 2**_N:
        k = (7 * _N - (length + 1)) % (8 * _N)
        bits += "1" + "0" * k + format(length, f"0{_N}b")
    else:
        k = (5 * _N - (length + 1)) % (8 * _N)
        bits += "1" + "0" * k + format(length, f"0{2 * _N}b") + "0" * _N
    assert len(bits) % 128 == 0
    padded = int(bits, 2).to_bytes(len(bits) // 8, "big")
    h = bytes(16)
    for i in range(0, len(padded), 16):
        m = padded[i : i + 16]
        enc = Cipher(algorithms.AES(h), modes.ECB()).encryptor()  # noqa: S305
        e = enc.update(m) + enc.finalize()
        h = bytes(x ^ y for x, y in zip(e, m, strict=True))
    return h


def _pattern(n: int) -> bytes:
    """C.5 long-message construction: bytes 0x00, 0x01, ..., 0xFF repeating."""
    return bytes(i % 256 for i in range(n))


@pytest.mark.parametrize(
    ("message", "digest"),
    [
        (b"\xc0", "ae3a102a28d43ee0d4a09e22788b206c"),  # secret-scan: allow
        (bytes(range(0xC0, 0xD0)), "a7977e88bc0b61e8210827109a228f2d"),  # secret-scan: allow
        (_pattern(8191), "24ec2fe75bbffcb34789bc0610e7f165"),  # secret-scan: allow
    ],
    ids=["C.5.1-1byte", "C.5.2-16bytes", "C.5.3-8191bytes"],
)
def test_spec_vectors(message: bytes, digest: str) -> None:
    assert mmo_hash(message).hex() == digest


@pytest.mark.parametrize(
    ("length", "digest"),
    [
        (8192, "dc6b0687f09f8607131c170b3bd31591"),  # secret-scan: allow
        (8201, "72c9b15e178aa843e4a16c58e33643a3"),  # secret-scan: allow
        (8202, "bc9828d59b2aa323daf20be5f2e66511"),  # secret-scan: allow
    ],
)
def test_long_form_vectors_match_reference(length: int, digest: str) -> None:
    message = _pattern(length)
    assert mmo_hash(message) == _reference_mmo(message)
    assert mmo_hash(message).hex() == digest


@pytest.mark.parametrize(
    "length",
    [0, 1, 12, 13, 14, 15, 16, 28, 29, 30, 31, 32, 8190, 8191, 8192, 8193, 8200, 8201, 8202],
)
def test_matches_reference(length: int) -> None:
    message = _pattern(length)
    assert mmo_hash(message) == _reference_mmo(message)


@pytest.mark.parametrize(("length", "padded_len"), [(0, 16), (12, 16), (13, 16), (14, 32)])
def test_short_form_padding_layout(length: int, padded_len: int) -> None:
    padded = mmo_pad(bytes(length))
    assert len(padded) == padded_len
    assert padded[length] == 0x80
    assert padded[-2:] == (length * 8).to_bytes(2, "big")


def test_long_form_padding_layout() -> None:
    padded = mmo_pad(bytes(8192))
    assert len(padded) % 16 == 0
    assert padded[8192] == 0x80
    assert padded[-6:] == (8192 * 8).to_bytes(4, "big") + b"\x00\x00"


def test_short_form_boundary_is_2_pow_16_bits() -> None:
    assert mmo_pad(bytes(8191))[-2:] == (8191 * 8).to_bytes(2, "big")
    assert mmo_pad(bytes(8192))[-2:] == b"\x00\x00"


def test_regression_research_padding_was_wrong_for_len_12() -> None:
    # Research padding (tools/zvd_crypto.py:54-66) used a 32-bit length in the last
    # 4 bytes; for 12 bytes it needed 2 blocks, the spec needs 1.
    assert len(mmo_pad(bytes(12))) == 16


def test_hmac_aes_mmo_definition() -> None:
    key = bytes(range(16))
    msg = b"message"
    inner = mmo_hash(bytes(k ^ 0x36 for k in key) + msg)
    expected = mmo_hash(bytes(k ^ 0x5C for k in key) + inner)
    assert hmac_aes_mmo(key, msg) == expected


def test_hmac_aes_mmo_rejects_bad_key_length() -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        hmac_aes_mmo(bytes(15), b"x")


def test_install_code_crc_known_answer() -> None:
    code = bytes.fromhex("83FED3407A939723A5C639B26916D505")  # secret-scan: allow
    assert install_code_crc16(code).to_bytes(2, "little") == bytes.fromhex("C3B5")


def test_crc16_x25_check_value() -> None:
    # Standard CRC-16/X-25 check value over ASCII "123456789".
    assert install_code_crc16(b"123456789") == 0x906E
