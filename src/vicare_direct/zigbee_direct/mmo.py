"""AES-MMO-128 hash, HMAC-AES-MMO-128 and the install-code CRC (Zigbee R23 Annex B).

These are plain-``bytes`` primitives. Callers that handle key material wrap the
results in ``SecretBytes`` (see ``crypto.py``).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16

# R23 B.4: the short padding form is used while the bit length fits in n = 16 bits.
_SHORT_FORM_LIMIT_BITS = 1 << 16
# The long form stores the bit length in 32 bits, so longer inputs are not representable.
_LONG_FORM_LIMIT_BITS = 1 << 32


def _aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 - MMO needs raw AES
    return enc.update(block) + enc.finalize()


def mmo_pad(data: bytes) -> bytes:
    """Return ``data`` padded per Zigbee R23 Annex B.4 (n = 16 bit block-size/8).

    * bit length l < 2**16: append ``0x80``, zero-pad to 14 mod 16 bytes, append
      l as a 16-bit big-endian value.
    * otherwise: append ``0x80``, zero-pad to 10 mod 16 bytes, append l as a
      32-bit big-endian value followed by ``0x0000``.

    Fixes the research padding (``tools/zvd_crypto.py:54-66``), which always used a
    32-bit length in the last 4 bytes and was wrong for len = 12/13 mod 16 and
    for inputs of 8192 bytes or more.
    """
    bit_len = len(data) * 8
    if bit_len >= _LONG_FORM_LIMIT_BITS:
        raise ValueError("AES-MMO input too long (>= 2**32 bits)")
    padded = bytearray(data)
    padded.append(0x80)
    if bit_len < _SHORT_FORM_LIMIT_BITS:
        padded.extend(bytes((14 - len(padded)) % BLOCK_SIZE))
        padded.extend(bit_len.to_bytes(2, "big"))
    else:
        padded.extend(bytes((10 - len(padded)) % BLOCK_SIZE))
        padded.extend(bit_len.to_bytes(4, "big"))
        padded.extend(b"\x00\x00")
    return bytes(padded)


def mmo_hash(data: bytes) -> bytes:
    """Zigbee AES-MMO-128 hash (R23 Annex B.4): ``H_j = E(H_{j-1}, M_j) XOR M_j``, ``H_0 = 0``."""
    padded = mmo_pad(data)
    digest = bytes(BLOCK_SIZE)
    for off in range(0, len(padded), BLOCK_SIZE):
        block = padded[off : off + BLOCK_SIZE]
        enc = _aes128_encrypt_block(digest, block)
        digest = bytes(a ^ b for a, b in zip(enc, block, strict=True))
    return digest


def hmac_aes_mmo(key: bytes, message: bytes) -> bytes:
    """HMAC with AES-MMO-128 as the hash (R23 Annex B.1.4); ``key`` must be 16 bytes."""
    if len(key) != BLOCK_SIZE:
        raise ValueError(f"HMAC-AES-MMO key must be {BLOCK_SIZE} bytes, got {len(key)}")
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5C for k in key)
    return mmo_hash(opad + mmo_hash(ipad + message))


def install_code_crc16(data: bytes) -> int:
    """CRC-16/X-25 (reflected poly 0x8408, init 0xFFFF, final complement) over an install code.

    On the wire the CRC follows the code in little-endian order.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF
