"""Educational, deterministic textbook RSA file codec; NOT production security.

No OAEP, authentication, or protection against deliberate forgery is provided.
RSA2 = b'RSA2' + key id (32 bytes) + original length (8-byte big-endian)
       + SHA-256 of plaintext (32 bytes) + encrypted blocks.
The key id is SHA-256(n || e), with both integers encoded as k-byte big-endian
values, where k = ceil(n.bit_length() / 8). Blocks encrypt b'\x01' followed
by at most k-2 plaintext bytes, producing exactly k ciphertext bytes.

RSA2 checks detect accidental corruption, truncation, reordering of distinct
blocks, extra blocks, and wrong keys. Its unkeyed checksum is NOT authenticity;
an attacker can construct a replacement file using the public key. Legacy
RSAF is readable but has no integrity: some modifications and wrong keys cannot
be detected (including any key for an empty file). Stripping RSA2 metadata and
prepending RSAF downgrades to that legacy behavior. Callers needing a security
boundary must not rely on this backwards-compatible codec.
"""

import hashlib
import hmac
import math
from collections.abc import Mapping

__all__ = ["decrypt_bytes", "encrypt_bytes"]

_HEADER_SIZE = 76


def _validate_key(key, private=False):
    if not isinstance(key, Mapping):
        raise ValueError("RSA key must be a mapping of integer components")
    names = ("n", "e", "d", "p", "q") if private else ("n", "e")
    for name in names:
        if name not in key or type(key[name]) is not int or key[name] <= 1:
            raise ValueError(f"RSA key component {name!r} must be an integer > 1")
    n, e = key["n"], key["e"]
    k = (n.bit_length() + 7) // 8
    if n % 2 == 0 or k < 3:
        raise ValueError("RSA modulus n must be odd and at least 3 bytes wide")
    if not 1 < e < n or e % 2 == 0:
        raise ValueError("RSA public exponent e must be odd and satisfy 1 < e < n")
    if private:
        d, p, q = key["d"], key["p"], key["q"]
        if (
            p <= 2
            or q <= 2
            or p % 2 == 0
            or q % 2 == 0
            or p == q
            or p * q != n
            or math.gcd(p, q) != 1
        ):
            raise ValueError(
                "RSA factors p and q must be distinct, odd, coprime, and multiply to n"
            )
        order = (p - 1) // math.gcd(p - 1, q - 1) * (q - 1)
        if not 1 < d < n or (e * d) % order != 1:
            raise ValueError(
                "RSA private exponent d must invert e modulo lcm(p-1, q-1)"
            )
    return n, e, k


def _key_id(n, e, k):
    return hashlib.sha256(n.to_bytes(k, "big") + e.to_bytes(k, "big")).digest()


def encrypt_bytes(data: bytes, key) -> bytes:
    """Encode bytes as RSA2; encryption needs only the public n/e components."""
    if not isinstance(data, bytes):
        raise ValueError("RSA plaintext must be bytes")
    n, e, k = _validate_key(key)
    if len(data) >= 1 << 64:
        raise ValueError("RSA2 plaintext length must fit in 8 bytes")
    out = bytearray(
        b"RSA2"
        + _key_id(n, e, k)
        + len(data).to_bytes(8, "big")
        + hashlib.sha256(data).digest()
    )
    for offset in range(0, len(data), k - 2):
        m = int.from_bytes(b"\x01" + data[offset : offset + k - 2], "big")
        out.extend(pow(m, e, n).to_bytes(k, "big"))
    return bytes(out)


def decrypt_bytes(blob: bytes, key) -> bytes:
    """Decode RSA2 or structurally valid legacy RSAF; raise ValueError on failure.

    Decryption requires n/e/d/p/q. Key validation checks arithmetic consistency,
    not primality; key generation and trustworthy key storage remain external.
    """
    if not isinstance(blob, bytes):
        raise ValueError("RSA file must be bytes")
    if blob[:4] not in (b"RSA2", b"RSAF"):
        raise ValueError("Unrecognized RSA file header (expected RSA2 or RSAF)")
    n, e, k = _validate_key(key, private=True)
    modern = blob[:4] == b"RSA2"
    start = _HEADER_SIZE if modern else 4
    if len(blob) < start:
        raise ValueError("Truncated RSA2 header")
    body = memoryview(blob)[start:]
    if len(body) % k:
        raise ValueError(
            "RSA ciphertext length must be a multiple of the modulus width"
        )
    size = k - 2
    count = len(body) // k
    length = None
    if modern:
        if not hmac.compare_digest(blob[4:36], _key_id(n, e, k)):
            raise ValueError("RSA2 key fingerprint does not match the supplied key")
        length = int.from_bytes(blob[36:44], "big")
        if count != (length + size - 1) // size:
            raise ValueError(
                "RSA2 ciphertext block count does not match the original length"
            )
    p, q, d = key["p"], key["q"], key["d"]
    dp, dq, qinv = d % (p - 1), d % (q - 1), pow(q, -1, p)
    out = bytearray()
    for index in range(count):
        c = int.from_bytes(body[index * k : (index + 1) * k], "big")
        if c >= n:
            raise ValueError(f"RSA ciphertext block {index} must be less than n")
        m1, m2 = pow(c, dp, p), pow(c, dq, q)
        m = m2 + (qinv * (m1 - m2) % p) * q
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if not raw.startswith(b"\x01"):
            raise ValueError(f"RSA block {index} has an invalid plaintext prefix")
        chunk = raw[1:]
        expected = size if index < count - 1 else None
        if modern and index == count - 1:
            expected = length - size * (count - 1)
        if not 1 <= len(chunk) <= size or (
            expected is not None and len(chunk) != expected
        ):
            raise ValueError(f"RSA block {index} has an invalid plaintext length")
        out.extend(chunk)
    if modern and not hmac.compare_digest(hashlib.sha256(out).digest(), blob[44:76]):
        raise ValueError("RSA2 plaintext checksum mismatch")
    return bytes(out)
