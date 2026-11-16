"""Pure unittest coverage: no diary_app import, database, or random key generation.

Run: python -B -m unittest discover -s tests -p test_rsa_files.py -v
"""

import hashlib
import math
import unittest
from typing import Any, cast
from unittest.mock import patch

from rsa_files import decrypt_bytes, encrypt_bytes

# Fixed 512-bit prime pairs generated independently of the codec under test.
_PRIMES = (
    (
        "8f668adeba5bed12c34a41aaf6bc0b3742deaa079f1bd00887788661c7be0a5b"
        "c7c828969ead9f8eca14c50597982a3252fd0fa2f8ab4e3a3b2aaa25250713f7",
        "d44e7b3d2b20f2fc67593d4e8a763cc66eedcd0fb363ab1e0c4e6f52c21c3de3"
        "1779e925a604fbd2f31d594a5441022c6b0b6a5e2bc29de8f33192b5b18c811b",
    ),
    (
        "9b9a2f32240dde9766e91c92aedbf3545ae8c211d52da723f67a38789b09bc52e"
        "1b4b589a461c914ec46e39a38cd05a490b71c829848087b1f2c369ec2411df1",
        "952b61280b727f76aa0a677bca45d14c64962d2fb35139a1046bf391f11ec7e9f"
        "dff0169f2494a4712d9524c8864633f2240a5534957e3317419d9528833c697",
    ),
)


def make_key(pair):
    p, q = (int(value, 16) for value in pair)
    e = 65537
    order = (p - 1) // math.gcd(p - 1, q - 1) * (q - 1)
    return dict(n=p * q, e=e, d=pow(e, -1, order), p=p, q=q)


def encrypt_raw(raw, key):
    """Independent textbook-RSA encoder, also used for malformed block fixtures."""
    k = (key["n"].bit_length() + 7) // 8
    return pow(int.from_bytes(raw, "big"), key["e"], key["n"]).to_bytes(k, "big")


def legacy_encode(data, key):
    size = (key["n"].bit_length() + 7) // 8 - 2
    return b"RSAF" + b"".join(
        encrypt_raw(b"\x01" + data[i : i + size], key)
        for i in range(0, len(data), size)
    )


class RSAFilesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.other = (make_key(pair) for pair in _PRIMES)
        cls.k = (cls.key["n"].bit_length() + 7) // 8
        cls.size = cls.k - 2

    def test_round_trips_binary_empty_and_boundaries(self):
        for length in (
            0,
            1,
            self.size - 1,
            self.size,
            self.size + 1,
            2 * self.size,
            2 * self.size + 1,
            65536,
        ):
            data = (bytes(range(256)) * (length // 256 + 1))[:length]
            with self.subTest(length=length):
                blob = encrypt_bytes(data, self.key)
                self.assertEqual(decrypt_bytes(blob, self.key), data)
                self.assertEqual(
                    len(blob), 76 + ((length + self.size - 1) // self.size) * self.k
                )

    def test_wire_format_and_independent_ciphertext(self):
        data = b"\x00\x00binary\xff\x00" * 30
        blob = encrypt_bytes(data, self.key)
        n, e = self.key["n"], self.key["e"]
        fingerprint = hashlib.sha256(
            n.to_bytes(self.k, "big") + e.to_bytes(self.k, "big")
        ).digest()
        expected = (
            b"RSA2"
            + fingerprint
            + len(data).to_bytes(8, "big")
            + hashlib.sha256(data).digest()
            + legacy_encode(data, self.key)[4:]
        )
        self.assertEqual(blob, expected)
        self.assertEqual(decrypt_bytes(expected, self.key), data)
        self.assertEqual(
            encrypt_bytes(data, self.key), blob
        )  # Explicitly deterministic.

    def test_public_only_encryption_and_no_key_mutation(self):
        public = {name: self.key[name] for name in ("n", "e")}
        original = self.key.copy()
        blob = encrypt_bytes(b"public", public)
        self.assertEqual(decrypt_bytes(blob, self.key), b"public")
        self.assertEqual(self.key, original)
        self.assertEqual(set(public), {"n", "e"})

    def test_legacy_valid_empty_binary_and_partial_last_block(self):
        for data in (
            b"",
            b"\x00",
            bytes(range(256)),
            b"\x00" * self.size,
            b"x" * (self.size * 2),
            b"\xff" * (self.size + 1),
        ):
            with self.subTest(length=len(data)):
                self.assertEqual(
                    decrypt_bytes(legacy_encode(data, self.key), self.key), data
                )

    def test_legacy_zero_and_short_malformed_bodies(self):
        self.assertEqual(decrypt_bytes(b"RSAF", self.key), b"")
        for length in (1, self.k - 1, self.k + 1):
            with self.subTest(length=length):
                with self.assertRaisesRegex(ValueError, "multiple"):
                    decrypt_bytes(b"RSAF" + bytes(length), self.key)
        with self.assertRaisesRegex(ValueError, "prefix"):
            decrypt_bytes(b"RSAF" + bytes(self.k), self.key)
        with self.assertRaisesRegex(ValueError, "length"):
            decrypt_bytes(b"RSAF" + encrypt_raw(b"\x01", self.key), self.key)

    def test_unknown_and_truncated_headers(self):
        valid = encrypt_bytes(b"", self.key)
        for blob in (b"", b"RSA", b"NOPE", b"rsa2"):
            with self.subTest(blob=blob), self.assertRaisesRegex(ValueError, "header"):
                decrypt_bytes(blob, self.key)
        for length in range(4, 76):
            with self.subTest(length=length):
                with self.assertRaisesRegex(ValueError, "header"):
                    decrypt_bytes(valid[:length], self.key)

    def test_wrong_key_including_empty_rsa2(self):
        for data in (b"", b"private", bytes(range(256))):
            with self.subTest(length=len(data)):
                with self.assertRaisesRegex(ValueError, "fingerprint"):
                    decrypt_bytes(encrypt_bytes(data, self.key), self.other)
        with self.assertRaises(ValueError):
            decrypt_bytes(legacy_encode(b"private" * 30, self.key), self.other)
        self.assertEqual(decrypt_bytes(b"RSAF", self.other), b"")

    def test_partial_ciphertext_blocks_rejected(self):
        for blob in (legacy_encode(b"abc", self.key), encrypt_bytes(b"abc", self.key)):
            for changed in (blob[:-1], blob + b"\x00"):
                with self.subTest(magic=blob[:4]):
                    with self.assertRaisesRegex(ValueError, "multiple"):
                        decrypt_bytes(changed, self.key)

    def test_ciphertext_integer_must_be_less_than_modulus(self):
        for value in (self.key["n"], self.key["n"] + 1, (1 << (8 * self.k)) - 1):
            block = value.to_bytes(self.k, "big")
            for header in (b"RSAF", encrypt_bytes(b"x", self.key)[:76]):
                with self.subTest(value=value, magic=header[:4]):
                    with self.assertRaisesRegex(ValueError, "less than n"):
                        decrypt_bytes(header + block, self.key)

    def test_invalid_decoded_prefix_and_lengths(self):
        for raw in (b"\x00", b"\x02abc", b"\x01", b"\x01" + b"x" * (self.size + 1)):
            block = encrypt_raw(raw, self.key)
            for header in (b"RSAF", encrypt_bytes(b"x", self.key)[:76]):
                with self.subTest(raw=raw[:5], magic=header[:4]):
                    with self.assertRaises(ValueError):
                        decrypt_bytes(header + block, self.key)
        # A short non-final block is invalid even when its prefix is correct.
        short = encrypt_raw(b"\x01x", self.key)
        full = encrypt_raw(b"\x01" + b"y" * self.size, self.key)
        with self.assertRaisesRegex(ValueError, "length"):
            decrypt_bytes(b"RSAF" + short + full, self.key)

    def test_rsa2_exact_last_block_length(self):
        blob = encrypt_bytes(b"a" * (self.size + 2), self.key)
        # Same block count, but the last decoded block has the wrong length.
        for length in (self.size + 1, self.size + 3):
            changed = blob[:36] + length.to_bytes(8, "big") + blob[44:]
            with self.subTest(length=length):
                with self.assertRaisesRegex(ValueError, "length"):
                    decrypt_bytes(changed, self.key)

    def test_truncated_extra_and_reordered_complete_blocks(self):
        blob = encrypt_bytes(b"a" * self.size + b"b" * self.size + b"end", self.key)
        variants = (
            blob[: -self.k],
            blob[:76],
            blob + blob[76 : 76 + self.k],
            blob[:76]
            + blob[76 + self.k : 76 + 2 * self.k]
            + blob[76 : 76 + self.k]
            + blob[76 + 2 * self.k :],
        )
        for changed in variants:
            with self.subTest(length=len(changed)), self.assertRaises(ValueError):
                decrypt_bytes(changed, self.key)

    def test_duplicate_and_reordered_distinct_blocks_fail_checksum(self):
        data = b"a" * self.size + b"b" * self.size + b"c" * self.size
        blob = encrypt_bytes(data, self.key)
        header = blob[:76]
        first, second, third = (
            blob[76 + i * self.k : 76 + (i + 1) * self.k] for i in range(3)
        )
        self.assertNotEqual(first, second)
        variants = {
            "duplicate": header + first + first + third,
            "reorder": header + second + first + third,
        }
        for name, changed in variants.items():
            with self.subTest(name=name):
                self.assertEqual(len(changed), len(blob))
                with self.assertRaisesRegex(ValueError, "checksum"):
                    decrypt_bytes(changed, self.key)

    def test_corrupted_metadata_and_valid_ciphertext_substitution(self):
        blob = encrypt_bytes(b"a" * self.size, self.key)
        for offset in (4, 35, 44, 75, 76, len(blob) - 1):
            changed = bytearray(blob)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                decrypt_bytes(bytes(changed), self.key)
        replacement = encrypt_raw(b"\x01" + b"b" * self.size, self.key)
        with self.assertRaisesRegex(ValueError, "checksum"):
            decrypt_bytes(blob[:76] + replacement, self.key)
        empty = encrypt_bytes(b"", self.key)
        with self.assertRaisesRegex(ValueError, "checksum"):
            decrypt_bytes(empty[:44] + bytes(32), self.key)

    def test_hostile_length_rejected_before_decryption(self):
        blob = encrypt_bytes(b"x", self.key)
        for length in (0, (1 << 64) - 1):
            changed = blob[:36] + length.to_bytes(8, "big") + blob[44:]
            with self.subTest(length=length):
                with patch("rsa_files.pow", create=True) as modular_pow:
                    with self.assertRaisesRegex(ValueError, "block count"):
                        decrypt_bytes(changed, self.key)
                    modular_pow.assert_not_called()
        empty = encrypt_bytes(b"", self.key)
        with self.assertRaisesRegex(ValueError, "block count"):
            decrypt_bytes(empty + blob[76:], self.key)

    def test_legacy_integrity_and_downgrade_limitations_are_explicit(self):
        data = b"a" * self.size + b"b" * self.size
        modern = encrypt_bytes(data, self.key)
        legacy = b"RSAF" + modern[76:]
        self.assertEqual(decrypt_bytes(legacy, self.key), data)
        self.assertEqual(decrypt_bytes(legacy[: -self.k], self.key), data[: self.size])
        swapped = b"RSAF" + legacy[4 + self.k :] + legacy[4 : 4 + self.k]
        self.assertEqual(
            decrypt_bytes(swapped, self.key), b"b" * self.size + b"a" * self.size
        )

    def test_invalid_keys_raise_actionable_value_errors(self):
        for key in (None, [], {}, {"n": 123}, {"n": True, "e": 3}):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "key|component"):
                    encrypt_bytes(b"", key)
        for name in ("n", "e", "d", "p", "q"):
            for value in (None, True, "17", 0, -1, 1):
                key = dict(self.key, **{name: value})
                with self.subTest(name=name, value=value):
                    with self.assertRaisesRegex(ValueError, name):
                        decrypt_bytes(b"RSAF", key)
            key = self.key.copy()
            del key[name]
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, name):
                decrypt_bytes(b"RSAF", key)
        cases = (
            (dict(self.key, n=257, e=3), "modulus"),
            (dict(self.key, n=self.key["n"] + 1), "modulus"),
            (dict(self.key, e=2), "exponent"),
            (dict(self.key, e=self.key["n"]), "exponent"),
            (dict(self.key, p=self.key["q"]), "factors"),
            (dict(self.key, q=9), "factors"),
            (dict(self.key, d=self.key["d"] + 1), "exponent"),
            (dict(self.key, d=self.key["n"]), "exponent"),
        )
        for key, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    decrypt_bytes(b"RSAF", key)

    def test_non_bytes_inputs_rejected(self):
        for value in (None, "text", 123, bytearray(b"abc"), memoryview(b"abc")):
            for function in (encrypt_bytes, decrypt_bytes):
                with self.subTest(function=function.__name__, value=repr(value)):
                    with self.assertRaisesRegex(ValueError, "bytes"):
                        function(cast(Any, value), self.key)


if __name__ == "__main__":
    unittest.main()
