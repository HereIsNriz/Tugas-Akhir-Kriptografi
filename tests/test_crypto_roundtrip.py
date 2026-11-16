"""Test extracted functions without importing diary_app or opening its real DB.

Run: python -B -m unittest discover -s tests -p test_crypto_roundtrip.py -v
The legacy cipher is unauthenticated: wrong passwords need not raise an error.
"""

import ast
import base64
import binascii
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

try:
    from PIL import Image as PillowImage
except ImportError:
    PillowImage = None


FUNCTION_NAMES = frozenset(
    (
        "vigenere_enc",
        "vigenere_dec",
        "lfsr_keystream",
        "_lfsr_xor",
        "super_encrypt",
        "super_decrypt",
        "stego_embed",
        "stego_extract",
    )
)


def extract_functions():
    path = Path(__file__).resolve().parents[1] / "diary_app.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    nodes = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in FUNCTION_NAMES
    ]
    missing = FUNCTION_NAMES - {node.name for node in nodes}
    if missing:
        raise AssertionError(f"Missing crypto functions: {sorted(missing)}")
    namespace = dict(hashlib=hashlib, base64=base64, Image=PillowImage)
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"),
        namespace,
    )
    return SimpleNamespace(**{name: namespace[name] for name in FUNCTION_NAMES})


class CryptoRoundtripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto = extract_functions()

    def test_text_roundtrips(self):
        texts = (
            "",
            "A diary entry",
            "Catatan rahasia: café, 日本語, 😀, e\u0301",
            "first line\nsecond line\r\n\tlast line\n",
            "\x00before\x00after\x00",
        )
        for text in texts:
            for password in ("password", "kunci-🔑-日本語"):
                with self.subTest(text=text, password=password):
                    ciphertext = self.crypto.super_encrypt(text, password)
                    self.assertIsInstance(ciphertext, str)
                    self.assertEqual(
                        len(base64.b64decode(ciphertext, validate=True)),
                        len(text.encode("utf-8")),
                    )
                    self.assertEqual(
                        self.crypto.super_decrypt(ciphertext, password), text
                    )

    def test_long_text_roundtrip(self):
        text = "Catatan 😀 日本語\n\x00" * 4096
        ciphertext = self.crypto.super_encrypt(text, "long-text-key")
        self.assertEqual(self.crypto.super_decrypt(ciphertext, "long-text-key"), text)

    def test_different_passwords_produce_different_ciphertexts(self):
        text = "Same plaintext, different keys: 😀\n\x00"
        first = self.crypto.super_encrypt(text, "first-password")
        second = self.crypto.super_encrypt(text, "second-password")
        self.assertNotEqual(first, second)
        self.assertEqual(self.crypto.super_decrypt(first, "first-password"), text)
        self.assertEqual(self.crypto.super_decrypt(second, "second-password"), text)

    def test_super_cipher_rejects_empty_password(self):
        for text in ("", "text"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self.crypto.super_encrypt(text, "")
        for ciphertext in ("", "YQ=="):
            with self.subTest(ciphertext=ciphertext):
                with self.assertRaises(ValueError):
                    self.crypto.super_decrypt(ciphertext, "")

    def test_strict_base64_rejects_malformed_input(self):
        valid = self.crypto.super_encrypt("x", "password")
        malformed = (
            "!" + valid,
            valid[:2] + "!" + valid[2:],
            " " + valid,
            valid + "\n",
            valid[:2] + "\t" + valid[2:],
            valid.rstrip("="),
            valid + "=",
            valid + "AAAA",
            "====",
            "A",
        )
        for ciphertext in malformed:
            with self.subTest(ciphertext=ciphertext):
                with self.assertRaises(binascii.Error):
                    self.crypto.super_decrypt(ciphertext, "password")

    def test_vigenere_all_bytes_roundtrip(self):
        data = bytes(range(256)) * 3
        for key in (b"\x00", b"\xff", b"key", bytes(range(256))):
            with self.subTest(key=key):
                encrypted = self.crypto.vigenere_enc(data, key)
                self.assertEqual(len(encrypted), len(data))
                self.assertEqual(self.crypto.vigenere_dec(encrypted, key), data)

    def test_vigenere_wraparound(self):
        self.assertEqual(self.crypto.vigenere_enc(b"\xff\x00", b"\x01"), b"\x00\x01")
        self.assertEqual(self.crypto.vigenere_dec(b"\x00\x01", b"\x01"), b"\xff\x00")

    def test_vigenere_empty_input_and_empty_key(self):
        for function in (self.crypto.vigenere_enc, self.crypto.vigenere_dec):
            self.assertEqual(function(b"", b"key"), b"")
            for data in (b"", b"text", bytes(range(256))):
                with self.subTest(function=function.__name__, data=data):
                    with self.assertRaises(ValueError):
                        function(data, b"")

    def test_lfsr_reproducibility_length_and_prefix(self):
        for seed in (1, 0x1234, 0xFFFF):
            with self.subTest(seed=seed):
                stream = self.crypto.lfsr_keystream(seed, 1024)
                self.assertIsInstance(stream, bytes)
                self.assertEqual(len(stream), 1024)
                self.assertEqual(stream, self.crypto.lfsr_keystream(seed, 1024))
                self.assertEqual(stream[:17], self.crypto.lfsr_keystream(seed, 17))
                self.assertEqual(self.crypto.lfsr_keystream(seed, 0), b"")
        self.assertNotEqual(
            self.crypto.lfsr_keystream(1, 64), self.crypto.lfsr_keystream(2, 64)
        )

    def test_lfsr_zero_seed_falls_back_after_16_bit_mask(self):
        expected = self.crypto.lfsr_keystream(0xACE1, 128)
        for seed in (0, 0x10000, 0x20000):
            with self.subTest(seed=seed):
                self.assertEqual(self.crypto.lfsr_keystream(seed, 128), expected)
        self.assertEqual(
            self.crypto.lfsr_keystream(0x11234, 128),
            self.crypto.lfsr_keystream(0x1234, 128),
        )

    def test_lfsr_xor_is_its_own_inverse(self):
        for data in (b"", bytes(range(256)) * 4):
            for password in ("password", "🔑"):
                with self.subTest(length=len(data), password=password):
                    encrypted = self.crypto._lfsr_xor(data, password)
                    self.assertEqual(len(encrypted), len(data))
                    self.assertEqual(self.crypto._lfsr_xor(encrypted, password), data)


@unittest.skipIf(PillowImage is None, "Pillow is not installed")
class StegoRoundtripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto = extract_functions()

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.source = self.directory / "source.png"
        self.output = self.directory / "output.png"

    def make_image(self, size=(16, 16), color=(120, 122, 124)):
        with PillowImage.new("RGB", size, color) as image:
            image.save(self.source, "PNG")

    def write_length_header(self, length):
        # Independent fixture encoder, not the embed function under test.
        bits = f"{length:032b}"
        channels = [120] * (16 * 16 * 3)
        for index, bit in enumerate(bits):
            channels[index] |= int(bit)
        with PillowImage.new("RGB", (16, 16)) as image:
            image.putdata(
                [tuple(channels[i : i + 3]) for i in range(0, len(channels), 3)]
            )
            image.save(self.source, "PNG")

    def test_encrypted_unicode_payload_roundtrip(self):
        self.make_image((64, 64))
        text = "Catatan rahasia 😀 日本語\nbaris kedua\x00akhir"
        password = "kunci-🔑"
        payload = self.crypto.super_encrypt(text, password).encode("ascii")
        original = self.source.read_bytes()
        self.crypto.stego_embed(self.source, self.output, payload)
        extracted = self.crypto.stego_extract(self.output)
        self.assertEqual(extracted, payload)
        self.assertEqual(
            self.crypto.super_decrypt(extracted.decode("ascii"), password), text
        )
        self.assertEqual(self.source.read_bytes(), original)
        with PillowImage.open(self.output) as image:
            self.assertEqual(image.format, "PNG")
            self.assertEqual(image.size, (64, 64))

    def test_header_is_four_byte_big_endian_payload_length(self):
        self.make_image((32, 24))
        payload = bytes(range(256)) + b"\x00\xff"
        self.crypto.stego_embed(self.source, self.output, payload)
        with PillowImage.open(self.output) as image:
            channels = [
                channel for pixel in image.convert("RGB").getdata() for channel in pixel
            ]
        bits = "".join(str(channel & 1) for channel in channels[:32])
        header = bytes(int(bits[i : i + 8], 2) for i in range(0, 32, 8))
        self.assertEqual(header, b"\x00\x00\x01\x02")
        self.assertEqual(self.crypto.stego_extract(self.output), payload)

    def test_exact_capacity_boundary(self):
        # 8 * 8 * 3 = 192 bits: exactly 4 header bytes + 20 payload bytes.
        self.make_image((8, 8))
        payload = bytes(range(20))
        self.crypto.stego_embed(self.source, self.output, payload)
        self.assertEqual(self.crypto.stego_extract(self.output), payload)

    def test_one_byte_over_capacity_rejected_without_output(self):
        self.make_image((8, 8))
        original = self.source.read_bytes()
        with self.assertRaises(ValueError):
            self.crypto.stego_embed(self.source, self.output, bytes(range(21)))
        self.assertFalse(self.output.exists())
        self.assertEqual(self.source.read_bytes(), original)

    def test_empty_payload_rejected_without_output(self):
        self.make_image()
        with self.assertRaises(ValueError):
            self.crypto.stego_embed(self.source, self.output, b"")
        self.assertFalse(self.output.exists())

    def test_malformed_lengths_rejected(self):
        capacity = (16 * 16 * 3) // 8 - 4
        for length in (0, capacity + 1, 0xFFFFFFFF):
            with self.subTest(length=length):
                self.write_length_header(length)
                with self.assertRaises(ValueError):
                    self.crypto.stego_extract(self.source)

    def test_tiny_images_rejected(self):
        for size in ((1, 1), (2, 2), (2, 5)):
            for color in ((0, 0, 0), (255, 255, 255)):
                with self.subTest(size=size, color=color):
                    self.make_image(size, color)
                    with self.assertRaises(ValueError):
                        self.crypto.stego_extract(self.source)
                    with self.assertRaises(ValueError):
                        self.crypto.stego_embed(self.source, self.output, b"x")
                    self.assertFalse(self.output.exists())

    def test_image_without_payload_rejected(self):
        self.make_image()
        with self.assertRaises(ValueError):
            self.crypto.stego_extract(self.source)


if __name__ == "__main__":
    unittest.main()
