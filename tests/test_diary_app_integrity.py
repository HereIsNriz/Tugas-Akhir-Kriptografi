"""GUI integration without a display or access to the real user database."""

import ast
import base64
import hashlib
import os
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import Mock

import diary_storage
import rsa_files

SOURCE = Path(__file__).resolve().parents[1] / "diary_app.py"


class AppIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / "source.txt"
        self.source.write_bytes(b"original content")
        self.output = str(self.source) + ".rsa"
        self.dialog = Mock()
        self.files = Mock()
        self.files.askopenfilename.return_value = str(self.source)
        self.files.asksaveasfilename.return_value = self.output
        self.storage = Mock()
        self.storage.save_encrypted_file.return_value = self.output
        self.encrypt = Mock(return_value=b"RSA2ciphertext")
        self.decrypt = Mock(return_value=b"decrypted content")
        self.self = SimpleNamespace(
            user_id=7,
            rsa={"test": "key"},
            password="password",
            e_judul=Mock(),
            t_isi=Mock(),
            config=Mock(),
            update=Mock(),
            refresh_diary=Mock(),
            tulis_baru=Mock(),
            l_file=Mock(),
        )
        self.self.e_judul.get.return_value = "Title"
        self.self.t_isi.get.return_value = "Body"
        self.db = object()
        self.namespace: Dict[str, Any] = dict(
            os=os,
            sqlite3=sqlite3,
            DB=self.db,
            DIFFICULTY="0",
            diary_storage=self.storage,
            messagebox=self.dialog,
            filedialog=self.files,
            rsa_encrypt_bytes=self.encrypt,
            rsa_decrypt_bytes=self.decrypt,
            super_encrypt=lambda text, password: "cipher:" + text,
            GREEN="green",
        )
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        app = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "App"
        )
        methods: List[ast.stmt] = [
            node
            for node in app.body
            if isinstance(node, ast.FunctionDef)
            and node.name in ("simpan_entri", "enkripsi_file", "dekripsi_file")
        ]
        exec(
            compile(ast.Module(body=methods, type_ignores=[]), str(SOURCE), "exec"),
            self.namespace,
        )

    def call(self, name):
        self.namespace[name](self.self)

    def test_entry_calls_atomic_helper(self):
        self.call("simpan_entri")
        self.storage.save_entry.assert_called_once_with(
            self.db, 7, "cipher:Title", "cipher:Body", "0"
        )
        self.self.tulis_baru.assert_called_once()
        self.dialog.showinfo.assert_called_once()

    def test_failed_entry_does_not_clear_unsaved_text_or_claim_success(self):
        self.storage.save_entry.side_effect = sqlite3.OperationalError("disk full")
        self.call("simpan_entri")
        self.self.tulis_baru.assert_not_called()
        self.self.refresh_diary.assert_not_called()
        self.dialog.showinfo.assert_not_called()
        self.dialog.showerror.assert_called_once()

    def test_encryption_calls_exclusive_file_and_block_helper(self):
        self.call("enkripsi_file")
        self.storage.save_encrypted_file.assert_called_once_with(
            self.db, self.output, b"RSA2ciphertext", 7, "0"
        )
        self.self.config.assert_called_with(cursor="")
        self.self.l_file.config.assert_called_once()

    def test_cancel_save_never_encrypts_or_writes(self):
        self.files.asksaveasfilename.return_value = ""
        self.call("enkripsi_file")
        self.encrypt.assert_not_called()
        self.storage.save_encrypted_file.assert_not_called()

    def test_existing_file_error_keeps_source_and_restores_cursor(self):
        self.storage.save_encrypted_file.side_effect = FileExistsError("exists")
        self.call("enkripsi_file")
        self.assertEqual(self.source.read_bytes(), b"original content")
        self.dialog.showerror.assert_called_once()
        self.self.config.assert_called_with(cursor="")
        self.self.l_file.config.assert_not_called()

    def test_source_io_failure_is_reported(self):
        self.source.unlink()
        self.call("enkripsi_file")
        self.dialog.showerror.assert_called_once()
        self.storage.save_encrypted_file.assert_not_called()
        self.self.config.assert_called_with(cursor="")

    def test_failed_decryption_never_offers_to_save_garbage(self):
        self.decrypt.side_effect = ValueError("bad checksum")
        self.call("dekripsi_file")
        self.files.asksaveasfilename.assert_not_called()
        self.dialog.showerror.assert_called_once()
        self.assertFalse(Path(self.output).exists())
        self.self.config.assert_called_with(cursor="")

    def test_decryption_refuses_to_overwrite_existing_file(self):
        self.files.asksaveasfilename.return_value = str(self.source)
        self.call("dekripsi_file")
        self.assertEqual(self.source.read_bytes(), b"original content")
        self.dialog.showerror.assert_called_once()
        self.self.l_file.config.assert_not_called()

    def test_legacy_format_warns_without_claiming_integrity(self):
        self.source.write_bytes(b"RSAFlegacy")
        self.call("dekripsi_file")
        self.dialog.showwarning.assert_called_once()
        self.assertEqual(Path(self.output).read_bytes(), b"decrypted content")


class StartupAndWrapperTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE entries(id INTEGER PRIMARY KEY, user_id INTEGER, tanggal TEXT,
                                 judul_enc TEXT, isi_enc TEXT);
            CREATE TABLE blocks(idx INTEGER PRIMARY KEY, ts TEXT, data TEXT, prev_hash TEXT,
                                nonce INTEGER, hash TEXT, user_id INTEGER);
        """)
        self.tree = ast.parse(SOURCE.read_text(encoding="utf-8"))

    def test_startup_does_not_recreate_deleted_chain_for_existing_entries(self):
        self.db.execute("INSERT INTO entries VALUES(1,1,'date','title','body')")
        self.db.commit()
        guard = next(
            node
            for node in self.tree.body
            if isinstance(node, ast.If)
            and "COUNT(*) FROM blocks"
            in (ast.get_source_segment(SOURCE.read_text(encoding="utf-8"), node) or "")
        )
        append = Mock()
        exec(
            compile(ast.Module(body=[guard], type_ignores=[]), str(SOURCE), "exec"),
            dict(DB=self.db, tambah_blok=append),
        )
        append.assert_not_called()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM blocks").fetchone()[0], 0
        )

    def test_wrappers_use_real_backends_with_in_memory_database(self):
        names = {
            "rsa_encrypt_bytes",
            "rsa_decrypt_bytes",
            "tambah_blok",
            "verifikasi_chain",
        }
        nodes: List[ast.stmt] = [
            node
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name in names
        ]
        namespace: Dict[str, Any] = dict(
            DB=self.db,
            diary_storage=diary_storage,
            rsa_files=rsa_files,
            BASE="unused",
            DATA="unused",
            DIFFICULTY="0",
        )
        exec(
            compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec"),
            namespace,
        )
        namespace["tambah_blok"](diary_storage.GENESIS, 0)
        self.assertTrue(namespace["verifikasi_chain"]()[0])
        diary_storage.save_entry(self.db, 1, "titlecipher", "bodycipher", "0")
        self.assertTrue(namespace["verifikasi_chain"]()[0])


class EndToEndStorageTests(unittest.TestCase):
    def test_real_key_crypto_storage_and_external_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = sqlite3.connect(":memory:")
            self.addCleanup(db.close)
            db.executescript("""
                CREATE TABLE entries(id INTEGER PRIMARY KEY, user_id INTEGER, tanggal TEXT,
                                     judul_enc TEXT, isi_enc TEXT);
                CREATE TABLE blocks(idx INTEGER PRIMARY KEY, ts TEXT, data TEXT, prev_hash TEXT,
                                    nonce INTEGER, hash TEXT, user_id INTEGER);
            """)
            names = {
                "_is_prime",
                "_gen_prime",
                "rsa_keygen",
                "rsa_encrypt_bytes",
                "rsa_decrypt_bytes",
                "vigenere_enc",
                "vigenere_dec",
                "lfsr_keystream",
                "_lfsr_xor",
                "super_encrypt",
                "super_decrypt",
            }
            tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
            namespace: Dict[str, Any] = dict(
                hashlib=hashlib, base64=base64, secrets=secrets, rsa_files=rsa_files
            )
            nodes: List[ast.stmt] = [
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name in names
            ]
            exec(
                compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec"),
                namespace,
            )
            key = namespace["rsa_keygen"]()
            diary_storage.append_block(db, diary_storage.GENESIS, 0, "0")
            title, body, password = (
                "Catatan rahasia",
                "Isi diary: 日本語 dan emoji 🔒",
                "password-ku",
            )
            title_cipher = namespace["super_encrypt"](title, password)
            body_cipher = namespace["super_encrypt"](body, password)
            entry_id = diary_storage.save_entry(db, 1, title_cipher, body_cipher, "0")
            saved = db.execute(
                "SELECT judul_enc, isi_enc FROM entries WHERE id=? AND user_id=?",
                (entry_id, 1),
            ).fetchone()
            self.assertEqual(namespace["super_decrypt"](saved[0], password), title)
            self.assertEqual(namespace["super_decrypt"](saved[1], password), body)
            self.assertIsNone(
                db.execute(
                    "SELECT id FROM entries WHERE id=? AND user_id=?", (entry_id, 2)
                ).fetchone()
            )
            payload = bytes(range(256)) * 4
            encrypted = namespace["rsa_encrypt_bytes"](payload, key)
            external = root / "external"
            external.mkdir()
            destination = external / "file.rsa"
            diary_storage.save_encrypted_file(db, destination, encrypted, 1, "0")
            self.assertEqual(
                namespace["rsa_decrypt_bytes"](destination.read_bytes(), key), payload
            )
            project = root / "project"
            self.assertTrue(
                diary_storage.verify_chain(db, project, project / "data", "0")[0]
            )
            destination.write_bytes(encrypted[:-1])
            self.assertFalse(
                diary_storage.verify_chain(db, project, project / "data", "0")[0]
            )


if __name__ == "__main__":
    unittest.main()
