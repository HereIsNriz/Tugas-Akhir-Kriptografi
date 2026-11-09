"""Isolated storage tests: no app import, live database, or project data access.

Run: python -B -m unittest discover -s tests -p test_diary_storage.py -v
"""

import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

import diary_storage as storage

SCHEMA = """
CREATE TABLE entries(
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, tanggal TEXT,
    judul_enc TEXT, isi_enc TEXT);
CREATE TABLE blocks(
    idx INTEGER PRIMARY KEY, ts TEXT, data TEXT,
    prev_hash TEXT, nonce INTEGER, hash TEXT, user_id INTEGER);
"""
DIFFICULTY = "0"
BLOB = b"RSA2\x00encrypted\xffciphertext"


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def initialize(db):
    db.executescript(SCHEMA)
    storage.append_block(db, storage.GENESIS, user_id=0, difficulty=DIFFICULTY)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        initialize(self.db)
        temporary = tempfile.TemporaryDirectory(prefix="diary-storage-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        project = Path(__file__).resolve().parents[1]
        self.assertNotIn(project, (self.root, *self.root.parents))
        self.base = self.root / "legacy-project"
        self.data = self.base / "data"
        self.outside = self.root / "external"
        self.data.mkdir(parents=True)
        self.outside.mkdir()

    def append(self, data, user_id=1):
        return storage.append_block(self.db, data, user_id, DIFFICULTY)

    def save_entry(self):
        return storage.save_entry(
            self.db, 1, "encrypted-title-秘密", "encrypted-body", DIFFICULTY
        )

    def verify(self):
        return storage.verify_chain(self.db, self.base, self.data, DIFFICULTY)

    def assert_valid(self):
        valid, message = self.verify()
        self.assertIs(valid, True, message)
        self.assertIsInstance(message, str)
        return message

    def assert_invalid(self, reason=None):
        valid, message = self.verify()
        self.assertIs(valid, False, message)
        self.assertTrue(message)
        if reason is not None:
            self.assertIn(reason, message)
        return message

    def snapshot(self):
        return (
            self.db.execute("SELECT * FROM entries ORDER BY id").fetchall(),
            self.db.execute("SELECT * FROM blocks ORDER BY idx").fetchall(),
            self.db.execute("SELECT * FROM sqlite_sequence ORDER BY name").fetchall(),
        )

    def fail_block_inserts(self):
        self.db.executescript("""
            CREATE TRIGGER reject_block BEFORE INSERT ON blocks
            BEGIN
                SELECT RAISE(ABORT, 'injected block insert failure');
            END;
        """)

    def insert_legacy_entry(self):
        timestamp, title, body = "2020-01-02 03:04:05", "old-title", "old-body"
        entry_id = self.db.execute(
            "INSERT INTO entries(user_id, tanggal, judul_enc, isi_enc) VALUES(?,?,?,?)",
            (1, timestamp, title, body),
        ).lastrowid
        self.db.commit()
        event = f"entry:{entry_id}:{digest((title + body).encode('utf-8'))}"
        return entry_id, event

    def test_import_does_not_open_database_files_or_import_app(self):
        spec = importlib.util.spec_from_file_location(
            "_isolated_diary_storage", storage.__file__
        )
        if spec is None or spec.loader is None:
            self.fail("Cannot load the storage module for the import isolation test")
        module = importlib.util.module_from_spec(spec)
        with (
            patch.dict(sys.modules, {"diary_app": None}),
            patch.object(
                sqlite3, "connect", side_effect=AssertionError("DB access")
            ) as connect,
            patch("builtins.open", side_effect=AssertionError("file access")) as opened,
            patch.object(
                Path, "open", side_effect=AssertionError("file access")
            ) as path_open,
        ):
            spec.loader.exec_module(module)
        connect.assert_not_called()
        opened.assert_not_called()
        path_open.assert_not_called()
        self.assertEqual(module.GENESIS, storage.GENESIS)

    def test_save_entry_commits_entry_and_matching_event_atomically(self):
        entry_id = self.save_entry()
        self.assertIsInstance(entry_id, int)
        row = self.db.execute(
            "SELECT * FROM entries WHERE id=?", (entry_id,)
        ).fetchone()
        self.assertEqual(row[1], 1)
        self.assertEqual(row[3:], ("encrypted-title-秘密", "encrypted-body"))
        blocks = self.db.execute("SELECT * FROM blocks ORDER BY idx").fetchall()
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[1][0], 1)
        self.assertEqual(blocks[1][3], blocks[0][5])
        self.assertEqual(blocks[1][6], 1)
        self.assertTrue(blocks[1][2].startswith("entry2:"))
        self.assertEqual(
            json.loads(blocks[1][2][7:]),
            {
                "id": entry_id,
                "user_id": 1,
                "tanggal": row[2],
                "sha256": digest(canonical(list(row[3:])).encode("utf-8")),
            },
        )
        self.assertFalse(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(len(self.snapshot()[0]), 1)
        self.assert_valid()

    def test_save_entry_rolls_back_when_append_raises_after_inserting_block(self):
        before = self.snapshot()
        original = storage._append_block

        def append_then_fail(*args):
            original(*args)
            raise RuntimeError("after block insertion")

        with (
            patch.object(
                storage, "_append_block", side_effect=append_then_fail
            ) as append,
            self.assertRaisesRegex(RuntimeError, "after block insertion"),
        ):
            self.save_entry()
        append.assert_called_once()
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.save_entry(), 1)
        self.assert_valid()

    def test_save_entry_rolls_back_on_sqlite_block_insert_trigger(self):
        self.fail_block_inserts()
        before = self.snapshot()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected block insert"):
            self.save_entry()
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.db.in_transaction)

    def test_standalone_append_commits_and_returns_next_index(self):
        self.assertEqual(
            self.append(
                storage.file_event(self.outside / "missing.enc", digest(BLOB), 1)
            ),
            1,
        )
        self.assertFalse(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(len(self.snapshot()[1]), 2)

    def test_standalone_append_rolls_back_sqlite_failure(self):
        self.fail_block_inserts()
        before = self.snapshot()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected block insert"):
            self.append("unused")
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.db.in_transaction)

    def test_standalone_append_rolls_back_exception_after_insert(self):
        before = self.snapshot()
        original = storage._append_block

        def append_then_fail(*args):
            original(*args)
            raise RuntimeError("after insert")

        with (
            patch.object(storage, "_append_block", side_effect=append_then_fail),
            self.assertRaisesRegex(RuntimeError, "after insert"),
        ):
            self.append("unused")
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.db.in_transaction)

    def test_all_writers_reject_pending_transaction_without_touching_it(self):
        destination = self.outside / "pending.enc"
        operations = {
            "entry": self.save_entry,
            "block": lambda: self.append("unused"),
            "file": lambda: storage.save_encrypted_file(
                self.db, destination, BLOB, 1, DIFFICULTY
            ),
        }
        for name, operation in operations.items():
            with self.subTest(operation=name):
                self.db.execute(
                    "INSERT INTO entries(user_id, tanggal, judul_enc, isi_enc) "
                    "VALUES(1, 'pending', 'title', 'body')"
                )
                before = self.snapshot()
                with (
                    patch.object(storage, "_append_block") as append,
                    self.assertRaises(ValueError),
                ):
                    operation()
                append.assert_not_called()
                self.assertTrue(self.db.in_transaction)
                self.assertEqual(self.snapshot(), before)
                self.assertFalse(destination.exists())
                self.db.rollback()
                self.assertEqual(self.snapshot()[0], [])

    def test_empty_chain_is_unverified_not_success(self):
        self.db.execute("DELETE FROM blocks")
        self.db.commit()
        self.assert_invalid("kosong")

    def test_genesis_only_chain_is_valid(self):
        self.assert_valid()

    def test_wrong_genesis_payload_or_owner_is_rejected_even_with_valid_hash(self):
        self.db.execute("DELETE FROM blocks")
        self.db.commit()
        timestamp = "2020-01-02 03:04:05"
        for data, owner in (("wrong genesis", 0), (storage.GENESIS, 1)):
            with self.subTest(data=data, owner=owner):
                nonce = 0
                block_digest = digest(f"0|{timestamp}|{data}|0|{nonce}".encode())
                while not block_digest.startswith(DIFFICULTY):
                    nonce += 1
                    block_digest = digest(f"0|{timestamp}|{data}|0|{nonce}".encode())
                # Seed corruption directly: the writer now rejects invalid genesis.
                self.db.execute(
                    "INSERT INTO blocks VALUES(?,?,?,?,?,?,?)",
                    (0, timestamp, data, "0", nonce, block_digest, owner),
                )
                self.db.commit()
                self.assert_invalid("Genesis")
                self.db.execute("DELETE FROM blocks")
                self.db.commit()

    def test_save_entry_with_missing_genesis_rolls_back(self):
        self.db.execute("DELETE FROM blocks")
        self.db.commit()
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "Genesis"):
            self.save_entry()
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.db.in_transaction)
        self.assert_invalid("kosong")
        self.assertEqual(self.append(storage.GENESIS, user_id=0), 0)
        self.assertEqual(self.save_entry(), 1)
        self.assert_valid()

    def test_standalone_initial_block_requires_genesis_and_user_zero(self):
        self.db.execute("DELETE FROM blocks")
        self.db.commit()
        before = self.snapshot()
        for data, owner in (
            ("non-genesis event", 0),
            ("non-genesis event", 1),
            (storage.GENESIS, 1),
        ):
            with self.subTest(data=data, owner=owner):
                with self.assertRaisesRegex(ValueError, "Genesis"):
                    self.append(data, owner)
                self.assertEqual(self.snapshot(), before)
                self.assertFalse(self.db.in_transaction)
                self.assert_invalid("kosong")
        self.assertEqual(self.append(storage.GENESIS, user_id=0), 0)
        self.assert_valid()

    def test_legacy_orphan_data_is_not_automatically_given_a_trusted_chain(self):
        self.db.execute("DELETE FROM blocks")
        self.db.commit()
        _, legacy_event = self.insert_legacy_entry()
        before = self.snapshot()
        self.assert_invalid("kosong")
        for operation in (self.save_entry, lambda: self.append(legacy_event)):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(ValueError, "Genesis"):
                    operation()
                self.assertEqual(self.snapshot(), before)
                self.assertFalse(self.db.in_transaction)
                self.assert_invalid("kosong")
        # Even explicit genesis creation cannot attest an existing orphan entry.
        self.assertEqual(self.append(storage.GENESIS, user_id=0), 0)
        self.assertEqual(self.snapshot()[0], before[0])
        self.assertEqual(self.snapshot()[2], before[2])
        self.assert_invalid("tidak memiliki blok")

    def test_index_gap_is_rejected(self):
        self.save_entry()
        self.db.execute("UPDATE blocks SET idx=3 WHERE idx=1")
        self.db.commit()
        self.assert_invalid("urutan")

    def test_changed_block_fields_are_rejected(self):
        self.save_entry()
        for field, value in (
            ("ts", "tampered timestamp"),
            ("data", "tampered event"),
            ("prev_hash", "f" * 64),
            ("nonce", -1),
            ("hash", "f" * 64),
        ):
            with self.subTest(field=field):
                self.db.execute(f"UPDATE blocks SET {field}=? WHERE idx=1", (value,))
                self.assert_invalid("Blok #1")
                self.db.rollback()

    def test_changed_entry_ciphertexts_owner_or_timestamp_are_rejected(self):
        entry_id = self.save_entry()
        for field, value in (
            ("judul_enc", "changed-title"),
            ("isi_enc", "changed-body"),
            ("user_id", 2),
            ("tanggal", "1999-01-01 00:00:00"),
        ):
            with self.subTest(field=field):
                self.db.execute(
                    f"UPDATE entries SET {field}=? WHERE id=?", (value, entry_id)
                )
                self.assert_invalid("diubah")
                self.db.rollback()

    def test_changed_block_owner_is_rejected(self):
        self.save_entry()
        self.db.execute("UPDATE blocks SET user_id=2 WHERE idx=1")
        self.db.commit()
        self.assert_invalid("pemilik")

    def test_deleted_entry_is_rejected(self):
        self.save_entry()
        self.db.execute("DELETE FROM entries")
        self.db.commit()
        self.assert_invalid("hilang")

    def test_entry_without_integrity_block_is_rejected(self):
        self.save_entry()
        self.db.execute("DELETE FROM blocks WHERE idx=1")
        self.db.commit()
        self.assert_invalid("tidak memiliki blok")

    def test_duplicate_entry_event_is_rejected(self):
        self.save_entry()
        event = self.db.execute("SELECT data FROM blocks WHERE idx=1").fetchone()[0]
        self.append(event)
        self.assert_invalid("duplikat")

    def test_legacy_entry_is_supported_without_rewriting_hashes(self):
        _, event = self.insert_legacy_entry()
        self.append(event)
        before = self.snapshot()
        self.assert_valid()
        self.assertEqual(self.snapshot(), before)

    def test_legacy_entry_changed_content_owner_or_missing_row_fails(self):
        entry_id, event = self.insert_legacy_entry()
        self.append(event)
        for sql, parameters in (
            ("UPDATE entries SET isi_enc='changed' WHERE id=?", (entry_id,)),
            ("UPDATE entries SET user_id=2 WHERE id=?", (entry_id,)),
            ("DELETE FROM entries WHERE id=?", (entry_id,)),
        ):
            with self.subTest(sql=sql):
                self.db.execute(sql, parameters)
                self.assert_invalid()
                self.db.rollback()

    def test_legacy_and_new_event_for_same_entry_are_duplicate(self):
        entry_id = self.save_entry()
        title, body = self.db.execute(
            "SELECT judul_enc, isi_enc FROM entries WHERE id=?", (entry_id,)
        ).fetchone()
        self.append(f"entry:{entry_id}:{digest((title + body).encode('utf-8'))}")
        self.assert_invalid("duplikat")

    def test_file2_verifies_exact_external_unicode_path_not_basename(self):
        destination = self.outside / "秘密-é.enc"
        destination.write_bytes(BLOB)
        (self.base / destination.name).write_bytes(b"wrong project file")
        (self.data / destination.name).write_bytes(b"wrong data file")
        event = storage.file_event(destination, digest(BLOB), 1)
        self.assertEqual(
            json.loads(event[6:]),
            {"path": str(destination), "sha256": digest(BLOB), "user_id": 1},
        )
        self.append(event)
        self.assert_valid()

    def test_file2_absolute_unicode_colon_path_is_json_and_opened_exactly(self):
        # A colon in a filename is not portable on Windows; never create this path.
        destination = os.path.abspath(str(self.outside / "秘密:catatan.enc"))
        event = storage.file_event(destination, digest(BLOB), 1)
        self.assertEqual(json.loads(event[6:])["path"], destination)
        self.append(event)
        opened = mock_open(read_data=BLOB)
        with patch.object(storage, "open", opened, create=True):
            self.assert_valid()
        opened.assert_called_once_with(destination, "rb")

    def test_file2_missing_file_fails_even_if_same_basename_exists(self):
        destination = self.outside / "missing.enc"
        (self.base / destination.name).write_bytes(BLOB)
        (self.data / destination.name).write_bytes(BLOB)
        self.append(storage.file_event(destination, digest(BLOB), 1))
        self.assert_invalid()

    def test_file2_modified_file_fails(self):
        destination = self.outside / "changed.enc"
        destination.write_bytes(BLOB)
        self.append(storage.file_event(destination, digest(BLOB), 1))
        destination.write_bytes(b"modified ciphertext")
        self.assert_invalid("diubah")

    def test_file2_unreadable_file_fails_closed(self):
        destination = self.outside / "unreadable.enc"
        destination.write_bytes(BLOB)
        self.append(storage.file_event(destination, digest(BLOB), 1))
        with patch.object(
            storage, "open", side_effect=PermissionError("denied"), create=True
        ) as opened:
            self.assert_invalid("denied")
        opened.assert_called_once_with(str(destination), "rb")

    def test_file2_event_owner_must_match_block_owner(self):
        destination = self.outside / "owner.enc"
        destination.write_bytes(BLOB)
        self.append(storage.file_event(destination, digest(BLOB), 2), user_id=1)
        self.assert_invalid("pemilik")

    def test_legacy_missing_file_is_not_success(self):
        self.append(f"file:missing.enc:{digest(BLOB)}")
        self.assert_invalid("tidak ditemukan")

    def test_legacy_same_basename_in_both_locations_is_ambiguous(self):
        for directory in (self.base, self.data):
            (directory / "legacy.enc").write_bytes(BLOB)
        self.append(f"file:legacy.enc:{digest(BLOB)}")
        self.assert_invalid("ambigu")

    def test_legacy_file_valid_in_either_single_location(self):
        self.append(f"file:legacy.enc:{digest(BLOB)}")
        for directory in (self.base, self.data):
            with self.subTest(directory=directory):
                path = directory / "legacy.enc"
                path.write_bytes(BLOB)
                before = self.snapshot()
                self.assert_valid()
                self.assertEqual(self.snapshot(), before)
                path.unlink()

    def test_legacy_modified_or_unreadable_file_fails(self):
        path = self.data / "legacy.enc"
        path.write_bytes(b"wrong ciphertext")
        self.append(f"file:legacy.enc:{digest(BLOB)}")
        self.assert_invalid("diubah")
        path.write_bytes(BLOB)
        with patch.object(
            storage, "open", side_effect=PermissionError("denied"), create=True
        ):
            self.assert_invalid("denied")

    def test_save_encrypted_file_commits_exact_file_and_event(self):
        destination = self.outside / "保存.enc"
        result = storage.save_encrypted_file(self.db, destination, BLOB, 1, DIFFICULTY)
        self.assertEqual(result, str(destination))
        self.assertEqual(destination.read_bytes(), BLOB)
        self.assertEqual(self.snapshot()[0], [])
        blocks = self.snapshot()[1]
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[1][6], 1)
        self.assertEqual(
            json.loads(blocks[1][2][6:]),
            {"path": str(destination), "sha256": digest(BLOB), "user_id": 1},
        )
        self.assertFalse(self.db.in_transaction)
        self.assert_valid()

    def test_save_encrypted_file_never_overwrites_or_chooses_another_path(self):
        destination = self.outside / "existing.enc"
        original = b"previous ciphertext must survive"
        destination.write_bytes(original)
        before = self.snapshot()
        with (
            patch.object(storage, "_append_block") as append,
            self.assertRaises(FileExistsError),
        ):
            storage.save_encrypted_file(self.db, destination, BLOB, 1, DIFFICULTY)
        append.assert_not_called()
        self.assertEqual(destination.read_bytes(), original)
        self.assertEqual(set(self.outside.iterdir()), {destination})
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.db.in_transaction)

    def test_save_encrypted_file_existing_tracked_file_and_chain_unchanged(self):
        destination = self.outside / "tracked.enc"
        storage.save_encrypted_file(self.db, destination, BLOB, 1, DIFFICULTY)
        before = self.snapshot()
        with self.assertRaises(FileExistsError):
            storage.save_encrypted_file(
                self.db, destination, b"replacement", 1, DIFFICULTY
            )
        self.assertEqual(destination.read_bytes(), BLOB)
        self.assertEqual(self.snapshot(), before)
        self.assert_valid()

    def test_save_encrypted_file_cleans_up_and_rolls_back_after_append_exception(self):
        destination = self.outside / "rollback.enc"
        before = self.snapshot()
        original = storage._append_block

        def append_then_fail(*args):
            self.assertEqual(destination.read_bytes(), BLOB)
            original(*args)
            raise RuntimeError("after file block insert")

        with (
            patch.object(storage, "_append_block", side_effect=append_then_fail),
            self.assertRaisesRegex(RuntimeError, "after file block insert"),
        ):
            storage.save_encrypted_file(self.db, destination, BLOB, 1, DIFFICULTY)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.outside.iterdir()), [])
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.db.in_transaction)
        self.assert_valid()

    def test_save_encrypted_file_cleans_up_on_sqlite_block_insert_failure(self):
        self.fail_block_inserts()
        destination = self.outside / "trigger-rollback.enc"
        before = self.snapshot()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected block insert"):
            storage.save_encrypted_file(self.db, destination, BLOB, 1, DIFFICULTY)
        self.assertFalse(destination.exists())
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.db.in_transaction)

    def test_two_writers_lock_then_retry_without_partial_entry_or_fork(self):
        # timeout=0 makes contention deterministic; no sleeps or real database.
        first = sqlite3.connect(str(self.root / "locking.sqlite"), timeout=0)
        self.addCleanup(first.close)
        initialize(first)
        second = sqlite3.connect(str(self.root / "locking.sqlite"), timeout=0)
        self.addCleanup(second.close)
        first.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
            storage.save_entry(second, 2, "title-2", "body-2", DIFFICULTY)
        self.assertTrue(first.in_transaction)
        self.assertFalse(second.in_transaction)
        self.assertEqual(
            second.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 0
        )
        first.rollback()
        first_id = storage.save_entry(first, 1, "title-1", "body-1", DIFFICULTY)
        second_id = storage.save_entry(second, 2, "title-2", "body-2", DIFFICULTY)
        self.assertNotEqual(first_id, second_id)
        self.assertEqual(
            second.execute("SELECT idx FROM blocks ORDER BY idx").fetchall(),
            [(0,), (1,), (2,)],
        )
        valid, message = storage.verify_chain(second, self.base, self.data, DIFFICULTY)
        self.assertIs(valid, True, message)


if __name__ == "__main__":
    unittest.main()
