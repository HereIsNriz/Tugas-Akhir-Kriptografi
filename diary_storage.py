"""SQLite diary/chain operations, independent of Tkinter and the live database.

Legacy block hashes are preserved. This local hash chain is not a trusted remote
checkpoint: deletion/remining of the entire history cannot be ruled out here.
"""

import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

GENESIS = "Genesis Block - Secret Diary"


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def block_hash(index, timestamp, data, previous, nonce):
    return sha256(f"{index}|{timestamp}|{data}|{previous}|{nonce}")


def _difficulty(value):
    if not isinstance(value, str) or re.fullmatch(r"0{0,6}", value) is None:
        raise ValueError("Difficulty harus berupa 0 sampai 6 karakter nol.")


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


@contextmanager
def _transaction(db):
    # Never commit or roll back somebody else's uncommitted changes.
    if db.in_transaction:
        raise ValueError("Ada transaksi database yang belum diselesaikan.")
    with db:
        db.execute("BEGIN IMMEDIATE")
        yield


def _append_block(db, data, user_id, difficulty):
    last = db.execute(
        "SELECT idx, hash FROM blocks ORDER BY idx DESC LIMIT 1"
    ).fetchone()
    if last is None and (data != GENESIS or user_id != 0):
        raise ValueError(
            "Genesis block hilang; jangan menambahkan data sebelum diperiksa."
        )
    index, previous = (last[0] + 1, last[1]) if last else (0, "0")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    nonce = 0
    while True:
        digest = block_hash(index, timestamp, data, previous, nonce)
        if digest.startswith(difficulty):
            break
        nonce += 1
    db.execute(
        "INSERT INTO blocks VALUES(?,?,?,?,?,?,?)",
        (index, timestamp, data, previous, nonce, digest, user_id),
    )
    return index


def append_block(db, data, user_id=0, difficulty="000"):
    _difficulty(difficulty)
    with _transaction(db):
        return _append_block(db, data, user_id, difficulty)


def save_entry(db, user_id, title_cipher, body_cipher, difficulty="000"):
    """Commit both the encrypted entry and its event, or roll back both."""
    _difficulty(difficulty)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _transaction(db):
        entry_id = db.execute(
            "INSERT INTO entries(user_id, tanggal, judul_enc, isi_enc) VALUES(?,?,?,?)",
            (user_id, timestamp, title_cipher, body_cipher),
        ).lastrowid
        event = "entry2:" + _json(
            {
                "id": entry_id,
                "user_id": user_id,
                "tanggal": timestamp,
                "sha256": sha256(_json([title_cipher, body_cipher])),
            }
        )
        _append_block(db, event, user_id, difficulty)
    return entry_id


def file_event(path, digest, user_id):
    if not _digest(digest):
        raise ValueError("Hash file SHA-256 tidak valid.")
    return "file2:" + _json(
        {"path": os.path.abspath(os.fspath(path)), "sha256": digest, "user_id": user_id}
    )


def save_encrypted_file(db, path, blob, user_id, difficulty="000"):
    """Exclusive creation avoids overwriting an already-tracked ciphertext.

    SQLite and the filesystem cannot share one atomic commit. On ordinary errors
    the newly-created file is removed; abrupt power loss can still leave an
    untracked file. No existing file is ever overwritten or deleted.
    """
    _difficulty(difficulty)
    destination = Path(path).absolute()
    event = file_event(destination, hashlib.sha256(blob).hexdigest(), user_id)
    created = False
    try:
        with _transaction(db):
            with destination.open("xb") as stream:
                created = True
                stream.write(blob)
                stream.flush()
                os.fsync(stream.fileno())
            _append_block(db, event, user_id, difficulty)
    except BaseException:
        if created:
            try:
                destination.unlink()
            except OSError as cleanup_error:
                raise OSError(
                    f"Penyimpanan gagal; file belum tercatat dan perlu diperiksa: {destination}"
                ) from cleanup_error
        raise
    return str(destination)


def _parse_event(data, prefix, fields):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Field event duplikat.")
            result[key] = value
        return result

    event = json.loads(data[len(prefix) :], object_pairs_hook=unique)
    if not isinstance(event, dict) or set(event) != set(fields):
        raise ValueError("Format event tidak valid.")
    if type(event["user_id"]) is not int or event["user_id"] <= 0:
        raise ValueError("Pemilik event tidak valid.")
    if not _digest(event["sha256"]):
        raise ValueError("Hash event tidak valid.")
    return event


def _check_file(path, expected):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    if hasher.hexdigest() != expected:
        raise ValueError(f"File sudah diubah: {path}")


def verify_chain(db, base, data_dir, difficulty="000"):
    """Return (False, explanation) for missing/unreadable/unverified assets too."""
    _difficulty(difficulty)
    try:
        blocks = db.execute(
            "SELECT idx, ts, data, prev_hash, nonce, hash, user_id FROM blocks ORDER BY idx"
        ).fetchall()
        entries = {
            row[0]: row[1:]
            for row in db.execute(
                "SELECT id, tanggal, judul_enc, isi_enc, user_id FROM entries"
            )
        }
        if not blocks:
            return False, "Blockchain kosong; integritas belum dapat diverifikasi."
        previous, seen_entries, file_count = "0", set(), 0
        for expected_index, row in enumerate(blocks):
            index, timestamp, data, prior, nonce, digest, user_id = row
            if (
                type(index) is not int
                or index != expected_index
                or type(nonce) is not int
                or nonce < 0
                or not isinstance(timestamp, str)
                or not isinstance(data, str)
                or not _digest(digest)
                or prior != previous
                or block_hash(index, timestamp, data, prior, nonce) != digest
                or not digest.startswith(difficulty)
            ):
                return False, f"Blok #{index} tidak valid (hash/urutan rantai rusak)."
            previous = digest
            if index == 0:
                if data != GENESIS or user_id != 0:
                    return False, "Genesis block tidak valid."
                continue
            if data.startswith("entry2:"):
                event = _parse_event(
                    data, "entry2:", ("id", "tanggal", "sha256", "user_id")
                )
                entry_id = event["id"]
                if type(entry_id) is not int or entry_id <= 0:
                    raise ValueError("ID entri tidak valid.")
                entry = entries.get(entry_id)
                if entry is None:
                    raise ValueError(f"Entri diary #{entry_id} hilang dari database.")
                timestamp_entry, title, body, owner = entry
                if (
                    owner != user_id
                    or event["user_id"] != user_id
                    or timestamp_entry != event["tanggal"]
                    or sha256(_json([title, body])) != event["sha256"]
                ):
                    raise ValueError(
                        f"Data/pemilik entri diary #{entry_id} sudah diubah."
                    )
                if entry_id in seen_entries:
                    raise ValueError(f"Blok entri diary #{entry_id} duplikat.")
                seen_entries.add(entry_id)
            elif data.startswith("entry:"):
                parts = data.split(":")
                if len(parts) != 3 or not parts[1].isdigit() or not _digest(parts[2]):
                    raise ValueError("Format blok entri lama tidak valid.")
                entry_id, expected = int(parts[1]), parts[2]
                entry = entries.get(entry_id)
                if entry is None:
                    raise ValueError(f"Entri diary #{entry_id} hilang dari database.")
                _, title, body, owner = entry
                if owner != user_id or sha256(title + body) != expected:
                    raise ValueError(
                        f"Isi/pemilik entri diary #{entry_id} sudah diubah."
                    )
                if entry_id in seen_entries:
                    raise ValueError(f"Blok entri diary #{entry_id} duplikat.")
                seen_entries.add(entry_id)
            elif data.startswith("file2:"):
                event = _parse_event(data, "file2:", ("path", "sha256", "user_id"))
                path = event["path"]
                if (
                    not isinstance(path, str)
                    or not path
                    or "\x00" in path
                    or not os.path.isabs(path)
                    or event["user_id"] != user_id
                ):
                    raise ValueError("Lokasi/pemilik file tidak valid.")
                _check_file(path, event["sha256"])
                file_count += 1
            elif data.startswith("file:"):
                parts = data.split(":")
                if len(parts) != 3 or not _digest(parts[2]):
                    raise ValueError("Format blok file lama tidak valid.")
                _, name, expected = parts
                if not name or name in (".", "..") or "/" in name or "\\" in name:
                    raise ValueError("Nama file lama tidak valid.")
                candidates = [Path(base) / name, Path(data_dir) / name]
                found = [path for path in candidates if path.is_file()]
                if not found:
                    raise ValueError(
                        f"File lama '{name}' tidak ditemukan; belum terverifikasi. "
                        "Salin file asli ke folder proyek/data tanpa mengubah blok lama."
                    )
                # A basename is ambiguous if both legacy locations contain it.
                if len(found) > 1:
                    raise ValueError(
                        f"Lokasi file lama '{name}' ambigu; belum terverifikasi."
                    )
                _check_file(found[0], expected)
                file_count += 1
            else:
                raise ValueError(f"Jenis event blok #{index} tidak dikenal.")
        orphaned = set(entries) - seen_entries
        if orphaned:
            return (
                False,
                f"Entri diary #{min(orphaned)} tidak memiliki blok integritas.",
            )
        return True, (
            f"Rantai valid; {len(seen_entries)} entri dan {file_count} file "
            "yang tercatat berhasil diverifikasi."
        )
    except (
        OSError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
        sqlite3.Error,
    ) as exc:
        return False, f"Verifikasi gagal/belum lengkap: {exc}"
