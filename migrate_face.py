"""One-time, explicit local-owner enrollment for a legacy LBPH account.

This is a trusted-local recovery operation, NOT identity verification. Anyone
with the password, dongle, and access to this console can enroll their own face.
Never expose it as an automatic fallback or a login-screen reset button.
"""

import argparse
import getpass
import hashlib
import hmac
import importlib
import re
from pathlib import Path

import face_auth

BASE = Path(__file__).resolve().parent


def migrate(app, username, password):
    """Only migrate a legacy account; leave DB, RSA keys, and YAML untouched."""
    if not re.fullmatch(r"[a-z0-9_]{3,20}", username):
        raise ValueError("Username tidak valid.")
    if not app.cek_dongle():
        raise ValueError("Dongle tidak terpasang atau tidak valid.")
    user = app.cari_user(username)
    if user is None or not hmac.compare_digest(
        hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(user[1]), 100_000
        ).hex(),
        user[2],
    ):
        raise ValueError("Username atau password salah.")
    legacy = Path(app.path_wajah(username))
    if Path(str(legacy) + ".sface.json").exists():
        raise ValueError("Profil SFace sudah ada; migrasi tidak boleh menimpanya.")
    if not legacy.is_file():
        raise ValueError("Model LBPH lama tidak ditemukan; bukan akun migrasi.")
    return face_auth.enroll(
        str(legacy), app.FACE_MODELS, app.cek_dongle, debug=app.DEBUG_BIOMETRIK
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    parser.add_argument(
        "--confirm-owner",
        action="store_true",
        help="konfirmasi Anda pemilik akun di komputer tepercaya",
    )
    parser.add_argument(
        "--dev-dongle",
        action="store_true",
        help="testing: gunakan dev/license.key, bukan flashdisk",
    )
    args = parser.parse_args(argv)
    if not args.confirm_owner:
        parser.error("Migrasi hanya untuk pemilik: tambahkan --confirm-owner.")
    if not (BASE / "data" / "diary_multi.db").is_file():
        parser.error("Database akun lama tidak ditemukan.")
    print(
        "PERINGATAN: ini pendaftaran ulang oleh pemilik lokal, bukan verifikasi wajah lama."
    )
    print(
        "Siapa pun dengan password + dongle + akses konsol ini dapat mendaftarkan wajah baru."
    )
    if (
        input("Hanya lanjut jika Anda pemilik akun. Ketik REKAM ULANG: ").strip()
        != "REKAM ULANG"
    ):
        print("Dibatalkan; tidak ada profil yang diubah.")
        return 1
    username = args.username.strip().lower()
    password = getpass.getpass("Password akun: ")
    app = importlib.import_module("diary_app")
    if args.dev_dongle:
        from run_demo import siapkan_license

        setattr(app, "DONGLE_DEV_PATH", siapkan_license())
    try:
        if not migrate(app, username, password):
            print("Migrasi dibatalkan/gagal; profil lama tetap tersimpan.")
            return 1
    except (ValueError, face_auth.FaceAuthError) as exc:
        print(f"Migrasi ditolak: {exc}")
        return 1
    finally:
        app.DB.close()
    print(
        "Profil SFace tersimpan. Login normal sekarang memakai wajah yang baru direkam."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
