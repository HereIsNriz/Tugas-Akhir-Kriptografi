"""Integration checks without importing diary_app (which opens the real DB)."""

import ast
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import face_auth
import migrate_face
import setup_face_models

BASE = Path(__file__).resolve().parents[1]


class AppWrapperTests(unittest.TestCase):
    def setUp(self):
        source = ast.parse((BASE / "diary_app.py").read_text(encoding="utf-8"))
        nodes = [
            node
            for node in source.body
            if isinstance(node, ast.FunctionDef)
            and node.name in ("_biometrik", "biometrik_daftar", "biometrik_verifikasi")
        ]
        self.backend = SimpleNamespace(
            enroll=Mock(return_value=True),
            verify=Mock(return_value=True),
            FaceAuthError=face_auth.FaceAuthError,
        )
        self.dongle = Mock(return_value=True)
        self.dialog = Mock()
        self.namespace = dict(
            os=os,
            face_auth=self.backend,
            cek_dongle=self.dongle,
            messagebox=self.dialog,
            FACE_MODELS="models",
            DEBUG_BIOMETRIK=False,
        )
        exec(
            compile(ast.Module(body=nodes, type_ignores=[]), "diary_wrappers", "exec"),
            self.namespace,
        )

    def test_legacy_profile_has_no_lbph_fallback(self):
        with patch.object(os.path, "isfile", return_value=False):
            self.assertFalse(self.namespace["biometrik_verifikasi"]("old.yml"))
        self.backend.verify.assert_not_called()
        self.dialog.showerror.assert_called_once()

    def test_missing_dongle_never_opens_camera(self):
        self.dongle.return_value = False
        self.assertFalse(self.namespace["biometrik_daftar"]("face.yml"))
        self.backend.enroll.assert_not_called()

    def test_new_enrollment_uses_sface_and_live_dongle_callback(self):
        self.assertTrue(self.namespace["biometrik_daftar"]("face.yml"))
        self.backend.enroll.assert_called_once_with(
            "face.yml", "models", self.dongle, debug=False
        )

    def test_sface_errors_fail_closed(self):
        self.backend.verify.side_effect = face_auth.FaceAuthError("bad camera")
        with patch.object(os.path, "isfile", return_value=True):
            self.assertFalse(self.namespace["biometrik_verifikasi"]("face.yml"))
        self.dialog.showerror.assert_called_once()


class MigrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.legacy = Path(directory.name) / "face_owner.yml"
        self.legacy.write_text("legacy profile", encoding="utf-8")
        salt = bytes(range(16))
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", b"correct-password", salt, 100_000
        ).hex()
        self.app = SimpleNamespace(
            cek_dongle=Mock(return_value=True),
            cari_user=Mock(return_value=(1, salt.hex(), password_hash)),
            path_wajah=Mock(return_value=str(self.legacy)),
            FACE_MODELS="models",
            DEBUG_BIOMETRIK=False,
        )

    def test_correct_credentials_allow_explicit_enrollment(self):
        with patch.object(face_auth, "enroll", return_value=True) as enroll:
            self.assertTrue(migrate_face.migrate(self.app, "owner", "correct-password"))
        enroll.assert_called_once_with(
            str(self.legacy), "models", self.app.cek_dongle, debug=False
        )
        self.assertEqual(self.legacy.read_text(encoding="utf-8"), "legacy profile")

    def test_wrong_password_no_enrollment(self):
        with patch.object(face_auth, "enroll") as enroll:
            with self.assertRaises(ValueError):
                migrate_face.migrate(self.app, "owner", "wrong-password")
        enroll.assert_not_called()

    def test_missing_dongle_no_enrollment(self):
        self.app.cek_dongle.return_value = False
        with patch.object(face_auth, "enroll") as enroll:
            with self.assertRaises(ValueError):
                migrate_face.migrate(self.app, "owner", "correct-password")
        enroll.assert_not_called()

    def test_no_profile_overwrite_even_if_existing_json_is_invalid(self):
        Path(str(self.legacy) + ".sface.json").write_text("invalid", encoding="utf-8")
        with patch.object(face_auth, "enroll") as enroll:
            with self.assertRaises(ValueError):
                migrate_face.migrate(self.app, "owner", "correct-password")
        enroll.assert_not_called()

    def test_nonlegacy_account_cannot_use_migration(self):
        self.legacy.unlink()
        with patch.object(face_auth, "enroll") as enroll:
            with self.assertRaises(ValueError):
                migrate_face.migrate(self.app, "owner", "correct-password")
        enroll.assert_not_called()

    def test_invalid_username_rejected_before_lookup(self):
        with self.assertRaises(ValueError):
            migrate_face.migrate(self.app, "../owner", "correct-password")
        self.app.cari_user.assert_not_called()


class ModelSetupTests(unittest.TestCase):
    def test_size_and_hash_must_both_match(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / "model.onnx"
            model.write_bytes(b"test model")
            digest = hashlib.sha256(b"test model").hexdigest()
            self.assertTrue(setup_face_models.valid_file(model, digest, 10))
            self.assertFalse(setup_face_models.valid_file(model, "0" * 64, 10))
            self.assertFalse(setup_face_models.valid_file(model, digest, 11))


if __name__ == "__main__":
    unittest.main()
