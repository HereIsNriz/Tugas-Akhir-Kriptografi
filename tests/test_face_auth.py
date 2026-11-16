"""Camera-free unittest coverage; no OpenCV/NumPy installation or models needed.

Run from the project root: python -B -m unittest discover -s tests -v
"""

import json
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock, patch

import face_auth as auth


def vector(x=1.0, y=0.0):
    return [x, y] + [0.0] * 126


class MatchingTests(unittest.TestCase):
    def test_normalized_centroid_not_nearest_template(self):
        self.assertAlmostEqual(auth.match_score(vector(9), [vector(3)]), 1.0)
        self.assertAlmostEqual(
            auth.match_score(vector(), [vector(), vector(0, 7)]), 1 / math.sqrt(2)
        )
        self.assertAlmostEqual(auth.match_score(vector(-1), [vector()]), -1.0)

    def test_orthogonal_impostor_scores_below_threshold(self):
        score = auth.match_score(vector(0, 7), [vector(2), vector(4)])
        self.assertAlmostEqual(score, 0.0)
        self.assertLess(score, auth.COSINE_THRESHOLD)

    def test_score_is_scale_invariant_even_for_extreme_finite_vectors(self):
        expected = 1 / math.sqrt(2)
        for scale in (math.ulp(0.0), 1.0, 1e308):
            with self.subTest(scale=scale):
                self.assertAlmostEqual(
                    auth.match_score(vector(scale, scale), [vector()]), expected
                )
                self.assertAlmostEqual(
                    auth.match_score(vector(), [vector(scale, scale)]), expected
                )

    def test_reject_invalid_embeddings_and_templates(self):
        invalid = [
            None,
            [],
            [1.0] * 127,
            [1.0] * 129,
            [0.0] * 128,
            [True] * 128,
            ["1"] * 128,
            vector(float("nan")),
            vector(float("inf")),
            vector(-float("inf")),
            vector(10**1000),
        ]
        for item in invalid:
            with self.subTest(item=str(item)[:50]):
                with self.assertRaises(auth.FaceAuthError):
                    auth.match_score(item, [vector()])
                with self.assertRaises(auth.FaceAuthError):
                    auth.match_score(vector(), [item])
        for templates in ([], None, [vector(), vector(-1)]):
            with self.assertRaises(auth.FaceAuthError):
                auth.match_score(vector(), templates)

    def test_import_and_pure_logic_without_opencv_or_numpy(self):
        code = (
            "import sys\n"
            "class Block:\n"
            " def find_spec(self, fullname, *args):\n"
            "  if fullname.split('.')[0] in ('cv2', 'numpy'):\n"
            "   raise ImportError('optional dependency blocked')\n"
            "sys.meta_path.insert(0, Block())\n"
            "import face_auth as a\n"
            "assert a.match_score([1.0] + [0.0]*127, [[1.0] + [0.0]*127]) == 1\n"
            "assert not a.VerificationGate().update(1.0, 0.0)\n"
            "assert 'cv2' not in sys.modules and 'numpy' not in sys.modules\n"
        )
        subprocess.run(
            [sys.executable, "-B", "-c", code],
            check=True,
            cwd=Path(auth.__file__).parent,
            timeout=10,
        )


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "face.yml"
        self.sidecar = Path(str(self.path) + ".sface.json")

    def payload(self):
        return {"version": 1, "model": auth.RECOGNIZER_MODEL, "embeddings": [vector(4)]}

    def test_round_trip_normalizes_and_preserves_legacy(self):
        self.path.write_text("legacy LBPH data", encoding="utf-8")
        auth.save_profile(self.path, [vector(4), vector(2)])
        self.assertEqual(auth.load_profile(self.path), [vector(), vector()])
        self.assertEqual(self.path.read_text(encoding="utf-8"), "legacy LBPH data")
        self.assertEqual(
            set(json.loads(self.sidecar.read_text(encoding="utf-8"))),
            {"version", "model", "embeddings"},
        )
        self.assertEqual(
            sorted(p.name for p in self.path.parent.iterdir()),
            ["face.yml", "face.yml.sface.json"],
        )

    def test_atomic_failure_keeps_old_profile_and_removes_temp(self):
        auth.save_profile(self.path, [vector()])
        original = self.sidecar.read_bytes()
        with patch.object(auth.os, "replace", side_effect=OSError("locked")):
            with self.assertRaises(auth.FaceAuthError):
                auth.save_profile(self.path, [vector(0, 1)])
        self.assertEqual(self.sidecar.read_bytes(), original)
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])

    def test_atomic_replace_uses_same_directory(self):
        real_replace = auth.os.replace
        with patch.object(auth.os, "replace", wraps=real_replace) as replace:
            auth.save_profile(self.path, [vector()])
        source, destination = replace.call_args.args
        self.assertEqual(Path(source).parent, self.sidecar.parent)
        self.assertEqual(destination, self.sidecar)

    def test_missing_legacy_only_or_missing_parent_are_errors(self):
        self.path.write_text("old model", encoding="utf-8")
        with self.assertRaises(auth.FaceAuthError):
            auth.load_profile(self.path)
        with self.assertRaises(auth.FaceAuthError):
            auth.save_profile(self.path.parent / "missing" / "face.yml", [vector()])

    def test_reject_malformed_or_incompatible_profiles(self):
        payload = self.payload()
        bad = [
            [],
            {},
            {"embeddings": [vector()]},
            dict(payload, version=True),
            dict(payload, version=1.0),
            dict(payload, version=2),
            dict(payload, model="LBPH"),
            dict(payload, unexpected=True),
            dict(payload, embeddings=[]),
            dict(payload, embeddings=[[0.0] * 128]),
            dict(payload, embeddings=[vector(), vector(-1)]),
            dict(payload, embeddings=[vector(float("nan"))]),
            dict(payload, embeddings=[vector(float("inf"))]),
        ]
        for value in bad:
            with self.subTest(value=str(value)[:60]):
                self.sidecar.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(auth.FaceAuthError):
                    auth.load_profile(self.path)
        for raw in (
            "not JSON",
            '{"version":1,"version":1}',
            '{"x":Infinity}',
            '{"x":-Infinity}',
            '{"x":NaN}',
        ):
            self.sidecar.write_text(raw, encoding="utf-8")
            with self.assertRaises(auth.FaceAuthError):
                auth.load_profile(self.path)

    def test_invalid_save_does_not_replace_profile(self):
        auth.save_profile(self.path, [vector()])
        original = self.sidecar.read_bytes()
        with self.assertRaises(auth.FaceAuthError):
            auth.save_profile(self.path, [[0.0] * 128])
        self.assertEqual(self.sidecar.read_bytes(), original)


class GateTests(unittest.TestCase):
    def test_no_early_pass_and_requires_eight_matches(self):
        gate = auth.VerificationGate()
        for i in range(8):
            self.assertFalse(gate.update(0.5, i * 0.25))
        self.assertEqual(gate.matches, 8)
        self.assertTrue(gate.update(0.5, 2.0))
        gate.reset()
        for i in range(7):
            self.assertFalse(gate.update(1.0, float(i)))
        self.assertTrue(gate.update(1.0, 7.0))

    def test_fast_frames_do_not_count(self):
        gate = auth.VerificationGate()
        for i in range(20):
            self.assertFalse(gate.update(1.0, i / 100))
        self.assertEqual(gate.matches, 1)
        self.assertFalse(gate.update(1.0, 0.25))
        self.assertEqual(gate.matches, 2)

    def test_long_gap_discards_stale_streak_and_requires_fresh_matches(self):
        for gap in (auth.VERIFICATION_MAX_GAP + 0.01, 100.0):
            with self.subTest(gap=gap):
                gate = auth.VerificationGate()
                for i in range(7):
                    self.assertFalse(gate.update(0.9, i * 0.25))
                resumed = 1.5 + gap
                self.assertFalse(gate.update(0.9, resumed))
                self.assertEqual(gate.matches, 1)
                for i in range(1, 8):
                    self.assertFalse(gate.update(0.9, resumed + i * 0.25))
                self.assertTrue(gate.update(0.9, resumed + 2.0))

    def test_maximum_gap_boundary_is_allowed(self):
        gate = auth.VerificationGate()
        for i in range(7):
            self.assertFalse(gate.update(0.9, i * 0.25))
        self.assertTrue(gate.update(0.9, 1.5 + auth.VERIFICATION_MAX_GAP))

    def test_long_gap_resets_already_successful_gate(self):
        gate = auth.VerificationGate()
        for i in range(8):
            self.assertFalse(gate.update(0.9, i * 0.25))
        self.assertTrue(gate.update(0.9, 2.0))
        self.assertFalse(gate.update(0.9, 2.0 + auth.VERIFICATION_MAX_GAP + 0.01))
        self.assertEqual(gate.matches, 1)

    def test_duration_must_span_counted_matches(self):
        gate = auth.VerificationGate()
        for now in (0, 0.25, 0.5, 0.75, 1, 1.25, 1.5, 1.99):
            self.assertFalse(gate.update(1.0, now))
        self.assertFalse(gate.update(1.0, 2.0))
        self.assertTrue(gate.update(1.0, 2.25))

    def test_every_mismatch_invalid_score_or_missing_face_resets(self):
        for score in (
            None,
            0.499,
            -1,
            float("nan"),
            float("inf"),
            -float("inf"),
            1.01,
            True,
            "1",
        ):
            with self.subTest(score=score):
                gate = auth.VerificationGate()
                for i in range(7):
                    gate.update(0.9, i * 0.3)
                self.assertFalse(gate.update(cast(Any, score), 2.1))
                self.assertEqual(gate.matches, 0)
                self.assertFalse(gate.update(0.9, 2.4))
                self.assertEqual(gate.matches, 1)

    def test_bad_or_backward_timestamps_reset(self):
        for now in (float("nan"), float("inf"), None, True, "2", 0.5):
            gate = auth.VerificationGate()
            gate.update(1.0, 1.0)
            self.assertFalse(gate.update(1.0, cast(Any, now)))
            self.assertEqual(gate.matches, 0)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.cv2 = Mock()
        self.np = Mock()
        self.np.asarray.return_value.reshape.return_value.tolist.return_value = vector(
            3
        )
        self.modules = patch.dict(sys.modules, {"cv2": self.cv2, "numpy": self.np})
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def engine(self) -> Any:
        with patch.object(auth.Path, "is_file", return_value=True):
            return auth.FaceEngine("models")

    @staticmethod
    def face(width=80, height=80, confidence=0.9):
        return [10, 10, width, height] + [20.0] * 10 + [confidence]

    def test_loads_required_model_names_and_apis(self):
        engine = self.engine()
        args = self.cv2.FaceDetectorYN.create.call_args.args
        self.assertEqual(Path(args[0]).name, auth.DETECTOR_MODEL)
        self.assertEqual(args[3], 0.9)
        self.assertEqual(
            Path(self.cv2.FaceRecognizerSF.create.call_args.args[0]).name,
            auth.RECOGNIZER_MODEL,
        )
        self.assertIs(engine._cv2, self.cv2)

    def test_missing_or_unloadable_models_raise(self):
        with patch.object(auth.Path, "is_file", return_value=False):
            with self.assertRaises(auth.FaceAuthError):
                auth.FaceEngine("models")
        self.cv2.FaceDetectorYN.create.side_effect = RuntimeError("bad onnx")
        with self.assertRaises(auth.FaceAuthError):
            self.engine()

    def test_feature_aligns_then_normalizes(self):
        engine = self.engine()
        face = self.face()
        engine._detector.detect.return_value = (1, [face])
        frame = SimpleNamespace(shape=(480, 640, 3))
        self.assertEqual(engine.feature(frame), vector())
        engine._detector.setInputSize.assert_called_once_with((640, 480))
        engine._recognizer.alignCrop.assert_called_once_with(frame, face)
        engine._recognizer.feature.assert_called_once_with(
            engine._recognizer.alignCrop.return_value
        )

    def test_unsuitable_detections_do_not_extract_features(self):
        engine = self.engine()
        bad_face = self.face()
        bad_face[4] = float("nan")
        for faces in (
            None,
            [],
            [self.face(), self.face()],
            [self.face(width=79)],
            [self.face(height=79)],
            [self.face(confidence=0.899)],
            [self.face(confidence=float("nan"))],
            [bad_face],
            [[-1, 10] + self.face()[2:]],
            [self.face(width=700)],
        ):
            with self.subTest(faces=faces):
                engine._detector.detect.return_value = (0, faces)
                self.assertIsNone(engine.feature(SimpleNamespace(shape=(480, 640, 3))))
        engine._recognizer.alignCrop.assert_not_called()

    def test_camera_or_extraction_errors_raise(self):
        engine = self.engine()
        with self.assertRaises(auth.FaceAuthError):
            engine.feature(SimpleNamespace(shape=(0, 640, 3)))
        engine._detector.detect.side_effect = RuntimeError("detect failed")
        with self.assertRaises(auth.FaceAuthError):
            engine.feature(SimpleNamespace(shape=(480, 640, 3)))


class SessionTests(unittest.TestCase):
    """Exercise the public entry points with a fake camera and monotonic clock."""

    def setUp(self):
        self.now = 0.0
        self.frames = 0
        self.step = 0.25
        self.cancel_at = None
        self.cancel_key = ord("q")
        self.closed_at = None
        self.failed_at = None
        self.embedding = lambda: vector()
        self.cv2 = Mock()
        self.cv2.WINDOW_NORMAL = 0
        self.cv2.WND_PROP_VISIBLE = 4
        self.cv2.CAP_DSHOW = 700
        self.cv2.FONT_HERSHEY_SIMPLEX = 0
        self.capture = self.cv2.VideoCapture.return_value
        self.capture.isOpened.return_value = True
        self.capture.read.side_effect = self.read
        self.cv2.waitKey.side_effect = lambda _: (
            self.cancel_key if self.frames == self.cancel_at else -1
        )
        self.cv2.getWindowProperty.side_effect = lambda *_: (
            0 if self.frames == self.closed_at else 1
        )
        self.engine = SimpleNamespace(
            _cv2=self.cv2, feature=Mock(side_effect=lambda _: self.embedding())
        )
        self.saved = Mock()
        patches = [
            patch.object(auth, "FaceEngine", return_value=self.engine),
            patch.object(auth, "load_profile", return_value=[vector()]),
            patch.object(auth, "save_profile", self.saved),
            patch.object(auth.time, "monotonic", side_effect=lambda: self.now),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def read(self):
        self.frames += 1
        self.now = round(self.now + self.step, 9)
        return (False, None) if self.frames == self.failed_at else (True, object())

    def verify(self, allowed=lambda: True, debug=False):
        return auth.verify("face.yml", "models", allowed, debug=debug)

    def enroll(self, allowed=lambda: True, debug=False):
        return auth.enroll("face.yml", "models", allowed, debug=debug)

    def assert_cleaned(self):
        self.capture.release.assert_called_once()
        self.cv2.destroyWindow.assert_called_once()

    def test_verification_success_spaced_and_not_early(self):
        self.assertTrue(self.verify())
        self.assertEqual(self.frames, 9)
        self.assertGreaterEqual(self.now - self.step, 2.0)
        self.assertEqual(self.cv2.putText.call_count, self.frames * 2)
        instructions = [call.args[1] for call in self.cv2.putText.call_args_list]
        self.assertIn("Verifikasi 9/8: satu wajah", instructions)
        self.assertIn("q / Esc = batal", instructions)
        self.assert_cleaned()

    def test_debug_does_not_change_decisions_or_timing(self):
        self.assertTrue(self.verify(debug=True))
        self.assertEqual(self.frames, 9)
        self.assert_cleaned()

    def test_mismatch_no_face_and_multi_face_reset_progress(self):
        # Engine returns None for both missing and multiple faces.
        for invalid in (None, vector(-1)):
            with self.subTest(invalid=invalid):
                self.now = 0
                self.frames = 0
                self.embedding = lambda invalid=invalid: (
                    invalid if self.frames == 8 else vector()
                )
                self.assertTrue(self.verify())
                self.assertEqual(self.frames, 17)

    def test_repeated_frames_cannot_shortcut_verification(self):
        self.step = 0.01
        self.assertTrue(self.verify())
        self.assertGreaterEqual(self.frames, 201)

    def test_q_escape_and_closed_window_win_on_success_frame(self):
        for key in (ord("q"), ord("Q"), 27):
            with self.subTest(key=key):
                self.now = 0
                self.frames = 0
                self.cancel_at = 9
                self.cancel_key = key
                self.assertFalse(self.verify())
        self.cancel_at = None
        self.closed_at = 9
        self.now = 0
        self.frames = 0
        self.assertFalse(self.verify())

    def test_access_loss_on_success_frame_fails_closed(self):
        self.assertFalse(self.verify(allowed=lambda: self.frames < 9))
        self.assertEqual(self.frames, 9)
        self.assert_cleaned()

    def test_access_callback_exception_fails_closed(self):
        def allowed():
            if self.frames >= 2:
                raise RuntimeError("dongle unavailable")
            return True

        self.assertFalse(self.verify(allowed=allowed, debug=True))
        self.assert_cleaned()

    def test_initial_access_denial_does_not_open_camera(self):
        self.assertFalse(self.verify(allowed=lambda: False))
        self.assertFalse(self.enroll(allowed=lambda: False))
        self.cv2.VideoCapture.assert_not_called()
        self.saved.assert_not_called()

    def test_camera_open_and_read_failures_raise_and_release(self):
        self.capture.isOpened.return_value = False
        with self.assertRaises(auth.FaceAuthError):
            self.verify()
        self.capture.release.assert_called_once()
        self.cv2.destroyWindow.assert_not_called()
        self.capture.reset_mock()
        self.capture.isOpened.return_value = True
        self.failed_at = 1
        with self.assertRaises(auth.FaceAuthError):
            self.verify()
        self.assert_cleaned()

    def test_extraction_failure_releases_camera_and_window(self):
        self.engine.feature.side_effect = auth.FaceAuthError("extract failed")
        with self.assertRaises(auth.FaceAuthError):
            self.verify()
        self.assert_cleaned()

    def test_window_errors_fail_closed_and_cleanup(self):
        self.cv2.imshow.side_effect = RuntimeError("GUI unavailable")
        with self.assertRaises(auth.FaceAuthError):
            self.verify()
        self.assert_cleaned()

    def test_nonfinite_window_visibility_fails_closed(self):
        self.cv2.getWindowProperty.side_effect = None
        self.cv2.getWindowProperty.return_value = float("nan")
        self.assertFalse(self.verify())
        self.assert_cleaned()

    def test_verification_timeout_and_deadline_win(self):
        self.embedding = lambda: None
        self.assertFalse(self.verify())
        self.assertEqual(self.now, 12.0)
        self.now = 0
        self.frames = 0
        self.step = 1.5
        self.embedding = lambda: vector()
        self.assertFalse(self.verify())

    def test_platform_specific_camera_backend(self):
        with patch.object(auth.sys, "platform", "win32"):
            self.assertTrue(self.verify())
        self.cv2.VideoCapture.assert_called_with(0, self.cv2.CAP_DSHOW)
        with patch.object(auth.sys, "platform", "linux"):
            self.assertTrue(self.verify())
        self.cv2.VideoCapture.assert_called_with(0)

    def test_enrollment_collects_twelve_spaced_samples(self):
        self.step = 0.1
        self.assertTrue(self.enroll())
        path, samples = self.saved.call_args.args
        self.assertEqual(path, "face.yml")
        self.assertEqual(len(samples), 12)
        self.assertGreaterEqual(self.now - self.step, 11 * 0.3)
        self.assertLess(self.now, 40)
        self.assert_cleaned()

    def test_enrollment_aborts_identity_change_even_between_samples(self):
        self.step = 0.1
        self.embedding = lambda: vector(-1) if self.frames == 2 else vector()
        self.assertFalse(self.enroll())
        self.assertEqual(self.frames, 2)
        self.saved.assert_not_called()
        self.assert_cleaned()

    def test_enrollment_rejects_mixed_orthogonal_identities_without_saving(self):
        self.step = 0.5
        self.embedding = lambda: vector() if self.frames <= 6 else vector(0, 1)
        self.assertFalse(self.enroll())
        self.assertEqual(self.frames, 7)
        self.saved.assert_not_called()
        self.assert_cleaned()

    def test_orthogonal_impostor_never_verifies(self):
        self.embedding = lambda: vector(0, 1)
        self.assertFalse(self.verify())
        self.assertEqual(self.now, auth.VERIFICATION_TIMEOUT)
        self.assert_cleaned()

    def test_verification_stalled_capture_cannot_reuse_old_matches(self):
        def embedding():
            if self.frames == 7:
                self.step = auth.VERIFICATION_MAX_GAP + 0.01
            elif self.frames == 8:
                self.step = 0.25
            return vector()

        self.embedding = embedding
        self.assertTrue(self.verify())
        self.assertEqual(self.frames, 16)
        self.assert_cleaned()

    def test_enrollment_rechecks_all_samples_against_centroid(self):
        # Each new direction matches the running centroid, but the oldest
        # sample eventually falls below threshold against the updated centroid.
        samples = [
            vector(math.cos(math.radians(angle)), math.sin(math.radians(angle)))
            for angle in (0, 55, 85, 100, 110, 115)
        ]
        self.step = 0.5
        self.embedding = lambda: samples[min(self.frames - 1, len(samples) - 1)]
        self.assertFalse(self.enroll())
        self.assertLessEqual(self.frames, len(samples))
        self.saved.assert_not_called()

    def test_enrollment_cancellation_and_timeout_never_save(self):
        self.step = 0.5
        self.cancel_at = 12
        self.assertFalse(self.enroll())
        self.saved.assert_not_called()
        self.cancel_at = None
        self.frames = 0
        self.now = 0
        self.embedding = lambda: None
        self.assertFalse(self.enroll())
        self.assertEqual(self.now, 40.0)
        self.saved.assert_not_called()

    def test_profile_and_model_errors_propagate(self):
        with patch.object(
            auth, "load_profile", side_effect=auth.FaceAuthError("bad profile")
        ):
            with self.assertRaises(auth.FaceAuthError):
                self.verify()
        self.cv2.VideoCapture.assert_not_called()
        with patch.object(
            auth, "FaceEngine", side_effect=auth.FaceAuthError("bad models")
        ):
            with self.assertRaises(auth.FaceAuthError):
                self.enroll()
        self.cv2.VideoCapture.assert_not_called()


if __name__ == "__main__":
    unittest.main()
