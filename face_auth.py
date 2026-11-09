"""Standalone YuNet/SFace authentication (no LBPH fallback and no liveness claim).

Public API: FaceAuthError, FaceEngine, save_profile, load_profile, match_score,
VerificationGate, enroll, verify. All profile paths are *legacy base paths*:
``user.yml`` reads/writes ``user.yml.sface.json`` and never modifies the YAML.
OpenCV and NumPy are imported only when FaceEngine is constructed.

COSINE_THRESHOLD=0.5 is a conservative starting point, not a calibrated guarantee.
Face recognition alone cannot detect photographs, replay, or other presentation
attacks. Callers must continue enforcing their own authorization policy.
"""

from __future__ import annotations

import json
import logging
import math
import os
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

__all__ = [
    "FaceAuthError",
    "FaceEngine",
    "VerificationGate",
    "enroll",
    "load_profile",
    "match_score",
    "save_profile",
    "verify",
]

DETECTOR_MODEL = "face_detection_yunet_2023mar.onnx"
RECOGNIZER_MODEL = "face_recognition_sface_2021dec.onnx"
PROFILE_VERSION = 1
EMBEDDING_DIMENSIONS = 128
COSINE_THRESHOLD = 0.5
ENROLLMENT_SAMPLES = 12
ENROLLMENT_INTERVAL = 0.3
ENROLLMENT_TIMEOUT = 40.0
VERIFICATION_MATCHES = 8
VERIFICATION_INTERVAL = 0.25
VERIFICATION_MAX_GAP = 1.5
VERIFICATION_DURATION = 2.0
VERIFICATION_TIMEOUT = 12.0
_LOG = logging.getLogger(__name__)


class FaceAuthError(Exception):
    """Invalid/missing models, camera failures, or invalid/unreadable profiles."""


def _normalize(embedding) -> list[float]:
    if (
        not isinstance(embedding, (list, tuple))
        or len(embedding) != EMBEDDING_DIMENSIONS
    ):
        raise FaceAuthError("An SFace embedding must have exactly 128 dimensions.")
    if any(isinstance(x, bool) or not isinstance(x, (int, float)) for x in embedding):
        raise FaceAuthError("Embedding components must be finite numbers.")
    try:
        values = [float(x) for x in embedding]
    except (ValueError, OverflowError) as exc:
        raise FaceAuthError("Invalid embedding components.") from exc
    if not all(math.isfinite(x) for x in values):
        raise FaceAuthError("Embeddings must be finite and have nonzero norm.")
    scale = max(abs(x) for x in values)
    if scale == 0:
        raise FaceAuthError("Embeddings must be finite and have nonzero norm.")
    # Scaling first avoids subnormal rounding and overflow in the vector norm.
    values = [x / scale for x in values]
    norm = math.hypot(*values)
    return [x / norm for x in values]


def _templates(embeddings) -> list[list[float]]:
    if not isinstance(embeddings, (list, tuple)) or not embeddings:
        raise FaceAuthError("A profile must contain at least one embedding.")
    return [_normalize(embedding) for embedding in embeddings]


def _centroid(templates: list[list[float]]) -> list[float]:
    return _normalize(
        [
            math.fsum(template[i] for template in templates) / len(templates)
            for i in range(EMBEDDING_DIMENSIONS)
        ]
    )


def match_score(embedding, templates) -> float:
    """Cosine against the normalized mean of unit templates, never the nearest.

    Invalid embeddings or a degenerate centroid raise FaceAuthError.
    """
    probe = _normalize(embedding)
    centroid = _centroid(_templates(templates))
    return max(-1.0, min(1.0, math.fsum(a * b for a, b in zip(probe, centroid))))


def _sidecar(path) -> Path:
    return Path(os.fspath(path) + ".sface.json")


def save_profile(path, embeddings) -> None:
    """Atomically save a versioned JSON sidecar; leave any legacy file intact."""
    templates = _templates(embeddings)
    _centroid(templates)  # Reject unusable profiles before touching the filesystem.
    payload = {
        "version": PROFILE_VERSION,
        "model": RECOGNIZER_MODEL,
        "embeddings": templates,
    }
    destination = _sidecar(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=destination.name + ".",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = stream.name
            json.dump(payload, stream, allow_nan=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except (OSError, ValueError, TypeError) as exc:
        raise FaceAuthError(f"Cannot save SFace profile: {destination}") from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            except OSError:
                _LOG.debug("Could not remove temporary SFace profile", exc_info=True)


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FaceAuthError("Duplicate JSON profile field.")
        result[key] = value
    return result


def _invalid_constant(value):
    raise FaceAuthError(f"Non-finite JSON number: {value}")


def load_profile(path) -> list[list[float]]:
    """Load validated unit templates from the sidecar; never read legacy YAML."""
    source = _sidecar(path)
    try:
        with source.open(encoding="utf-8") as stream:
            payload = json.load(
                stream,
                object_pairs_hook=_json_object,
                parse_constant=_invalid_constant,
            )
    except (OSError, ValueError, RecursionError) as exc:
        raise FaceAuthError(f"Cannot read SFace profile: {source}") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "version",
        "model",
        "embeddings",
    }:
        raise FaceAuthError("Malformed or unversioned SFace profile.")
    if type(payload["version"]) is not int or payload["version"] != PROFILE_VERSION:
        raise FaceAuthError("Unsupported SFace profile version.")
    if payload["model"] != RECOGNIZER_MODEL:
        raise FaceAuthError("SFace profile model does not match the required model.")
    templates = _templates(payload["embeddings"])
    _centroid(templates)
    return templates


class FaceEngine:
    """Lazy OpenCV YuNet detector and SFace embedding extractor."""

    def __init__(self, model_dir):
        directory = Path(model_dir)
        detector_path = directory / DETECTOR_MODEL
        recognizer_path = directory / RECOGNIZER_MODEL
        if not detector_path.is_file() or not recognizer_path.is_file():
            raise FaceAuthError(
                f"YuNet and SFace ONNX models are required in {directory}"
            )
        try:
            import cv2
            import numpy as np

            self._cv2 = cv2
            self._np = np
            self._detector = cv2.FaceDetectorYN.create(
                str(detector_path),
                "",
                (320, 320),
                0.9,
                0.3,
                5000,
            )
            self._recognizer = cv2.FaceRecognizerSF.create(str(recognizer_path), "")
        except Exception as exc:
            raise FaceAuthError("Cannot initialize OpenCV YuNet/SFace models.") from exc

    def feature(self, frame) -> list[float] | None:
        """Return one unit embedding, or None for absent/multiple/unsuitable faces."""
        try:
            height, width = frame.shape[:2]
            if height <= 0 or width <= 0:
                raise FaceAuthError("Camera returned an empty frame.")
            self._detector.setInputSize((width, height))
            _, faces = self._detector.detect(frame)
            if faces is None or len(faces) != 1:
                return None
            face = faces[0]
            if len(face) < 15 or not all(math.isfinite(float(x)) for x in face):
                return None
            x, y, box_width, box_height = (float(v) for v in face[:4])
            confidence = float(face[-1])
            if (
                box_width < 80
                or box_height < 80
                or not 0.9 <= confidence <= 1.0
                or x < 0
                or y < 0
                or x + box_width > width
                or y + box_height > height
            ):
                return None
            aligned = self._recognizer.alignCrop(frame, face)
            feature = self._recognizer.feature(aligned)
            values = (
                self._np.asarray(feature, dtype=self._np.float64).reshape(-1).tolist()
            )
            return _normalize(values)
        except FaceAuthError:
            raise
        except Exception as exc:
            raise FaceAuthError(
                "OpenCV face detection/embedding extraction failed."
            ) from exc


class VerificationGate:
    """Pure temporal decision state; invalid observations reset all progress.

    Call update(score, monotonic_timestamp) for *every* frame, using None for
    missing/multiple faces. Eight counted matches, >=0.25s apart and spanning
    >=2s, are necessary; gaps >1.5s between counted matches restart the streak.
    The caller must process cancellation before using True.
    """

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        self.matches = 0
        self._first_match = None
        self._last_match = None
        self._last_observation = None

    def update(self, score: float | None, now: float) -> bool:
        if (
            isinstance(now, bool)
            or not isinstance(now, (int, float))
            or not math.isfinite(now)
        ):
            self.reset()
            return False
        if self._last_observation is not None and now < self._last_observation:
            self.reset()
            self._last_observation = now
            return False
        if (
            self._last_match is not None
            and now - self._last_match > VERIFICATION_MAX_GAP
        ):
            self.reset()
        self._last_observation = now
        if (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not COSINE_THRESHOLD <= score <= 1.0
            or not math.isfinite(score)
        ):
            self.reset()
            return False
        if self._last_match is None or now - self._last_match >= VERIFICATION_INTERVAL:
            if self._first_match is None:
                self._first_match = now
            self.matches += 1
            self._last_match = now
        return (
            self._first_match is not None
            and self._last_match is not None
            and self.matches >= VERIFICATION_MATCHES
            and self._last_match - self._first_match >= VERIFICATION_DURATION
        )


def _allowed(access_allowed: Callable[[], bool], debug: bool) -> bool:
    try:
        return bool(access_allowed())
    except Exception:
        if debug:
            _LOG.debug(
                "Access callback failed; denying face authentication", exc_info=True
            )
        return False


def _consistent(samples: list[list[float]]) -> bool:
    return all(match_score(sample, samples) >= COSINE_THRESHOLD for sample in samples)


def _session(engine, access_allowed, templates, debug):
    cv2 = engine._cv2
    enrolling = templates is None
    title = "SFace enrollment" if enrolling else "SFace verification"
    timeout = ENROLLMENT_TIMEOUT if enrolling else VERIFICATION_TIMEOUT
    samples = []
    last_sample = None
    gate = VerificationGate()
    capture = None
    window_created = False
    started = time.monotonic()
    try:
        if sys.platform == "win32":
            capture = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        else:
            capture = cv2.VideoCapture(0)
        if not capture.isOpened():
            raise FaceAuthError("Cannot open camera 0.")
        cv2.namedWindow(title, cv2.WINDOW_NORMAL)
        window_created = True
        while time.monotonic() - started < timeout:
            if not _allowed(access_allowed, debug):
                return False
            ok, frame = capture.read()
            if not ok or frame is None:
                raise FaceAuthError("Camera failed to provide a frame.")
            embedding = engine.feature(frame)
            now = time.monotonic()
            score = None
            identity_changed = False
            if enrolling:
                if embedding is not None:
                    if samples and match_score(embedding, samples) < COSINE_THRESHOLD:
                        identity_changed = True
                    elif (
                        last_sample is None or now - last_sample >= ENROLLMENT_INTERVAL
                    ):
                        samples.append(embedding)
                        last_sample = now
                        identity_changed = not _consistent(samples)
                ready = len(samples) >= ENROLLMENT_SAMPLES and not identity_changed
            else:
                if embedding is not None:
                    score = match_score(embedding, templates)
                ready = gate.update(score, now)
            progress = len(samples) if enrolling else gate.matches
            if debug:
                print(f"[BIOMETRIK SFace] score={score} progress={progress}")
            instruction = (
                f"Rekam {progress}/{ENROLLMENT_SAMPLES}: satu wajah, gerak perlahan"
                if enrolling
                else f"Verifikasi {progress}/{VERIFICATION_MATCHES}: satu wajah"
            )
            cv2.putText(
                frame,
                instruction,
                (10, 25),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.55,
                (0, 255, 255),
                1,
            )
            cv2.putText(
                frame,
                "q / Esc = batal",
                (10, 50),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.55,
                (0, 255, 255),
                1,
            )
            cv2.imshow(title, frame)
            key = cv2.waitKey(1) & 0xFF
            # Cancellation, window closure, access loss, and timeout always win
            # over a candidate success on the same frame.
            if key in (ord("q"), ord("Q"), 27):
                return False
            visible = cv2.getWindowProperty(title, cv2.WND_PROP_VISIBLE)
            if not math.isfinite(visible) or visible < 1:
                return False
            if not _allowed(access_allowed, debug):
                return False
            if time.monotonic() - started >= timeout:
                return False
            if identity_changed:
                return False
            if ready:
                return samples if enrolling else True
        return False
    except FaceAuthError:
        raise
    except Exception as exc:
        raise FaceAuthError("Camera/OpenCV authentication session failed.") from exc
    finally:
        if capture is not None:
            try:
                capture.release()
            except Exception:
                _LOG.debug("Camera release failed", exc_info=True)
        if window_created:
            try:
                cv2.destroyWindow(title)
            except Exception:
                _LOG.debug("Authentication window cleanup failed", exc_info=True)


def enroll(profile_path, model_dir, access_allowed, debug=False) -> bool:
    """Collect 12 consistent samples >=0.3s apart within 40s, then save.

    Cancellation, timeout, access loss, or an identity change returns False and
    leaves the existing profile untouched. Model/camera/profile errors raise
    FaceAuthError. model_dir is normally the project's root/models directory.
    """
    if not _allowed(access_allowed, debug):
        return False
    engine = FaceEngine(model_dir)
    samples = _session(engine, access_allowed, None, debug)
    if samples is False or not _allowed(access_allowed, debug):
        return False
    save_profile(profile_path, samples)
    return True


def verify(profile_path, model_dir, access_allowed, debug=False) -> bool:
    """Verify against a validated sidecar for at most 12s (no liveness check).

    Requires >=8 spaced matches spanning >=2s; missing/multiple faces or a
    mismatch reset progress. Debug changes logging only, never decisions.
    """
    if not _allowed(access_allowed, debug):
        return False
    templates = load_profile(profile_path)
    engine = FaceEngine(model_dir)
    result = _session(engine, access_allowed, templates, debug)
    return result is True and _allowed(access_allowed, debug)
