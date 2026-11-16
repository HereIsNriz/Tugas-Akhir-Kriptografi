"""Download the public OpenCV Zoo YuNet/SFace models; never upload user data."""

import hashlib
import os
import urllib.request
from pathlib import Path

MODELS = (
    (
        "face_detection_yunet",
        "face_detection_yunet_2023mar.onnx",
        "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
        232589,
    ),
    (
        "face_recognition_sface",
        "face_recognition_sface_2021dec.onnx",
        "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79",
        38696353,
    ),
)
BASE_URL = "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models"
MODEL_DIR = Path(__file__).resolve().parent / "models"


def valid_file(path, digest, size):
    if not path.is_file() or path.stat().st_size != size:
        return False
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest() == digest


def download_models():
    MODEL_DIR.mkdir(exist_ok=True)
    for folder, name, digest, size in MODELS:
        destination = MODEL_DIR / name
        if valid_file(destination, digest, size):
            print(f"OK: {name}")
            continue
        temporary = destination.with_suffix(".download")
        print(f"Mengunduh {name} ({size / 1_000_000:.1f} MB)...", flush=True)
        try:
            request = urllib.request.Request(
                f"{BASE_URL}/{folder}/{name}",
                headers={"User-Agent": "SecretDiary-model-setup"},
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                with temporary.open("wb") as stream:
                    downloaded = 0
                    while chunk := response.read(1024 * 1024):
                        downloaded += len(chunk)
                        if downloaded > size:
                            raise ValueError(f"Ukuran model tidak sesuai: {name}")
                        stream.write(chunk)
            if not valid_file(temporary, digest, size):
                raise ValueError(f"Checksum SHA-256 model tidak sesuai: {name}")
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    print("Model YuNet + SFace siap. Foto/embedding tidak dikirim ke internet.")


if __name__ == "__main__":
    try:
        download_models()
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Gagal menyiapkan model: {exc}") from exc
