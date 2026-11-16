"""
Launcher pengujian tanpa flashdisk.

Membuat dev/license.key (di-ignore Git) lalu menjalankan aplikasi dengan
DONGLE_DEV_PATH diarahkan ke file tersebut. diary_app.py tidak diubah, jadi
mode demo dengan flashdisk tetap normal.

Jalankan:
    python run_demo.py          # validasi dongle lewat dev/license.key
    python run_demo.py --demo   # lewati dongle sepenuhnya
    python run_demo.py --check  # cek dongle saja, tanpa membuka GUI
"""
import os
import sys
import tkinter as tk
from tkinter import messagebox

BASE = os.path.dirname(os.path.abspath(__file__))
LICENSE_PATH = os.path.join(BASE, "dev", "license.key")
LICENSE_ISI = "KUNCI-DIARY-2026"


def siapkan_license():
    os.makedirs(os.path.dirname(LICENSE_PATH), exist_ok=True)
    if not os.path.exists(LICENSE_PATH):
        with open(LICENSE_PATH, "w", encoding="utf-8") as f:
            f.write(LICENSE_ISI)
    return LICENSE_PATH


def main():
    try:
        import cv2  # noqa: F401
    except ImportError:
        print("OpenCV belum terpasang. Jalankan: pip install -r requirements.txt")
        return 1

    import diary_app as app

    app.DONGLE_DEV_PATH = siapkan_license()
    if "--demo" in sys.argv:
        app.DEMO_MODE = True

    if not app.cek_dongle():
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Akses Ditolak", "Dongle tidak valid.")
        root.destroy()
        return 1

    if "--check" in sys.argv:
        print("Dongle valid:", app.DONGLE_DEV_PATH)
        return 0

    app.App().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
