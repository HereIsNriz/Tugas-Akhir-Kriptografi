"""
MEDILOCK - Aplikasi Pengamanan Dokumen dan Catatan Kesehatan Pasien
Tugas Akhir Kriptografi
-------------------------------------------------------------------
Fitur & algoritma:
 1. Dongle (flashdisk + license.key)  -> aplikasi hanya jalan bila flashdisk terpasang
 2. Multi akun tenaga medis           -> tiap akun punya data, wajah, dan kunci RSA sendiri
 3. Login biometrik (wajah, OpenCV)   -> verifikasi setelah password
 4. Login password                    -> hash PBKDF2-HMAC-SHA256 + salt
 5. Catatan medis (teks)              -> SUPER ENKRIPSI: Vigenere (klasik) + LFSR (modern)
 6. Dokumen pasien (file)             -> RSA (implementasi sendiri, tanpa library)
 7. Data penting di basisdata         -> nama pasien & catatan tersimpan terenkripsi di SQLite
 8. Citra medis (gambar)              -> Steganografi LSB (PNG)
 9. Aset penting                      -> Blockchain sederhana (SHA-256 + proof of work)

Install:  pip install pillow opencv-contrib-python
Jalankan: python medilock_app.py
"""
import os
import re
import json
import time
import base64
import hashlib
import hmac
import secrets
import sqlite3
import string
import ctypes
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog

try:
    import cv2
    import numpy as np
    HAS_CV = hasattr(cv2, "face")      # butuh opencv-contrib-python
except ImportError:
    HAS_CV = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ====================== KONFIGURASI ======================
DONGLE_WAJIB = True            # False hanya untuk testing tanpa flashdisk
DONGLE_HANYA_REMOVABLE = True  # Ubah ke False jika flashdisk tidak terdeteksi
DONGLE_KEY = "KUNCI-MEDILOCK-2026"  # isi file license.key di flashdisk
DIFFICULTY = "000"             # tingkat kesulitan proof of work
FACE_THRESHOLD = 70            # makin kecil = makin ketat

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
os.makedirs(DATA, exist_ok=True)
DB_FILE = os.path.join(DATA, "medilock.db")
CASCADE_NAMA = "haarcascade_frontalface_default.xml"
KATEGORI = ["Hasil Laboratorium", "Resep Dokter", "Catatan Pemeriksaan"]
TAG_KATEGORI = {"Hasil Laboratorium": "LAB", "Resep Dokter": "RESEP", "Catatan Pemeriksaan": "PERIKSA"}

# ====================== TEMA (MEDILOCK) ======================
BG = "#EEF6F8"        # latar biru-putih klinik
CARD = "#FFFFFF"      # kartu putih
NAVY = "#0B3C49"      # sidebar
NAVY2 = "#14566A"
TEAL = "#1AA7A1"      # aksen medis
TEAL_D = "#13827D"
ROSE = "#D64550"      # merah medis (error / logout)
GREEN = "#2E9E6B"
TEXT = "#1F3A44"
MUTED = "#6B8791"
BORDER = "#D3E3E8"
FIELD = "#F3FAFB"

FONT_JUDUL = ("Segoe UI Semibold", 26, "bold")
FONT_H1 = ("Segoe UI Semibold", 20, "bold")
FONT_H2 = ("Segoe UI", 12, "bold")
FONT_ISI = ("Segoe UI", 11)
FONT_KECIL = ("Segoe UI", 9)
FONT_TULIS = ("Segoe UI", 11)
FONT_MONO = ("Consolas", 9)


# ====================== 1. DONGLE ======================
def cek_dongle():
    if not DONGLE_WAJIB:
        return True
    if not hasattr(ctypes, "windll"):
        return False
    for huruf in string.ascii_uppercase:
        root = f"{huruf}:\\"
        if DONGLE_HANYA_REMOVABLE and ctypes.windll.kernel32.GetDriveTypeW(root) != 2:
            continue
        path = root + "license.key"
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    if f.read().strip() == DONGLE_KEY:
                        return True
            except OSError:
                pass
    return False


# ====================== 2. PASSWORD (HASH) ======================
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()


# ====================== 3. SUPER ENKRIPSI: VIGENERE + LFSR ======================
def vigenere_enc(data: bytes, key: bytes) -> bytes:
    return bytes((b + key[i % len(key)]) % 256 for i, b in enumerate(data))


def vigenere_dec(data: bytes, key: bytes) -> bytes:
    return bytes((b - key[i % len(key)]) % 256 for i, b in enumerate(data))


def lfsr_keystream(seed: int, n: int) -> bytes:
    """LFSR 16-bit, polinomial x^16 + x^14 + x^13 + x^11 + 1."""
    state = seed & 0xFFFF
    if state == 0:
        state = 0xACE1
    out = bytearray()
    for _ in range(n):
        byte = 0
        for _ in range(8):
            out_bit = state & 1
            fb = (state ^ (state >> 2) ^ (state >> 3) ^ (state >> 5)) & 1
            state = (state >> 1) | (fb << 15)
            byte = (byte << 1) | out_bit
        out.append(byte)
    return bytes(out)


def _lfsr_xor(data: bytes, password: str) -> bytes:
    seed = int.from_bytes(hashlib.sha256(password.encode()).digest()[:2], "big")
    ks = lfsr_keystream(seed, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def super_encrypt(teks: str, password: str) -> str:
    """Plaintext -> Vigenere -> LFSR (XOR) -> Base64."""
    v = vigenere_enc(teks.encode("utf-8"), password.encode())
    return base64.b64encode(_lfsr_xor(v, password)).decode()


def super_decrypt(cipher_b64: str, password: str) -> str:
    """Base64 -> LFSR (XOR) -> Vigenere -> Plaintext."""
    v = _lfsr_xor(base64.b64decode(cipher_b64), password)
    return vigenere_dec(v, password.encode()).decode("utf-8")


# ====================== 4. RSA (UNTUK FILE) ======================
def _is_prime(n, k=20):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(c):
            return c


def rsa_keygen(bits=1024):
    e = 65537
    while True:
        p, q = _gen_prime(bits // 2), _gen_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e != 0:
            break
    return {"n": p * q, "e": e, "d": pow(e, -1, phi), "p": p, "q": q}


def rsa_encrypt_bytes(data: bytes, key) -> bytes:
    n, e = key["n"], key["e"]
    k = (n.bit_length() + 7) // 8
    size = k - 2                      # 1 byte untuk prefix 0x01
    out = bytearray(b"RSAF")
    for i in range(0, len(data), size):
        m = int.from_bytes(b"\x01" + data[i:i + size], "big")
        out += pow(m, e, n).to_bytes(k, "big")
    return bytes(out)


def rsa_decrypt_bytes(blob: bytes, key) -> bytes:
    if blob[:4] != b"RSAF":
        raise ValueError("Bukan file hasil enkripsi RSA aplikasi ini.")
    n, d, p, q = key["n"], key["d"], key["p"], key["q"]
    k = (n.bit_length() + 7) // 8
    dp, dq, qinv = d % (p - 1), d % (q - 1), pow(q, -1, p)
    out = bytearray()
    body = blob[4:]
    for i in range(0, len(body), k):
        c = int.from_bytes(body[i:i + k], "big")
        m1, m2 = pow(c, dp, p), pow(c, dq, q)       # CRT supaya lebih cepat
        m = m2 + ((qinv * (m1 - m2)) % p) * q
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        out += raw[1:]                               # buang prefix 0x01
    return bytes(out)


def path_rsa(username):
    return os.path.join(DATA, f"rsa_{username}.json")


def path_wajah(username):
    return os.path.join(DATA, f"face_{username}.yml")


def muat_rsa(username):
    """Tiap akun punya pasangan kunci RSA sendiri."""
    path = path_rsa(username)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    key = rsa_keygen(1024)
    with open(path, "w") as f:
        json.dump(key, f)
    return key


# ====================== 5. STEGANOGRAFI LSB ======================
def stego_embed(src, dst, payload: bytes):
    img = Image.open(src).convert("RGB")
    data = len(payload).to_bytes(4, "big") + payload
    bits = "".join(f"{b:08b}" for b in data)
    flat = [c for px in img.getdata() for c in px]
    if len(bits) > len(flat):
        raise ValueError("Gambar terlalu kecil untuk pesan ini.")
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & ~1) | int(bit)
    img.putdata([tuple(flat[i:i + 3]) for i in range(0, len(flat), 3)])
    img.save(dst, "PNG")                              # harus PNG (lossless)


def stego_extract(src) -> bytes:
    img = Image.open(src).convert("RGB")
    flat = [c for px in img.getdata() for c in px]
    length = int("".join(str(c & 1) for c in flat[:32]), 2)
    if length <= 0 or (length + 4) * 8 > len(flat):
        raise ValueError("Tidak ada pesan tersembunyi di gambar ini.")
    bits = "".join(str(c & 1) for c in flat[32:32 + length * 8])
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


# ====================== 6. DATABASE + BLOCKCHAIN ======================
DB = sqlite3.connect(DB_FILE)
DB.execute("""CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE,
    salt TEXT, hash TEXT, dibuat TEXT)""")
DB.execute("""CREATE TABLE IF NOT EXISTS records(
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, tanggal TEXT,
    kategori TEXT, pasien_enc TEXT, catatan_enc TEXT)""")
DB.execute("""CREATE TABLE IF NOT EXISTS blocks(
    idx INTEGER PRIMARY KEY, ts TEXT, data TEXT,
    prev_hash TEXT, nonce INTEGER, hash TEXT, user_id INTEGER)""")
DB.commit()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def hitung_hash(idx, ts, data, prev, nonce):
    return sha256(f"{idx}|{ts}|{data}|{prev}|{nonce}")


def tambah_blok(data: str, user_id: int = 0):
    last = DB.execute("SELECT idx, hash FROM blocks ORDER BY idx DESC LIMIT 1").fetchone()
    idx, prev = (last[0] + 1, last[1]) if last else (0, "0")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    nonce = 0
    while True:
        h = hitung_hash(idx, ts, data, prev, nonce)
        if h.startswith(DIFFICULTY):
            break
        nonce += 1
    DB.execute("INSERT INTO blocks VALUES(?,?,?,?,?,?,?)", (idx, ts, data, prev, nonce, h, user_id))
    DB.commit()


if DB.execute("SELECT COUNT(*) FROM blocks").fetchone()[0] == 0:
    tambah_blok("Genesis Block - MediLock", 0)


def verifikasi_chain():
    """Memeriksa seluruh rantai (semua akun) dan kecocokan data rekam medis."""
    prev = "0"
    for idx, ts, data, ph, nonce, h, uid in DB.execute(
            "SELECT idx, ts, data, prev_hash, nonce, hash, user_id FROM blocks ORDER BY idx"):
        if ph != prev or hitung_hash(idx, ts, data, ph, nonce) != h or not h.startswith(DIFFICULTY):
            return False, f"Blok #{idx} tidak valid (rantai rusak)."
        prev = h
        if data.startswith("record:"):
            _, rid, hs = data.split(":")
            row = DB.execute("SELECT kategori, pasien_enc, catatan_enc, user_id FROM records WHERE id=?",
                             (rid,)).fetchone()
            if row is None:
                return False, f"Rekam medis #{rid} hilang dari database."
            if sha256(row[0] + row[1] + row[2]) != hs:
                return False, f"Isi rekam medis #{rid} sudah diubah!"
            if row[3] != uid:
                return False, f"Pemilik rekam medis #{rid} sudah diubah!"
    return True, "Semua blok valid. Data rekam medis tidak pernah diubah."


def cari_user(username):
    return DB.execute("SELECT id, salt, hash FROM users WHERE username=?",
                      (username.lower(),)).fetchone()


# ====================== 7. BIOMETRIK WAJAH ======================
def _detektor():
    """Cari file cascade: folder proyek, folder data, lalu folder bawaan OpenCV."""
    kandidat = [os.path.join(BASE, CASCADE_NAMA), os.path.join(DATA, CASCADE_NAMA)]
    if hasattr(cv2, "data"):
        kandidat.append(os.path.join(cv2.data.haarcascades, CASCADE_NAMA))
    for path in kandidat:
        if os.path.isfile(path):
            det = cv2.CascadeClassifier(path)
            if not det.empty():
                return det
    raise FileNotFoundError(
        f"File {CASCADE_NAMA} tidak ditemukan.\n"
        f"Letakkan file tersebut di folder:\n{BASE}")


def biometrik_daftar(face_path) -> bool:
    if not HAS_CV:
        return messagebox.askyesno("Biometrik (Simulasi)",
                                   "OpenCV tidak terpasang.\nDaftarkan sidik jari simulasi?")
    try:
        det = _detektor()
    except FileNotFoundError as ex:
        messagebox.showerror("Biometrik", str(ex))
        return False
    cap, samples = cv2.VideoCapture(0, cv2.CAP_DSHOW), []
    while len(samples) < 40:
        ok, frame = cap.read()
        if not ok:
            break
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        for (x, y, w, h) in det.detectMultiScale(gray, 1.3, 5)[:1]:
            samples.append(cv2.resize(gray[y:y + h, x:x + w], (200, 200)))
            cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)
        cv2.putText(frame, f"Merekam wajah {len(samples)}/40 (q = batal)", (10, 25),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
        cv2.imshow("Daftar Wajah", frame)
        if cv2.waitKey(100) & 0xFF == ord("q"):
            break
    cap.release()
    cv2.destroyAllWindows()
    if len(samples) < 20:
        return False
    rec = cv2.face.LBPHFaceRecognizer_create()
    rec.train(samples, np.zeros(len(samples), dtype=np.int32))
    rec.write(face_path)
    return True


def biometrik_verifikasi(face_path) -> bool:
    if not HAS_CV:
        return messagebox.askyesno("Biometrik (Simulasi)", "Sidik jari simulasi cocok?")
    if not os.path.exists(face_path):
        messagebox.showerror("Biometrik", "Data wajah akun ini tidak ditemukan.")
        return False
    try:
        det = _detektor()
    except FileNotFoundError as ex:
        messagebox.showerror("Biometrik", str(ex))
        return False
    rec = cv2.face.LBPHFaceRecognizer_create()
    rec.read(face_path)
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    cocok, mulai = 0, time.time()
    while time.time() - mulai < 10 and cocok < 5:
        ok, frame = cap.read()
        if not ok:
            break
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        for (x, y, w, h) in det.detectMultiScale(gray, 1.3, 5)[:1]:
            _, conf = rec.predict(cv2.resize(gray[y:y + h, x:x + w], (200, 200)))
            warna = (0, 255, 0) if conf < FACE_THRESHOLD else (0, 0, 255)
            if conf < FACE_THRESHOLD:
                cocok += 1
            cv2.rectangle(frame, (x, y), (x + w, y + h), warna, 2)
        cv2.putText(frame, "Verifikasi wajah... (q = batal)", (10, 25),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
        cv2.imshow("Login Biometrik", frame)
        if cv2.waitKey(100) & 0xFF == ord("q"):
            break
    cap.release()
    cv2.destroyAllWindows()
    return cocok >= 5


# ====================== KOMPONEN UI ======================
def gaya_ttk():
    st = ttk.Style()
    st.theme_use("clam")
    st.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                 rowheight=30, borderwidth=0, font=FONT_ISI)
    st.configure("Treeview.Heading", background=NAVY2, foreground="white",
                 font=("Segoe UI", 10, "bold"), relief="flat", padding=6)
    st.map("Treeview", background=[("selected", TEAL)], foreground=[("selected", "white")])
    st.map("Treeview.Heading", background=[("active", NAVY)])
    st.configure("Vertical.TScrollbar", background=BORDER, troughcolor=CARD,
                 bordercolor=CARD, arrowcolor=NAVY2, relief="flat")
    st.configure("TCombobox", fieldbackground=FIELD, background=FIELD, foreground=TEXT,
                 bordercolor=BORDER, arrowcolor=NAVY2, padding=4)
    st.map("TCombobox", fieldbackground=[("readonly", FIELD), ("disabled", FIELD)],
           foreground=[("disabled", TEXT)])


GAYA_TOMBOL = {  # (warna, teks, hover)
    "primary": (TEAL, "#FFFFFF", TEAL_D),
    "ghost": (CARD, NAVY, "#E3F1F3"),
    "danger": (ROSE, "#FFFFFF", "#B3333D"),
}


def tombol(parent, teks, cmd, gaya="primary", **kw):
    bg, fg, hover = GAYA_TOMBOL[gaya]
    b = tk.Button(parent, text=teks, command=cmd, bg=bg, fg=fg, activebackground=hover,
                  activeforeground=fg, disabledforeground="#A7BDC3", relief="flat", bd=0,
                  cursor="hand2", font=("Segoe UI", 10, "bold"), padx=16, pady=9,
                  highlightthickness=1 if gaya == "ghost" else 0, highlightbackground=BORDER, **kw)
    b.bind("<Enter>", lambda e: b.config(bg=hover) if str(b["state"]) != "disabled" else None)
    b.bind("<Leave>", lambda e: b.config(bg=bg))
    return b


def input_field(parent, label, show=None):
    tk.Label(parent, text=label, bg=parent["bg"], fg=MUTED, font=FONT_KECIL,
             anchor="w").pack(fill="x", pady=(12, 3))
    e = tk.Entry(parent, show=show, font=FONT_ISI, relief="flat", bg=FIELD, fg=TEXT,
                 insertbackground=TEXT, highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=TEAL, width=32)
    e.pack(fill="x", ipady=8)
    return e


def kartu(parent, **kw):
    return tk.Frame(parent, bg=CARD, highlightthickness=1, highlightbackground=BORDER, **kw)


def judul_halaman(parent, judul, sub):
    h = tk.Frame(parent, bg=BG)
    h.pack(fill="x", pady=(0, 14))
    tk.Label(h, text=judul, bg=BG, fg=NAVY, font=FONT_H1).pack(anchor="w")
    tk.Label(h, text=sub, bg=BG, fg=MUTED, font=FONT_ISI).pack(anchor="w")


def teks_readonly(widget, isi):
    widget.config(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", isi)
    widget.config(state="disabled")


# ---------- Dialog bertema MediLock (pengganti messagebox bawaan Windows) ----------
def _dialog(judul, pesan, ikon, warna, ya="OK", tidak=None):
    """Dialog modal bertema MediLock. Mengembalikan True jika tombol utama ditekan."""
    parent = tk._default_root
    win = tk.Toplevel(parent)
    win.withdraw()
    win.title(judul)
    win.configure(bg=CARD)
    win.resizable(False, False)
    hasil = {"v": False}

    def tutup(v):
        hasil["v"] = v
        win.destroy()

    head = tk.Frame(win, bg=warna)
    head.pack(fill="x")
    tk.Label(head, text=ikon, bg=warna, fg="white", font=("Segoe UI Emoji", 22)).pack(
        side="left", padx=(22, 10), pady=14)
    tk.Label(head, text=judul, bg=warna, fg="white", font=("Segoe UI Semibold", 15, "bold")).pack(
        side="left", pady=14, padx=(0, 24))
    tk.Label(win, text=pesan, bg=CARD, fg=TEXT, font=FONT_ISI, justify="left", anchor="w",
             wraplength=380).pack(fill="x", padx=26, pady=(22, 8))
    bar = tk.Frame(win, bg=CARD)
    bar.pack(fill="x", padx=22, pady=(10, 20))
    btn = tombol(bar, ya, lambda: tutup(True))
    btn.pack(side="right")
    if tidak:
        tombol(bar, tidak, lambda: tutup(False), "ghost").pack(side="right", padx=(0, 8))
    win.bind("<Return>", lambda e: tutup(True))
    win.bind("<Escape>", lambda e: tutup(False))
    win.protocol("WM_DELETE_WINDOW", lambda: tutup(False))

    win.update_idletasks()
    w, h = win.winfo_reqwidth(), win.winfo_reqheight()
    if parent is not None and parent.winfo_viewable():
        win.transient(parent)
        x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
    else:
        x = (win.winfo_screenwidth() - w) // 2
        y = (win.winfo_screenheight() - h) // 2
    win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
    win.deiconify()
    try:
        win.wait_visibility()
        win.grab_set()
    except tk.TclError:
        pass
    win.lift()
    win.focus_force()
    btn.focus_set()
    win.wait_window()
    return hasil["v"]


class messagebox:
    """Pengganti tkinter.messagebox dengan tampilan senada aplikasi."""
    @staticmethod
    def showinfo(judul, pesan):
        _dialog(judul, pesan, "✅", GREEN)

    @staticmethod
    def showwarning(judul, pesan):
        _dialog(judul, pesan, "⚠️", TEAL_D)

    @staticmethod
    def showerror(judul, pesan):
        _dialog(judul, pesan, "❌", ROSE)

    @staticmethod
    def askyesno(judul, pesan):
        return _dialog(judul, pesan, "❓", NAVY2, ya="Ya", tidak="Tidak")


# ====================== APLIKASI TKINTER ======================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MediLock - Pengamanan Dokumen Kesehatan Pasien")
        self.configure(bg=BG)
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        lebar, tinggi = min(1040, sw - 60), min(700, sh - 110)   # tidak melebihi layar kecil
        self.geometry(f"{lebar}x{tinggi}+{(sw - lebar) // 2}+{max((sh - tinggi) // 2 - 20, 0)}")
        self.minsize(min(900, lebar), min(600, tinggi))
        self.bind("<F11>", lambda e: self.atur_fullscreen(not self.attributes("-fullscreen")))
        self.bind("<Escape>", lambda e: self.atur_fullscreen(False))
        gaya_ttk()
        self.option_add("*TCombobox*Listbox.font", FONT_ISI)

        self.user = None
        self.user_id = None
        self.password = None
        self.rsa = None
        self.frame = None
        self.sudah_logout = False      # tombol Exit hanya muncul setelah logout
        self.entry_ids = []
        self.tampil_login()

    def atur_fullscreen(self, aktif):
        self.attributes("-fullscreen", bool(aktif))

    def bersihkan(self):
        if self.frame:
            self.frame.destroy()
        self.frame = tk.Frame(self, bg=BG)
        self.frame.pack(fill="both", expand=True)

    # ---------- Kerangka halaman login / register ----------
    def bangun_auth(self, judul, sub):
        self.bersihkan()
        root = self.frame
        root.columnconfigure(0, weight=4, uniform="a")
        root.columnconfigure(1, weight=6, uniform="a")
        root.rowconfigure(0, weight=1)

        kiri = tk.Frame(root, bg=NAVY)
        kiri.grid(row=0, column=0, sticky="nsew")
        box = tk.Frame(kiri, bg=NAVY)
        box.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(box, text="🏥", bg=NAVY, fg="#E6F6F7", font=("Segoe UI Emoji", 60)).pack()
        tk.Label(box, text="MediLock", bg=NAVY, fg="#E6F6F7", font=FONT_JUDUL).pack(pady=(8, 2))
        tk.Label(box, text="Dokumen & catatan kesehatan pasien,\nterlindungi dengan kriptografi.",
                 bg=NAVY, fg="#A9D3D8", font=FONT_ISI, justify="center").pack(pady=(0, 18))
        tk.Label(box, text="🔐 Vigenere + LFSR     🗝 RSA\n🖼 Steganografi     ⛓ Blockchain",
                 bg=NAVY, fg="#7FB2B8", font=FONT_KECIL, justify="center").pack()

        kanan = tk.Frame(root, bg=BG)
        kanan.grid(row=0, column=1, sticky="nsew")
        card = kartu(kanan, padx=40, pady=32)
        card.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(card, text=judul, bg=CARD, fg=NAVY, font=FONT_H1).pack(anchor="w")
        tk.Label(card, text=sub, bg=CARD, fg=MUTED, font=FONT_ISI).pack(anchor="w")
        return card

    def tombol_exit_jika_logout(self, card):
        if self.sudah_logout:
            tombol(card, "⏻  Keluar dari Aplikasi", self.keluar_aplikasi, "danger").pack(
                fill="x", pady=(10, 0))

    def keluar_aplikasi(self):
        if messagebox.askyesno("Keluar", "Tutup aplikasi MediLock?"):
            self.destroy()

    # ---------- Login ----------
    def tampil_login(self):
        card = self.bangun_auth("Login Tenaga Medis", "Masuk untuk mengakses data pasien")
        self.e_user = input_field(card, "USERNAME")
        self.e_pw = input_field(card, "PASSWORD", show="•")
        tombol(card, "Masuk  (Password + Wajah)", self.login).pack(fill="x", pady=(22, 8))
        tk.Label(card, text="Belum punya akun?", bg=CARD, fg=MUTED, font=FONT_KECIL).pack(pady=(6, 2))
        tombol(card, "Buat Akun Baru", self.tampil_registrasi, "ghost").pack(fill="x")
        self.tombol_exit_jika_logout(card)
        self.e_user.focus()
        self.e_user.bind("<Return>", lambda e: self.e_pw.focus())
        self.e_pw.bind("<Return>", lambda e: self.login())

    def login(self):
        username, pw = self.e_user.get().strip().lower(), self.e_pw.get()
        u = cari_user(username) if username else None
        if not u or not hmac.compare_digest(hash_password(pw, bytes.fromhex(u[1])), u[2]):
            messagebox.showerror("Gagal", "Username atau password salah.")
            return
        if not biometrik_verifikasi(path_wajah(username)):
            messagebox.showerror("Gagal", "Verifikasi biometrik gagal.")
            return
        self.config(cursor="watch")
        self.update()
        self.user, self.user_id, self.password = username, u[0], pw
        self.rsa = muat_rsa(username)
        self.sudah_logout = False
        self.config(cursor="")
        self.tampil_utama()

    # ---------- Registrasi ----------
    def tampil_registrasi(self):
        card = self.bangun_auth("Daftar Tenaga Medis", "Buat akun untuk mengelola data pasien dengan aman")
        self.e_user = input_field(card, "USERNAME  (3-20 karakter: huruf, angka, _)")
        self.e_pw = input_field(card, "PASSWORD  (min. 6 karakter)", show="•")
        self.e_pw2 = input_field(card, "ULANGI PASSWORD", show="•")
        tombol(card, "Daftar + Rekam Wajah", self.daftar).pack(fill="x", pady=(22, 8))
        tombol(card, "← Sudah punya akun? Masuk", self.tampil_login, "ghost").pack(fill="x")
        self.tombol_exit_jika_logout(card)
        self.e_user.focus()

    def daftar(self):
        username = self.e_user.get().strip().lower()
        pw, pw2 = self.e_pw.get(), self.e_pw2.get()
        if not re.fullmatch(r"[a-z0-9_]{3,20}", username):
            messagebox.showwarning("Username tidak valid",
                                   "Username 3-20 karakter, hanya huruf, angka, dan underscore.")
            return
        if cari_user(username):
            messagebox.showwarning("Username dipakai", "Username sudah terdaftar. Pilih yang lain.")
            return
        if len(pw) < 6 or pw != pw2:
            messagebox.showwarning("Password", "Password minimal 6 karakter dan harus sama.")
            return
        if not biometrik_daftar(path_wajah(username)):
            messagebox.showerror("Gagal", "Pendaftaran biometrik gagal / dibatalkan.")
            return
        self.config(cursor="watch")
        self.update()
        salt = secrets.token_bytes(16)
        DB.execute("INSERT INTO users(username, salt, hash, dibuat) VALUES(?,?,?,?)",
                   (username, salt.hex(), hash_password(pw, salt),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        DB.commit()
        muat_rsa(username)                            # buat kunci RSA akun ini
        self.config(cursor="")
        messagebox.showinfo("Berhasil", f"Akun '{username}' dibuat. Silakan login.")
        self.tampil_login()

    # ---------- Logout ----------
    def logout(self):
        if not messagebox.askyesno("Logout", "Yakin ingin logout?"):
            return
        self.user = self.user_id = self.password = self.rsa = None   # hapus kunci dari memori
        self.sudah_logout = True
        self.tampil_login()

    # ---------- Halaman utama (sidebar + konten) ----------
    def tampil_utama(self):
        self.bersihkan()
        side = tk.Frame(self.frame, bg=NAVY, width=240)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        tk.Label(side, text="🏥 MediLock", bg=NAVY, fg="#E6F6F7",
                 font=("Segoe UI Semibold", 17, "bold")).pack(pady=(26, 4), padx=18, anchor="w")
        tk.Label(side, text=f"Halo, {self.user}", bg=NAVY, fg="#A9D3D8",
                 font=FONT_ISI).pack(padx=20, anchor="w", pady=(0, 22))

        self.konten = tk.Frame(self.frame, bg=BG)
        self.konten.pack(side="left", fill="both", expand=True)

        self.halaman, self.nav, self.aktif = {}, {}, None
        menu = [("rekam", "🩺   Rekam Medis", self.hal_rekam),
                ("file", "📁   Dokumen Pasien", self.hal_file),
                ("stego", "🖼   Citra Medis", self.hal_stego),
                ("chain", "⛓   Audit Blockchain", self.hal_chain)]
        for kode, label, builder in menu:
            frm = tk.Frame(self.konten, bg=BG)
            builder(frm)
            self.halaman[kode] = frm
            b = tk.Button(side, text=label, anchor="w", relief="flat", bd=0, bg=NAVY,
                          fg="#CFE8EA", activebackground=NAVY2, activeforeground="white",
                          font=("Segoe UI", 11), padx=22, pady=11, cursor="hand2",
                          command=lambda k=kode: self.buka(k))
            b.pack(fill="x")
            b.bind("<Enter>", lambda e, k=kode: self.nav[k].config(bg=NAVY2) if k != self.aktif else None)
            b.bind("<Leave>", lambda e, k=kode: self.nav[k].config(bg=NAVY) if k != self.aktif else None)
            self.nav[kode] = b

        bawah = tk.Frame(side, bg=NAVY)
        bawah.pack(side="bottom", fill="x", padx=18, pady=20)
        tk.Label(bawah, text="🔌 Dongle terpasang", bg=NAVY, fg="#7FB2B8",
                 font=FONT_KECIL).pack(anchor="w", pady=(0, 8))
        tombol(bawah, "↩  Logout", self.logout, "danger").pack(fill="x")
        self.buka("rekam")

    def buka(self, kode):
        for k, f in self.halaman.items():
            f.pack_forget()
            self.nav[k].config(bg=NAVY, fg="#CFE8EA", font=("Segoe UI", 11))
        self.aktif = kode
        self.nav[kode].config(bg=TEAL, fg="white", font=("Segoe UI", 11, "bold"))
        self.halaman[kode].pack(fill="both", expand=True, padx=30, pady=24)
        if kode == "rekam":
            self.refresh_rekam()
        elif kode == "chain":
            self.refresh_chain()

    # ---------- Halaman Rekam Medis ----------
    def hal_rekam(self, p):
        judul_halaman(p, "Rekam Medis Pasien",
                      "Setiap catatan dienkripsi (Vigenere + LFSR) sebelum disimpan ke database")
        isi = tk.Frame(p, bg=BG)
        isi.pack(fill="both", expand=True)
        isi.columnconfigure(1, weight=1)
        isi.rowconfigure(0, weight=1)

        # daftar rekam medis
        kiri = kartu(isi, padx=12, pady=12)
        kiri.grid(row=0, column=0, sticky="ns", padx=(0, 16))
        top = tk.Frame(kiri, bg=CARD)
        top.pack(fill="x", pady=(0, 8))
        tk.Label(top, text="Daftar Rekam Medis", bg=CARD, fg=NAVY, font=FONT_H2).pack(side="left")
        tombol(top, "＋ Baru", self.tulis_baru).pack(side="right")
        lw = tk.Frame(kiri, bg=CARD)
        lw.pack(fill="both", expand=True)
        sb = ttk.Scrollbar(lw, orient="vertical")
        self.lb = tk.Listbox(lw, width=30, bd=0, highlightthickness=0, bg=CARD, fg=TEXT,
                             selectbackground=TEAL, selectforeground="white", font=FONT_ISI,
                             activestyle="none", yscrollcommand=sb.set)
        sb.config(command=self.lb.yview)
        sb.pack(side="right", fill="y")
        self.lb.pack(side="left", fill="both", expand=True)
        self.lb.bind("<<ListboxSelect>>", self.pilih_entri)

        # formulir rekam medis
        kanan = kartu(isi, padx=22, pady=18)
        kanan.grid(row=0, column=1, sticky="nsew")
        self.l_tgl = tk.Label(kanan, text="", bg=CARD, fg=MUTED, font=FONT_KECIL)
        self.l_tgl.pack(anchor="w", pady=(0, 8))
        form = tk.Frame(kanan, bg=CARD)
        form.pack(fill="x")
        form.columnconfigure(0, weight=1)
        tk.Label(form, text="NAMA PASIEN", bg=CARD, fg=MUTED, font=FONT_KECIL).grid(row=0, column=0, sticky="w")
        tk.Label(form, text="JENIS DOKUMEN", bg=CARD, fg=MUTED, font=FONT_KECIL).grid(
            row=0, column=1, sticky="w", padx=(12, 0))
        self.e_judul = tk.Entry(form, font=FONT_ISI, relief="flat", bg=FIELD, fg=TEXT,
                                insertbackground=TEXT, readonlybackground=FIELD,
                                highlightthickness=1, highlightbackground=BORDER, highlightcolor=TEAL)
        self.e_judul.grid(row=1, column=0, sticky="ew", ipady=7, pady=(3, 0))
        self.cb_kat = ttk.Combobox(form, values=KATEGORI, state="readonly", font=FONT_ISI, width=22)
        self.cb_kat.grid(row=1, column=1, sticky="ew", padx=(12, 0), ipady=4, pady=(3, 0))
        tk.Label(kanan, text="ISI CATATAN / HASIL PEMERIKSAAN", bg=CARD, fg=MUTED,
                 font=FONT_KECIL).pack(anchor="w", pady=(12, 3))

        # bagian bawah dipasang lebih dulu supaya tombol Simpan tetap terlihat di jendela kecil
        self.t_cipher = tk.Text(kanan, height=3, wrap="char", font=FONT_MONO, bg="#E6F1F3",
                                fg=NAVY2, relief="flat", state="disabled", padx=8, pady=6)
        self.t_cipher.pack(side="bottom", fill="x")
        tk.Label(kanan, text="🔒 Ciphertext yang tersimpan di database:", bg=CARD, fg=MUTED,
                 font=FONT_KECIL).pack(side="bottom", anchor="w")
        bar = tk.Frame(kanan, bg=CARD)
        bar.pack(side="bottom", fill="x", pady=10)
        self.btn_simpan = tombol(bar, "💾  Simpan Rekam Medis", self.simpan_entri)
        self.btn_simpan.pack(side="left")
        tombol(bar, "Kosongkan", self.tulis_baru, "ghost").pack(side="left", padx=8)
        self.t_isi = tk.Text(kanan, height=6, wrap="word", font=FONT_TULIS, bg="#FBFEFE", fg=TEXT,
                             relief="flat", padx=14, pady=10, spacing2=4, spacing3=4,
                             insertbackground=TEXT, highlightthickness=1,
                             highlightbackground=BORDER, highlightcolor=TEAL)
        self.t_isi.pack(fill="both", expand=True)
        self.tulis_baru()

    def set_baca(self, baca):
        self.e_judul.config(state="readonly" if baca else "normal")
        self.cb_kat.config(state="disabled" if baca else "readonly")
        self.t_isi.config(state="disabled" if baca else "normal")
        self.btn_simpan.config(state="disabled" if baca else "normal")

    def tulis_baru(self):
        self.set_baca(False)
        self.e_judul.delete(0, "end")
        self.cb_kat.current(0)
        self.t_isi.delete("1.0", "end")
        self.lb.selection_clear(0, "end")
        self.l_tgl.config(text="✏️  Rekam medis baru - " + datetime.now().strftime("%d %B %Y"))
        teks_readonly(self.t_cipher, "")
        self.e_judul.focus()

    def refresh_rekam(self):
        self.lb.delete(0, "end")
        self.entry_ids = []
        for rid, kat, pasien_enc in DB.execute(
                "SELECT id, kategori, pasien_enc FROM records WHERE user_id=? ORDER BY id DESC",
                (self.user_id,)):
            try:
                nama = super_decrypt(pasien_enc, self.password)
            except Exception:
                nama = "(gagal dekripsi)"
            self.lb.insert("end", f" [{TAG_KATEGORI.get(kat, '?')}]  {nama}")
            self.entry_ids.append(rid)

    def simpan_entri(self):
        nama, kat = self.e_judul.get().strip(), self.cb_kat.get()
        isi = self.t_isi.get("1.0", "end").strip()
        if not nama or not isi:
            messagebox.showwarning("Data belum lengkap", "Nama pasien dan isi catatan harus diisi.")
            return
        p_enc, c_enc = super_encrypt(nama, self.password), super_encrypt(isi, self.password)
        cur = DB.execute(
            "INSERT INTO records(user_id, tanggal, kategori, pasien_enc, catatan_enc) VALUES(?,?,?,?,?)",
            (self.user_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), kat, p_enc, c_enc))
        DB.commit()
        tambah_blok(f"record:{cur.lastrowid}:{sha256(kat + p_enc + c_enc)}", self.user_id)
        self.refresh_rekam()
        self.tulis_baru()
        messagebox.showinfo("Tersimpan", "Rekam medis dienkripsi, disimpan, dan dicatat di blockchain.")

    def pilih_entri(self, _):
        sel = self.lb.curselection()
        if not sel:
            return
        row = DB.execute("SELECT tanggal, kategori, pasien_enc, catatan_enc FROM records "
                         "WHERE id=? AND user_id=?", (self.entry_ids[sel[0]], self.user_id)).fetchone()
        if not row:
            return
        self.set_baca(False)
        self.e_judul.delete(0, "end")
        self.t_isi.delete("1.0", "end")
        try:
            self.e_judul.insert(0, super_decrypt(row[2], self.password))
            self.t_isi.insert("1.0", super_decrypt(row[3], self.password))
        except Exception:
            messagebox.showerror("Error", "Gagal mendekripsi rekam medis.")
        self.cb_kat.set(row[1])
        self.l_tgl.config(text="🩺  Dicatat pada " + row[0])
        teks_readonly(self.t_cipher, row[3])
        self.set_baca(True)

    # ---------- Halaman File (RSA) ----------
    def hal_file(self, p):
        judul_halaman(p, "Dokumen Pasien", "Amankan dokumen kesehatan (hasil lab, resep, surat rujukan) dengan RSA 1024-bit")
        c = kartu(p, padx=30, pady=26)
        c.pack(fill="x")
        tk.Label(c, text="📁", bg=CARD, font=("Segoe UI Emoji", 40)).pack()
        tk.Label(c, text="Cocok untuk PDF hasil laboratorium, foto resep, atau surat rujukan (< 2 MB agar cepat).\n"
                         "File hasil enkripsi berekstensi .rsa dan hanya bisa dibuka oleh akun tenaga medis ini.",
                 bg=CARD, fg=MUTED, font=FONT_ISI, justify="center").pack(pady=(4, 18))
        row = tk.Frame(c, bg=CARD)
        row.pack()
        tombol(row, "🔒  Enkripsi Dokumen...", self.enkripsi_file).pack(side="left", padx=6)
        tombol(row, "🔓  Dekripsi Dokumen (.rsa)...", self.dekripsi_file, "ghost").pack(side="left", padx=6)
        self.l_file = tk.Label(c, text="", bg=CARD, fg=GREEN, font=FONT_ISI, wraplength=640)
        self.l_file.pack(pady=(18, 0))

    def enkripsi_file(self):
        path = filedialog.askopenfilename(title="Pilih dokumen pasien")
        if not path:
            return
        if os.path.getsize(path) > 5 * 1024 * 1024:
            messagebox.showwarning("Terlalu besar", "Maksimal 5 MB.")
            return
        self.config(cursor="watch")
        self.update()
        with open(path, "rb") as f:
            blob = rsa_encrypt_bytes(f.read(), self.rsa)
        out = path + ".rsa"
        with open(out, "wb") as f:
            f.write(blob)
        tambah_blok(f"file:{os.path.basename(out)}:{hashlib.sha256(blob).hexdigest()}", self.user_id)
        self.config(cursor="")
        self.l_file.config(text=f"✅ Berhasil dienkripsi:\n{out}", fg=GREEN)

    def dekripsi_file(self):
        path = filedialog.askopenfilename(title="Pilih file .rsa", filetypes=[("RSA", "*.rsa")])
        if not path:
            return
        try:
            self.config(cursor="watch")
            self.update()
            with open(path, "rb") as f:
                hasil = rsa_decrypt_bytes(f.read(), self.rsa)
            self.config(cursor="")
        except Exception as ex:
            self.config(cursor="")
            messagebox.showerror("Gagal", str(ex))
            return
        nama = os.path.basename(path)[:-4] if path.endswith(".rsa") else "hasil"
        out = filedialog.asksaveasfilename(initialfile=nama, title="Simpan hasil dekripsi")
        if out:
            with open(out, "wb") as f:
                f.write(hasil)
            self.l_file.config(text=f"✅ Berhasil didekripsi:\n{out}", fg=GREEN)

    # ---------- Halaman Steganografi ----------
    def hal_stego(self, p):
        judul_halaman(p, "Steganografi Citra Medis", "Sembunyikan catatan rahasia di dalam citra medis (mis. hasil rontgen) - LSB, PNG")
        c = kartu(p, padx=26, pady=20)
        c.pack(fill="both", expand=True)
        if not HAS_PIL:
            tk.Label(c, text="Pillow belum terpasang.\nJalankan: pip install pillow",
                     bg=CARD, fg=ROSE, font=FONT_ISI).pack(pady=30)
            return
        tk.Label(c, text="Catatan rahasia (dienkripsi Vigenere + LFSR sebelum disisipkan):",
                 bg=CARD, fg=MUTED, font=FONT_KECIL).pack(anchor="w")
        self.t_stego = tk.Text(c, height=6, wrap="word", font=FONT_TULIS, bg="#FBFEFE", fg=TEXT,
                               relief="flat", padx=12, pady=8, highlightthickness=1,
                               highlightbackground=BORDER, highlightcolor=TEAL)
        self.t_stego.pack(fill="x", pady=(4, 12))
        row = tk.Frame(c, bg=CARD)
        row.pack(anchor="w")
        tombol(row, "🖼  Pilih Citra & Sisipkan Catatan", self.sisip).pack(side="left")
        tombol(row, "🔍  Ekstrak Catatan dari Citra", self.ekstrak, "ghost").pack(side="left", padx=8)
        tk.Label(c, text="Hasil:", bg=CARD, fg=MUTED, font=FONT_KECIL).pack(anchor="w", pady=(16, 3))
        self.t_hasil = tk.Text(c, height=6, wrap="word", font=FONT_TULIS, bg="#E6F1F3", fg=NAVY,
                               relief="flat", padx=12, pady=8, state="disabled")
        self.t_hasil.pack(fill="x")

    def sisip(self):
        pesan = self.t_stego.get("1.0", "end").strip()
        if not pesan:
            messagebox.showwarning("Kosong", "Isi catatan rahasia dulu.")
            return
        src = filedialog.askopenfilename(title="Citra medis (gambar sampul)",
                                         filetypes=[("Gambar", "*.png *.jpg *.jpeg *.bmp")])
        if not src:
            return
        dst = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")],
                                           title="Simpan gambar hasil (PNG)")
        if not dst:
            return
        try:
            self.config(cursor="watch")
            self.update()
            stego_embed(src, dst, super_encrypt(pesan, self.password).encode())
            self.config(cursor="")
            teks_readonly(self.t_hasil, f"✅ Catatan berhasil disisipkan ke:\n{dst}")
        except Exception as ex:
            self.config(cursor="")
            messagebox.showerror("Gagal", str(ex))

    def ekstrak(self):
        src = filedialog.askopenfilename(title="Gambar stego", filetypes=[("PNG", "*.png")])
        if not src:
            return
        try:
            self.config(cursor="watch")
            self.update()
            pesan = super_decrypt(stego_extract(src).decode(), self.password)
            self.config(cursor="")
            teks_readonly(self.t_hasil, pesan)
        except Exception:
            self.config(cursor="")
            messagebox.showerror("Gagal", "Tidak ada pesan valid di gambar ini\n"
                                          "(atau gambar ini disisipkan oleh akun lain).")

    # ---------- Halaman Blockchain ----------
    def hal_chain(self, p):
        judul_halaman(p, "Audit Blockchain", "Hash setiap rekam medis & dokumen dicatat agar perubahan data pasien mudah terdeteksi")
        c = kartu(p, padx=14, pady=14)
        c.pack(fill="both", expand=True)
        wrap = tk.Frame(c, bg=CARD)
        wrap.pack(fill="both", expand=True)
        cols = ("idx", "waktu", "data", "hash")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings")
        for col, w, teks in zip(cols, (50, 150, 360, 260), ("#", "Waktu", "Data", "Hash")):
            self.tree.heading(col, text=teks)
            self.tree.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        bar = tk.Frame(c, bg=CARD)
        bar.pack(fill="x", pady=(12, 0))
        tombol(bar, "✔  Verifikasi Blockchain", self.cek_chain).pack(side="left")
        tombol(bar, "⟳ Refresh", self.refresh_chain, "ghost").pack(side="left", padx=8)
        self.l_chain = tk.Label(bar, text="", bg=CARD, font=("Segoe UI", 10, "bold"))
        self.l_chain.pack(side="left", padx=10)

    def refresh_chain(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for idx, ts, data, h in DB.execute(
                "SELECT idx, ts, data, hash FROM blocks WHERE user_id=? OR idx=0 ORDER BY idx",
                (self.user_id,)):
            self.tree.insert("", "end", values=(idx, ts, data[:50], h[:30] + "..."))

    def cek_chain(self):
        ok, msg = verifikasi_chain()
        self.l_chain.config(text=("✅ " if ok else "❌ ") + msg, fg=GREEN if ok else ROSE)


if __name__ == "__main__":
    if not cek_dongle():
        r = tk.Tk()
        r.withdraw()
        messagebox.showerror("Akses Ditolak",
                             "Dongle tidak ditemukan!\nPasang flashdisk yang berisi license.key.")
        r.destroy()
        raise SystemExit
    App().mainloop()
