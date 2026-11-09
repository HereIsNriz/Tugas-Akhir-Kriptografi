# Secret Diary

Aplikasi desktop bertema buku harian yang dibangun dengan **Python + Tkinter**
untuk Tugas Akhir mata kuliah Kriptografi. Semua catatan disimpan dalam bentuk
terenkripsi, file diamankan dengan RSA, pesan dapat disembunyikan di dalam
gambar, dan integritas aset dijaga dengan blockchain sederhana. Login memakai
password (PBKDF2) dan verifikasi wajah, dengan **dongle** sebagai syarat
aktivasi.

## Fitur

- **Multi-akun** — registrasi dan login; setiap akun punya data, model wajah,
  dan pasangan kunci RSA sendiri.
- **Login aman** — password di-hash dengan PBKDF2-HMAC-SHA256 + salt, lalu
  diverifikasi dengan biometrik wajah (OpenCV LBPH).
- **Dongle** — aplikasi hanya berjalan jika flashdisk berisi `license.key`;
  pencabutan saat sesi aktif memaksa logout.
- **Super Encryption teks** — Vigenère (klasik) + LFSR (modern) + Base64,
  diterapkan pada judul dan isi diary sebelum disimpan.
- **Enkripsi file** — RSA implementasi sendiri (tanpa library kripto), hasil
  berekstensi `.rsa`.
- **Enkripsi database** — judul dan isi diary tersimpan sebagai ciphertext di
  SQLite.
- **Steganografi** — menyembunyikan pesan terenkripsi di dalam gambar PNG
  memakai LSB.
- **Blockchain** — mencatat hash entri dan file dengan SHA-256 + proof of work
  untuk mendeteksi perubahan data.
- **Penampil database** — `lihat_db.py` untuk melihat isi database apa adanya
  (terenkripsi), hanya-baca.

## Teknologi

- Python 3.8+
- Tkinter (bawaan Python)
- [Pillow](https://python-pillow.org/) — pemrosesan gambar
- [OpenCV contrib](https://opencv.org/) + NumPy — deteksi & pengenalan wajah

## Instalasi

```bash
pip install -r requirements.txt
```

Atau manual:

```bash
pip install pillow opencv-contrib-python numpy
```

> Catatan: gunakan `opencv-contrib-python` (bukan `opencv-python`), karena
> modul `cv2.face` hanya tersedia di paket contrib.

## Menjalankan

1. **Siapkan dongle**: colokkan flashdisk dan letakkan file `license.key` di
   root-nya dengan isi:

   ```text
   KUNCI-DIARY-2026
   ```

2. Jalankan aplikasi:

   ```bash
   python diary_app.py
   ```

3. Buat akun baru, rekam wajah saat registrasi, lalu login.

4. Untuk melihat isi database (terenkripsi):

   ```bash
   python lihat_db.py
   ```

### Menjalankan tanpa flashdisk (testing)

Buka `diary_app.py` dan sesuaikan konfigurasi di bagian atas file. Pilih salah
satu:

```python
DEMO_MODE = True        # lewati pemeriksaan dongle sepenuhnya (khusus demo)
# atau
DONGLE_DEV_PATH = r"D:\dev\license.key"  # uji file license.key lokal
```

`DONGLE_WAJIB = False` juga bisa dipakai, tetapi `DEMO_MODE` lebih eksplisit
untuk demo. Jangan commit nilai testing ini.

## Struktur Proyek

```text
.
├── diary_app.py                        # aplikasi utama (GUI + algoritma)
├── lihat_db.py                         # penampil database (read-only)
├── haarcascade_frontalface_default.xml # model deteksi wajah OpenCV
├── requirements.txt
├── data/                               # database, model wajah, kunci RSA
└── docs/                               # dokumentasi algoritma
```

## Dokumentasi Algoritma

Penjelasan teori dan implementasi tersedia di folder [`docs/`](docs/):

- `SUPER_ENCRYPTION.md` — rantai Vigenère + LFSR
- `VIGENERE.md`, `LFSR.md`, `BASE64.md`
- `RSA.md`, `FILE_ENCRYPTION.md`
- `PBKDF2.md`, `AUTH_DONGLE.md`, `HAAR_CASCADE_LBPH.md`
- `SHA256.md`, `BLOCKCHAIN_POW.md`
- `STEGANOGRAFI_LSB.md`, `DATABASE_ENCRYPTION.md`
- `REFERENSI.md`

## Catatan Keamanan

Proyek ini dibuat untuk **tujuan pembelajaran**. Beberapa bagian sengaja
disederhanakan dan **belum layak untuk data sensitif di produksi**:

- RSA masih 1024-bit tanpa padding OAEP.
- LFSR masih 16-bit dan belum memakai nonce per pesan.
- Pemeriksaan dongle bersifat client-side.
- Private key dan model wajah belum dienkripsi at-rest.
