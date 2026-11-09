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
  diverifikasi dengan biometrik wajah (OpenCV YuNet + SFace).
- **Dongle** — aplikasi hanya berjalan jika flashdisk berisi `license.key`;
  pencabutan saat sesi aktif memaksa logout.
- **Super Encryption teks** — Vigenère (klasik) + LFSR (modern) + Base64,
  diterapkan pada judul dan isi diary sebelum disimpan.
- **Enkripsi file** — RSA implementasi sendiri (tanpa library kripto), format
  baru RSA2 berekstensi `.rsa`, dengan identitas kunci, panjang asli, dan checksum
  SHA-256 plaintext; format lama RSAF tetap dapat dibaca dengan peringatan.
- **Enkripsi database** — judul dan isi diary tersimpan sebagai ciphertext di
  SQLite.
- **Steganografi** — menyembunyikan pesan terenkripsi di dalam gambar PNG
  memakai LSB.
- **Blockchain** — rantai hash lokal SHA-256 + proof of work. Entri dan blok
  `entry2` disimpan atomik di SQLite; event `file2` mencatat path absolut,
  pemilik, dan hash ciphertext. Verifikasi mencocokkan rantai dengan asetnya.
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

Siapkan model publik YuNet + SFace (unduhan sekitar **39 MB**, diperiksa SHA-256):

```bash
python setup_face_models.py
```

Pencocokan berjalan lokal; tidak mengunggah foto atau embedding. Jika model
belum tersedia atau rusak, autentikasi ditolak, bukan fallback ke LBPH.

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

Cara cepat (disarankan):

```bash
python run_demo.py          # validasi dongle lewat dev/license.key
python run_demo.py --demo   # lewati dongle sepenuhnya
```

Atau double-click `run_demo.bat`. Launcher ini otomatis membuat
`dev/license.key` (di-ignore Git) dan mengarahkan `DONGLE_DEV_PATH` ke file
tersebut tanpa mengubah `diary_app.py`.

Alternatif manual: sesuaikan konfigurasi di bagian atas `diary_app.py`:

```python
DEMO_MODE = True        # lewati pemeriksaan dongle sepenuhnya (khusus demo)
# atau
DONGLE_DEV_PATH = r"D:\dev\license.key"  # uji file license.key lokal
```

Jangan commit nilai testing ini.

## Migrasi wajah akun lama (LBPH)

Model LBPH lama tidak dapat dikonversi ke SFace. **Jangan hapus database, akun,
atau kunci RSA.** Login akun lama akan ditolak sampai pemilik merekam ulang
wajah melalui proses lokal eksplisit berikut (tutup aplikasi dahulu):

```bash
python migrate_face.py --username nama_akun --confirm-owner
```

Untuk testing tanpa flashdisk, tambahkan `--dev-dongle`. Script meminta konfirmasi
`REKAM ULANG` dan password akun, memeriksa dongle, lalu merekam wajah pemilik.
Model `.yml`, password, diary, dan kunci RSA tidak diubah; profil baru disimpan
sebagai `data/face_<username>.yml.sface.json`. Profil SFace yang sudah ada tidak
boleh ditimpa oleh script migrasi.

**Batas kepercayaan:** migrasi ini adalah pemulihan oleh pemilik di komputer
tepercaya, bukan bukti identitas wajah lama. Siapa pun dengan password, dongle,
dan akses konsol tersebut dapat merekam wajah pengganti. Jangan jadikan proses
ini tombol reset di login atau berikan aksesnya ke orang lain.

## Pengujian

Jalankan tes otomatis (termasuk penyimpanan/rantai, codec RSA, dan biometrik):

```bash
python -B -m unittest discover -s tests -v
```

Tes otomatis tidak memerlukan webcam. Jumlah tes mengikuti isi folder `tests/`.

### Pengujian biometrik langsung

Untuk uji langsung, rekam wajah Anda saja,
lalu coba akun yang sama dengan wajah Anda dan wajah beberapa orang lain secara
bergantian. Pastikan orang lain ditolak; tes juga dua wajah sekaligus, pembatalan
`q`/Esc, kamera gagal, dan dongle dicabut. Pendaftaran perlu 12 sampel berjarak
waktu; verifikasi membutuhkan minimal 8 kecocokan selama minimal 2 detik.

Skor diagnostik dapat diaktifkan di PowerShell:

```powershell
$env:DIARY_DEBUG_BIOMETRIK = "1"
python run_demo.py
```

Skor baru adalah cosine similarity SFace (lebih besar = lebih mirip), bukan jarak
LBPH. Ambang `0.5` di `face_auth.py` adalah titik awal yang belum dikalibrasi pada
pengguna proyek ini. Mode debug tidak mengubah keputusan login. Belum ada
_liveness detection_: jangan menganggap sistem ini tahan foto/video wajah.

## Struktur Proyek

```text
.
├── diary_app.py                        # aplikasi utama (GUI + integrasi)
├── diary_storage.py                    # transaksi entri/file dan verifikasi rantai
├── rsa_files.py                        # codec file RSA2 + pembaca legacy RSAF
├── face_auth.py                        # pencocokan identitas YuNet + SFace
├── setup_face_models.py                # unduh model dan periksa SHA-256
├── migrate_face.py                     # rekam ulang pemilik akun LBPH lama
├── models/                             # model publik ONNX (ignored)
├── tests/                              # tes penyimpanan, RSA, dan biometrik
├── run_demo.py                         # launcher uji tanpa flashdisk
├── run_demo.bat                        # shortcut Windows untuk run_demo.py
├── lihat_db.py                         # penampil database (read-only)
├── haarcascade_frontalface_default.xml # model deteksi wajah OpenCV
├── requirements.txt
├── data/                               # database, model wajah, kunci RSA
├── dev/                                # license.key lokal (dibuat run_demo.py, ignored)
└── docs/                               # dokumentasi algoritma
```

## Dokumentasi Algoritma

Penjelasan teori dan implementasi tersedia di folder [`docs/`](docs/):

- `SUPER_ENCRYPTION.md` — rantai Vigenère + LFSR
- `VIGENERE.md`, `LFSR.md`, `BASE64.md`
- `RSA.md`, `FILE_ENCRYPTION.md`
- `PBKDF2.md`, `AUTH_DONGLE.md`, `FACE_AUTH.md`
- `HAAR_CASCADE_LBPH.md` — dokumentasi historis implementasi lama
- `SHA256.md`, `BLOCKCHAIN_POW.md`
- `STEGANOGRAFI_LSB.md`, `DATABASE_ENCRYPTION.md`
- `REFERENSI.md`

## Penyimpanan dan kompatibilitas

- `diary_storage.save_entry` menyimpan ciphertext judul/isi dan blok `entry2:`
  dalam satu transaksi. JSON event mengikat ID entri, `user_id`, `tanggal`, dan
  SHA-256 atas array JSON `[judul_enc, isi_enc]`, bukan penggabungan tanpa batas.
- `file2:` memakai JSON berisi path absolut, `user_id`, dan SHA-256 ciphertext.
  Enkripsi dan dekripsi memakai dialog simpan; **file yang sudah ada tidak boleh
  ditimpa**, termasuk file sumber. Pilih nama baru bila tujuan sudah ada.
- Bila pencatatan blok file gagal, file terenkripsi yang baru dibuat dibersihkan
  dan transaksi DB dibatalkan. Kegagalan pembersihan dilaporkan. Filesystem dan
  SQLite tidak memiliki commit atomik bersama; hard crash/listrik padam masih
  dapat meninggalkan file tanpa blok.
- Event lama `entry:` dan `file:` serta file RSAF tetap dibaca **tanpa menulis
  ulang data, blok, atau kunci privat**. `entry:` lama tidak mengikat tanggal
  atau batas judul/isi seperti `entry2:`. Untuk `file:` lama, basename dicari di
  root proyek dan `data/`: file hilang, tidak terbaca, atau ditemukan di kedua
  lokasi menghasilkan verifikasi gagal/belum lengkap, **bukan sukses**. Jika
  perlu, salin file terenkripsi asli ke salah satu lokasi tersebut tanpa
  mengubah blok lama. `file2:` harus tetap tersedia di path absolut tercatat.
- Verifikasi menolak rantai kosong, genesis hilang/tidak valid, celah indeks,
  dan entri tanpa blok. Tanpa checkpoint eksternal tepercaya, rantai lokal ini
  tidak dapat mendeteksi semua penghapusan ekor atau penulisan ulang seluruh
  riwayat. Lihat [`docs/BLOCKCHAIN_POW.md`](docs/BLOCKCHAIN_POW.md).

## Catatan Keamanan

Proyek ini dibuat untuk **tujuan pembelajaran**. Beberapa bagian sengaja
disederhanakan dan **belum layak untuk data sensitif di produksi**:

- RSA masih 1024-bit, deterministik, tanpa padding OAEP. RSA2 bukan peningkatan
  ukuran kunci atau padding. Checksum mendeteksi kerusakan tidak sengaja, bukan
  autentisitas; pemilik public key dapat membuat file pengganti. RSAF lama tidak
  memiliki checksum dan sebagian kerusakan/kunci salah tidak dapat dideteksi.
- LFSR masih 16-bit dan belum memakai nonce per pesan.
- Pemeriksaan dongle bersifat client-side.
- Private key dan profil embedding wajah belum dienkripsi at-rest.
- Biometrik belum memiliki liveness detection dan masih perlu evaluasi
  false acceptance/false rejection menggunakan kamera dan pengguna nyata.
