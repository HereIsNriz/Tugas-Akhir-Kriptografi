# Panduan Implementasi: Autentikasi, Dongle, dan Biometrik

## 1. Konsep Dasar
Autentikasi aplikasi terdiri dari dua faktor:
1. **Password** yang di-hash dengan PBKDF2-HMAC-SHA256 (lihat `PBKDF2.md`).
2. **Biometrik wajah** dengan Haar Cascade + LBPH (lihat
   `HAAR_CASCADE_LBPH.md`).

Selain itu, sesuai `INSTRUCTION.md` 2.1, fitur biometrik hanya dapat diaktifkan
dengan bantuan **dongle**: aplikasi menolak berjalan jika dongle tidak
terpasang.

## 2. Arsitektur & Prinsip Kerja
### Dongle
- Dongle adalah **flashdisk** yang berisi file teks `license.key` di root.
- Aplikasi memindai drive `A:` sampai `Z:`.
- Drive hanya diterima jika tipenya **removable** (`GetDriveTypeW == 2`).
- Isi `license.key` dibandingkan dengan konstanta `DONGLE_KEY`.
- Jika tidak ditemukan, aplikasi menampilkan "Akses Ditolak" lalu keluar.

### Login
1. Pengguna memasukkan username dan password.
2. Password di-hash ulang dengan salt pengguna, lalu dibandingkan
   *constant-time*.
3. Jika password benar, verifikasi wajah dijalankan.
4. Jika wajah cocok, sesi dimulai dan kunci RSA pengguna dimuat.

### Registrasi
1. Validasi username (`[a-z0-9_]{3,20}`) dan password (min. 6 karakter).
2. Rekam 40 sampel wajah, latih model LBPH, simpan `face_<username>.yml`.
3. Buat salt 16 byte, simpan hash password.
4. Buat pasangan kunci RSA untuk akun tersebut.

## 3. Rumus & Operasi
- **Verifikasi password:**
  $$\text{valid} \iff \mathrm{compare\_digest}\big(\mathrm{PBKDF2}(pw, salt),\ hash\big)$$
- **Verifikasi wajah:** cocok jika `confidence < FACE_THRESHOLD` (70) pada
  minimal 5 frame dalam 10 detik.
- **Dongle:** valid jika
  $$\exists\, d \in \{A,\dots,Z\}:\ \mathrm{type}(d)=2 \ \wedge\ \mathrm{read}(d \parallel \texttt{"license.key"}) = \texttt{DONGLE\_KEY}$$

## 4. Implementasi pada Aplikasi
### Konfigurasi — `diary_app.py:47-49`
```python
DONGLE_WAJIB = True            # False hanya untuk testing tanpa flashdisk
DONGLE_HANYA_REMOVABLE = True  # Ubah ke False jika flashdisk tidak terdeteksi
DONGLE_KEY = "KUNCI-DIARY-2026"
```

### Pemeriksaan dongle — `diary_app.py:83-100`
```python
for huruf in string.ascii_uppercase:
    root = f"{huruf}:\\"
    if DONGLE_HANYA_REMOVABLE and ctypes.windll.kernel32.GetDriveTypeW(root) != 2:
        continue
    path = root + "license.key"
    ...
```
Dipanggil di `__main__` — `diary_app.py:1020`.

### Login — `diary_app.py:635-650`
1. `cari_user(username)` — `diary_app.py:329-331`.
2. Bandingkan hash — `diary_app.py:638`.
3. `biometrik_verifikasi(path_wajah(username))` — `diary_app.py:641`.
4. Muat kunci RSA — `diary_app.py:647`.

### Registrasi — `diary_app.py:663-689`
- Validasi input, cek username, rekam wajah (`biometrik_daftar`), simpan salt +
  hash, buat kunci RSA.

### Biometrik
- `biometrik_daftar` — `diary_app.py:350-380`.
- `biometrik_verifikasi` — `diary_app.py:383-416`.
- Detail parameter ada di `HAAR_CASCADE_LBPH.md`.

## 5. Catatan Keamanan & Keterbatasan
- **Dongle bersifat client-side**: siapa pun yang mengubah source dapat
  menonaktifkannya (`DONGLE_WAJIB = False`). Ini memenuhi syarat tugas, bukan
  proteksi produksi.
- `DONGLE_KEY` saat ini **hardcoded plaintext** di source; disarankan menyimpan
  hash-nya.
- Dongle hanya dicek **saat startup**; pencabutan setelah login belum memaksa
  logout.
- Jika OpenCV tidak terpasang, ada fallback **simulasi** biometrik yang
  menanyakan "cocok?" — ini melemahkan syarat biometrik dan direncanakan
  dihapus (fail-closed).
- Tidak ada *rate limiting* atau penguncian setelah percobaan login gagal.

### Rencana peningkatan
- Mode pengembangan `DEMO_MODE` (bypass, default `False`) dan
  `DONGLE_DEV_PATH` (uji `license.key` lokal tanpa flashdisk).
- Pemeriksaan dongle berkala + logout otomatis saat dicabut.
- Simpan hash `DONGLE_KEY`, bukan plaintext.
- Hapus fallback simulasi; biometrik gagal = login gagal.
