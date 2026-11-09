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
- Hash SHA-256 isi `license.key` dibandingkan dengan konstanta
  `DONGLE_KEY_HASH` (bukan plaintext).
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
  $$\exists\, d \in \{A,\dots,Z\}:\ \mathrm{type}(d)=2 \ \wedge\ \mathrm{SHA256}\big(\mathrm{read}(d \parallel \texttt{"license.key"})\big) = \texttt{DONGLE\_KEY\_HASH}$$

## 4. Implementasi pada Aplikasi
### Konfigurasi — `diary_app.py:47-52`
```python
DONGLE_WAJIB = True
DONGLE_HANYA_REMOVABLE = True
DONGLE_KEY_HASH = "9d8e7c17..."  # sha256("KUNCI-DIARY-2026")
DEMO_MODE = False                # True = lewati dongle (khusus demo)
DONGLE_DEV_PATH = None           # path license.key lokal untuk uji tanpa flashdisk
```

### Pemeriksaan dongle — `diary_app.py:94-108`
```python
def cek_dongle():
    if DEMO_MODE or not DONGLE_WAJIB:
        return True
    if DONGLE_DEV_PATH:
        return _dongle_cocok(DONGLE_DEV_PATH)
    for huruf in string.ascii_uppercase:
        root = f"{huruf}:\\"
        if DONGLE_HANYA_REMOVABLE and ctypes.windll.kernel32.GetDriveTypeW(root) != 2:
            continue
        if _dongle_cocok(root + "license.key"):
            return True
    return False
```
`_dongle_cocok` membandingkan `sha256(isi)` dengan `DONGLE_KEY_HASH`.
Dipanggil di `__main__` (`diary_app.py:1063`), di `login` (`diary_app.py:676`),
dan di awal `biometrik_daftar` / `biometrik_verifikasi`.

### Login — `diary_app.py:675-693`
1. `cari_user(username)` — `diary_app.py:350-352`.
2. Bandingkan hash — `diary_app.py:681`.
3. `biometrik_verifikasi(path_wajah(username))` — `diary_app.py:684`.
4. Muat kunci RSA — `diary_app.py:690`.

### Registrasi — `diary_app.py:706-732`
- Validasi input, cek username, rekam wajah (`biometrik_daftar`), simpan salt +
  hash, buat kunci RSA.

### Biometrik
- `biometrik_daftar` — `diary_app.py:371-404`.
- `biometrik_verifikasi` — `diary_app.py:407-444`.
- Detail parameter ada di `HAAR_CASCADE_LBPH.md`.

## 5. Catatan Keamanan & Keterbatasan
- **Dongle bersifat client-side**: siapa pun yang mengubah source dapat
  menonaktifkannya (`DONGLE_WAJIB = False`). Ini memenuhi syarat tugas, bukan
  proteksi produksi.
- `DONGLE_KEY_HASH` disimpan sebagai hash SHA-256, bukan plaintext.
- Dongle dicek **berkala setiap 5 detik**; jika dicabut saat sesi aktif,
  aplikasi memaksa logout (`_monitor_dongle` / `_logout_paksa`).
- Biometrik bersifat **fail-closed**: bila dongle tidak ada atau OpenCV tidak
  terpasang, pendaftaran/verifikasi gagal (tidak ada fallback simulasi).
- Tidak ada *rate limiting* atau penguncian setelah percobaan login gagal.

### Peningkatan yang sudah diterapkan
- `DEMO_MODE` (bypass, default `False`) dan `DONGLE_DEV_PATH` (uji
  `license.key` lokal tanpa flashdisk).
- Pemeriksaan dongle berkala + logout otomatis saat dicabut.
- Hash `DONGLE_KEY_HASH`, bukan plaintext.
- Fallback simulasi dihapus; biometrik gagal = login gagal.
