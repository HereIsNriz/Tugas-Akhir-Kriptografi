# Panduan Implementasi: PBKDF2-HMAC-SHA256 (Hash Password)

## 1. Konsep Dasar
PBKDF2 (*Password-Based Key Derivation Function 2*) adalah fungsi turunan kunci
yang **sengaja dibuat lambat** agar tebakan password secara brute-force menjadi
mahal. Pada aplikasi ini PBKDF2 dipakai untuk **menyimpan password pengguna**,
bukan untuk enkripsi isi diary.

Dua komponen penting:
- **Salt**: nilai acak unik per pengguna, mencegah *rainbow table* dan membuat
  dua password identik menghasilkan hash berbeda.
- **Iterasi**: jumlah putaran hashing. Semakin besar, semakin lambat bagi
  penyerang (dan juga bagi aplikasi). Aplikasi memakai **100.000 iterasi**.

Referensi: [5], [8].

## 2. Arsitektur & Prinsip Kerja
1. Saat registrasi, buat salt acak 16 byte dengan `secrets.token_bytes(16)`.
2. Hitung `DK = PBKDF2-HMAC-SHA256(password, salt, 100000, dkLen=32)`.
3. Simpan `salt` (hex) dan `DK` (hex) di tabel `users`. **Password asli tidak
   pernah disimpan.**
4. Saat login, ambil salt pengguna, hitung ulang PBKDF2 dengan password yang
   diketik, lalu bandingkan dengan hash tersimpan memakai perbandingan
   *constant-time* (`hmac.compare_digest`).

## 3. Rumus & Operasi
PBKDF2 menghasilkan kunci turunan $DK$ sepanjang `dkLen`:

$$DK = T_1 \parallel T_2 \parallel \dots \parallel T_l, \qquad
l = \left\lceil \frac{dkLen}{hLen} \right\rceil$$

Setiap blok:

$$T_i = F(P, S, c, i) = U_1 \oplus U_2 \oplus \dots \oplus U_c$$

dengan:

$$U_1 = \mathrm{PRF}(P,\ S \parallel \mathrm{INT}_{32}(i)), \qquad
U_j = \mathrm{PRF}(P,\ U_{j-1})$$

Keterangan:
- $P$ = password, $S$ = salt, $c$ = jumlah iterasi, $i$ = indeks blok (1-based).
- $\mathrm{PRF}$ = HMAC-SHA256, $hLen = 32$ byte.
- Aplikasi memakai $dkLen = 32$ byte sehingga $l = 1$ (cukup $T_1$).

## 4. Contoh Perhitungan Manual
- **Password:** `rahasia`
- **Salt (hex):** `00112233445566778899aabbccddeeff`
- **Iterasi:** `100000`
- **PRF:** HMAC-SHA256

Hasil:

```text
DK = 1f2c1e890f25334643baa956b2647fdc
     1f07778f26a600391d148dd3c4a50bcb
```

Nilai ini dapat diverifikasi dengan:

```python
hashlib.pbkdf2_hmac(
    "sha256", b"rahasia",
    bytes.fromhex("00112233445566778899aabbccddeeff"),
    100_000,
).hex()
```

## 5. Implementasi pada Aplikasi
- `hash_password(password, salt)` — `diary_app.py:104-105`:

  ```python
  hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()
  ```

- Registrasi: salt acak 16 byte lalu disimpan hex — `diary_app.py:681-684`:

  ```python
  salt = secrets.token_bytes(16)
  DB.execute("INSERT INTO users(username, salt, hash, dibuat) VALUES(?,?,?,?)",
             (username, salt.hex(), hash_password(pw, salt), ...))
  ```

- Login: hash dihitung ulang dan dibandingkan *constant-time* —
  `diary_app.py:638`:

  ```python
  hmac.compare_digest(hash_password(pw, bytes.fromhex(u[1])), u[2])
  ```

- Skema tabel `users` — `diary_app.py:270-272` (`id`, `username`, `salt`,
  `hash`, `dibuat`).

## 6. Catatan Keamanan
- **Jangan** memakai SHA-256 langsung untuk password; SHA-256 terlalu cepat.
- Salt harus unik per pengguna dan disimpan bersama hash.
- `hmac.compare_digest` mencegah *timing attack*; jangan memakai `==`.
- 100.000 iterasi adalah batas bawah yang wajar; nilai lebih tinggi lebih baik
  (mis. 300.000–600.000) bila performa login masih nyaman.
- PBKDF2 tidak memiliki *pepper*; bisa ditambahkan sebagai rahasia server bila
  diperlukan.
- Hash password **tidak** dapat didekripsi; lupa password berarti reset, bukan
  pemulihan.
