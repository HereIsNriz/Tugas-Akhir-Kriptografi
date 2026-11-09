# Panduan Implementasi: Enkripsi File dengan RSA

## 1. Konsep Dasar
Sesuai `INSTRUCTION.md` 2.4, file yang disimpan harus dienkripsi dengan
algoritma yang **berbeda** dari enkripsi teks. Teks memakai Vigenère + LFSR
(`SUPER_ENCRYPTION.md`), sedangkan file memakai **RSA** (`RSA.md`).

RSA bersifat asimetris: file dienkripsi dengan **public key** akun dan hanya
dapat didekripsi dengan **private key** akun yang sama.

## 2. Arsitektur & Prinsip Kerja
### Enkripsi
1. Pengguna memilih file.
2. File dibaca sebagai byte.
3. Byte dipecah menjadi blok-blok kecil (karena RSA hanya bisa memproses nilai
   $m < n$).
4. Tiap blok dienkripsi: $c = m^e \bmod n$.
5. Output diberi header `RSAF`, ditulis ke `<nama_file>.rsa`.
6. Hash ciphertext dicatat ke blockchain sebagai aset `file:...`.

### Dekripsi
1. Pengguna memilih file `.rsa`.
2. Header `RSAF` diperiksa.
3. Tiap blok didekripsi dengan private key (memakai CRT).
4. Byte prefix dibuang, hasil disimpan ke file tujuan.

## 3. Rumus & Operasi
- **Ukuran modulus:**
  $$k = \left\lceil \frac{\text{bit length}(n)}{8} \right\rceil$$
- **Ukuran blok plaintext:** $k - 2$ byte (1 byte dipakai prefix `0x01`).
- **Enkripsi per blok:**
  $$m = \mathrm{int}\big(\texttt{0x01} \parallel \text{blok}\big), \qquad c = m^e \bmod n$$
  Ciphertext ditulis tepat $k$ byte.
- **Dekripsi per blok (CRT):**
  $$m_1 = c^{d_p} \bmod p,\quad m_2 = c^{d_q} \bmod q,\quad
  m = m_2 + q_{\text{inv}}\big((m_1 - m_2) \bmod p\big)q$$
  lalu byte pertama (`0x01`) dibuang.
- **Format file:**
  ```text
  [ "RSAF" (4 byte) ][ ciphertext blok 1 (k byte) ][ blok 2 ] ... [ blok n ]
  ```

## 4. Contoh Ilustrasi
Misal $n$ 1024-bit → $k = 128$ byte → ukuran blok plaintext $= 126$ byte.
File 1.000 byte akan menghasilkan:

$$\left\lceil \frac{1000}{126} \right\rceil = 8 \text{ blok}$$

Ukuran ciphertext:

$$4 + 8 \times 128 = 1028 \text{ byte}$$

Jadi file hasil sedikit lebih besar dari aslinya (overhead header + padding per
blok).

## 5. Implementasi pada Aplikasi
### Enkripsi — `diary_app.py:925-941`
- Batas ukuran file **5 MB** (`diary_app.py:929`).
- `rsa_encrypt_bytes(data, key)` — `diary_app.py:203-211`.
- Output ditulis ke `path + ".rsa"`.
- Hash ciphertext dicatat ke blockchain — `diary_app.py:939`:

  ```python
  tambah_blok(f"file:{os.path.basename(out)}:{hashlib.sha256(blob).hexdigest()}", self.user_id)
  ```

### Dekripsi — `diary_app.py:943-962`
- `rsa_decrypt_bytes(blob, key)` — `diary_app.py:214-228`.
- Header `RSAF` wajib; jika tidak, muncul error "Bukan file hasil enkripsi RSA
  aplikasi ini."
- Nama file hasil default = nama asli tanpa `.rsa`.

### Kunci
- `muat_rsa(username)` — `diary_app.py:239-248`: memuat atau membuat kunci
  akun, disimpan di `data/rsa_<username>.json`.

## 6. Catatan Keamanan & Keterbatasan
- RSA murni lambat untuk file besar; karena itu ada batas 5 MB.
- Implementasi saat ini **1024-bit** dan **tanpa padding OAEP/PKCS#1** →
  deterministik dan kurang aman untuk produksi.
- Private key disimpan **plaintext** di JSON; enkripsi at-rest direncanakan.
- Blockchain mencatat hash ciphertext, tetapi verifikasi file asli belum
  dilakukan otomatis.
- Jika file JSON kunci hilang, file `.rsa` tidak dapat didekripsi lagi.

### Rencana peningkatan
- RSA **2048-bit + padding OAEP-like** (format `RSA2`), tetap membaca `RSAF`.
- Enkripsi private key dengan kunci turunan password.
- Opsi hybrid RSA + AES untuk file besar (tetap berbeda dari cipher teks).
