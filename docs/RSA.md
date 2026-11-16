# Panduan Implementasi: RSA (Rivest–Shamir–Adleman)

## 1. Konsep Dasar

RSA adalah algoritma **kriptografi kunci publik / asimetris** [2], [4].
Algoritma ini menggunakan sepasang kunci: **public key** untuk enkripsi dan
**private key** untuk dekripsi [2]. Keamanannya didasarkan pada sulitnya
memfaktorkan dua bilangan prima berukuran besar [2].

Pada aplikasi ini RSA dipakai untuk **enkripsi file**, sehingga algoritmanya
berbeda dari enkripsi teks (Vigenère + LFSR), sesuai syarat 2.4.

## 2. Pembentukan Kunci (Key Generation)

1. Pilih 2 bilangan prima $p$ dan $q$.
2. Hitung $n = p \times q$ (modulus) [2], [4].
3. Hitung totient Euler: $\phi(n) = (p - 1)(q - 1)$.
4. Pilih public exponent $e$ dengan $1 < e < \phi(n)$ dan
   $\gcd(e, \phi(n)) = 1$ (aplikasi memakai $e = 65537$).
5. Hitung private exponent $d$:
   $$d \equiv e^{-1} \pmod{\phi(n)} \quad \text{atau} \quad (d \times e) \bmod \phi(n) = 1$$

- **Public key:** $(e, n)$
- **Private key:** $(d, n)$, ditambah $p$ dan $q$ untuk optimasi CRT.

## 3. Rumus Matematis Enkripsi & Dekripsi

### Enkripsi

$$C = P^e \bmod n$$

### Dekripsi

$$P = C^d \bmod n$$

### Dekripsi dengan CRT (Chinese Remainder Theorem)

Agar lebih cepat, dekripsi dihitung modulo $p$ dan $q$ terpisah:

$$m_1 = C^{d_p} \bmod p, \qquad m_2 = C^{d_q} \bmod q$$
$$d_p = d \bmod (p-1), \qquad d_q = d \bmod (q-1), \qquad q_{\text{inv}} = q^{-1} \bmod p$$
$$m = m_2 + q_{\text{inv}} \cdot \big((m_1 - m_2) \bmod p\big) \cdot q$$

## 4. Contoh Perhitungan Manual (Sederhana)

- **Prima:** $p = 61$, $q = 53$
- $n = 61 \times 53 = 3233$
- $\phi(n) = (61-1)(53-1) = 60 \times 52 = 3120$
- **Pilih $e$:** $17$ (memenuhi $\gcd(17, 3120) = 1$)
- **Hitung $d$:** $d = 2753$ karena $(2753 \times 17) \bmod 3120 = 1$

### Enkripsi karakter $P = 65$ (`'A'`):

$$C = 65^{17} \bmod 3233 = 2790$$

### Dekripsi $C = 2790$:

$$P = 2790^{2753} \bmod 3233 = 65 \rightarrow \text{'A'}$$

## 5. Catatan Implementasi di Aplikasi

Aplikasi mengimplementasikan RSA **tanpa library kripto**, memakai modul
standar Python.

### Pembangkitan kunci — `diary_app.rsa_keygen`

- `_is_prime(n, k=20)` — uji **Miller–Rabin** dengan 20 putaran dan penyaringan
  bilangan prima kecil.
- `_gen_prime(bits)` — membangkitkan bilangan prima acak `bits`-bit
  (bit teratas diset 1, selalu ganjil).
- `rsa_keygen(bits=1024)` — $p$ dan $q$ masing-masing 512-bit, $e = 65537$,
  $\phi = (p-1)(q-1)$, $d = e^{-1} \bmod \phi$.
- `diary_app.muat_rsa` / `path_rsa` menyimpan JSON `n`, `e`, `d`, `p`, `q`
  di `data/rsa_<username>.json`. Kunci lama yang tersedia tetap dimuat, tidak
  dikonversi atau ditulis ulang oleh perubahan format file.

### Enkripsi file — `rsa_files.encrypt_bytes`

`diary_app.rsa_encrypt_bytes` adalah wrapper codec ini. Enkripsi hanya memerlukan
komponen public key `n` dan `e`.
Karena pesan harus lebih kecil dari $n$, file dipecah per blok:

$$k = \left\lceil \frac{\text{bit length}(n)}{8} \right\rceil, \qquad \text{ukuran blok} = k - 2$$

Setiap blok diberi prefix byte `0x01` agar tidak kehilangan nol di depan:

$$m = \mathrm{int}\big(\texttt{0x01} \parallel \text{blok}\big), \qquad c = m^e \bmod n$$

Penulisan baru memakai **RSA2** dengan header **76 byte**, lalu setiap blok
ciphertext ditulis tepat $k$ byte. Ekstensi tetap `.rsa`:

| Offset byte | Panjang       | Isi                                                                |
| ----------- | ------------- | ------------------------------------------------------------------ |
| 0–3         | 4             | Magic `b"RSA2"`                                                    |
| 4–35        | 32            | Key ID: SHA-256 dari `n.to_bytes(k, "big") + e.to_bytes(k, "big")` |
| 36–43       | 8             | Panjang plaintext asli, unsigned big-endian                        |
| 44–75       | 32            | SHA-256 plaintext (digest biner)                                   |
| 76–akhir    | Kelipatan $k$ | Blok ciphertext                                                    |

Untuk panjang plaintext $L$, jumlah blok tepat $\lceil L/(k-2) \rceil$ dan ukuran
file $76 + k\lceil L/(k-2) \rceil$. File kosong menghasilkan header saja dengan
panjang 0 dan SHA-256 plaintext kosong. RSA2 **bukan** nama untuk RSA 2048-bit
atau padding OAEP: algoritma blok dan kunci default tetap seperti sebelumnya.

### Dekripsi file — `rsa_files.decrypt_bytes`

`diary_app.rsa_decrypt_bytes` meneruskan ke codec; `diary_app.App.dekripsi_file`
menangani dialog dan penyimpanan hasil.

- Menerima magic RSA2 atau **legacy RSAF**; header lain ditolak.
- `rsa_files._validate_key` memeriksa komponen integer dan konsistensi aritmetika
  kunci. Dekripsi memerlukan `n`, `e`, `d`, `p`, `q`; faktor harus berbeda,
  ganjil, koprima, menghasilkan `n`, dan `d` harus menginvers `e` modulo
  `lcm(p-1, q-1)`. Ini bukan uji primalitas ulang faktor kunci.
- Body harus kelipatan $k$ byte; setiap ciphertext harus bernilai $c < n$.
  Dekripsi memakai **CRT** (`dp`, `dq`, `qinv`). Prefix `0x01` wajib sebelum
  dibuang; tiap chunk berukuran 1 sampai $k-2$ dan semua chunk selain terakhir
  harus penuh.
- Untuk RSA2, header harus lengkap, key ID harus cocok, jumlah blok dan panjang
  chunk terakhir harus sesuai panjang asli, serta SHA-256 hasil harus cocok.
  Validasi ini mendeteksi kerusakan tidak sengaja, blok berbeda yang tertukar,
  pemotongan/penambahan blok, dan kunci yang salah.
- **Legacy RSAF** hanya berisi `b"RSAF"` + blok-blok $k$ byte (header 4 byte).
  Validasi struktur di atas tetap berlaku, tetapi tidak ada key ID, panjang asli,
  atau checksum. Sebagian perubahan/kunci salah tidak dapat dideteksi; RSAF
  kosong tidak dapat membedakan kunci yang dipakai. UI memperingatkan bahwa
  hasil legacy tidak bisa dipastikan utuh dan perlu dibandingkan dengan aslinya.
  Membaca RSAF tidak mengonversi file atau mengubah private key.

### Catatan penting

- Implementasi ini adalah **textbook RSA** tanpa padding OAEP/PKCS#1. Akibatnya
  deterministik dan kurang aman untuk produksi. RSA2 hanya menambah metadata
  dan checksum, tidak menambah padding acak.
- `diary_app.App.enkripsi_file` membatasi plaintext 5 MB; `App.dekripsi_file`
  membatasi ciphertext 6 MB. RSA murni lambat untuk data besar.
- Enkripsi/dekripsi memakai dialog simpan dan pembuatan eksklusif (`xb`):
  file yang sudah ada tidak ditimpa. Pilih nama tujuan baru. Pencatatan file
  ke rantai dan batas atomicity dijelaskan di `FILE_ENCRYPTION.md`.

## 6. Catatan Keamanan

- 1024-bit sudah dianggap lemah untuk standar modern; gunakan ≥ 2048-bit.
- Tanpa padding, ciphertext deterministik (blok sama → ciphertext sama) dan
  rentan terhadap serangan tertentu.
- Private key saat ini disimpan plaintext di `data/rsa_<user>.json`; enkripsi
  at-rest direncanakan.
- Checksum SHA-256 RSA2 mendeteksi kerusakan tidak sengaja, **bukan autentisitas**.
  Siapa pun dengan public key dapat membuat file pengganti beserta checksum yang
  cocok. Key ID bukan tanda tangan dan tidak membuktikan siapa pengirimnya.
- Kompatibilitas RSAF bukan batas keamanan: menghapus metadata RSA2 dan mengganti
  header dengan RSAF menurunkan pemeriksaan ke format legacy tanpa checksum.
  Jangan mengandalkan codec kompatibel ini untuk menolak pemalsuan disengaja.
- Jangan membagikan `d`, `p`, atau `q`; hanya $(e, n)$ yang publik.

## 7. Pengujian

```bash
python -B -m unittest discover -s tests -v
```

Codec dapat diuji tanpa GUI dan tanpa mengubah kunci/file pengguna. Jumlah tes
mengikuti isi `tests/`; checksum yang lolos bukan pengujian autentisitas.
