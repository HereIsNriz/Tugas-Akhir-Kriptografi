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

### Pembangkitan kunci — `diary_app.py:153-193`
- `_is_prime(n, k=20)` — uji **Miller–Rabin** dengan 20 putaran dan penyaringan
  bilangan prima kecil.
- `_gen_prime(bits)` — membangkitkan bilangan prima acak `bits`-bit
  (bit teratas diset 1, selalu ganjil).
- `rsa_keygen(bits=1024)` — $p$ dan $q$ masing-masing 512-bit, $e = 65537$,
  $\phi = (p-1)(q-1)$, $d = e^{-1} \bmod \phi$.
- Kunci disimpan sebagai JSON: `n`, `e`, `d`, `p`, `q` — `diary_app.py:232-241`.

### Enkripsi file — `diary_app.py:196-204`
Karena pesan harus lebih kecil dari $n$, file dipecah per blok:

$$k = \left\lceil \frac{\text{bit length}(n)}{8} \right\rceil, \qquad \text{ukuran blok} = k - 2$$

Setiap blok diberi prefix byte `0x01` agar tidak kehilangan nol di depan:

$$m = \mathrm{int}\big(\texttt{0x01} \parallel \text{blok}\big), \qquad c = m^e \bmod n$$

Output diawali header `b"RSAF"`, lalu setiap ciphertext blok ditulis tepat
$k$ byte. Ekstensi file hasil: `.rsa`.

### Dekripsi file — `diary_app.py:207-221`
- Memeriksa header `RSAF`; jika tidak cocok → error "Bukan file hasil enkripsi
  RSA aplikasi ini."
- Dekripsi memakai **CRT** (`dp`, `dq`, `qinv`) untuk kecepatan.
- Byte prefix `0x01` dibuang dari setiap blok hasil dekripsi.

### Catatan penting
- Implementasi ini adalah **textbook RSA** tanpa padding OAEP/PKCS#1. Akibatnya
  deterministik dan kurang aman untuk produksi. Peningkatan ke **2048-bit +
  OAEP** direncanakan (lihat `FILE_ENCRYPTION.md`).
- Ukuran file dibatasi 5 MB (`diary_app.py:886`) karena RSA murni lambat untuk
  data besar.

## 6. Catatan Keamanan
- 1024-bit sudah dianggap lemah untuk standar modern; gunakan ≥ 2048-bit.
- Tanpa padding, ciphertext deterministik (blok sama → ciphertext sama) dan
  rentan terhadap serangan tertentu.
- Private key saat ini disimpan plaintext di `data/rsa_<user>.json`; enkripsi
  at-rest direncanakan.
- Jangan membagikan `d`, `p`, atau `q`; hanya $(e, n)$ yang publik.
