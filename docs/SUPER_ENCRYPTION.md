# Panduan Implementasi: Super Encryption (Vigenère + LFSR)

## 1. Konsep Dasar
**Super Encryption** adalah teknik mengenkripsi plaintext dengan **lebih dari
satu algoritma secara berlapis**. Sesuai `INSTRUCTION.md` 2.3, komposisinya
harus memuat minimal **satu algoritma klasik** dan **satu algoritma modern**.

Aplikasi memakai:

```text
plaintext → Vigenère (klasik) → LFSR XOR (modern) → Base64 → simpan
```

- **Vigenère** = substitusi polialfabetik klasik (lihat `VIGENERE.md`).
- **LFSR** = stream cipher modern/PRNG (lihat `LFSR.md`).
- **Base64** = encoding agar ciphertext aman disimpan sebagai teks
  (lihat `BASE64.md`), bukan lapisan keamanan.

## 2. Arsitektur & Prinsip Kerja
1. Plaintext diubah menjadi byte UTF-8.
2. Setiap byte digeser dengan byte password (Vigenère mod 256).
3. Hasilnya di-XOR dengan keystream LFSR yang seed-nya diturunkan dari
   password.
4. Hasil akhir di-encode Base64 dan disimpan di database.

Dekripsi menjalankan kebalikannya:

```text
Base64 decode → LFSR XOR (sama) → Vigenère dikurangi → plaintext
```

XOR bersifat simetris, sehingga LFSR yang sama dipakai untuk enkripsi dan
dekripsi. Vigenère didekripsi dengan pengurangan modulo 256.

## 3. Rumus & Operasi
Misalkan $P_i$ byte plaintext, $K_i$ byte password berulang, $S_i$ byte
keystream LFSR.

**Enkripsi:**
$$A_i = (P_i + K_i) \bmod 256$$
$$B_i = A_i \oplus S_i$$
$$\text{ciphertext} = \mathrm{Base64}(B)$$

**Dekripsi:**
$$A_i = B_i \oplus S_i$$
$$P_i = (A_i - K_i) \bmod 256$$

**Seed LFSR:**
$$\text{seed} = \mathrm{int}_{16}\big(\mathrm{SHA256}(\text{password})[0..2]\big)$$

## 4. Contoh Perhitungan Manual (sesuai kode)
- **Plaintext:** `Halo` → byte `[72, 97, 108, 111]`
- **Password:** `kunci` → byte `[107, 117, 110, 99, 105]`

### Langkah 1 — Vigenère (mod 256)
| i | $P_i$ | $K_i$ | $(P_i + K_i) \bmod 256$ |
|---|---|---|---|
| 0 | 72 | 107 | 179 |
| 1 | 97 | 117 | 214 |
| 2 | 108 | 110 | 218 |
| 3 | 111 | 99 | 210 |

Hasil: `[179, 214, 218, 210]`

### Langkah 2 — Seed & keystream LFSR
- $\mathrm{SHA256}(\text{"kunci"})$ → 2 byte pertama = `0x77A9`
- Keystream 4 byte: `[149, 238, 208, 249]` (`95 ee d0 f9`)

### Langkah 3 — XOR
| $A_i$ | $S_i$ | $A_i \oplus S_i$ |
|---|---|---|
| 179 | 149 | 38 |
| 214 | 238 | 56 |
| 218 | 208 | 10 |
| 210 | 249 | 43 |

Hasil: `[38, 56, 10, 43]`

### Langkah 4 — Base64
`[38, 56, 10, 43]` → **`JjgKKw==`**

Dekripsi `JjgKKw==` dengan password `kunci` mengembalikan `Halo`.

## 5. Implementasi pada Aplikasi
- `super_encrypt(teks, password)` — `diary_app.py:140-143`:

  ```python
  v = vigenere_enc(teks.encode("utf-8"), password.encode())
  return base64.b64encode(_lfsr_xor(v, password)).decode()
  ```

- `super_decrypt(cipher_b64, password)` — `diary_app.py:146-149`:

  ```python
  v = _lfsr_xor(base64.b64decode(cipher_b64), password)
  return vigenere_dec(v, password.encode()).decode("utf-8")
  ```

- Dipakai untuk:
  - Judul dan isi diary sebelum disimpan — `diary_app.py:837`.
  - Membaca kembali diary — `diary_app.py:858-859`.
  - Pesan pada steganografi — `diary_app.py:961`, `975`.

## 6. Catatan Keamanan
- Kedua lapisan memakai **password yang sama** (tidak ada kunci independen).
- **Deterministik**: password + plaintext sama → ciphertext sama, karena tidak
  ada nonce/IV. Ini membuka risiko *two-time pad*.
- LFSR hanya 16-bit dan seed-nya 2 byte, sehingga keystream mudah ditebak dan
  berulang untuk pesan panjang.
- Tidak ada MAC, sehingga perubahan ciphertext tidak terdeteksi.

### Rencana peningkatan (v2)
- Tambahkan **nonce acak** per pesan.
- Turunkan kunci per lapisan dengan `PBKDF2(password, nonce)`.
- Perbesar LFSR menjadi 32/64-bit dengan seed penuh.
- Tambahkan **HMAC-SHA256** (encrypt-then-MAC).
- Beri penanda versi format agar data lama tetap terbaca.
