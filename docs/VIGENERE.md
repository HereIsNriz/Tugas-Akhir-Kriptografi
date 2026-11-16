# Panduan Implementasi: Vigenère Cipher

## 1. Konsep Dasar
Vigenère Cipher adalah algoritma kriptografi klasik berbasis **substitusi
polialfabetik** [1]. Algoritma ini menggunakan kata kunci (*key string*) yang
diulang secara periodik sepanjang teks asli untuk menentukan pergeseran
karakter [1].

## 2. Pemetaan & Pemodelan Karakter (Teori)
- Alfabet dipetakan dari **0 hingga 25** ($A=0, B=1, \dots, Z=25$) [1].
- Kunci disesuaikan panjangnya dengan *plaintext* dengan cara diulang
  (*repeated key*) [1].
- Pada Vigenère klasik, karakter non-alfabet pada plaintext tidak mengonsumsi
  huruf kunci.

## 3. Rumus Matematis (Teori)
### Enkripsi
$$C_i = (P_i + K_i) \bmod 26$$

### Dekripsi
$$P_i = (C_i - K_i) \bmod 26$$

*Catatan implementasi:* agar hasil modulo selalu positif dipakai
$$P_i = ((C_i - K_i) \bmod 26 + 26) \bmod 26$$

## 4. Contoh Perhitungan Manual (Teori)
- **Plaintext ($P$):** `TEKNIK`
- **Key ($K$):** `MAJU` $\rightarrow$ disesuaikan menjadi `MAJUMA`

### Enkripsi:
1. `T` (19) + `M` (12) = $(19 + 12) \bmod 26 = 31 \bmod 26 = 5 \rightarrow$ **F**
2. `E` (4) + `A` (0) = $(4 + 0) \bmod 26 = 4 \rightarrow$ **E**
3. `K` (10) + `J` (9) = $(10 + 9) \bmod 26 = 19 \rightarrow$ **T**
4. `N` (13) + `U` (20) = $(13 + 20) \bmod 26 = 33 \bmod 26 = 7 \rightarrow$ **H**
5. `I` (8) + `M` (12) = $(8 + 12) \bmod 26 = 20 \rightarrow$ **U**
6. `K` (10) + `A` (0) = $(10 + 0) \bmod 26 = 10 \rightarrow$ **K**
- **Ciphertext:** `FETHUK`

## 5. Catatan Implementasi di Aplikasi
Aplikasi **tidak** memakai alfabet A–Z, melainkan mengenkripsi **byte UTF-8**
langsung dengan modulo 256. Dengan demikian rumus yang dipakai:

$$C_i = (P_i + K_i) \bmod 256, \qquad P_i = (C_i - K_i) \bmod 256$$

dengan $P_i$ = byte plaintext ke-$i$, $K_i$ = byte password ke-$(i \bmod
\ell)$ (password diulang). Semua byte ikut diproses, termasuk spasi/tanda baca.

- `vigenere_enc(data, key)` — `diary_app.py:116-117`:

  ```python
  bytes((b + key[i % len(key)]) % 256 for i, b in enumerate(data))
  ```

- `vigenere_dec(data, key)` — `diary_app.py:120-121`:

  ```python
  bytes((b - key[i % len(key)]) % 256 for i, b in enumerate(data))
  ```

### Contoh perhitungan sesuai kode
- **Plaintext:** `Halo` → byte `[72, 97, 108, 111]`
- **Key:** `kunci` → byte `[107, 117, 110, 99, 105]`
- **Enkripsi:**
  - $(72 + 107) \bmod 256 = 179$
  - $(97 + 117) \bmod 256 = 214$
  - $(108 + 110) \bmod 256 = 218$
  - $(111 + 99) \bmod 256 = 210$
- **Ciphertext (byte):** `[179, 214, 218, 210]`
- **Base64:** `s9ba0g==`

Vigenère menjadi **lapisan klasik** pada Super Encryption, lalu dilanjutkan
LFSR (lihat `SUPER_ENCRYPTION.md` dan `LFSR.md`).

## 6. Catatan Keamanan
- Vigenère klasik rentan terhadap analisis frekuensi dan uji Kasiski karena
  kunci berulang.
- Karena itu aplikasi menambahkan lapisan LFSR + (rencana) nonce, bukan
  mengandalkan Vigenère saja.
- Panjang password memengaruhi panjang periode kunci; password pendek membuat
  pola berulang lebih cepat terlihat.
