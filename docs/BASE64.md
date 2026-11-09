# Panduan Implementasi: Base64

## 1. Konsep Dasar
Base64 adalah skema **encoding** (bukan enkripsi) yang mengubah data biner
menjadi teks ASCII yang aman [2]. Di aplikasi ini hasil Super Encryption
(Vigenère + LFSR) berupa byte bernilai 0–255 yang tidak aman disimpan langsung
sebagai teks di database, JSON, atau UI, sehingga dikemas dengan Base64.

Penting: Base64 **tidak memberi keamanan apa pun** karena siapa saja bisa
men-decode-nya. Keamanan tetap berasal dari Vigenère + LFSR.

## 2. Arsitektur & Prinsip Kerja
- Alfabet 64 karakter: `A-Z` (0–25), `a-z` (26–51), `0-9` (52–61), `+` (62),
  `/` (63).
- Cara kerja:
  1. Ambil data per 3 byte (24 bit).
  2. Pecah menjadi 4 kelompok × 6 bit.
  3. Tiap kelompok (0–63) dipetakan ke karakter alfabet.
- **Padding `=`:** jika sisa data 1 byte → `==`, sisa 2 byte → `=`.
- Ukuran output ≈ 4/3 dari ukuran input.

## 3. Rumus & Operasi
- **Ukuran output:**
  $$\text{len}_{b64} = 4 \times \left\lceil \frac{n}{3} \right\rceil$$
- **Pemetaan 3 byte → 4 karakter:**
  $$(b_1 \ll 16) \mid (b_2 \ll 8) \mid b_3 \;\rightarrow\; [\,x \gg 18,\ (x \gg 12) \wedge 63,\ (x \gg 6) \wedge 63,\ x \wedge 63\,]$$

## 4. Contoh Perhitungan Manual
### Input `"Man"` (3 byte, tanpa padding)
```text
M = 77  = 01001101
a = 97  = 01100001
n = 110 = 01101110

Gabung 24 bit : 01001101 01100001 01101110
Pecah 6 bit   : 010011 | 010110 | 000101 | 101110
Nilai desimal :   19   |   22   |    5   |   46
Karakter      :    T   |    W   |    F   |    u
Hasil         : TWFu
```

### Input `"Ma"` (2 byte, padding 1)
```text
01001101 01100001 → 010011 | 010110 | 0001(00)
Nilai : 19 | 22 | 4  → T W E
Hasil : TWE=
```

### Input `"M"` (1 byte, padding 2)
```text
01001101 → 010011 | 01(0000)
Nilai : 19 | 16  → T Q
Hasil : TQ==
```

## 5. Implementasi pada Aplikasi
- Modul standar `base64` dipakai (`b64encode`, `b64decode`); tidak ada
  implementasi manual.
- Posisi dalam pipeline (wajib urut):
  - **Enkripsi:** `plaintext → Vigenère → LFSR → Base64 → simpan`
  - **Dekripsi:** `Base64 decode → LFSR → Vigenère → plaintext`
- `super_encrypt` — `diary_app.py:140-143`:
  ```python
  v = vigenere_enc(teks.encode("utf-8"), password.encode())
  return base64.b64encode(_lfsr_xor(v, password)).decode()
  ```
- `super_decrypt` — `diary_app.py:146-149`:
  ```python
  v = _lfsr_xor(base64.b64decode(cipher_b64), password)
  return vigenere_dec(v, password.encode()).decode("utf-8")
  ```

### Contoh sesuai kode
- Plaintext `Halo`, password `kunci`
- Setelah Vigenère: `[179, 214, 218, 210]`
- Setelah LFSR XOR: `[38, 56, 10, 43]`
- Setelah Base64: `JjgKKw==`

### Catatan penting: format salt & hash password
Pada aplikasi ini **salt dan hash password tidak memakai Base64**, melainkan
**hexadecimal**:
- `salt.hex()` saat registrasi — `diary_app.py:683`
- `hash_password(...).hex()` — `diary_app.py:105`

Base64 hanya dipakai untuk ciphertext pesan (dan payload steganografi).

## 6. Catatan Keamanan
- Base64 bukan lapisan keamanan; jangan menyebutnya sebagai enkripsi di laporan
  atau UI.
- Kesalahan decode (`binascii.Error`) harus ditangani dengan pesan jelas, bukan
  crash.
- Ukuran ciphertext Base64 ~33% lebih besar dari data biner aslinya.
