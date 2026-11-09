# Panduan Implementasi: LFSR (Linear Feedback Shift Register)

## 1. Konsep Dasar
LFSR adalah pembangkit aliran bit acak semu (*Pseudo-Random Keystream
Generator*) yang digunakan dalam **stream cipher (cipher aliran)** [1], [2].
LFSR bekerja berbasis bit menggunakan register geser dan fungsi umpan balik
beroperasi bitwise XOR ($\oplus$) [2].

## 2. Arsitektur & Prinsip Kerja (Teori)
- Memiliki register berukuran $n$-bit (misal 4-bit, 8-bit) [2].
- Pada setiap siklus/detak clock:
  1. Bit paling kanan ($b_1$) dikeluarkan sebagai bit *keystream* [2].
  2. Bit umpan balik baru dihitung dengan meng-XOR-kan bit-bit tertentu
     (*tap positions*) [2].
  3. Seluruh bit di dalam register digeser ke kanan 1 posisi [2].
  4. Bit umpan balik dimasukkan ke posisi paling kiri ($b_n$) [2].

## 3. Rumus & Operasi (Teori)
- **Fungsi umpan balik (contoh 4-bit standar):**
  $$b_{\text{feedback}} = b_1 \oplus b_4$$
- **Enkripsi:**
  $$C_i = P_i \oplus K_i$$
- **Dekripsi:**
  $$P_i = C_i \oplus K_i$$

## 4. Contoh Perhitungan Manual (Teori, 4-bit)
- **Seed/Inisialisasi Register (4-bit):** `1111` ($b_4 b_3 b_2 b_1$)
- **Fungsi Taps:** $b_1 \oplus b_4$
- **Plaintext (Binary/ASCII):** karakter `'e'` = `01100101`

### Pembangkitan Keystream 8-bit:
- **Siklus 1:** Register `1111` $\rightarrow$ Out = `1`, Feed = $1 \oplus 1 = 0 \rightarrow$ Next Reg: `0111`
- **Siklus 2:** Register `0111` $\rightarrow$ Out = `1`, Feed = $1 \oplus 0 = 1 \rightarrow$ Next Reg: `1011`
- **Siklus 3:** Register `1011` $\rightarrow$ Out = `1`, Feed = $1 \oplus 1 = 0 \rightarrow$ Next Reg: `0101`
- **Siklus 4:** Register `0101` $\rightarrow$ Out = `1`, Feed = $1 \oplus 0 = 1 \rightarrow$ Next Reg: `1010`
- **Siklus 5:** Register `1010` $\rightarrow$ Out = `0`, Feed = $0 \oplus 1 = 1 \rightarrow$ Next Reg: `1101`
- **Siklus 6:** Register `1101` $\rightarrow$ Out = `1`, Feed = $1 \oplus 1 = 0 \rightarrow$ Next Reg: `0110`
- **Siklus 7:** Register `0110` $\rightarrow$ Out = `0`, Feed = $0 \oplus 0 = 0 \rightarrow$ Next Reg: `0011`
- **Siklus 8:** Register `0011` $\rightarrow$ Out = `1`, Feed = $1 \oplus 0 = 1 \rightarrow$ Next Reg: `1001`
- **Keystream Terbentuk:** `11110101`

### Enkripsi XOR:
```text
  Plaintext ('e'): 01100101
  Keystream      : 11110101
  ------------------------- (XOR)
  Ciphertext     : 10010000
```

## 5. Catatan Implementasi di Aplikasi
Aplikasi memakai LFSR **16-bit** dengan polinomial karakteristik:

$$x^{16} + x^{14} + x^{13} + x^{11} + 1$$

Fungsi umpan balik yang dihitung dari state:

$$\text{fb} = (s \oplus (s \gg 2) \oplus (s \gg 3) \oplus (s \gg 5)) \wedge 1$$

Prosedur per byte (8 detak):
1. `out_bit = state & 1` (LSB dikeluarkan lebih dulu).
2. `fb = (state ^ (state >> 2) ^ (state >> 3) ^ (state >> 5)) & 1`.
3. `state = (state >> 1) | (fb << 15)`.
4. Bit keluaran disusun menjadi 1 byte (MSB dari bit pertama).

Seed diturunkan dari password:

$$\text{seed} = \mathrm{int}_{16}\big(\mathrm{SHA256}(\text{password})[0..2]\big)$$

Jika seed bernilai 0, dipakai `0xACE1` karena state 0 tidak menghasilkan
keystream.

- `lfsr_keystream(seed, n)` — `diary_app.py:117-131`
- `_lfsr_xor(data, password)` — `diary_app.py:134-137`

### Contoh perhitungan sesuai kode
- **Password:** `abc`
- **Seed:** `int.from_bytes(sha256("abc")[:2], "big") = 0xBA78`
- **8 byte keystream pertama (hex):** `1e 5d 5e 69 19 a6 86 d8`
- Enkripsi: setiap byte hasil Vigenère di-XOR dengan byte keystream.

## 6. Catatan Keamanan
- LFSR 16-bit hanya memiliki $2^{16}-1 = 65.535$ state bukan-nol, sehingga
  periodenya paling lama 65.535 bit (sekitar 8 KB). Untuk pesan lebih panjang,
  keystream **berulang**.
- Seed hanya 2 byte SHA-256, jadi hanya ada 65.536 kemungkinan keystream.
- Karena itu LFSR di sini berfungsi sebagai lapisan "modern" untuk memenuhi
  konsep Super Encryption, bukan sebagai cipher produksi. Peningkatan ke
  LFSR 32/64-bit + nonce direncanakan (lihat `SUPER_ENCRYPTION.md`).
