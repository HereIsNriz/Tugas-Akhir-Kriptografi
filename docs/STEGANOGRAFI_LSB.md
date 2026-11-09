# Panduan Implementasi: Steganografi LSB (Least Significant Bit) pada PNG

## 1. Konsep Dasar
Steganografi adalah teknik **menyembunyikan keberadaan pesan** di dalam media
lain [2]. LSB mengganti bit paling kanan (paling tidak signifikan) dari setiap
nilai warna piksel dengan bit pesan. Perubahan maksimal ±1 pada nilai warna
tidak terlihat mata manusia.

Syarat penting: gunakan **PNG (lossless)**. JPEG tidak boleh, karena
kompresinya merusak LSB.

## 2. Arsitektur & Prinsip Kerja
- Mode gambar: `RGB`, tiap piksel punya 3 channel (R, G, B), masing-masing
  menyimpan 1 bit.
- **Kapasitas:** $\text{lebar} \times \text{tinggi} \times 3$ bit.
- **Format payload:** `[header 32 bit: panjang pesan dalam byte, big-endian] [bit pesan]`.
- **Urutan penanaman:** piksel kiri ke kanan, atas ke bawah, channel R → G → B.
- Pesan yang disisipkan sudah berupa **ciphertext** hasil Super Encryption
  (string Base64 yang di-encode).

## 3. Rumus & Operasi
- **Embed (ganti LSB):**
  $$v' = (v \wedge \texttt{0xFE}) \mid b$$
  dengan $v$ nilai channel asli dan $b$ bit pesan.
- **Extract (ambil LSB):**
  $$b = v' \wedge 1$$
- **Kapasitas maksimum pesan (byte):**
  $$\left\lfloor \frac{W \times H \times 3}{8} \right\rfloor - 4$$

## 4. Contoh Perhitungan Manual
- **Pesan:** karakter `'A'` = ASCII 65 = `01000001`
- **Cover (3 piksel):** P1 = (200, 101, 54), P2 = (77, 128, 255), P3 = (10, 33, 90)

| Channel | Nilai asli (biner) | Bit pesan | Nilai baru |
|---|---|---|---|
| P1.R | 200 (`11001000`) | 0 | 200 |
| P1.G | 101 (`01100101`) | 1 | 101 |
| P1.B | 54 (`00110110`) | 0 | 54 |
| P2.R | 77 (`01001101`) | 0 | 76 |
| P2.G | 128 (`10000000`) | 0 | 128 |
| P2.B | 255 (`11111111`) | 0 | 254 |
| P3.R | 10 (`00001010`) | 0 | 10 |
| P3.G | 33 (`00100001`) | 1 | 33 |
| P3.B | 90 | (tidak dipakai) | 90 |

Piksel hasil: P1 = (200, 101, 54), P2 = (76, 128, 254), P3 = (10, 33, 90).

**Ekstraksi:** LSB dari 8 channel pertama = `0 1 0 0 0 0 0 1` = `01000001` =
65 = `'A'`.

Hanya 2 dari 8 channel yang benar-benar berubah nilainya, dan perubahannya
hanya 1 tingkat.

## 5. Implementasi pada Aplikasi
- `stego_embed(src, dst, payload)` — `diary_app.py:245-255`:
  1. Buka gambar, `convert("RGB")`.
  2. Payload = 4 byte panjang (big-endian) + data.
  3. Ubah payload menjadi string bit.
  4. Jika jumlah bit melebihi jumlah channel → `ValueError("Gambar terlalu
     kecil untuk pesan ini.")`.
  5. Ganti LSB tiap channel, simpan sebagai **PNG**.
- `stego_extract(src)` — `diary_app.py:258-265`:
  1. Baca 32 bit pertama sebagai panjang.
  2. Validasi `(panjang + 4) * 8 <= total bit`.
  3. Baca bit pesan sesuai panjang, kembalikan sebagai byte.
- Alur terintegrasi di UI — `diary_app.py:945-981`:
  - Sisip: `pesan → super_encrypt(pesan, password) → .encode() → stego_embed`.
  - Ekstrak: `stego_extract → .decode() → super_decrypt(...)`.

### Catatan
- Aplikasi memakai `PIL.Image.getdata()/putdata()` untuk membaca/menulis
  piksel; logika LSB ditulis manual.
- Belum ada pendaftaran hash gambar stego ke blockchain (fitur yang
  direkomendasikan untuk memperkuat syarat 2.7).
- Kapasitas tidak ditampilkan di UI; pesan yang terlalu besar akan memunculkan
  dialog error.

## 6. Catatan Keamanan
- LSB mudah dirusak oleh kompresi ulang, resize, atau crop; gunakan PNG asli.
- Keamanan berasal dari enkripsi payload, bukan dari LSB itu sendiri.
- Penyerang yang mencurigai steganografi bisa menganalisis LSB; enkripsi tetap
  wajib.
