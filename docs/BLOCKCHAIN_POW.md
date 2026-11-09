# Panduan Implementasi: Blockchain Sederhana + Proof of Work (PoW)

## 1. Konsep Dasar
Blockchain adalah daftar blok yang saling terhubung lewat hash. Setiap blok
menyimpan hash blok sebelumnya, sehingga perubahan pada satu blok akan merusak
seluruh blok sesudahnya [7]. **Proof of Work (PoW)** mewajibkan pencarian nilai
`nonce` sehingga hash blok diawali sejumlah karakter `0` (difficulty), yang
membuat pemalsuan menjadi mahal [7].

Di aplikasi ini blockchain dipakai untuk **menjaga integritas aset penting**.
Yang dicatat adalah **hash aset** (SHA-256), bukan isi aset.

## 2. Arsitektur & Prinsip Kerja
- **Struktur blok (tabel `blocks`)** — `diary_app.py:283-285`:
  `idx`, `ts` (timestamp), `data`, `prev_hash`, `nonce`, `hash`, `user_id`.
- **Genesis block:** blok pertama dengan `idx = 0` dan `prev_hash = "0"`
  (bukan 64 nol) — `diary_app.py:311-312`.
- **Hash blok:** SHA-256 atas string dengan pemisah `|` — `diary_app.py:293-294`.
- **PoW:** ulangi `nonce += 1` sampai hash diawali `DIFFICULTY = "000"`
  (tiga karakter hex nol) — `diary_app.py:52`, `297-308`.
- **Validasi chain:** untuk setiap blok, (a) hash tersimpan = hash hitung ulang,
  (b) `prev_hash` = hash blok sebelumnya, (c) hash memenuhi difficulty —
  `diary_app.py:315-347`.
- **Verifikasi entri:** blok dengan `data` berawalan `entry:` juga dicek ke
  tabel `entries` (hash isi dan kepemilikan) — `diary_app.py:323-335`.

## 3. Rumus & Operasi
- **Hash blok:**
  $$H_i = \text{SHA256}\big(\text{idx} \parallel \text{"|"} \parallel \text{ts}
  \parallel \text{"|"} \parallel \text{data} \parallel \text{"|"} \parallel
  H_{i-1} \parallel \text{"|"} \parallel \text{nonce}\big)$$
  Tepatnya: `sha256(f"{idx}|{ts}|{data}|{prev}|{nonce}")`.
- **Syarat PoW (difficulty $d$):**
  $$H_i \text{ diawali } d \text{ karakter hex } \texttt{0}, \quad d = 3$$
- **Syarat chain valid:**
  $$\forall i \ge 1:\ \text{block}_i.\text{prev\_hash} = \text{block}_{i-1}.\text{hash}$$

## 4. Contoh Perhitungan Manual (sesuai kode)
Difficulty yang dipakai `"000"`.

### Blok 0 (Genesis)
```text
idx       = 0
ts        = 2026-01-01 00:00:00
data      = "Genesis Block - Secret Diary"
prev_hash = "0"
nonce     = 2919   (hasil mining)
hash      = 000249c95949193023fbf743f57905e45053e7bd87fec2a6dd5cde7b3e86ffe2
```

### Blok 1 (contoh entri diary)
```text
idx       = 1
ts        = 2026-01-02 10:30:00
data      = entry:1:4d0fb35c5987b981a1dc12e6b0f8485fa1677783b0926503882b463a8bae1a9a
prev_hash = 000249c95949193023fbf743f57905e45053e7bd87fec2a6dd5cde7b3e86ffe2
nonce     = 11050   (hasil mining)
hash      = 000e9fe07a2c127132dd2788523d360ad21015ff59b3f8efd2fb8f497ab82a5c
```

`entry:1:...` berarti: entri diary dengan `id = 1`, diikuti hash SHA-256 dari
`judul_enc + isi_enc` (ciphertext).

### Deteksi pemalsuan
Jika `data` blok 1 diubah (mis. hash entri diganti), hash hitung ulang blok 1
tidak lagi sama dengan `hash` tersimpan, sehingga verifikasi mengembalikan
`False`. Penyerang harus me-mining ulang blok 1 dan semua blok sesudahnya.

## 5. Implementasi pada Aplikasi
- Konstanta `DIFFICULTY = "000"` — `diary_app.py:52`.
- `hitung_hash(idx, ts, data, prev, nonce)` — `diary_app.py:293-294`.
- `tambah_blok(data, user_id=0)` — `diary_app.py:297-308`:
  mengambil blok terakhir, menentukan `idx` dan `prev`, lalu mining.
- Genesis otomatis dibuat saat database masih kosong — `diary_app.py:311-312`.
- `verifikasi_chain()` — `diary_app.py:315-347`:
  memeriksa seluruh rantai (semua akun) + kecocokan data entri dan hash file
  (bila file masih tersedia).
- Aset yang dicatat:
  - **Entri diary:** `entry:<id>:<sha256(judul_enc+isi_enc)>` — `diary_app.py:884`.
  - **File terenkripsi:** `file:<nama>:<sha256(blob)>` — `diary_app.py:939`.
- Tampilan UI hanya menampilkan blok milik pengguna + genesis —
  `diary_app.py:1049-1055`.

### Keterbatasan saat ini
- Verifikasi `file:` mengecek `sha256` isi file bila file ditemukan di folder
  proyek atau `data/`; jika file sudah tidak ada, hanya integritas rantai yang
  diperiksa.
- Steganografi belum mendaftarkan hash gambar ke blockchain.
- Blockchain disimpan di tabel SQLite yang sama, sehingga tidak tahan terhadap
  penghapusan seluruh tabel (tidak ada node terdistribusi).

## 6. Catatan Keamanan
- Difficulty `"000"` sangat rendah; cukup untuk demo, bukan produksi.
- PoW membuat pemalsuan mahal secara komputasi, tetapi bukan mustahil pada
  difficulty rendah.
- Hash aset membuktikan integritas, bukan kerahasiaan; isi aset tetap harus
  dienkripsi terpisah (RSA / Super Encryption).
