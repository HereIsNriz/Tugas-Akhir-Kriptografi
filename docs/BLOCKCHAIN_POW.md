# Panduan Implementasi: Blockchain Sederhana + Proof of Work (PoW)

## 1. Konsep Dasar

Blockchain adalah daftar blok yang saling terhubung lewat hash. Setiap blok
menyimpan hash blok sebelumnya, sehingga perubahan pada satu blok akan merusak
seluruh blok sesudahnya [7]. **Proof of Work (PoW)** mewajibkan pencarian nilai
`nonce` sehingga hash blok diawali sejumlah karakter `0` (difficulty), yang
menambah biaya penghitungan ulang [7]. Difficulty demo ini rendah dan bukan
jaminan terhadap penyerang yang dapat menulis ulang database.

Di aplikasi ini blockchain adalah **rantai hash lokal untuk memeriksa konsistensi
aset penting**. Blok mencatat hash aset (SHA-256) dan metadata, bukan isi aset.
Tidak ada node terdistribusi atau checkpoint eksternal tepercaya.

## 2. Arsitektur & Prinsip Kerja

- **Struktur blok (tabel `blocks`)** — inisialisasi DB di `diary_app.py`:
  `idx`, `ts` (timestamp), `data`, `prev_hash`, `nonce`, `hash`, `user_id`.
- **Genesis block:** `idx = 0`, `prev_hash = "0"` (bukan 64 nol),
  `data = "Genesis Block - Secret Diary"`, dan `user_id = 0`.
- **Hash blok:** `diary_storage.block_hash` memakai string berseparator `|`;
  rumus hash lama dipertahankan agar blok lama tetap dapat diverifikasi.
- **PoW:** `diary_storage._append_block` menaikkan nonce sampai hash memenuhi
  `diary_app.DIFFICULTY = "000"` (tiga karakter hex nol).
- **Validasi:** `diary_storage.verify_chain` memeriksa urutan indeks mulai 0
  tanpa celah, genesis, hash hitung ulang, hubungan `prev_hash`, dan difficulty,
  lalu mencocokkan semua event dengan entri/file. Rantai kosong tidak valid.
- **Penulisan baru:** `entry2:` dan `file2:` memakai JSON kanonik dari
  `diary_storage._json`: `ensure_ascii=False`, `sort_keys=True`, dan
  `separators=(",", ":")`. Parser menolak field hilang/tambahan/duplikat.

## 3. Rumus & Operasi

**Hash blok:**

$$
H_i = \text{SHA256}\big(\text{idx} \parallel \text{"|"} \parallel \text{ts}
\parallel \text{"|"} \parallel \text{data} \parallel \text{"|"} \parallel
H_{i-1} \parallel \text{"|"} \parallel \text{nonce}\big)
$$

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

### Blok 1 (contoh entri diary legacy, bukan format tulis baru)

```text
idx       = 1
ts        = 2026-01-02 10:30:00
data      = entry:1:4d0fb35c5987b981a1dc12e6b0f8485fa1677783b0926503882b463a8bae1a9a
prev_hash = 000249c95949193023fbf743f57905e45053e7bd87fec2a6dd5cde7b3e86ffe2
nonce     = 11050   (hasil mining)
hash      = 000e9fe07a2c127132dd2788523d360ad21015ff59b3f8efd2fb8f497ab82a5c
```

`entry:1:...` adalah format **legacy**: entri diary dengan `id = 1`, diikuti
hash SHA-256 dari `judul_enc + isi_enc` (ciphertext). Penulisan baru memakai
`entry2:` dengan framing JSON dan metadata seperti dijelaskan berikut.

### Deteksi pemalsuan

Jika `data` blok 1 diubah (mis. hash entri diganti), hash hitung ulang blok 1
tidak lagi sama dengan `hash` tersimpan, sehingga verifikasi mengembalikan
`False`. Penyerang harus me-mining ulang blok 1 dan semua blok sesudahnya.

## 5. Implementasi pada Aplikasi

### Entri baru: transaksi atomik dan `entry2:`

`diary_app.App.simpan_entri` memanggil `diary_storage.save_entry`. Insert entri,
mining, dan insert blok berada dalam satu transaksi SQLite (`BEGIN IMMEDIATE`):
semuanya commit atau semuanya rollback. Tidak ada entri baru yang sengaja
tertinggal tanpa blok bila penyimpanan gagal.

`data` blok berisi `entry2:` diikuti JSON dengan field:

- `id`: ID baris entri;
- `user_id`: pemilik, harus sama dengan pemilik entri dan blok;
- `tanggal`: timestamp entri, harus sama dengan `entries.tanggal`;
- `sha256`: SHA-256 UTF-8 dari JSON kanonik `[judul_enc, isi_enc]`.

Array JSON memberi batas tegas antara judul dan isi: pasangan `("ab", "c")`
dan `("a", "bc")` tidak lagi memiliki representasi hash input yang sama.
Verifier menolak entri hilang, pemilik/tanggal/hash berubah, event entri duplikat,
dan **entri orphan** (baris `entries` yang tidak memiliki blok).

### File baru: `file2:` dan penyimpanan eksklusif

`diary_storage.file_event` menghasilkan `file2:` + JSON dengan `path` absolut,
`user_id`, dan `sha256` ciphertext. `save_encrypted_file` membuat file secara
**eksklusif** (`xb`), melakukan flush/fsync, dan mencatat blok di transaksi DB.
File yang sudah ada tidak ditimpa. Bila penulisan/pencatatan blok gagal, transaksi
rollback dan hanya file yang baru dibuat itu yang dibersihkan; jika pembersihan
gagal, error menyebut file yang perlu diperiksa.

Filesystem dan SQLite **tidak memiliki commit atomik bersama**. Hard crash atau
listrik padam masih dapat meninggalkan file tanpa blok; rollback/pembersihan
pada error biasa tidak menghilangkan batas ini. Verifikasi membaca path absolut
yang tercatat: file dipindah, hilang, tidak terbaca, atau hash berbeda berarti
verifikasi gagal/belum lengkap. Path ini juga mengurangi portabilitas backup.

### Pembacaan legacy tanpa penulisan ulang

- `entry:<id>:<sha256(judul_enc+isi_enc)>` tetap diverifikasi, termasuk pemilik
  entri terhadap blok. Format legacy tidak mengikat timestamp entri atau batas
  judul/isi; jaminannya tidak setara dengan `entry2:`.
- `file:<basename>:<sha256(blob)>` tetap dibaca. Verifier mencari file di root
  proyek dan `data/`. Harus ada **tepat satu** kandidat yang terbaca dan hash-nya
  cocok. Tidak ditemukan, tidak terbaca, atau ada di kedua lokasi (ambigu, meski
  isinya sama) berarti gagal/belum lengkap, **bukan sukses hanya karena hash
  rantainya valid**. Untuk memulihkan verifikasi, salin file terenkripsi asli ke
  salah satu lokasi tersebut; jangan ubah atau mining ulang blok lama.
- Pembacaan/verifikasi tidak menulis ulang entri, file, atau blok legacy.

### Integrasi UI dan inisialisasi

- `diary_app.tambah_blok` meneruskan ke `diary_storage.append_block`.
- Inisialisasi aplikasi membuat genesis hanya bila tabel `blocks` **dan**
  `entries` sama-sama kosong. Verifier sendiri tidak membuat/memperbaiki genesis;
  genesis hilang/tidak valid atau rantai kosong ditolak.
- `diary_app.verifikasi_chain` meneruskan ke `diary_storage.verify_chain` untuk
  memeriksa seluruh rantai (semua akun). `App.refresh_chain` hanya menampilkan
  blok milik pengguna + genesis; filter UI bukan cakupan verifikasi.
- Steganografi belum mendaftarkan hash gambar ke blockchain.

## 6. Catatan Keamanan

- Difficulty `"000"` sangat rendah; cukup untuk demo, bukan produksi.
- Hash/PoW memeriksa konsistensi lokal, bukan autentisitas atau identitas penulis.
  Penyerang dengan akses tulis DB dapat mengganti aset dan mining ulang rantai.
- Tanpa checkpoint eksternal tepercaya, tidak semua penghapusan ekor dapat
  dideteksi: misalnya blok file terakhir yang dihapus tanpa meninggalkan entri
  orphan. Penulisan ulang seluruh rantai yang konsisten juga tidak terdeteksi.
  Ini berbeda dari rantai kosong, genesis hilang, celah indeks, atau entri orphan,
  yang memang ditolak verifier.
- Hash aset tidak memberi kerahasiaan; isi tetap dienkripsi terpisah (RSA /
  Super Encryption). Jangan menganggap hasil verifikasi sebagai bukti riwayat
  lengkap atau perlindungan dari pemalsuan yang disengaja.

## 7. Pengujian

```bash
python -B -m unittest discover -s tests -v
```

Gunakan tes penyimpanan/rantai tanpa membuka GUI atau database pengguna; jumlah
kasus mengikuti isi `tests/`, bukan angka tetap dalam dokumentasi.
