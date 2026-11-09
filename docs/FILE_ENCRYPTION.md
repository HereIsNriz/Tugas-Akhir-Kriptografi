# Panduan Implementasi: Enkripsi File dengan RSA

## 1. Konsep Dasar

File memakai **RSA** (`RSA.md`), berbeda dari enkripsi teks Vigenère + LFSR
(`SUPER_ENCRYPTION.md`). RSA bersifat asimetris: enkripsi memakai **public key**
akun, sedangkan dekripsi memerlukan **private key** yang sesuai.

Penulisan baru menghasilkan format **RSA2**, tetap berekstensi `.rsa`. Format
lama **RSAF** masih dapat dibaca tanpa konversi file atau perubahan kunci privat.
RSA2 menambah pemeriksaan kerusakan, bukan autentisitas, padding OAEP, atau
peningkatan ukuran kunci. Ini tetap textbook RSA deterministik untuk pembelajaran.

## 2. Arsitektur & Prinsip Kerja

### Enkripsi — `diary_app.App.enkripsi_file`

1. Pengguna memilih sumber dan tujuan melalui dialog simpan. Nama yang disarankan
   adalah `<nama_file>.rsa`, tetapi **tujuan harus nama baru**. File yang sudah
   ada, termasuk sumber, tidak boleh ditimpa.
2. Aplikasi membaca plaintext, maksimal **5 MB** (`5 * 1024 * 1024` byte).
3. `diary_app.rsa_encrypt_bytes` meneruskan ke `rsa_files.encrypt_bytes`, yang
   membentuk header RSA2 dan mengenkripsi chunk plaintext menjadi blok RSA.
4. `diary_storage.save_encrypted_file` membuat file secara eksklusif (`xb`),
   melakukan flush/fsync, dan mencatat blok integritas dalam transaksi SQLite.
5. Event baru adalah `file2:` + JSON kanonik berisi **path absolut**, `user_id`,
   dan SHA-256 seluruh ciphertext (`blob`), bukan basename saja.
6. UI menyatakan sukses setelah file dan pencatatan blok berhasil.

Jika tujuan sudah ada, operasi ditolak; jalankan lagi dan pilih nama baru di
dialog simpan. Tidak ada overwrite meskipun dialog sistem meminta konfirmasi.

### Kegagalan penyimpanan dan batas atomicity

Bila penulisan file atau pencatatan blok gagal, transaksi DB di-rollback dan
file terenkripsi yang **baru dibuat** dibersihkan. File yang sudah ada tidak
pernah ditimpa atau dihapus oleh cleanup ini. Jika cleanup gagal, error menyebut
file yang belum tercatat dan perlu diperiksa.

Filesystem dan SQLite **tidak memiliki commit atomik bersama**. Hard crash atau
listrik padam dapat meninggalkan file tanpa blok; penanganan error biasa bukan
jaminan atomicity lintas filesystem/DB. Sebaliknya, `diary_storage.save_entry`
memang menyimpan baris entri diary dan blok `entry2:` dalam satu transaksi SQLite.

### Dekripsi — `diary_app.App.dekripsi_file`

1. Pengguna memilih `.rsa`; ciphertext dibatasi **6 MB**.
2. `diary_app.rsa_decrypt_bytes` meneruskan ke `rsa_files.decrypt_bytes`.
   Codec menerima RSA2 atau legacy RSAF dengan validasi struktur ketat.
3. RSA2 harus lolos pemeriksaan key ID, panjang asli/jumlah blok, struktur tiap
   blok, dan SHA-256 plaintext sebelum hasil ditawarkan untuk disimpan.
4. RSAF yang lolos struktur memunculkan **peringatan legacy tanpa checksum**:
   hasilnya belum tentu utuh, dan perlu dibandingkan dengan file asli jika ada.
5. Pengguna memilih tujuan melalui dialog simpan. Nama default menghapus `.rsa`,
   tetapi jika file asli masih ada, **pilih nama baru**. Hasil ditulis dengan
   `xb`; file yang sudah ada tidak ditimpa. Dekripsi tidak mencatat event file baru.

## 3. Rumus & Format

- **Ukuran modulus:**
  $$k = \left\lceil \frac{\text{bit length}(n)}{8} \right\rceil$$
- **Chunk plaintext:** maksimal $k - 2$ byte, didahului prefix `0x01` agar nol
  di awal plaintext tidak hilang dan nilai pesan tetap lebih kecil dari $n$.
- **Enkripsi per blok:**
  $$m = \mathrm{int}\big(\texttt{0x01} \parallel \text{chunk}\big), \qquad c = m^e \bmod n$$
  Ciphertext ditulis tepat $k$ byte, big-endian.
- **Dekripsi per blok (CRT):**
  $$ m_1 = c^{d_p} \bmod p,\quad m_2 = c^{d_q} \bmod q,\quad
  m = m_2 + \big(q_{\text{inv}}(m_1 - m_2) \bmod p\big)q$$
  Prefix `0x01` diperiksa sebelum dibuang.
  $$

### Format tulis baru: RSA2

```text
[ "RSA2" (4) ][ key ID (32) ][ panjang plaintext (8) ][ SHA-256 plaintext (32) ]
[ ciphertext blok 1 (k) ][ blok 2 (k) ] ... [ blok terakhir (k) ]
```

Header berukuran **76 byte**:

- Key ID adalah digest biner SHA-256 dari gabungan `n` dan `e`, masing-masing
  dikodekan sebagai integer big-endian selebar $k$ byte.
- Panjang plaintext adalah unsigned integer 8-byte big-endian.
- SHA-256 plaintext adalah digest biner 32 byte, bukan string hex 64 karakter.
- Body selalu kelipatan $k$ byte. Untuk panjang asli $L$, jumlah blok harus
  tepat $\lceil L/(k-2) \rceil$. File kosong hanya memiliki header, panjang 0,
  dan checksum plaintext kosong.

### Pembacaan legacy: RSAF

```text
[ "RSAF" (4 byte) ][ ciphertext blok 1 (k byte) ] ... [ blok terakhir (k byte) ]
```

RSAF bukan format penulisan baru. Tidak ada key ID, panjang asli, atau checksum.
Kedua format memeriksa konsistensi aritmetika kunci, body kelipatan $k$, setiap
$c < n$, prefix `0x01`, ukuran chunk 1 sampai $k-2$, dan chunk selain terakhir
harus penuh. RSA2 juga memeriksa panjang chunk terakhir dan checksum sesuai
header. Struktur yang lolos pada RSAF **tidak menjamin keutuhan**: beberapa
kerusakan atau kunci salah tidak terdeteksi, termasuk kunci berbeda untuk file
RSAF kosong. Pembacaan tidak menulis ulang file lama.

## 4. Contoh Ukuran

Misal $n$ 1024-bit: $k = 128$ byte dan chunk plaintext maksimal 126 byte.
File 1.000 byte membutuhkan:

$$\left\lceil \frac{1000}{126} \right\rceil = 8 \text{ blok}$$

Ukuran file **RSA2 baru**:

$$76 + 8 \times 128 = 1100 \text{ byte}$$

Sebagai perbandingan, **legacy RSAF** berukuran $4 + 8 \times 128 = 1028$ byte.
Selisih berasal dari metadata header; prefix bukan padding acak yang aman.

## 5. Kunci dan Integrasi Verifikasi

- `diary_app.muat_rsa` / `path_rsa` memuat kunci yang sudah ada di
  `data/rsa_<username>.json`, atau membuat kunci untuk akun yang belum memiliki
  file kunci. Format JSON tetap `n`, `e`, `d`, `p`, `q`; perubahan codec **tidak
  memigrasi, mengganti, atau mengenkripsi ulang private key lama**.
- `diary_storage.file_event` membentuk `file2:`. JSON memakai
  `ensure_ascii=False`, `sort_keys=True`, dan `separators=(",", ":")`.
- `diary_storage.verify_chain` memeriksa SHA-256 ciphertext di path absolut
  `file2:` serta kecocokan `user_id` event dan blok. Pemindahan/penghapusan file,
  file tidak terbaca, atau hash berubah membuat verifikasi gagal/belum lengkap.
- Event **legacy** `file:<basename>:<sha256(blob)>` tetap diverifikasi tanpa
  perubahan blok. File dicari di root proyek dan `data/`; harus ada tepat satu
  kandidat yang terbaca dengan hash cocok. File hilang, tidak terbaca, atau
  basename ada di kedua lokasi (ambigu) **bukan sukses**. Bila perlu, salin file
  terenkripsi asli ke salah satu lokasi itu tanpa menulis ulang blok lama.
- Verifikasi chain dijalankan melalui halaman blockchain; dekripsi memvalidasi
  codec, bukan otomatis memeriksa seluruh rantai. Hash ciphertext dalam blok
  berbeda dari checksum plaintext dalam header RSA2.

Lihat `BLOCKCHAIN_POW.md` untuk `entry2:` (timestamp/pemilik/hash judul-isi dengan
framing JSON), kompatibilitas `entry:` lama, serta penolakan rantai kosong,
genesis hilang/tidak valid, celah indeks, dan entri tanpa blok.

## 6. Catatan Keamanan & Keterbatasan

- RSA murni lambat untuk file besar; aplikasi membatasi ukuran input.
- Kunci default tetap **1024-bit**, **tanpa padding OAEP/PKCS#1**, dan
  **deterministik** (chunk sama dengan kunci sama menghasilkan ciphertext sama).
  RSA2 tidak mengubah batas keamanan ini.
- Key ID/panjang/checksum RSA2 membantu mendeteksi kunci salah dan kerusakan tidak
  sengaja, termasuk pemotongan, blok tambahan, dan pertukaran blok berbeda.
  **Checksum bukan autentisitas**: siapa pun dengan public key dapat membuat
  ciphertext pengganti beserta checksum valid. Tidak ada tanda tangan atau MAC.
- Menghapus metadata RSA2 dan mengganti magic menjadi RSAF menurunkan pemeriksaan
  ke legacy tanpa checksum; kompatibilitas ini bukan batas keamanan terhadap
  penyerang aktif.
- Rantai lokal tidak memiliki checkpoint eksternal tepercaya: tidak semua
  penghapusan ekor atau penulisan ulang seluruh riwayat dapat dideteksi.
- Private key tetap disimpan **plaintext** di JSON, belum dienkripsi at-rest.
  Hilangnya kunci asli berarti file `.rsa` lama tidak dapat dipulihkan hanya
  dengan membuat pasangan kunci baru. Simpan backup kunci secara aman.

### Arah peningkatan (belum diterapkan)

- RSA minimal 2048-bit dengan OAEP dari library kriptografi yang teruji.
- Enkripsi private key dengan kunci turunan password.
- Enkripsi hybrid dengan cipher terautentikasi untuk file besar.

## 7. Pengujian

```bash
python -B -m unittest discover -s tests -v
```

Tes codec dan penyimpanan dapat berjalan tanpa GUI dan tanpa menulis ulang data
pengguna. Jumlah kasus mengikuti isi `tests/`, bukan angka tetap di dokumentasi.
