# Panduan Implementasi: Enkripsi Data pada Database

## 1. Konsep Dasar
Sesuai `INSTRUCTION.md` 2.5, pesan penting yang disimpan di database harus
dalam bentuk terenkripsi, dan data sensitif tidak boleh plaintext. Aplikasi
memakai SQLite (`data/diary_multi.db`) dengan enkripsi pada tingkat aplikasi:
data dienkripsi **sebelum** ditulis ke database, lalu didekripsi **setelah**
dibaca.

## 2. Skema Database — `diary_app.py:276-286`
### Tabel `users`
| Kolom | Isi | Status |
|---|---|---|
| `id` | ID pengguna | plaintext |
| `username` | nama pengguna | plaintext (perlu unik) |
| `salt` | salt PBKDF2 (hex) | aman (bukan rahasia) |
| `hash` | hash PBKDF2 password (hex) | aman (satu arah) |
| `dibuat` | timestamp | plaintext |

### Tabel `entries`
| Kolom | Isi | Status |
|---|---|---|
| `id` | ID entri | plaintext |
| `user_id` | pemilik entri | plaintext |
| `tanggal` | timestamp | plaintext |
| `judul_enc` | judul terenkripsi (Base64) | **terenkripsi** |
| `isi_enc` | isi diary terenkripsi (Base64) | **terenkripsi** |

### Tabel `blocks`
| Kolom | Isi | Status |
|---|---|---|
| `idx`, `ts`, `data`, `prev_hash`, `nonce`, `hash`, `user_id` | metadata blockchain + hash aset | plaintext (hash bersifat publik) |

## 3. Alur Penyimpanan & Pengambilan
### Simpan entri — `diary_app.py:875-887`
1. Ambil judul dan isi dari UI.
2. Enkripsi keduanya dengan `super_encrypt(..., password)`.
3. `INSERT` ke `entries(user_id, tanggal, judul_enc, isi_enc)`.
4. Catat hash ciphertext ke blockchain:
   `entry:<id>:<sha256(judul_enc + isi_enc)>`.

### Ambil entri — `diary_app.py:862-873`, `889-907`
1. `SELECT id, tanggal, judul_enc FROM entries WHERE user_id=?` untuk daftar.
2. Dekripsi judul dengan `super_decrypt(judul_enc, password)`.
3. Saat entri dipilih, dekripsi `isi_enc` dan tampilkan.
4. Tampilkan ciphertext mentah di panel "Ciphertext yang tersimpan".

## 4. Rumus & Operasi
- **Enkripsi saat simpan:**
  $$\text{judul\_enc} = \mathrm{SuperEncrypt}(\text{judul}, pw), \quad
  \text{isi\_enc} = \mathrm{SuperEncrypt}(\text{isi}, pw)$$
- **Dekripsi saat baca:**
  $$\text{judul} = \mathrm{SuperDecrypt}(\text{judul\_enc}, pw), \quad
  \text{isi} = \mathrm{SuperDecrypt}(\text{isi\_enc}, pw)$$
- **Integritas entri:**
  $$h = \mathrm{SHA256}(\text{judul\_enc} \parallel \text{isi\_enc})$$
  disimpan di blockchain sebagai `entry:<id>:<h>`.

## 5. Data Sensitif di Luar Database
Selain tabel di atas, aplikasi menyimpan aset di folder `data/`:

| File | Isi | Status saat ini |
|---|---|---|
| `rsa_<user>.json` | private key RSA (`n,e,d,p,q`) | **plaintext** |
| `face_<user>.yml` | model wajah LBPH | **plaintext** |
| `diary_multi.db` | database | lihat tabel di atas |

Meskipun isi diary sudah terenkripsi, **private key** dan **model wajah**
belum dienkripsi at-rest. Ini bertentangan dengan semangat "data sensitif
tidak boleh plaintext" dan direncanakan diperbaiki.

## 6. Catatan Keamanan & Keterbatasan
- Enkripsi bergantung pada **password pengguna**; password lemah melemahkan
  seluruh entri.
- Metadata (username, timestamp, kepemilikan) tetap plaintext; ini normal untuk
  fungsionalitas, tetapi perlu disadari.
- `lihat_db.py` sengaja menampilkan data **apa adanya (terenkripsi)** untuk
  membuktikan bahwa isi diary tidak tersimpan plaintext.
- Database SQLite tidak dienkripsi pada tingkat file; proteksi berasal dari
  enkripsi kolom.
- Enkripsi private key, model wajah, serta nonce + HMAC pada pesan
  direncanakan (lihat `SUPER_ENCRYPTION.md` dan `FILE_ENCRYPTION.md`).
