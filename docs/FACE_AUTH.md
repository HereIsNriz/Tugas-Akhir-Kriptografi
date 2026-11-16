# Biometrik Wajah: YuNet + SFace

## Mengapa LBPH diganti

Implementasi sebelumnya melatih LBPH dengan satu identitas, lalu menerima jarak
`confidence < 70` selama lima frame. Angka tersebut bukan probabilitas identitas,
dan belum dikalibrasi dengan wajah orang lain. Frame berurutan sangat berkorelasi,
sehingga false match yang sama dapat bertahan selama seluruh frame penerimaan.
Hanya menambah jumlah frame atau menurunkan ambang LBPH bukan solusi yang terbukti.

## Alur baru

`diary_app.py` tetap memeriksa password dan dongle. `face_auth.py` menangani:

1. **YuNet** mendeteksi wajah dan landmark. Frame harus berisi tepat satu wajah
   terdeteksi, skor deteksi minimal 0.9 dan bounding box minimal 80x80 piksel.
2. **SFace** menyelaraskan wajah melalui `alignCrop` dan menghasilkan embedding
   128 dimensi. Embedding dinormalisasi sebelum disimpan/dibandingkan.
3. **Pendaftaran:** 12 sampel, minimal 0.3 detik antar-sampel, maksimal 40 detik.
   Pergantian identitas yang tidak konsisten membatalkan pendaftaran.
4. **Verifikasi:** cosine similarity terhadap centroid ternormalisasi profil,
   bukan memilih sampel terdekat yang kebetulan cocok. Ambang awal 0.5 belum
   dikalibrasi dengan pengguna proyek ini. Skor lebih besar berarti lebih mirip.
5. Minimal 8 kecocokan berjarak minimal 0.25 detik dan membentang minimal 2 detik
   diperlukan sebelum diterima. Jeda pengamatan lebih dari 1.5 detik, mismatch,
   tidak ada wajah, atau beberapa wajah mereset progres. Batas sesi 12 detik.
6. `q`, Esc, penutupan jendela, dongle hilang, atau error kamera selalu menolak,
   termasuk jika terjadi pada frame yang sebenarnya memenuhi syarat penerimaan.
   Kamera dilepas dan jendela dibersihkan dalam `finally`.
7. Mode debug hanya mencetak skor; jalur keputusan login tetap sama.

Batas waktu diperiksa di antara panggilan OpenCV; driver kamera yang macet dapat
memblokir panggilan lebih lama. Ini bukan sistem real-time dengan deadline keras.

## Model dan penyimpanan

Jalankan `python setup_face_models.py` untuk mengunduh model dari OpenCV Zoo:

- `models/face_detection_yunet_2023mar.onnx` (~0.2 MB)
- `models/face_recognition_sface_2021dec.onnx` (~38.7 MB)

SHA-256 dan ukuran harus sesuai dengan konstanta installer sebelum file dipakai.
Tidak ada data wajah yang diunggah. Model publik dan profil biometrik tidak masuk
Git. Profil per akun berada di `data/face_<username>.yml.sface.json`, berisi versi,
identitas model dan embedding. Penulisan profil atomik; pembatalan tidak menimpa
profil. JSON tidak memakai pickle dan menolak nilai tidak finite/format invalid.

## Akun lama

Tidak ada fallback ke model LBPH. Akun lama harus direkam ulang oleh pemilik
menggunakan `migrate_face.py` sesuai README. File `.yml`, database dan kunci RSA
lama tetap utuh. Migrasi bukan verifikasi identitas lama: proses ini mempercayai
pemilik lokal dengan password + dongle + akses konsol. Jangan mengeksposnya sebagai
pemulihan akun jarak jauh atau fallback otomatis di login.

## Validasi dan batas keamanan

Tes `python -B -m unittest discover -s tests -v` mencakup keputusan temporal,
cosine, penolakan embedding/profil invalid, mixed identity, pembatalan pada frame
sukses, beberapa wajah, kamera/error dan cleanup memakai mock. Tes logika ini
bukan pengukuran akurasi wajah manusia.

Uji langsung wajib memakai pemilik dan beberapa impostor dalam kondisi cahaya,
jarak, dan pose yang berbeda. Catat false acceptance/false rejection; sesuaikan
ambang berdasarkan data validasi terpisah, bukan hanya satu percobaan. Jika
skornya tumpang tindih, jangan melonggarkan ambang untuk memaksa login.

Tidak ada liveness detection. Foto atau video dapat menipu pengenalan wajah.
Profil belum dienkripsi/diautentikasi at-rest; pengguna dengan akses tulis lokal
masih dapat menggantinya. Sistem ini tetap demonstrasi pendidikan, bukan jaminan
keamanan produksi.

Referensi model/API:
- https://github.com/opencv/opencv_zoo/tree/main/models/face_detection_yunet
- https://github.com/opencv/opencv_zoo/tree/main/models/face_recognition_sface
- https://docs.opencv.org/4.x/d0/dd4/tutorial_dnn_face.html
