# Panduan Implementasi: Biometrik Wajah (Haar Cascade + LBPH)

## 1. Konsep Dasar
Login biometrik memakai dua tahap [6]:
1. **Haar Cascade (Viola–Jones)** untuk **mendeteksi** di mana wajah berada pada
   frame kamera.
2. **LBPH (Local Binary Patterns Histograms)** untuk **mengenali** wajah
   tersebut milik siapa, dengan membandingkan pola tekstur lokal.

Haar hanya menjawab "ada wajah di mana", LBPH menjawab "wajah ini cocok dengan
pengguna terdaftar atau tidak".

## 2. Arsitektur & Prinsip Kerja
### Haar Cascade
- Memakai **fitur Haar** (selisih jumlah piksel area terang dan gelap, misal
  area mata lebih gelap dari pipi).
- **Integral image** membuat jumlah piksel pada persegi panjang apa pun bisa
  dihitung dengan 4 titik acuan, sehingga cepat.
- **AdaBoost** memilih fitur terbaik, lalu fitur disusun dalam **cascade**
  bertahap. Window yang gagal di tahap awal langsung dibuang.

### LBPH
1. Untuk tiap piksel, bandingkan dengan 8 tetangganya (3×3): tetangga ≥ pusat →
   `1`, selain itu `0`. Baca searah jarum jam menjadi angka 8 bit (0–255).
2. Bagi gambar wajah menjadi grid sel (default OpenCV 8×8), hitung histogram
   256 bin per sel, lalu gabungkan menjadi satu vektor fitur.
3. Saat verifikasi, bandingkan histogram wajah baru dengan histogram tersimpan
   memakai jarak chi-square. **Semakin kecil jarak (confidence), semakin mirip.**

## 3. Rumus & Operasi
- **Nilai fitur Haar:**
  $$f = \sum \text{piksel area putih} - \sum \text{piksel area hitam}$$
- **Integral image:**
  $$ii(x,y) = \sum_{x' \le x,\ y' \le y} i(x',y')$$
- **Jumlah persegi panjang dengan 4 titik:**
  $$\text{Sum} = D - B - C + A$$
- **Kode LBP:**
  $$LBP = \sum_{p=0}^{7} s(g_p - g_c)\, 2^p,\quad s(x)=\begin{cases}1 & x \ge 0\\ 0 & x<0\end{cases}$$
- **Jarak chi-square antar histogram:**
  $$\chi^2(H_1,H_2) = \sum_i \frac{(H_1(i)-H_2(i))^2}{H_1(i)+H_2(i)}$$
  (OpenCV memakai varian `HISTCMP_CHISQR_ALT` yang bernilai 2 kali rumus ini,
  tidak mengubah urutan kemiripan.)

## 4. Contoh Perhitungan Manual
### a. Integral image (4×4)
```text
Gambar:             Integral image:
 1  2  3  4          1   3   6  10
 5  6  7  8          6  14  24  36
 9 10 11 12         15  33  54  78
13 14 15 16         28  60  96 136
```
Hitung jumlah area baris ke-2 sampai ke-3 dan kolom ke-2 sampai ke-3
(nilai `6, 7, 10, 11`, jumlah = 34) dengan indeks 0-based:

- $D = ii[2][2] = 54$ (kanan-bawah)
- $B = ii[0][2] = 6$ (kanan-atas)
- $C = ii[2][0] = 15$ (kiri-bawah)
- $A = ii[0][0] = 1$ (kiri-atas)

$$\text{Sum} = D - B - C + A = 54 - 6 - 15 + 1 = 34$$

### b. Kode LBP satu piksel
```text
Tetangga 3×3:        Pusat = 65
 54  70  90
 60 [65] 80
 40  66  75
```
Baca searah jarum jam mulai kiri-atas: `54, 70, 90, 80, 75, 66, 40, 60`.
Bandingkan dengan 65 (≥ 65 → 1): `0 1 1 1 1 1 0 0` = $124$.

### c. Jarak histogram (contoh 4 bin)
```text
H1 = [4, 2, 0, 6]
H2 = [3, 3, 1, 5]
χ² = 1²/7 + 1²/5 + 1²/1 + 1²/11
   = 0.143 + 0.200 + 1.000 + 0.091 = 1.434
```
Dibanding pengguna lain yang jaraknya misal 8.2, pengguna ini dikenali karena
jaraknya jauh lebih kecil.

## 5. Implementasi pada Aplikasi
- Dependency: `opencv-contrib-python` (wajib contrib, karena `cv2.face` tidak
  ada di `opencv-python` biasa) dan `numpy`.
- Detektor: `haarcascade_frontalface_default.xml`, dicari di folder proyek,
  folder `data/`, lalu folder bawaan OpenCV — `diary_app.py:335-347`.
- Kamera: `cv2.VideoCapture(0, cv2.CAP_DSHOW)`.

### Pendaftaran wajah — `diary_app.py:350-380`
- Target **40 sampel**, minimal **20 sampel** agar dianggap berhasil
  (`diary_app.py:360`, `375`).
- Deteksi: `det.detectMultiScale(gray, 1.3, 5)[:1]` (ambil satu wajah).
- Crop lalu resize **200×200** grayscale.
- Latih `cv2.face.LBPHFaceRecognizer_create()` dan simpan model ke
  `data/face_<username>.yml`.

### Verifikasi wajah — `diary_app.py:383-416`
- Batas waktu **10 detik** (`diary_app.py:398`).
- Butuh **5 frame cocok** (`cocok >= 5`) — `diary_app.py:398`, `416`.
- `predict()` mengembalikan `(label, confidence)`.
- Ambang `FACE_THRESHOLD = 70` (`diary_app.py:51`): dianggap cocok bila
  `confidence < 70` (`diary_app.py:405`).

### Kaitan dengan dongle
Sesuai `INSTRUCTION.md` 2.1, biometrik hanya aktif dengan bantuan dongle.
Saat ini dongle dicek di awal aplikasi (`diary_app.py:1020`); pengikatan
eksplisit `cek_dongle()` ke fungsi biometrik direncanakan (lihat
`AUTH_DONGLE.md`).

### Catatan
- Jika OpenCV tidak terpasang, saat ini ada fallback **simulasi** yang
  menanyakan "cocok?" — ini **melanggar** semangat syarat biometrik dan
  direncanakan dihapus (fail-closed).
- Hanya model `.yml` yang disimpan, bukan foto mentah wajah.

## 6. Catatan Keamanan
- Tidak ada *liveness detection*; foto wajah bisa menipu kamera.
- Model wajah disimpan plaintext; enkripsi at-rest direncanakan.
- Threshold perlu dikalibrasi ulang di lingkungan nyata (pencahayaan berbeda).
- Verifikasi sebaiknya dianggap faktor tambahan setelah password, bukan
  pengganti password.
