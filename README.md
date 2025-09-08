# Saya telah membangun jalur pentesting otomatis yang komprehensif dengan fitur-fitur berikut:

## ⚠️ PERINGATAN PENTING

**Tool ini hanya untuk tujuan edukasi dan pengujian pada sistem yang Anda miliki sendiri. Penggunaan pada sistem tanpa izin adalah ILEGAL dan dapat melanggar hukum. Pengguna bertanggung jawab penuh atas penggunaan tool ini.**

---

## 🛡️ Kemampuan Inti:
1. Fase Penemuan Sasaran
Pencacahan Subdomain: Menggunakan transparansi sertifikat (crt.sh) dan bruteforcing DNS
Pengumpulan Aset: Mengumpulkan semua subdomain dan menghapus duplikat hasil
Penemuan Multi-sumber: Menggabungkan beberapa teknik pengintaian

2. Pemindaian Port & Deteksi Layanan
Pemindaian Port Cepat: Memindai port umum (21, 22, 80, 443, 3306, dll.)
Sidik Jari Layanan: Mengidentifikasi layanan yang berjalan pada port terbuka
Cakupan Komprehensif: Memindai semua subdomain yang ditemukan

3. Pemindaian Kerentanan
Header Keamanan Web: Memeriksa header keamanan yang hilang (HSTS, CSP, X-Frame-Options, dll.)
Kerentanan Umum: Mendeteksi potensi kesalahan konfigurasi keamanan
Klasifikasi Keparahan: Mengkategorikan temuan berdasarkan tingkat risiko (Tinggi/Sedang/Rendah)

4. Fitur Lanjutan
Pelacakan Kemajuan Waktu Nyata: Pembaruan langsung selama eksekusi pemindaian
Berbagai Jenis Pemindaian: Pemindaian Penuh, Khusus Subdomain, Khusus Port, atau Khusus Kerentanan
Ekspor JSON: Unduh hasil pemindaian lengkap
Dasbor Web Modern: Antarmuka yang indah dan responsif dengan pembaruan waktu nyata
Pemrosesan Async: Eksekusi pemindaian latar belakang tanpa pemblokiran

---

## 🚀 Cara Menggunakan:
Memulai Pemindaian: Masukkan domain (mis., example.com) dan pilih jenis pemindaian
Pantau Kemajuan: Saksikan kemajuan waktu nyata dengan indikator fase
Lihat Hasil: Lihat subdomain yang ditemukan, port terbuka, dan kerentanan
Ekspor Data: Unduh hasil dalam format JSON untuk analisis lebih lanjut

---

## 🔧 Arsitektur Teknis:
Backend: FastAPI dengan pemrosesan asinkron
Frontend: HTML5/CSS3/JavaScript modern dengan desain glassmorphism
Integrasi Alat Keamanan: Desain modular untuk penambahan alat yang mudah
Pembaruan Waktu Nyata: jajak pendapat seperti WebSocket untuk pembaruan status langsung
Aplikasi sekarang berjalan dan siap digunakan! Anda dapat:

---

## 🛠️ Instalasi dan Setup

### 1. Clone Repository
```bash
git clone <repository-url>
cd fastapi_template
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Security Tools
```bash
sudo apt install nikto
```

### 4. Install Subfinder
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### 5. Akses Web Interface
Buka browser dan kunjungi: `http://localhost:8000`

---

## 🤝 Kontribusi

Untuk berkontribusi pada project ini:

1. Fork repository
2. Buat branch fitur baru
3. Commit perubahan Anda
4. Push ke branch
5. Buat Pull Request

## 📄 Lisensi

Project ini dilisensikan di bawah MIT License. Lihat file LICENSE untuk detail lengkap.

## 🙏 Acknowledgments

- **Nmap** - Gordon Lyon dan [Nmap](https://nmap.org/) Project
- **Subfinder** - [ProjectDiscovery team](https://github.com/projectdiscovery/subfinder)
- **Nikto** - [CIRT.net](https://cirt.net/nikto2)
- **FastAPI** - [Sebastián Ramirez](https://de.linkedin.com/in/tiangolo)

---

**Disclaimer**: Tool ini dibuat untuk tujuan edukasi dan testing keamanan yang sah. Penulis tidak bertanggung jawab atas penyalahgunaan tool ini. Gunakan dengan bijak dan sesuai hukum yang berlaku.

---
