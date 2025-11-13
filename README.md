# Simple Encrypted Chat v3 (DES + RSA Key Exchange)

Mirip dengan versi Tugas2, tetapi sekarang ada distribusi kunci publik RSA untuk menegosiasikan kunci sesi DES secara otomatis. Perbedaan dibuat sekecil mungkin.

## File

- `client3.py` : Aplikasi chat + relay embedded (port default 8002)
- `des_traditional.py` : Implementasi DES (ECB) sama seperti versi sebelumnya
- `rsa_small.py` : RSA sederhana (tanpa padding, edukasi) untuk menukar kunci sesi 8 byte

## Cara Pakai (1 Mesin / 2 Mesin)

### Requirements

- Python 3.8 or newer.
- Works on Windows PowerShell.

Jika Anda menggunakan Python 3.8, seluruh anotasi tipe sudah disesuaikan agar kompatibel (tidak perlu Python 3.9).

1. Terminal 1 (misal `alice`):

   ```
   python client3.py alice
   ```

   Tekan Enter saat diminta peer kalau ingin menunggu.

2. Terminal 2 (misal `bob`):

   ```
   python client3.py bob alice
   ```

3. Handshake (otomatis):

   - Jalankan `alice` dulu (tanpa peer). Alice akan menunggu pesan masuk.
   - Jalankan `bob` dengan peer `alice`. Bob otomatis mengirim `pub` ke `alice`.
   - Alice otomatis "auto-adopt" peer dari pengirim pertama `pub`, mengirim balik `pub`.
   - HANYA salah satu pihak mengirim `keyx` (penentu: id yang lebih kecil secara leksikografis, mis. `alice` < `bob`). Pengirim langsung menganggap sesi siap setelah mengirim `keyx`; penerima akan siap setelah berhasil mendekripsi.
   - Ketika kunci sesi 8 byte diterima dan didekripsi, akan muncul: "Session key established".

4. Chat:
   - Ketik pesan biasa setelah sesi siap.
   - Dari sisi yang belum set peer: gunakan `/to <id>`.

## Perintah

- `/to <id>` : Set penerima
- `/quit` : Keluar

## Catatan

- Port relay default: 8002 (ubah `SERVER_DEFAULT` di `client3.py` bila perlu).
- RSA ini minimal (tidak aman untuk produksi, tidak ada padding). DES ECB juga tidak disarankan untuk produksi.
- Fokus tugas: demonstrasi distribusi kunci publik + penggunaan kunci sesi simetris.

## Ringkas Perbedaan vs Tugas2

- Penambahan modul RSA kecil (`rsa_small.py`).
- Handshake otomatis: kirim `pub`, lalu `keyx` berisi kunci DES terenkripsi.
- Sisanya (relay, struktur pesan, DES) hampir sama.
