# Simple Encrypted Chat (DES + RSA Key Exchange)

## Overview

Lightweight HTTP relay server and console chat client using DES (ECB) for message confidentiality and a simple RSA key exchange to establish an 8-byte session key. Designed for learning; not secure for production.

# Chat Terenkripsi Sederhana (DES + Pertukaran Kunci RSA)

## Ikhtisar

Server relay HTTP ringan dan klien obrolan berbasis konsol yang menggunakan DES (ECB) untuk kerahasiaan pesan serta pertukaran kunci RSA sederhana untuk menetapkan kunci sesi 8 byte. Contoh ini ditujukan untuk pembelajaran; tidak aman untuk penggunaan produksi.

## Struktur Repository

- `server.py`: Server relay HTTP yang menyediakan endpoint `/register`, `/pub`, `/send`, `/recv`.
- `client.py`: Klien obrolan konsol yang mengenkripsi pesan dengan DES dan menggunakan RSA untuk penukaran kunci.
- `des_traditional.py`: Implementasi DES (ECB) dengan padding mirip PKCS#7.
- `rsa_small.py`: Utilitas RSA minimal untuk pembuatan pasangan kunci, enkripsi/dekripsi, dan serialisasi.
- `build_http.py`: Helper ringan untuk HTTP GET/POST.
- `server.log`: File log output server.

## Persyaratan

- Python 3.8 atau lebih baru
- Windows PowerShell (didukung)

## Panduan Singkat

1. Jalankan relay server

```
python server.py
```

Jika ingin menentukan host dan port:

```
python server.py 0.0.0.0 8002
```

2. Jalankan dua klien (bisa di mesin yang sama atau berbeda)

Terminal A:

```
python client.py alice bob
```

Terminal B:

```
python client.py bob alice
```

Jika tidak menyertakan peer, klien akan meminta input atau menunggu:

```
python client.py alice
```

## Perintah Klien

- `/to <peer>`: Mengatur atau mengganti peer.
- `/quit`: Keluar dari aplikasi.

## Cara Kerja

- Setiap klien membuat pasangan kunci RSA saat dijalankan.
- Klien dapat mendaftarkan kunci publiknya ke server menggunakan endpoint `/register`.
- ID yang lebih kecil secara leksikografis mengirim pesan `keyx` yang berisi kunci sesi DES (8 byte) terenkripsi dengan kunci publik RSA peer.
- Setelah kedua pihak mengetahui kunci sesi 8 byte, pesan bertipe `text` akan dikirim terenkripsi menggunakan DES-ECB dan didekripsi oleh penerima.

## API HTTP (Server)

### POST `/register`

Contoh request:

```
{"id":"alice","pub":{"n":"<hex>","e":65537}}
```

Contoh response:

```
{"ok":true}
```

### GET `/pub?client=<id>`

Response 200 contoh:

```
{"n":"<hex>","e":65537}
```

### POST `/send`

Contoh request:

```
{"from":"alice","to":"bob","type":"pub","msg":"{...}"}
```

```
{"from":"alice","to":"bob","type":"keyx","msg":"<hex>","size":8}
```

```
{"from":"alice","to":"bob","type":"text","cipher":"<hex>","size":N}
```

Response contoh:

```
{"queued":true}
```

### GET `/recv?client=<id>&wait=<seconds>`

Response 200 contoh:

```
{"from":"bob","type":"text","msg":"<hex>","size":N}
```

Response 204: Tidak ada konten

## Log

- Server menampilkan pratinjau request ke konsol dan menulis entri bertanda waktu ke `server.log`.

## Catatan

- DES-ECB dan RSA tanpa padding tidak aman; proyek ini hanya untuk tujuan edukasi.

## Notes

- DES-ECB and RSA without padding are insecure; this project is for educational use only.
