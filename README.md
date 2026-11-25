# vulnextract

Tool untuk mengekstrak fitur pada tingkat statement dari dataset kerentanan kode dan menyimpannya sebagai CSV untuk riset deteksi kerentanan. Entry point aplikasi hanya menyediakan ekstraksi `features`; mode `pairs` dan `classify` tidak tersedia dari menu atau CLI.

## Prasyarat

- Python 3.10+
- pip

## Instalasi

Dari root repo:

```bash
python -m venv .venv
```

Aktifkan virtual environment:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependency:

```bash
pip install -r requirements.txt
```

## Menjalankan ekstraksi features

Menu interaktif:

```bash
python src/main.py
```

Menu hanya menyediakan ekstraksi statement features dan keluar.

CLI:

```bash
python src/main.py -m features
python src/main.py -m features -i data/input/code_vulnerabilities.csv
python src/main.py -m features -i data/input/CVEFixes.csv --max-rows 5000
python src/main.py -m features -i "data/input/Security Vulnerabilities.csv"
python src/main.py -m features -i "data/input/Security Vulnerabilities.csv" --allow-synthetic
```

Opsi yang tersedia:

| Opsi | Deskripsi | Default |
|---|---|---|
| `-i`, `--input` | Path atau URL file input | `input_file` di `global.yaml` |
| `-m`, `--mode` | Mode ekstraksi (satu-satunya nilai: `features`) | `features` |
| `--max-rows` | Batas baris input (`0` = tanpa batas) | `max_rows` di `global.yaml` |
| `--allow-synthetic` | Aktifkan fallback kode AST sintetis untuk advisory tanpa diff commit | `allow_synthetic_fallback` di `global.yaml` (default `false`) |
| `-v`, `--verbose` | Aktifkan log debug | `verbose` di `global.yaml` |

Mode `features` selalu menambahkan hasil ke `data/output/output_statement_features.csv`; CLI tidak menerima opsi output per dataset. Writer menyamakan urutan kolom berdasarkan nama, tidak menulis header berulang, dan menolak schema yang berbeda sebelum mengubah arsip.

## Format input

Pipeline menggunakan adapter/normalizer di [src/dataset_loader.py](src/dataset_loader.py) untuk mendukung beberapa bentuk dataset:

1. **Dataset berpasangan** seperti `data/input/cve_fix_pairs.csv` dengan `vulnerable_code` dan `fixed_code` atau aliasnya.
2. **Dataset snippet tunggal** seperti `Code Snippet`, `Vulnerability Type`, `Location`, dan `Preprocessed Tokens`.
3. **Dataset berlabel safety** seperti `code`, `language`, dan `safety` (`vulnerable` / `safe`).
4. **Dataset advisory/link GitHub** dengan kolom seperti `Title`, `Date`, `Severity`, `Summary`, dan `Link`.

Mode feature extraction memproses Go, Python, JavaScript, TypeScript, dan PHP. Bahasa lain dilewati.

## Output

Setiap baris output mewakili sebuah statement hasil parsing AST, beserta identitas/lokasi, teks, fitur leksikal dan perilaku, serta label. Kolom `origin` membedakan sumber statement:

Pemetaan statement mencakup PHP `global_decl` dan `unset`, Go `receive` untuk receive statement mandiri (kepala `select case <-x:` tetap bagian dari case, bukan baris), serta Python `decorated_def` yang menyertakan baris decorator. `future_import_statement` Python memakai tipe `import`. Node bernama tak dikenal pada posisi statement dilewati, dihitung per bahasa dan jenis node, serta dilaporkan di ringkasan akhir.

| `origin` | Sumber | Label | `vulnerability_type` |
|---|---|---:|---|
| `vulnerable` | `vulnerable_code` | Hasil diff/aturan labeling | `none` untuk label `0`; jenis asli input untuk label `1` (`unknown` bila kosong) |
| `fixed` | `fixed_code` | `0` | `none` |
| `unchanged` | Kode vulnerable dan fixed yang sama | `0` | `none` |

Rincian skema fitur tersedia di [context.md](context.md).

Kolom `call_target_kind` dan deteksi concatenation adalah heuristik syntax-level: import/alias serta fungsi yang didefinisikan di sumber yang sedang diparse dipakai bila terlihat, tanpa indeks simbol lintas repo atau analisis tipe. `cyclomatic_contribution` menghitung tiap `if`, loop, case, dan catch; untuk Go `select`, jumlah cabangnya disimpan pada baris `select` karena kepala komunikasi case bukan baris statement terpisah.

## Konfigurasi

Path input/output, batas baris, dan logging dapat diatur di [global.yaml](global.yaml). Jika file tersebut tidak ada, nilai bawaan tersedia di [src/config.py](src/config.py).

## Menjalankan test

```bash
python -m pytest -q
```

Test juga mencakup modul pipeline internal lain yang tidak diekspos sebagai mode aplikasi.
