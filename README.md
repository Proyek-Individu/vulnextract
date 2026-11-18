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
```

Opsi yang tersedia:

| Opsi | Deskripsi | Default |
|---|---|---|
| `-i`, `--input` | Path atau URL file input | `input_file` di `global.yaml` |
| `-m`, `--mode` | Mode ekstraksi (satu-satunya nilai: `features`) | `features` |
| `--max-rows` | Batas baris input (`0` = tanpa batas) | `max_rows` di `global.yaml` |
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

| `origin` | Sumber | Label |
|---|---|---|
| `vulnerable` | `vulnerable_code` | Hasil diff/aturan labeling |
| `fixed` | `fixed_code` | `0` |
| `unchanged` | Kode vulnerable dan fixed yang sama | `0` |

Rincian skema fitur tersedia di [context.md](context.md).

## Konfigurasi

Path input/output, batas baris, dan logging dapat diatur di [global.yaml](global.yaml). Jika file tersebut tidak ada, nilai bawaan tersedia di [src/config.py](src/config.py).

## Menjalankan test

```bash
python -m pytest -q
```

Test juga mencakup modul pipeline internal lain yang tidak diekspos sebagai mode aplikasi.
