# vulnextract

Pipeline untuk mengubah dataset pasangan kode CVE (vulnerable vs fixed) menjadi dataset tabular (CSV), sebagai bahan riset deteksi kerentanan perangkat lunak. Mendukung Go, Python, JavaScript, TypeScript, PHP, Java, Rust, dan C — parsing per bahasa menggunakan [tree-sitter](https://tree-sitter.github.io/tree-sitter/).

## Prasyarat

- Python 3.10+
- pip

## Instalasi

Dari root repo:

```bash
python -m venv .venv
```

Aktifkan virtual environment:

```bash
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Windows (cmd)
.venv\Scripts\activate.bat

# Linux / macOS
source .venv/bin/activate
```

Install dependency:

```bash
pip install -r requirements.txt
```

Siapkan file secret (opsional — belum ada yang benar-benar dipakai kode saat ini, tapi infrastrukturnya sudah disiapkan untuk pengembangan selanjutnya):

```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

Itu saja — **tidak perlu mengedit kode apa pun** untuk mulai pakai. Path input/output dan opsi lain sudah disetel lewat [global.yaml](global.yaml) (lihat bagian [Konfigurasi](#konfigurasi) di bawah).

## Menjalankan

```bash
python src/main.py
```

Akan muncul menu:

```
================================================
 vulnextract - CVE Extraction Pipeline
================================================
  1. Ekstraksi pairs (vulnerable/fixed text pairs)
  2. Ekstraksi features (statement-level, untuk ML)
  3. Deteksi vulnerability (belum tersedia)
  0. Keluar
Pilih menu [1]:
```

Pilih mode, lalu untuk tiap pertanyaan berikutnya (input file, output file, dst.) tinggal tekan **Enter** untuk pakai nilai default dari `global.yaml`, atau ketik nilai lain kalau mau override khusus untuk sekali jalan itu saja. Setelah proses selesai, ditanya mau kembali ke menu atau keluar.

Menu **"3. Deteksi vulnerability"** masih placeholder — akan diisi pada tahap pengembangan berikutnya (model ML/DL di atas dataset hasil mode `features`).

### Kalau butuh dijalankan tanpa menu (scripting/CI)

Beri argumen CLI apa saja dan menu interaktif otomatis dilewati:

```bash
python src/main.py -m features
python src/main.py -m pairs -g method -s strict
python src/main.py -m features -i data/input/my_dataset.csv -o data/output/my_result.csv -v
```

| Opsi | Deskripsi | Default (dari global.yaml) |
|---|---|---|
| `-i`, `--input` | Path atau URL file CSV input | `input_file` |
| `-o`, `--output` | Path file CSV output | `output.pairs` / `output.features` sesuai `--mode` |
| `-m`, `--mode` | `pairs` atau `features` | `pairs` |
| `-g`, `--granularity` | `statement` atau `method` (hanya mode `pairs`) | `pairs.granularity` |
| `-s`, `--strategy` | Strategi pairing: `aligned` atau `strict` (hanya mode `pairs`) | `pairs.strategy` |
| `-v`, `--verbose` | Aktifkan log debug | `verbose` |

## Konfigurasi

### `global.yaml` — pengaturan non-rahasia

File ini di root repo, **aman di-commit**, isinya semua nilai yang biasanya diketik lewat argumen CLI:

```yaml
input_file: data/input/cve_fix_pairs.csv   # path lokal ATAU URL http(s)

output:
  pairs: data/output/output_csv_fix_pairs.csv
  features: data/output/output_statement_features.csv

pairs:
  granularity: statement   # statement | method
  strategy: aligned        # aligned | strict

verbose: false
```

Ubah nilainya kapan pun — menu interaktif dan argumen CLI sama-sama membaca default dari sini ([src/config.py](src/config.py)). Kalau `global.yaml` dihapus/rusak, pipeline tetap jalan dengan default bawaan di `src/config.py`.

### `.env` — pengaturan rahasia

Beda dari `global.yaml`: file `.env` **tidak** di-commit (sudah ada di `.gitignore`). Salin dari [.env.example](.env.example) lalu isi kalau diperlukan. Saat ini belum ada kode yang membaca variabel di sini — disiapkan untuk kebutuhan ke depan (mis. token API kalau tahap deteksi vulnerability nanti memanggil layanan eksternal).

## Format data

### Input

CSV dengan kolom minimal berikut (lihat [data/input/cve_fix_pairs.csv](data/input/cve_fix_pairs.csv)):

`cve_id, vulnerability_type, language, file, method, vulnerable_code, fixed_code, commit_hash, repo, commit_msg`

Satu baris merepresentasikan satu method/fungsi (vulnerable dan fixed) dari satu commit perbaikan CVE. Nilai `language` harus salah satu dari: `go`, `python`, `javascript`, `typescript`, `php`, `java`, `rust`, `c` (case-insensitive; beberapa alias seperti `py`, `js`, `ts`, `golang`, `rs`, `cpp` juga didukung — lihat [src/extractors/__init__.py](src/extractors/__init__.py)). Mode `features` hanya memproses 5 bahasa pertama.

`input_file` boleh juga diarahkan ke URL (http/https) yang menyajikan CSV langsung — pandas akan mengambilnya tanpa perlu diunduh manual dulu.

### Output — mode `pairs`

Satu baris output = satu pasangan teks `(vulnerable_code, fixed_code)` pada granularitas `statement` atau `method` — cocok untuk pendekatan diff/contrastive (mis. fine-tune model code-repair). Kolom sama seperti input, ditambah `granularity`.

### Output — mode `features`

Satu baris output = satu **statement nyata** (hierarkis — statement di dalam `if`/`for`/`try` dst dapat baris sendiri, terhubung lewat `parent_statement_id`), dengan seluruh kolom kategori A–F sesuai skema [context.md](context.md) (`statement_id`, `nesting_depth`, `statement_type`, `parent_block_type`, `line_start`/`line_end`, `raw_text`, `token_count`, `is_db_query`, `guard_count`, `is_compound`, dst.) plus kolom traceability (`cve_id`, `vulnerability_type`, `commit_hash`, `repo`) dan `label`.

Setiap baris input CSV bisa menyumbang statement ke **dua kelas** (kolom `label`: 1 = vulnerable, 0 = aman), dibedakan lewat kolom `origin`:

| `origin` | Sumber | `label` | `vulnerability_type` |
|---|---|---|---|
| `vulnerable` | `vulnerable_code`, di-diff ke `fixed_code` | 1 kalau statement itu memang berubah di fix, 0 kalau tidak | nilai asli dari CSV |
| `fixed` | `fixed_code` dari baris yang memang berubah — ini kode hasil perbaikan | selalu 0 | dipaksa `"none"` (bukan instance vulnerability) |
| `unchanged` | baris di mana `vulnerable_code == fixed_code` sejak awal (aman dari awal) — diekstrak sekali saja, tidak dobel dengan `vulnerable`/`fixed` | selalu 0 | dipaksa `"none"` |

Ini supaya dataset tidak cuma berisi kelas vulnerable — kelas aman/negative diambil dari kode hasil perbaikan itu sendiri (bukan cuma sisa statement yang kebetulan tidak berubah di method vulnerable), ditambah baris yang memang sudah aman sejak awal kalau ada di data mentah.

## Menjalankan test

```bash
python -m unittest tests.test_pipeline tests.test_features -v
```

## Struktur proyek

```
global.yaml                # konfigurasi non-rahasia (path input/output, default opsi)
.env.example                # template variabel rahasia -> salin jadi .env
src/
  main.py                    # entry point: menu interaktif (tanpa argumen) / CLI flags (dengan argumen)
  config.py                   # baca global.yaml + .env, expose DEFAULT_*
  pipeline.py                  # mode "pairs": baca CSV -> extract -> pairing -> tulis CSV
  feature_pipeline.py          # mode "features": baca CSV -> tree -> label -> extract fitur -> tulis CSV
  models.py                    # dataclass/enum (CodePair, PairingResult, PipelineStats)
  extractors/                   # satu extractor tree-sitter per bahasa (dipakai kedua mode)
  strategies/pairing.py          # strategi pairing vulnerable<->fixed (aligned/strict), mode "pairs"
  features/
    models.py                     # StatementRecord (baris output mode "features"), FeaturePipelineStats
    tree_builder.py                # ekstraksi hierarkis (StatementNode) via AST
    labeler.py                     # tree-diff rekursif utk label 0/1 per statement
    feature_extractor.py            # StatementNode -> StatementRecord (kategori A-F)
    langs/                           # skema per bahasa: taksonomi node, kamus sink (D) & sanitizer (E)
tests/
  test_pipeline.py             # unit test mode "pairs"
  test_features.py             # unit test mode "features"
data/
  input/                      # dataset CVE mentah
  output/                     # hasil ekstraksi (kedua mode)
context.md                    # panduan skema kolom fitur mode "features"
```

## Catatan & keterbatasan yang diketahui

- `extract_statements`/`tree_builder` mengambil statement dari body function/method via AST (bukan split baris kosong), sehingga hasilnya stabil walau gaya format (jumlah baris kosong) berbeda antara versi vulnerable dan fixed.
- **Skema labeling mode `features`** hanya menandai statement yang benar-benar berubah di diff (bukan seluruh statement di method vulnerable). Konsekuensinya: CVE bertipe "missing validation" (fix-nya murni menambah statement baru, tidak mengubah statement yang sudah ada) akan menghasilkan **nol** baris `origin=vulnerable` berlabel 1 untuk method tersebut — tapi tetap menyumbang kelas aman lewat `origin=fixed`.
- Kamus signature kategori D (sink berbahaya) dan E (sanitizer) di `features/langs/*.py` ditranskripsi langsung dari nama fungsi yang disebut di context.md — per catatan context.md sendiri, kamus ini akan selalu tidak lengkap (mis. verb query-builder ORM lain di luar `.Query`/`.Exec`/`.QueryRow` belum tercakup untuk Go).
- `call_target_kind` (stdlib/third_party/user_defined) memakai daftar prefix kecil per bahasa sebagai pendekatan kasar — bukan resolusi import sungguhan.
- `guard_count`/`sanitization_call_detected` adalah heuristik pendekatan taint tracking, bukan taint tracking sesungguhnya (lihat context.md).
- `statement_id` menyertakan index baris CSV di dalam prefix-nya — beberapa baris di `data/input/cve_fix_pairs.csv` punya `(repo, file, method, commit_hash)` yang identik (termasuk duplikat literal, mis. `CVE-2026-47144`/`CVE-2026-48089`), jadi index baris dipakai sebagai pembeda supaya `statement_id` tetap unik.
- Dataset saat ini (104 baris) belum punya baris `vulnerable_code == fixed_code` (origin `unchanged`) — penanganannya sudah diimplementasikan dan diuji ([tests/test_features.py](tests/test_features.py)), tapi baru benar-benar terpakai kalau data mentah ke depan menambahkan baris semacam itu.
