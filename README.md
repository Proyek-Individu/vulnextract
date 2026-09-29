# vulnextract

Pipeline untuk mengubah dataset pasangan kode CVE (vulnerable vs fixed) menjadi dataset tabular (CSV) pada granularitas **method** atau **statement**, sebagai bahan riset deteksi kerentanan perangkat lunak. Mendukung Go, Python, JavaScript, TypeScript, PHP, Java, Rust, dan C — parsing per bahasa menggunakan [tree-sitter](https://tree-sitter.github.io/tree-sitter/).

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

## Menjalankan pipeline

Entry point ada di [src/main.py](src/main.py). Ada dua mode:

```bash
python src/main.py                    # mode "pairs" (default)
python src/main.py -m features        # mode "features"
```

### Mode `pairs` (default)

Membaca `data/input/cve_fix_pairs.csv`, menulis ke `data/output/output_csv_fix_pairs.csv`. Satu baris output = satu pasangan teks `(vulnerable_code, fixed_code)` pada granularitas `statement` atau `method` — cocok untuk pendekatan diff/contrastive (mis. fine-tune model code-repair).

| Opsi | Deskripsi | Default |
|---|---|---|
| `-i`, `--input` | Path file CSV input | `data/input/cve_fix_pairs.csv` |
| `-o`, `--output` | Path file CSV output | `data/output/output_csv_fix_pairs.csv` (mode `pairs`) / `data/output/output_statement_features.csv` (mode `features`) |
| `-m`, `--mode` | `pairs` atau `features` | `pairs` |
| `-g`, `--granularity` | `statement` atau `method` (hanya mode `pairs`) | `statement` |
| `-s`, `--strategy` | Strategi pairing: `aligned` atau `strict` (hanya mode `pairs`) | `aligned` |
| `-v`, `--verbose` | Aktifkan log debug | nonaktif |

Contoh — ekstraksi per method dengan pairing ketat:

```bash
python src/main.py -g method -s strict
```

### Mode `features`

Membaca CSV input yang sama, tapi menghasilkan **tabel fitur berlabel per statement** sesuai skema di [context.md](context.md) (kategori A–F: identitas/struktur, lokasi, teks, sink berbahaya, guard/validasi, struktural). Satu baris output = satu statement nyata (hierarkis — statement di dalam `if`/`for`/`try` dst dapat baris sendiri, terhubung lewat `parent_statement_id`), diberi `label` 1 kalau statement itu memang berubah antara versi vulnerable dan fixed (bukan sekadar "berada di method yang sama"), 0 kalau tidak.

Dibatasi ke bahasa target [context.md](context.md): **Go, Python, JavaScript, TypeScript, PHP** — baris berbahasa Java/Rust/C otomatis dilewati (dihitung di `skipped_unsupported_language`).

```bash
python src/main.py -m features -i data/input/cve_fix_pairs.csv -o data/output/output_statement_features.csv
```

## Format data

### Input

CSV dengan kolom minimal berikut (lihat [data/input/cve_fix_pairs.csv](data/input/cve_fix_pairs.csv)):

`cve_id, vulnerability_type, language, file, method, vulnerable_code, fixed_code, commit_hash, repo, commit_msg`

Satu baris merepresentasikan satu method/fungsi (vulnerable dan fixed) dari satu commit perbaikan CVE. Nilai `language` harus salah satu dari: `go`, `python`, `javascript`, `typescript`, `php`, `java`, `rust`, `c` (case-insensitive; beberapa alias seperti `py`, `js`, `ts`, `golang`, `rs`, `cpp` juga didukung — lihat [src/extractors/__init__.py](src/extractors/__init__.py)). Mode `features` hanya memproses 5 bahasa pertama.

### Output

**Mode `pairs`**: kolom sama seperti input, ditambah `granularity` (`method`/`statement`). Satu baris input method bisa menghasilkan banyak baris output.

**Mode `features`**: kolom traceability (`cve_id`, `vulnerability_type`, `commit_hash`, `repo`) + seluruh kolom kategori A–F dari context.md (`statement_id`, `parent_statement_id`, `nesting_depth`, `statement_type`, `parent_block_type`, `line_start`, `line_end`, `raw_text`, `token_count`, `is_db_query`, `guard_count`, `is_compound`, dst.) + `label`.

## Menjalankan test

```bash
python -m unittest tests.test_pipeline tests.test_features -v
```

## Struktur proyek

```
src/
  main.py                # CLI entry point (mode "pairs" / "features")
  config.py               # path default input/output
  pipeline.py              # mode "pairs": baca CSV -> extract -> pairing -> tulis CSV
  feature_pipeline.py      # mode "features": baca CSV -> tree -> label -> extract fitur -> tulis CSV
  models.py                # dataclass/enum (CodePair, PairingResult, PipelineStats)
  extractors/               # satu extractor tree-sitter per bahasa (dipakai kedua mode)
  strategies/pairing.py      # strategi pairing vulnerable<->fixed (aligned/strict), mode "pairs"
  features/
    models.py                 # StatementRecord (baris output mode "features"), FeaturePipelineStats
    tree_builder.py            # ekstraksi hierarkis (StatementNode) via AST
    labeler.py                 # tree-diff rekursif utk label 0/1 per statement
    feature_extractor.py        # StatementNode -> StatementRecord (kategori A-F)
    langs/                       # skema per bahasa: taksonomi node, kamus sink (D) & sanitizer (E)
tests/
  test_pipeline.py         # unit test mode "pairs"
  test_features.py         # unit test mode "features"
data/
  input/                  # dataset CVE mentah
  output/                 # hasil ekstraksi (kedua mode)
context.md                # panduan skema kolom fitur mode "features"
```

## Catatan & keterbatasan yang diketahui

- `extract_statements`/`tree_builder` mengambil statement dari body function/method via AST (bukan split baris kosong), sehingga hasilnya stabil walau gaya format (jumlah baris kosong) berbeda antara versi vulnerable dan fixed.
- **Skema labeling mode `features`** hanya menandai statement yang benar-benar berubah di diff (bukan seluruh statement di method vulnerable). Konsekuensinya: CVE bertipe "missing validation" (fix-nya murni menambah statement baru, tidak mengubah statement yang sudah ada) akan menghasilkan **nol** baris berlabel 1 untuk method tersebut — karakteristik dari skema, bukan bug.
- Kamus signature kategori D (sink berbahaya) dan E (sanitizer) di `features/langs/*.py` ditranskripsi langsung dari nama fungsi yang disebut di context.md — per catatan context.md sendiri, kamus ini akan selalu tidak lengkap (mis. verb query-builder ORM lain di luar `.Query`/`.Exec`/`.QueryRow` belum tercakup untuk Go).
- `call_target_kind` (stdlib/third_party/user_defined) memakai daftar prefix kecil per bahasa sebagai pendekatan kasar — bukan resolusi import sungguhan.
- `guard_count`/`sanitization_call_detected` adalah heuristik pendekatan taint tracking, bukan taint tracking sesungguhnya (lihat context.md).
