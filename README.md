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
  3. Klasifikasi vulnerability (ML + XAI, mentah vs split)
  0. Keluar
Pilih menu [1]:
```

Pilih mode, lalu untuk tiap pertanyaan berikutnya (input file, output file, dst.) tinggal tekan **Enter** untuk pakai nilai default dari `global.yaml`, atau ketik nilai lain kalau mau override khusus untuk sekali jalan itu saja. Setelah proses selesai, ditanya mau kembali ke menu atau keluar.

Menu **"3. Klasifikasi vulnerability"** melatih model ML yang diatur di `global.yaml` (default: Random Forest) dan membandingkan performa klasifikasi dari **data mentah** vs **data hasil split** mode `features`, lengkap dengan XAI — lihat [Klasifikasi & XAI](#klasifikasi--xai-menu-3).

### Kalau butuh dijalankan tanpa menu (scripting/CI)

Beri argumen CLI apa saja dan menu interaktif otomatis dilewati:

```bash
python src/main.py -m features
python src/main.py -m pairs -g method -s strict
python src/main.py -m features -i data/input/my_dataset.csv -o data/output/my_result.csv -v
python src/main.py -m classify
python src/main.py -m classify --models random_forest,logistic_regression --cv-folds 5 --formats xlsx
```

| Opsi | Deskripsi | Default (dari global.yaml) |
|---|---|---|
| `-i`, `--input` | Path atau URL file CSV input (mode `classify`: data mentah) | `input_file` / `classification.raw_input` |
| `-o`, `--output` | Path file CSV output (mode `classify`: **folder** output) | `output.pairs` / `output.features` / `classification.output_dir` sesuai `--mode` |
| `-m`, `--mode` | `pairs`, `features`, atau `classify` | `pairs` |
| `-g`, `--granularity` | `statement` atau `method` (hanya mode `pairs`) | `pairs.granularity` |
| `-s`, `--strategy` | Strategi pairing: `aligned` atau `strict` (hanya mode `pairs`) | `pairs.strategy` |
| `-v`, `--verbose` | Aktifkan log debug | `verbose` |
| `--split-input` | Data split / hasil mode `features` (hanya `classify`) | `classification.split_input` |
| `--models` | Daftar model dipisah koma (hanya `classify`) | `classification.models` |
| `--test-size` | Porsi data test, `0.2` atau `20%` (hanya `classify`) | `classification.split.test_size` |
| `--cv-folds` | Jumlah fold k-fold, `0` = holdout sekali (hanya `classify`) | `classification.split.cv_folds` |
| `--formats` | `xlsx`, `csv`, atau `xlsx,csv` (hanya `classify`) | `classification.output_formats` |
| `--no-xai` | Lewati XAI (hanya `classify`) | `classification.xai.enabled` |

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

classification:           # mode "classify" (menu 3) — lihat bagian Klasifikasi & XAI
  models:
    - name: random_forest
  split:
    test_size: 0.2
    cv_folds: 0
  # ... (lengkapnya di global.yaml, tiap kunci ada komentarnya)
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

## Klasifikasi & XAI (menu 3)

Tujuannya menjawab: *apakah aturan split statement-level (mode `features`) memang membantu klasifikasi dibanding langsung memakai data mentah?* Kedua pendekatan dilatih dengan model, konfigurasi, dan **pembagian train/test yang sama**:

| `approach` | Unit sampel | Label | Fitur |
|---|---|---|---|
| `raw` | 1 method dari CSV mentah | `vulnerable_code` = 1, `fixed_code` = 0 | TF-IDF token kode method utuh (tanpa AST / aturan split) |
| `split` | 1 statement dari hasil mode `features` | kolom `label` (1 = statement yang berubah di fix) | kolom terstruktur kategori A–F ([context.md](context.md)) |

Hasil dievaluasi di tiga `eval_level`:

- `raw | method` — skor per method dari model raw.
- `split | statement` — skor per statement dari model split.
- `split | method` — skor statement **diagregasi** per method (`method_aggregation: max` → method dianggap serawan statement paling rawannya). Sampel test-nya **identik** dengan `raw | method`, jadi dua kolom inilah yang dibandingkan apple-to-apple (kolom `selisih (split - raw) @method` di sheet `comparison`).

Hal penting soal pembagian data:

- Train/test dibagi **per grup** (default `group_by: method` = repo+file+method), bukan per baris. Versi vulnerable dan fixed dari method yang sama (teksnya hampir identik) tidak boleh terpisah ke train dan test, karena itu kebocoran data. `test_size` dihitung atas jumlah grup, jadi porsi *statement* di test bisa berbeda dari 20%.
- `align_samples: true` mempersempit data mentah ke method yang juga ada di data split (mode `features` hanya mendukung Go/Python/JS/TS/PHP), supaya perbandingannya adil.
- Kolom ID/lokasi dan proxy label (`origin`, `vulnerability_type`, `cve_id`, `line_start`, …) otomatis dibuang dari fitur split.
- Data split ditautkan ke baris CSV mentah lewat index baris di dalam `statement_id`, jadi data split harus dibuat (menu 2) dari CSV mentah yang sama. Kalau file `split_input` belum ada, menu 3 menjalankan ekstraksi features dulu secara otomatis.
- Untuk dataset kecil seperti sekarang disarankan `cv_folds: 5`. Holdout sekali dengan ~16 grup test sangat dipengaruhi keberuntungan split; dengan k-fold, laporan berisi rata-rata dan std.

### Memilih model

Atur di `classification.models` pada [global.yaml](global.yaml) — semua model di daftar dijalankan dan dibandingkan:

```yaml
models:
  - name: random_forest            # alias bawaan
    params: {n_estimators: 300, class_weight: balanced}
  - name: logistic_regression
  - name: xgboost                  # butuh: pip install xgboost
    params: {scale_pos_weight: 10}
  - label: bagging                 # kelas sklearn-compatible apa pun
    class: sklearn.ensemble.BaggingClassifier
    params: {n_estimators: 50}
```

Alias bawaan: `random_forest`, `extra_trees`, `decision_tree`, `gradient_boosting`, `hist_gradient_boosting`, `adaboost`, `logistic_regression`, `svm`, `linear_svm`, `knn`, `naive_bayes`, `mlp`, `xgboost`, `lightgbm`. Default hyperparameter-nya ada di [src/classification/model_registry.py](src/classification/model_registry.py), dan `params` di yaml menimpanya. Model berbasis jarak/linear (`logistic_regression`, `svm`, `linear_svm`, `knn`, `mlp`) otomatis di-standardisasi (`scale: true`). Dari menu cukup ketik nama dipisah koma; nama yang cocok dengan entri di yaml memakai `params` entri tersebut.

### XAI

Untuk setiap model × approach × fold:

- **native importance**: `feature_importances_` (tree) atau `|coef_|` (linear).
- **permutation importance**: penurunan skor test (`permutation_scoring`, default PR-AUC) saat satu kolom fitur diacak. Model-agnostik.
- **SHAP** (`pip install shap`): TreeExplainer untuk model tree, LinearExplainer untuk model linear (KernelExplainer opsional via `shap_kernel_fallback: true`). Menghasilkan ranking global (`shap_mean_abs`), arah pengaruh (`shap_value_corr` > 0 = nilai fitur makin tinggi → makin vulnerable), dan **penjelasan lokal**: untuk sampel test berskor tertinggi, fitur apa saja yang mendorong prediksinya.

Kalau `shap` tidak terinstall, XAI tetap jalan dengan native + permutation importance.

### Output

Tiap run menulis folder baru `data/output/classification/run_YYYYmmdd_HHMMSS/` berisi `classification_report.xlsx` (satu sheet per tabel) dan/atau CSV per tabel, plus `plots/*.png`:

| Sheet / file | Isi |
|---|---|
| `README` | Penjelasan singkat tiap sheet & approach |
| `comparison` | **Ringkasan utama**: baris = (model, metrik), kolom = raw@method, split@method (agregasi), split@statement, dan selisih split−raw |
| `summary` | Rata-rata (& std bila k-fold) semua metrik per approach/level/model |
| `metrics_per_fold` | Metrik tiap fold: accuracy, balanced_accuracy, precision, recall, f1, mcc, roc_auc, pr_auc, tp/fp/tn/fn |
| `feature_importance` | XAI global per approach/model (rata-rata antar fold) |
| `local_explanations` | XAI lokal (SHAP) per sampel test berskor tertinggi, dengan cuplikan kodenya |
| `predictions` | Prediksi tiap sampel test (`y_true`, `y_score`, `y_pred`) + metadata untuk ditelusuri balik |
| `dataset_info` | Jumlah sampel, positif, fitur, dan grup per fold/approach |
| `xai_notes`, `config` | Metode XAI yang dipakai/dilewati, dan konfigurasi persis yang dipakai run tersebut |

Label 1 di level statement sangat sedikit (~3%), jadi baca **PR-AUC, MCC, dan F1**. Accuracy di level statement hampir selalu tinggi hanya karena mayoritas sampelnya kelas 0.

## Menjalankan test

```bash
python -m unittest tests.test_pipeline tests.test_features tests.test_classification -v
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
  classification/               # mode "classify" (menu 3): ML + XAI, data mentah vs data split
    model_registry.py            # alias model + loader kelas sklearn-compatible dari global.yaml
    datasets.py                  # dataset raw (method) & split (statement), pembagian per grup, matriks fitur
    metrics.py                   # metrik evaluasi + agregasi skor statement -> method
    explain.py                   # XAI: native, permutation, SHAP (global & lokal)
    report.py                    # tabel perbandingan, tulis CSV/XLSX, plot
    pipeline.py                  # orkestrasi per fold x model x approach
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
  test_classification.py       # unit test mode "classify"
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
