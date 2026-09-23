# Panduan Kolom Fitur — Ekstraksi Statement-Level untuk Vulnerability Detection

**Bahasa target:** Go, Python, JavaScript/TypeScript, PHP
**Unit ekstraksi:** satu statement (hierarchical — compound statement dan child-nya masing-masing jadi baris terpisah, dihubungkan lewat `parent_statement_id`)

## Catatan sebelum menggunakan panduan ini

- Beberapa flag di bawah (kategori D) hanya bisa dideteksi akurat lewat **kamus signature per bahasa** (daftar nama fungsi berbahaya seperti `os.system`, `exec.Command`, `eval`, `unserialize`, dll). Kamus ini harus disusun dan divalidasi manual per bahasa — tidak ada cara generik untuk mendeteksinya tanpa daftar referensi.
- `statement_type` dan `parent_block_type` butuh **tabel mapping manual** dari node AST tiap parser (Go `go/ast`, Python `ast`, TypeScript Compiler API atau Babel/acorn untuk JS/TS, `nikic/php-parser` untuk PHP) ke satu taksonomi umum. Nama node di keempat parser ini tidak seragam, jadi pemetaan ini adalah pekerjaan tersendiri sebelum ekstraksi jalan.
- Untuk kolom flag biner (`is_x`) yang konsepnya tidak ada di suatu bahasa (mis. `is_deserialization` untuk statement Go yang tidak memakai serialisasi), isi dengan `false`/`0`, bukan `null`. `null` sebaiknya direservasi untuk "gagal diekstrak", bukan "tidak relevan".
- Panduan ini adalah draft awal untuk memandu ekstraksi — jumlah kolom akhir yang benar-benar dipakai akan ditentukan lewat feature selection, bukan semua kolom di sini otomatis berguna.
- **Setiap kolom di tabel akhir wajib bernilai skalar tunggal per baris (flat) — tidak ada kolom bertipe list/array.** Kalau suatu fitur secara alami berupa kumpulan (mis. daftar nama fungsi yang dipanggil, daftar variabel yang dipakai), kolom yang disimpan adalah turunan skalarnya (count, boolean, atau satu nilai representatif), bukan array mentahnya. Data mentah berupa list boleh dipakai sebagai artefak antara saat proses ekstraksi, tapi tidak masuk ke baris tabel final.

---

## A. Identitas & Relasi Struktural

### `statement_id`
**Definisi:** ID unik per baris/statement.
**Cara ekstraksi:** Gabungkan `repo:file_path:function_name:line_start-line_end` atau gunakan counter increment per file. Harus deterministik supaya bisa ditelusuri balik ke source.
**Kenapa penting:** Tanpa ini, hasil feature selection atau anomaly detection tidak bisa ditelusuri balik ke lokasi kode aslinya — krusial untuk validasi manual temuan.

### `parent_statement_id`
**Definisi:** ID statement induk langsung (null kalau top-level dalam fungsi).
**Cara ekstraksi:** Saat traversal AST, teruskan ID node induk ke setiap child saat rekursi (context passing, bukan visitor independen).
**Kenapa penting:** Merekonstruksi struktur nesting dan memungkinkan agregasi balik ke level blok/fungsi kapan pun dibutuhkan. Juga basis untuk menghitung `guard_count` (kategori E).

### `nesting_depth`
**Definisi:** Kedalaman statement dari body fungsi (0 = top-level dalam fungsi).
**Cara ekstraksi:** Increment counter setiap turun satu level blok (body if/for/while/try/function).
**Kenapa penting:** Statement yang sangat dalam nesting-nya sering berkorelasi dengan kompleksitas kontrol alur — salah satu proxy kompleksitas yang dipakai di literatur vulnerability prediction (kompleksitas tinggi → lebih sulit diaudit manual → riskan menyembunyikan bug).

### `statement_type`
**Definisi:** Kategori umum lintas bahasa: `assign`, `call_expr`, `if`, `for`, `while`, `try_catch`, `return`, `import`, `function_def`, `throw_raise`, `switch_case`, dst.
**Cara ekstraksi:** Petakan node type dari parser masing-masing bahasa ke taksonomi umum ini (tabel mapping manual — lihat catatan di atas).
**Kenapa penting:** Ini kolom pengelompokan paling dasar. Tanpa ini, tidak mungkin membandingkan pola antar bahasa atau memfilter statement per kategori sebelum analisis lanjutan.

### `parent_block_type`
**Definisi:** Tipe blok tempat statement ini berada: loop body, exception/catch handler, if-branch (true/false), function body, switch case, dst.
**Cara ekstraksi:** Diturunkan dari tipe node parent saat traversal.
**Kenapa penting:** Statement yang berada di dalam exception handler atau di dalam error-suppression block punya profil risiko berbeda (misalnya kesalahan yang di-swallow diam-diam adalah pola umum di banyak CWE terkait error handling).

---

## B. Lokasi & Metadata

### `repo_name`, `file_path`, `function_name`
**Definisi:** Identitas lokasi kode.
**Cara ekstraksi:** Langsung dari path file dan nama fungsi/method pembungkus saat traversal AST.
**Kenapa penting:** Diperlukan untuk grouping (mis. analisis per fungsi, per file) dan untuk validasi manual — bukan fitur prediktif langsung, tapi wajib ada untuk traceability.

### `language`
**Definisi:** Bahasa sumber statement (`go`, `python`, `javascript`, `typescript`, `php`).
**Cara ekstraksi:** Dari ekstensi file / parser yang dipakai.
**Kenapa penting:** Base rate pola berbahaya berbeda signifikan antar bahasa (mis. `unserialize` relevan di PHP, tidak ada padanan langsung di Go). Tanpa kolom ini, model/analisis bisa keliru menyamakan pola lintas bahasa yang sebenarnya tidak sebanding.

### `line_start`, `line_end`, `num_source_lines`
**Definisi:** Rentang baris asli sebelum digabung.
**Cara ekstraksi:** Posisi token awal/akhir dari AST node (bukan regex, supaya akurat untuk statement yang membentang banyak baris).
**Kenapa penting:** Untuk validasi manual dan audit balik ke source. `num_source_lines` juga proxy kompleksitas statement itu sendiri.

---

## C. Teks & Lexical

### `raw_text`
**Definisi:** Teks asli statement (hasil rekonstruksi dari posisi token AST, bukan concat manual).
**Cara ekstraksi:** Slice source code asli menggunakan posisi start/end dari AST node.
**Kenapa penting:** Basis untuk semua fitur turunan lain di bawah, dan berguna untuk inspeksi manual saat memvalidasi hasil analisis.

### `token_count`, `char_length`
**Definisi:** Jumlah token dan jumlah karakter statement.
**Cara ekstraksi:** Tokenizer dari parser masing-masing bahasa (atau tokenizer generik seperti `tree-sitter` kalau ingin konsisten lintas bahasa).
**Kenapa penting:** Proxy kompleksitas kasar. Perlu diwaspadai: fitur ini gampang mendominasi distance-based method (clustering) kalau tidak dinormalisasi — bukan indikator vulnerability langsung, lebih ke pelengkap.

---

## D. Sink & Perilaku Berbahaya

Kategori ini yang paling langsung berkaitan dengan vulnerability class tertentu — masing-masing flag butuh kamus signature fungsi berbahaya per bahasa.

### `num_calls`
**Definisi:** Jumlah pemanggilan fungsi/method langsung di statement ini (bukan di child-nya).
**Cara ekstraksi:** Hitung semua node `CallExpression`/`Call`/`FunctionCall` yang menjadi anak langsung dari statement.
**Kenapa penting:** Proxy kompleksitas statement; statement dengan banyak call bertumpuk (chained call) lebih sulit diaudit manual dan lebih mungkin menyembunyikan sink berbahaya di tengah rangkaian.

### `top_level_call_name`
**Definisi:** Nama fungsi/method dari pemanggilan **paling luar** (outermost) di statement ini — satu nilai string, bukan list (kalau statement tidak mengandung call sama sekali, isi string kosong/`none`).
**Cara ekstraksi:** Ambil node `CallExpression` paling luar dalam pohon ekspresi statement (bukan argumen di dalamnya), ambil qualified name-nya (mis. `os.path.exists`, `exec.Command`).
**Kenapa penting:** Ini representasi flat dari "apa yang dilakukan statement ini secara utama" — jadi basis pencocokan terhadap kamus signature untuk flag `is_x` di bawah, tanpa perlu menyimpan seluruh daftar call sebagai array. Kalau statement punya beberapa call (mis. argumen ke call lain), call internal itu tetap bisa memicu flag lewat pencocokan substring/parsing terpisah saat proses ekstraksi — tapi yang disimpan di kolom akhir cukup satu nilai representatif.

### `call_target_kind`
**Definisi:** Kategori asal `top_level_call_name` — salah satu dari: `stdlib`, `third_party`, `user_defined`, `none`.
**Cara ekstraksi:** Cocokkan nama fungsi terhadap daftar modul standar bahasa (mis. `os`, `net/http` untuk Go; builtin dan modul standar Python) vs import third-party vs fungsi yang didefinisikan sendiri di repo (bisa dicek dari daftar `function_def` yang sudah diekstrak sebelumnya dari repo yang sama).
**Kenapa penting:** Panggilan ke fungsi standar library punya profil risiko yang lebih dikenal/terdokumentasi dibanding panggilan ke fungsi custom internal repo (yang perilakunya tidak diketahui tanpa menelusuri definisinya) — kategori ini membantu memisahkan dua populasi risiko yang berbeda tanpa perlu deep-tracing setiap kali.

### `is_process_exec`
**Definisi:** Statement memanggil eksekusi proses/perintah OS.
**Cara ekstraksi:** Cocokkan `calls_made` terhadap kamus per bahasa — Go: `exec.Command`, `exec.CommandContext`; Python: `os.system`, `subprocess.run/Popen/call`; JS/Node: `child_process.exec/execSync/spawn`; PHP: `exec`, `shell_exec`, `system`, `passthru`, backtick operator.
**Kenapa penting:** Sink langsung untuk **command injection (CWE-78)** — salah satu kelas vulnerability paling umum kalau argumennya berasal dari input tidak tervalidasi.

### `is_db_query`
**Definisi:** Statement menjalankan query database.
**Cara ekstraksi:** Cocokkan terhadap kamus per bahasa — Go: method `Query`/`Exec`/`QueryRow` dari `database/sql`, `gorm.Raw`; Python: `cursor.execute`, `.raw()` di Django ORM; JS: `.query()` dari `mysql`/`pg`, Sequelize `.query()`; PHP: `mysqli_query`, PDO `->query()`/`->exec()`.
**Kenapa penting:** Sink untuk **SQL injection (CWE-89)**, terutama kalau dikombinasikan dengan `uses_string_concat_or_format = true`.

### `is_dynamic_eval`
**Definisi:** Statement mengeksekusi kode secara dinamis dari string.
**Cara ekstraksi:** Kamus per bahasa — JS: `eval()`, `new Function()`; Python: `eval()`, `exec()`; PHP: `eval()`, `create_function`; Go: relatif jarang ada padanan langsung (plugin loading kadang mendekati, tapi biasanya `false`).
**Kenapa penting:** Sink untuk **code injection (CWE-94)** — salah satu kelas paling berbahaya karena bisa mengeksekusi kode arbitrer.

### `is_deserialization`
**Definisi:** Statement melakukan deserialisasi data dari input eksternal.
**Cara ekstraksi:** Kamus per bahasa — PHP: `unserialize()`; Python: `pickle.loads`, `yaml.load` (tanpa `SafeLoader`); JS: `JSON.parse` (risiko rendah kecuali dikombinasi prototype pollution pattern tertentu); Go: `encoding/gob`, `json.Unmarshal` ke struct dengan reflection tidak lazim jadi sink utama.
**Kenapa penting:** Sink untuk **insecure deserialization (CWE-502)** — bisa berujung remote code execution tergantung bahasa dan library.

### `is_file_io`
**Definisi:** Statement melakukan operasi baca/tulis/hapus file.
**Cara ekstraksi:** Kamus per bahasa — Go: `os.Open`, `os.Remove`, `ioutil`/`os.ReadFile`; Python: `open()`, `os.remove`, `shutil`; JS/Node: `fs.readFile`, `fs.unlink`; PHP: `fopen`, `file_get_contents`, `unlink`, `include`/`require` (perlu flag terpisah karena include/require juga sink code execution).
**Kenapa penting:** Sink untuk **path traversal (CWE-22)** kalau path-nya berasal dari input yang tidak divalidasi (mis. `os.remove(userInput)` pada contoh yang Anda beri sebelumnya adalah kandidat relevan di sini).

### `is_network_call`
**Definisi:** Statement melakukan request jaringan keluar (outbound).
**Cara ekstraksi:** Kamus per bahasa — Go: `net/http` client calls; Python: `requests.get/post`, `urllib`; JS: `fetch`, `axios`, `http.request`; PHP: `curl_exec`, `file_get_contents` dengan URL.
**Kenapa penting:** Sink untuk **SSRF (CWE-918)** kalau URL/host tujuan berasal dari input pengguna.

### `is_output_render`
**Definisi:** Statement mengeluarkan output ke response/HTML/template tanpa encoding.
**Cara ekstraksi:** Kamus per bahasa — PHP: `echo`/`print` langsung ke output HTML, template tanpa `htmlspecialchars`; JS: `innerHTML =`, template literal langsung ke DOM; Python: `render_template_string`, response tanpa auto-escape; Go: `template.HTML()` (bypass auto-escaping `html/template`).
**Kenapa penting:** Sink untuk **XSS (CWE-79)** — relevan terutama untuk PHP dan JS karena konteks web rendering lebih umum di sana.

### `uses_string_concat_or_format`
**Definisi:** Statement membangun string lewat concatenation atau formatting (bukan parameter binding).
**Cara ekstraksi:** Deteksi operator `+` pada string, `fmt.Sprintf`, f-string/`.format()`/`%` (Python), template literal `${}` (JS), string interpolation PHP (`"$var"` atau `.`).
**Kenapa penting:** Fitur pembeda paling penting antara query/command yang **parameterized (aman)** vs **dibangun manual (rawan injection)**. Kombinasi `is_db_query=true` + `uses_string_concat_or_format=true` adalah salah satu sinyal terkuat untuk SQL injection.

### `num_variables_defined`, `num_variables_used`
**Definisi:** Jumlah variabel yang di-assign (LHS) dan jumlah variabel yang dibaca (RHS/argumen) di statement ini — dua kolom count terpisah, bukan list nama variabel.
**Cara ekstraksi:** Traversal identifier node dalam statement, pisahkan berdasarkan posisi (LHS assignment vs referensi dalam ekspresi/argumen call), lalu hitung jumlahnya masing-masing.
**Kenapa penting:** Proxy kasar untuk data-flow tanpa menyimpan nama variabel mentah (nama variabel tidak portable untuk analisis lintas file/repo karena penamaannya arbitrer). `num_variables_used` tinggi pada statement sink (mis. `is_db_query=true`) bisa mengindikasikan query yang dibangun dari banyak sumber input sekaligus — pola yang lebih rawan salah validasi dibanding satu sumber tunggal.

### `uses_only_literals`
**Definisi:** Apakah argumen ke call/ekspresi di statement ini seluruhnya berupa literal konstan (string/angka tetap), tanpa variabel sama sekali.
**Cara ekstraksi:** `true` kalau `num_variables_used == 0` untuk statement yang mengandung call/ekspresi (bukan statement kosong seperti `pass`).
**Kenapa penting:** Sink dengan `uses_only_literals=true` praktis tidak mungkin rawan injection karena tidak ada input eksternal yang masuk ke sana — kolom ini berguna sebagai filter cepat untuk **mengecualikan** kandidat vulnerable, mengurangi ruang pencarian sebelum analisis lebih lanjut.

---

## E. Guard / Validasi Konteks

Kategori ini butuh informasi dari rantai `parent_statement_id`, bukan hanya statement itu sendiri.

### `guard_count`
**Definisi:** Jumlah node `if`/kondisi validasi di rantai leluhur (ancestor chain) sebelum mencapai statement ini.
**Cara ekstraksi:** Saat traversal, akumulasikan counter setiap melewati node `if` yang polanya menyerupai validasi (heuristik awal: setiap `if` dihitung, penyempurnaan lanjut bisa membedakan validasi vs kondisi bisnis biasa — ini area yang perlu iterasi).
**Kenapa penting:** Sink yang tidak punya guard sama sekali (`guard_count = 0`) secara intuitif lebih riskan dibanding sink yang sudah melewati beberapa lapis pengecekan — meskipun ini heuristik kasar, bukan bukti definitif validasi benar-benar terjadi.

### `inside_error_handler`
**Definisi:** Apakah statement berada di dalam blok exception/error handler (try/catch, PHP catch, Go pola `if err != nil`).
**Cara ekstraksi:** Cek `parent_block_type` di rantai ancestor.
**Kenapa penting:** Statement di dalam error handler (seperti contoh `except` Anda sebelumnya) sering berkaitan dengan pola **error handling yang tidak aman** (CWE-755 improper handling) — misalnya cleanup yang menghapus file tanpa validasi ulang, atau informasi error yang di-expose ke output (`is_output_render` di dalam error handler adalah kombinasi mencurigakan).

### `is_error_handling_statement`
**Definisi:** Statement ini sendiri adalah bagian dari body except/catch (bukan sekadar berada di dalamnya secara nested lebih dalam).
**Cara ekstraksi:** Cek apakah `parent_statement_id` langsung bertipe `try_catch`/exception handler.
**Kenapa penting:** Membedakan statement langsung di body catch vs statement yang nested lebih dalam lagi di dalamnya — granularitas tambahan untuk analisis pola error handling.

### `sanitization_call_detected`
**Definisi:** Apakah ada pemanggilan fungsi sanitasi/escaping yang dikenal di rantai sebelum sink.
**Cara ekstraksi:** Kamus fungsi sanitasi per bahasa — PHP: `htmlspecialchars`, `filter_var`, `mysqli_real_escape_string`; JS: `DOMPurify.sanitize`, `encodeURIComponent`; Python: `shlex.quote`, `bleach.clean`; Go: `html/template` auto-escape (implisit, sulit dideteksi eksplisit — catat sebagai limitasi).
**Kenapa penting:** Ini upaya awal mendekati taint tracking tanpa membangun full data-flow graph. **Perlu diwaspadai:** ini heuristik lemah — keberadaan pemanggilan fungsi sanitasi di rantai ancestor tidak menjamin fungsi itu benar-benar diterapkan ke variabel yang relevan. Anggap ini sinyal kasar, bukan bukti valid.

---

## F. Struktural Tambahan

### `is_compound`
**Definisi:** Apakah statement ini punya child statement (if/for/while/try/function def) vs statement sederhana (assign/call/return).
**Cara ekstraksi:** Cek tipe node — compound statement types vs simple statement types sesuai `statement_type`.
**Kenapa penting:** Filter dasar untuk memisahkan analisis "container" (compound) dari "leaf" (simple) — beberapa fitur di atas hanya relevan untuk salah satu jenis.

### `num_direct_children`
**Definisi:** Jumlah statement anak langsung (bukan cucu) di dalam blok ini.
**Cara ekstraksi:** Hitung langsung dari body block AST.
**Kenapa penting:** Proxy ukuran blok — blok yang sangat besar (banyak statement digabung dalam satu try/except misalnya) berkorelasi dengan kompleksitas yang sulit diaudit.

### `cyclomatic_contribution`
**Definisi:** Kontribusi statement ini terhadap cyclomatic complexity fungsi (if/for/while/case/catch masing-masing +1).
**Cara ekstraksi:** 1 kalau `statement_type` termasuk kategori percabangan, 0 kalau tidak.
**Kenapa penting:** Fitur klasik di literatur vulnerability prediction (kompleksitas siklomatik function-level sering dipakai sebagai baseline feature) — di sini didekomposisi ke level statement supaya bisa diagregasi ulang ke berbagai granularitas (function, file, dst) sesuai kebutuhan analisis nanti.

---

## Ringkasan keterbatasan yang perlu diingat

1. Kolom kategori D dan E bergantung penuh pada kamus signature fungsi per bahasa yang harus disusun manual dan akan selalu tidak lengkap — perlu proses iteratif menambah signature baru begitu ditemukan pola yang terlewat.
2. `guard_count` dan `sanitization_call_detected` adalah heuristik kasar untuk mendekati taint tracking, bukan taint tracking sesungguhnya. Kalau nanti akurasi ini jadi masalah, langkah lanjutannya adalah membangun data-flow graph eksplisit (lebih mahal secara implementasi, tapi jauh lebih akurat).
3. Distribusi nilai kolom-kolom ini akan sangat tidak seimbang antar bahasa (mis. `is_deserialization` jarang true di Go, sering di PHP) — kalau nanti dipakai lintas bahasa dalam satu model/analisis yang sama, base rate ini perlu diperhitungkan, bukan diasumsikan seragam.