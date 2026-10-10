"""
Invariant checker untuk output_statement_features.csv vulnextract.

Beda dari unit test: script ini TIDAK peduli dataset input apa yang dipakai.
Dia cuma ngecek apakah output-nya KONSISTEN SECARA LOGIKA -- aturan yang
harus selalu benar di dataset manapun. Cocok dijalankan tiap kali ganti
sumber dataset, buat mastiin pipeline-nya generalize, bukan cuma cocok
kebetulan di satu dataset doang.

Usage:
    python validate_output_invariants.py data/output/output_statement_features.csv
"""
import sys
import pandas as pd


def check(df):
    errors = []

    # 1. statement_id harus unik -- nggak boleh ada dua baris dengan ID yang sama
    dupes = df["statement_id"][df["statement_id"].duplicated()]
    if len(dupes) > 0:
        errors.append(f"[statement_id] {len(dupes)} ID duplikat, contoh: {dupes.iloc[0]}")

    # 2. parent_statement_id (kalau diisi) harus merujuk ke statement_id yang beneran ada
    known_ids = set(df["statement_id"])
    has_parent = df[df["parent_statement_id"].notna() & (df["parent_statement_id"] != "")]
    orphan = has_parent[~has_parent["parent_statement_id"].isin(known_ids)]
    if len(orphan) > 0:
        errors.append(
            f"[parent_statement_id] {len(orphan)} baris parent-nya tidak ditemukan, "
            f"contoh: {orphan.iloc[0]['statement_id']}"
        )

    # 3. label cuma boleh 0 atau 1
    bad_label = df[~df["label"].isin([0, 1])]
    if len(bad_label) > 0:
        errors.append(f"[label] {len(bad_label)} baris nilainya di luar {{0,1}}")

    # 4. vulnerability_type harus konsisten dengan label statement.
    if "vulnerability_type" not in df.columns:
        errors.append("[vulnerability_type] kolom tidak ditemukan")
    else:
        vulnerability_type = df["vulnerability_type"].astype("string").str.strip()
        vulnerable_with_none = df[
            df["label"].eq(1) & vulnerability_type.str.lower().eq("none").fillna(False)
        ]
        if len(vulnerable_with_none) > 0:
            errors.append(
                f"[vulnerability_type] {len(vulnerable_with_none)} baris label=1 "
                f"bernilai 'none', contoh statement_id: "
                f"{vulnerable_with_none.iloc[0]['statement_id']}"
            )

        unchanged_not_none = df[
            df["label"].eq(0) & ~vulnerability_type.eq("none").fillna(False)
        ]
        if len(unchanged_not_none) > 0:
            errors.append(
                f"[vulnerability_type] {len(unchanged_not_none)} baris label=0 "
                f"tidak bernilai 'none', contoh statement_id: "
                f"{unchanged_not_none.iloc[0]['statement_id']}"
            )

    # 5. line_start harus <= line_end
    bad_lines = df[df["line_start"] > df["line_end"]]
    if len(bad_lines) > 0:
        errors.append(f"[line_start/line_end] {len(bad_lines)} baris line_start > line_end")

    # 6. INTI PALING PENTING: untuk statement leaf (is_compound=False, tanpa anak),
    #    is_same harus PERSIS kebalikan dari label.
    #    Statement leaf yang teksnya identik antara vulnerable/fixed WAJIB label=0,
    #    dan yang teksnya beda WAJIB label=1. Kalau ketemu kontradiksi di sini,
    #    berarti ada bug di cara is_same atau label dihitung.
    if "is_same" in df.columns:
        leaf = df[df["is_compound"] == False]
        mismatch = leaf[
            ((leaf["is_same"] == True) & (leaf["label"] != 0))
            | ((leaf["is_same"] == False) & (leaf["label"] != 1))
        ]
        if len(mismatch) > 0:
            errors.append(
                f"[is_same vs label] {len(mismatch)} dari {len(leaf)} baris leaf "
                f"(is_compound=False) is_same dan label-nya SALING BERTENTANGAN. "
                f"Contoh statement_id: {mismatch.iloc[0]['statement_id']}"
            )

    # 7. num_direct_children harus cocok sama jumlah anak yang beneran ada di data
    actual_children_count = df["parent_statement_id"].value_counts()

    def children_ok(row):
        expected = row["num_direct_children"]
        actual = actual_children_count.get(row["statement_id"], 0)
        return expected == actual

    bad_children = df[~df.apply(children_ok, axis=1)]
    if len(bad_children) > 0:
        errors.append(
            f"[num_direct_children] {len(bad_children)} baris nilainya tidak cocok "
            f"jumlah anak aktual, contoh: {bad_children.iloc[0]['statement_id']}"
        )

    return errors


def main(path):
    df = pd.read_csv(path)
    errors = check(df)

    print(f"Total baris dicek: {len(df)}")
    if not errors:
        print("Semua invariant lolos. Output konsisten secara logika.")
    else:
        print(f"Ditemukan {len(errors)} jenis pelanggaran invariant:\n")
        for e in errors:
            print(f"  - {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python validate_output_invariants.py <path_ke_output_csv>")
        sys.exit(1)
    main(sys.argv[1])