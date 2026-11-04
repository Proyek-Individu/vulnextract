"""
Output-facing data shapes for the statement-level feature pipeline.

StatementRecord mirrors context.md's column schema (categories A-F) plus a
`label` column. Every field is a scalar (str/int/bool) per context.md's own
rule that no column may hold a list/array. Boolean D/E columns default to
False rather than Optional/None: `null` is reserved strictly for genuine
extraction failure (a row that could not be produced at all), never for
"flag not applicable to this language/statement" — see context.md's
"Catatan sebelum menggunakan panduan ini".
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StatementRecord:
    # --- traceability back to the source CVE record (not in context.md's
    # schema itself, but required to trace a row back to its CSV row) ---
    cve_id: str = ""
    vulnerability_type: str = ""
    commit_hash: str = ""
    repo: str = ""

    # --- which side of the CSV row this statement came from (not in
    # context.md's schema; needed once the pipeline emits a safe/negative
    # class too, not just the vulnerable side) ---
    # "vulnerable": from vulnerable_code, diffed against fixed_code (label 0 or 1)
    # "fixed": from fixed_code of a row that DID change — always label 0,
    #          vulnerability_type forced to "none" (this code is the fix itself)
    # "unchanged": vulnerable_code was already identical to fixed_code — the
    #              method was safe from the start; always label 0,
    #              vulnerability_type forced to "none"
    origin: str = ""

    # --- A. Identitas & Relasi Struktural ---
    statement_id: str = ""
    parent_statement_id: Optional[str] = None
    nesting_depth: int = 0
    statement_type: str = ""
    parent_block_type: str = ""

    # --- B. Lokasi & Metadata ---
    repo_name: str = ""
    file_path: str = ""
    function_name: str = ""
    language: str = ""
    line_start: int = 0
    line_end: int = 0
    num_source_lines: int = 0

    # --- C. Teks & Lexical ---
    raw_text: str = ""
    token_count: int = 0
    char_length: int = 0

    # --- D. Sink & Perilaku Berbahaya ---
    num_calls: int = 0
    top_level_call_name: str = ""
    call_target_kind: str = "none"  # stdlib | third_party | user_defined | none
    is_process_exec: bool = False
    is_db_query: bool = False
    is_dynamic_eval: bool = False
    is_deserialization: bool = False
    is_file_io: bool = False
    is_network_call: bool = False
    is_output_render: bool = False
    uses_string_concat_or_format: bool = False
    num_variables_defined: int = 0
    num_variables_used: int = 0
    uses_only_literals: bool = False

    # --- E. Guard / Validasi Konteks ---
    guard_count: int = 0
    inside_error_handler: bool = False
    is_error_handling_statement: bool = False
    sanitization_call_detected: bool = False

    # --- F. Struktural Tambahan ---
    is_compound: bool = False
    num_direct_children: int = 0
    cyclomatic_contribution: int = 0

    # --- label: derived from the vulnerable/fixed diff, not part of
    # context.md's column list but the whole point of this pipeline ---
    label: int = 0


@dataclass
class FeaturePipelineStats:
    """Mirrors src/models.py's PipelineStats for this parallel pipeline."""
    total_input_rows: int = 0
    total_output_rows: int = 0
    total_positive_labels: int = 0
    total_from_vulnerable_side: int = 0
    total_from_fixed_side: int = 0
    total_from_unchanged_rows: int = 0
    skipped_unsupported_language: int = 0
    skipped_no_code: int = 0
    skipped_extraction_failure: int = 0
