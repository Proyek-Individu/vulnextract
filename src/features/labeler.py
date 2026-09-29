"""
Recursive tree-diff labeling: decides which vulnerable-side statements
actually changed between the vulnerable and fixed versions of a method.

Per the user's confirmed labeling scheme: only statements that actually
changed get label=1; everything else in the same vulnerable method
(unchanged statements) gets label=0. Fixed-only statements (added by the
fix, no vulnerable-side counterpart) are not part of this population at all
and are simply dropped — not emitted as their own row.

Generalizes the flat, single-level opcode handling already proven in
src/strategies/pairing.py's AlignedPairingStrategy (equal-length replace ->
positional pairing, unequal-length -> merge) to every level of the
statement tree, plus two refinements a flat text diff can't express:

1. Header-vs-children separation: when two same-type, same-position
   statements are compound (if/for/try/...), a condition-only edit (e.g.
   tightening `if x` to `if x && isValid(x)`) must not vanish just because
   the branch bodies are byte-identical — so the node's own "header" text
   (its span minus its recursed children's spans) is diffed independently
   of whether its children changed.
2. Move detection: a pure reorder (`[A, B] -> [B, A]`) must not be labeled
   as a change to both A and B just because SequenceMatcher sees it as a
   delete+insert — a lightweight guardrail reclassifies an exactly-matching
   delete/insert pair at the same level as "moved, unchanged".

Diffing uses whitespace-normalized text (not context.md's `raw_text`
column, which stays unnormalized) so pure reformatting in the same commit
doesn't get mislabeled as a semantic change.
"""

import difflib
import re
from typing import List

from .tree_builder import StatementNode, local_scope_text

_WHITESPACE_RE = re.compile(r"\s+")


def _normalize(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text).strip()


def _normalized_text(node: StatementNode) -> str:
    return _normalize(node.ast_node.text.decode("utf-8", errors="replace"))


def _normalized_header(node: StatementNode, source_bytes: bytes) -> str:
    return _normalize(local_scope_text(node, source_bytes))


def _mark_subtree(node: StatementNode, label: int) -> None:
    node.label = label
    for child in node.children:
        _mark_subtree(child, label)


def label_statements(
    v_nodes: List[StatementNode],
    f_nodes: List[StatementNode],
    v_source: bytes,
    f_source: bytes,
) -> None:
    """
    Labels every node in `v_nodes` (and recursively their descendants) with
    0/1 by diffing against `f_nodes` at this tree level, then descending
    into matched same-type pairs. Mutates `v_nodes` in place; `f_nodes` are
    read-only (fixed-side statements are never themselves labeled/emitted).
    """
    if not v_nodes:
        return

    v_keys = [_normalized_text(n) for n in v_nodes]
    f_keys = [_normalized_text(n) for n in f_nodes]

    opcodes = difflib.SequenceMatcher(None, v_keys, f_keys).get_opcodes()

    # Move-detection guardrail: reclassify a delete/insert pair at this
    # level whose normalized text matches exactly as "moved, unchanged"
    # rather than "deleted"+"inserted" (avoids false positives from pure
    # reordering, which SequenceMatcher can't otherwise distinguish from a
    # real removal).
    unclaimed_f_indices = set()
    for tag, _i1, _i2, j1, j2 in opcodes:
        if tag == "insert":
            unclaimed_f_indices.update(range(j1, j2))

    moved_v_indices = set()
    for tag, i1, i2, _j1, _j2 in opcodes:
        if tag != "delete":
            continue
        for vi in range(i1, i2):
            for fj in list(unclaimed_f_indices):
                if v_keys[vi] == f_keys[fj]:
                    moved_v_indices.add(vi)
                    unclaimed_f_indices.discard(fj)
                    break

    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            # Identical normalized text implies identical children too —
            # no need to recurse.
            for vi in range(i1, i2):
                _mark_subtree(v_nodes[vi], 0)

        elif tag == "replace":
            v_len, f_len = i2 - i1, j2 - j1
            if v_len == f_len:
                for k in range(v_len):
                    v_node, f_node = v_nodes[i1 + k], f_nodes[j1 + k]
                    if v_node.statement_type == f_node.statement_type:
                        v_header = _normalized_header(v_node, v_source)
                        f_header = _normalized_header(f_node, f_source)
                        v_node.label = 1 if v_header != f_header else 0
                        label_statements(v_node.children, f_node.children, v_source, f_source)
                    else:
                        # Type changed shape entirely (e.g. if -> ternary) —
                        # no meaningful header/children split to recurse into.
                        _mark_subtree(v_node, 1)
            else:
                # Unequal counts: this region was restructured (statements
                # collapsed/expanded), not rewritten 1:1 — same reasoning as
                # AlignedPairingStrategy's merge-on-mismatch fix, generalized
                # here to "no positional correspondence to diff against".
                for vi in range(i1, i2):
                    _mark_subtree(v_nodes[vi], 1)

        elif tag == "delete":
            for vi in range(i1, i2):
                _mark_subtree(v_nodes[vi], 0 if vi in moved_v_indices else 1)

        # "insert": fixed-only statements have no vulnerable-side node to
        # label and are never emitted — nothing to do.
