"""
Strategies for pairing extracted vulnerable and fixed code snippets.
"""

from abc import ABC, abstractmethod
import difflib
from typing import List, Optional

from ..models import CodePair, PairingResult, PairingStatus


class BasePairingStrategy(ABC):
    """Abstract interface for pairing vulnerable and fixed code snippets."""

    @abstractmethod
    def pair(
        self,
        vulnerable_methods: Optional[List[str]] = None,
        fixed_methods: Optional[List[str]] = None,
        vulnerable_snippets: Optional[List[str]] = None,
        fixed_snippets: Optional[List[str]] = None
    ) -> PairingResult:
        """
        Pairs vulnerable code snippets with fixed code snippets.

        Args:
            vulnerable_methods: List of extracted vulnerable method strings (backward compatibility).
            fixed_methods: List of extracted fixed method strings (backward compatibility).
            vulnerable_snippets: List of extracted vulnerable snippet strings.
            fixed_snippets: List of extracted fixed snippet strings.

        Returns:
            PairingResult containing matched pairs and status.
        """
        pass


class StrictZipPairingStrategy(BasePairingStrategy):
    """
    Pairs code snippets strictly 1-to-1 based on index order when counts match.
    Skips if vulnerable snippets are missing or if snippet counts mismatch.
    """

    def pair(
        self,
        vulnerable_methods: Optional[List[str]] = None,
        fixed_methods: Optional[List[str]] = None,
        vulnerable_snippets: Optional[List[str]] = None,
        fixed_snippets: Optional[List[str]] = None
    ) -> PairingResult:
        v_list = vulnerable_snippets if vulnerable_snippets is not None else (vulnerable_methods or [])
        f_list = fixed_snippets if fixed_snippets is not None else (fixed_methods or [])

        if not v_list:
            return PairingResult(
                status=PairingStatus.NO_VULNERABLE_CODE,
                message="No vulnerable code snippet found"
            )

        if len(v_list) != len(f_list):
            return PairingResult(
                status=PairingStatus.MISMATCH,
                message=(
                    f"Snippet count mismatch: "
                    f"vulnerable={len(v_list)}, "
                    f"fixed={len(f_list)}"
                )
            )

        pairs = [
            CodePair(vulnerable_code=v, fixed_code=f)
            for v, f in zip(v_list, f_list)
        ]

        return PairingResult(
            status=PairingStatus.SUCCESS,
            pairs=pairs
        )


class AlignedPairingStrategy(BasePairingStrategy):
    """
    Intelligently aligns vulnerable and fixed code snippets using sequence diff matching.
    Prevents off-by-one misalignment when lines/blocks are inserted or deleted in fixes.
    """

    def pair(
        self,
        vulnerable_methods: Optional[List[str]] = None,
        fixed_methods: Optional[List[str]] = None,
        vulnerable_snippets: Optional[List[str]] = None,
        fixed_snippets: Optional[List[str]] = None
    ) -> PairingResult:
        v_list = vulnerable_snippets if vulnerable_snippets is not None else (vulnerable_methods or [])
        f_list = fixed_snippets if fixed_snippets is not None else (fixed_methods or [])

        if not v_list and not f_list:
            return PairingResult(
                status=PairingStatus.NO_VULNERABLE_CODE,
                message="No code snippets found for pairing"
            )

        if not v_list:
            return PairingResult(
                status=PairingStatus.NO_VULNERABLE_CODE,
                message="No vulnerable code snippet found"
            )

        matcher = difflib.SequenceMatcher(None, v_list, f_list)
        pairs: List[CodePair] = []

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                for v, f in zip(v_list[i1:i2], f_list[j1:j2]):
                    pairs.append(CodePair(vulnerable_code=v, fixed_code=f))

            elif tag == "replace":
                v_sub = v_list[i1:i2]
                f_sub = f_list[j1:j2]
                if len(v_sub) == len(f_sub):
                    # Equal-length rewrite: positional pairing is meaningful,
                    # each vulnerable statement maps to the fixed statement
                    # at the same position.
                    for v, f in zip(v_sub, f_sub):
                        pairs.append(CodePair(vulnerable_code=v, fixed_code=f))
                else:
                    # Unequal statement counts mean this region was
                    # restructured (e.g. several statements collapsed into
                    # one, or one expanded into several) rather than
                    # rewritten 1:1 — pairing by index would fabricate
                    # misleading pairs with an empty counterpart on one
                    # side. Keep the whole region as a single pair instead.
                    pairs.append(CodePair(
                        vulnerable_code="\n\n".join(v_sub),
                        fixed_code="\n\n".join(f_sub)
                    ))

            elif tag == "delete":
                for v in v_list[i1:i2]:
                    pairs.append(CodePair(vulnerable_code=v, fixed_code=""))

            elif tag == "insert":
                for f in f_list[j1:j2]:
                    pairs.append(CodePair(vulnerable_code="", fixed_code=f))

        return PairingResult(
            status=PairingStatus.SUCCESS,
            pairs=pairs
        )

