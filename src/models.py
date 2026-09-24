"""
Domain Models and Type Definitions for Vulnerability Code Pair Extraction.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class PairingStatus(str, Enum):
    SUCCESS = "success"
    NO_VULNERABLE_CODE = "no_vulnerable_code"
    NO_VULNERABLE_METHODS = "no_vulnerable_code"
    MISMATCH = "mismatch"


@dataclass(frozen=True)
class CodePair:
    """Represents a matched pair of vulnerable and fixed code snippets (statement or method)."""
    vulnerable_code: str
    fixed_code: str

    def __init__(
        self,
        vulnerable_code: Optional[str] = None,
        fixed_code: Optional[str] = None,
        vulnerable_method: Optional[str] = None,
        fixed_method: Optional[str] = None
    ) -> None:
        v = vulnerable_code if vulnerable_code is not None else vulnerable_method
        f = fixed_code if fixed_code is not None else fixed_method
        object.__setattr__(self, "vulnerable_code", v or "")
        object.__setattr__(self, "fixed_code", f or "")

    @property
    def vulnerable_method(self) -> str:
        """Alias for backward compatibility with method-level consumers."""
        return self.vulnerable_code

    @property
    def fixed_method(self) -> str:
        """Alias for backward compatibility with method-level consumers."""
        return self.fixed_code


# Backward compatibility aliases
MethodPair = CodePair
StatementPair = CodePair


@dataclass
class PairingResult:
    """Result of attempting to pair vulnerable and fixed snippets for a record."""
    status: PairingStatus
    pairs: List[CodePair] = field(default_factory=list)
    message: Optional[str] = None


@dataclass
class PipelineStats:
    """Summary metrics of the pipeline execution."""
    total_input_rows: int = 0
    total_output_rows: int = 0
    skipped_no_code: int = 0
    skipped_mismatch: int = 0
    skipped_unsupported_language: int = 0

    @property
    def skipped_no_methods(self) -> int:
        return self.skipped_no_code

    @skipped_no_methods.setter
    def skipped_no_methods(self, value: int) -> None:
        self.skipped_no_code = value
