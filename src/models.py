"""
Domain Models and Type Definitions for Method-Level Vulnerability Extraction.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class PairingStatus(str, Enum):
    SUCCESS = "success"
    NO_VULNERABLE_METHODS = "no_vulnerable_methods"
    MISMATCH = "mismatch"


@dataclass(frozen=True)
class MethodPair:
    """Represents a matched pair of vulnerable and fixed method snippets."""
    vulnerable_method: str
    fixed_method: str


@dataclass
class PairingResult:
    """Result of attempting to pair vulnerable and fixed methods for a record."""
    status: PairingStatus
    pairs: List[MethodPair] = field(default_factory=list)
    message: Optional[str] = None


@dataclass
class PipelineStats:
    """Summary metrics of the pipeline execution."""
    total_input_rows: int = 0
    total_output_rows: int = 0
    skipped_no_methods: int = 0
    skipped_mismatch: int = 0
    skipped_unsupported_language: int = 0
