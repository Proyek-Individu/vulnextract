"""
Strategies for pairing extracted vulnerable and fixed methods.
"""

from abc import ABC, abstractmethod
from typing import List

from ..models import MethodPair, PairingResult, PairingStatus


class BasePairingStrategy(ABC):
    """Abstract interface for pairing vulnerable and fixed methods."""

    @abstractmethod
    def pair(
        self,
        vulnerable_methods: List[str],
        fixed_methods: List[str]
    ) -> PairingResult:
        """
        Pairs vulnerable methods with fixed methods.

        Args:
            vulnerable_methods: List of extracted vulnerable method strings.
            fixed_methods: List of extracted fixed method strings.

        Returns:
            PairingResult containing matched pairs and status.
        """
        pass


class StrictZipPairingStrategy(BasePairingStrategy):
    """
    Pairs methods strictly 1-to-1 based on index order when counts match.
    Skips if vulnerable methods are missing or if method counts mismatch.
    """

    def pair(
        self,
        vulnerable_methods: List[str],
        fixed_methods: List[str]
    ) -> PairingResult:
        if not vulnerable_methods:
            return PairingResult(
                status=PairingStatus.NO_VULNERABLE_METHODS,
                message="No vulnerable method found"
            )

        if len(vulnerable_methods) != len(fixed_methods):
            return PairingResult(
                status=PairingStatus.MISMATCH,
                message=(
                    f"Method count mismatch: "
                    f"vulnerable={len(vulnerable_methods)}, "
                    f"fixed={len(fixed_methods)}"
                )
            )

        pairs = [
            MethodPair(vulnerable_method=v, fixed_method=f)
            for v, f in zip(vulnerable_methods, fixed_methods)
        ]

        return PairingResult(
            status=PairingStatus.SUCCESS,
            pairs=pairs
        )
