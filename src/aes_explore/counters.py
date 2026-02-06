"""
Counters for cycle and randomness tracking.
"""


class CycleCounter:
    """
    Tracks the number of cycles consumed during AES execution.
    """

    def __init__(self):
        self._count = 0

    def increment(self, amount: int = 1) -> None:
        """Add cycles to the counter."""
        self._count += amount

    def reset(self) -> None:
        """Reset counter to zero."""
        self._count = 0

    @property
    def count(self) -> int:
        """Get current cycle count."""
        return self._count

    def __repr__(self) -> str:
        return f"CycleCounter(count={self._count})"


class RandomnessCounter:
    """
    Tracks fresh randomness bits consumed during masked AES execution.

    Tracks both total bits and breakdown by field width.
    """

    def __init__(self):
        self._total_bits = 0
        self._by_width: dict[int, int] = {}  # width -> total bits
        self._by_operation: dict[str, int] = {}  # operation name -> total bits

    def add(self, bits: int, width: int = 0, operation: str = "") -> None:
        """
        Record consumption of fresh random bits.

        Args:
            bits: Number of random bits consumed
            width: Field width in bits (e.g., 2, 4, 8 for GF operations)
            operation: Name of the operation consuming randomness
        """
        self._total_bits += bits

        if width > 0:
            self._by_width[width] = self._by_width.get(width, 0) + bits

        if operation:
            self._by_operation[operation] = self._by_operation.get(operation, 0) + bits

    def reset(self) -> None:
        """Reset all counters to zero."""
        self._total_bits = 0
        self._by_width.clear()
        self._by_operation.clear()

    @property
    def total_bits(self) -> int:
        """Get total random bits consumed."""
        return self._total_bits

    @property
    def by_width(self) -> dict[int, int]:
        """Get bits consumed broken down by field width."""
        return dict(self._by_width)

    @property
    def by_operation(self) -> dict[str, int]:
        """Get bits consumed broken down by operation."""
        return dict(self._by_operation)

    def summary(self) -> str:
        """Return a summary string of randomness consumption."""
        lines = [f"Total random bits: {self._total_bits}"]

        if self._by_width:
            lines.append("By field width:")
            for width in sorted(self._by_width.keys()):
                lines.append(f"  GF(2^{width}): {self._by_width[width]} bits")

        if self._by_operation:
            lines.append("By operation:")
            for op in sorted(self._by_operation.keys()):
                lines.append(f"  {op}: {self._by_operation[op]} bits")

        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"RandomnessCounter(total_bits={self._total_bits})"
