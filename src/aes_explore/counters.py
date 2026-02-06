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
    Optionally maintains a draw-level log with monotonic IDs for verbose
    tracing (enabled via track_draws=True).
    """

    def __init__(self, track_draws: bool = False):
        self._total_bits = 0
        self._draw_counter = 0
        self._by_width: dict[int, int] = {}
        self._by_operation: dict[str, int] = {}
        # Draw-level log (only when track_draws is enabled)
        self._track_draws = track_draws
        self._draw_log: list[dict] = []
        self._snapshot_pos = 0

    def add(self, bits: int, width: int = 0, operation: str = "") -> tuple[int, int]:
        """
        Record consumption of fresh random bits.

        Args:
            bits: Number of random bits consumed
            width: Field width in bits (e.g., 2, 4, 8 for GF operations)
            operation: Name of the operation consuming randomness

        Returns:
            Tuple of (first_draw_id, num_draws) assigned to this event.
        """
        self._total_bits += bits

        if width > 0:
            self._by_width[width] = self._by_width.get(width, 0) + bits

        if operation:
            self._by_operation[operation] = self._by_operation.get(operation, 0) + bits

        num_draws = max(1, bits // width) if width > 0 else 1
        first_id = self._draw_counter
        self._draw_counter += num_draws

        if self._track_draws:
            self._draw_log.append({
                "first_id": first_id,
                "num_draws": num_draws,
                "bits": bits,
                "width": width,
                "operation": operation,
            })

        return first_id, num_draws

    # ------------------------------------------------------------------
    # Snapshot / delta helpers for per-cycle verbose tracing
    # ------------------------------------------------------------------

    def snapshot(self) -> None:
        """Mark current position for per-cycle delta tracking."""
        self._snapshot_pos = len(self._draw_log)

    def draws_since_snapshot(self) -> list[dict]:
        """Get draw events recorded since the last snapshot."""
        if not self._track_draws:
            return []
        return self._draw_log[self._snapshot_pos:]

    def bits_since_snapshot(self) -> int:
        """Total bits consumed since last snapshot."""
        return sum(d["bits"] for d in self.draws_since_snapshot())

    def ids_since_snapshot(self) -> tuple[int, int]:
        """Return (first_id, last_id_exclusive) range since snapshot."""
        draws = self.draws_since_snapshot()
        if not draws:
            return (self._draw_counter, self._draw_counter)
        first = draws[0]["first_id"]
        last_entry = draws[-1]
        last = last_entry["first_id"] + last_entry["num_draws"]
        return (first, last)

    def reset(self) -> None:
        """Reset all counters to zero."""
        self._total_bits = 0
        self._draw_counter = 0
        self._by_width.clear()
        self._by_operation.clear()
        self._draw_log.clear()
        self._snapshot_pos = 0

    @property
    def total_bits(self) -> int:
        """Get total random bits consumed."""
        return self._total_bits

    @property
    def draw_counter(self) -> int:
        """Current draw counter (next ID to be assigned)."""
        return self._draw_counter

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
