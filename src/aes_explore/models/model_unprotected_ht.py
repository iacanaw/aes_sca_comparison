"""
Unprotected High-Throughput AES-128 Model.

Features:
- One AES round per cycle with 16 parallel LUT S-boxes
- Pre-computed round keys
- Explicit cycle schedule

Cycle schedule:
- Cycle 0: AddRoundKey (round 0)
- Cycles 1-9: Full round (SubBytes, ShiftRows, MixColumns, AddRoundKey)
- Cycle 10: Final round (SubBytes, ShiftRows, AddRoundKey, no MixColumns)

Total: 11 cycles
"""

from ..aes_core import (
    key_expansion,
    sub_bytes,
    shift_rows,
    mix_columns,
    add_round_key,
)
from ..counters import CycleCounter
from ..trace import TraceRecorder
from ..utils import (
    bytes_to_state,
    state_to_bytes,
    copy_state,
    format_state_line,
)


# Cycle schedule definition (easy to modify)
CYCLE_SCHEDULE = [
    # (cycle, round, operations)
    (0, 0, ["AddRoundKey"]),
    (1, 1, ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"]),
    (2, 2, ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"]),
    (3, 3, ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"]),
    (4, 4, ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"]),
    (5, 5, ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"]),
    (6, 6, ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"]),
    (7, 7, ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"]),
    (8, 8, ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"]),
    (9, 9, ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"]),
    (10, 10, ["SubBytes", "ShiftRows", "AddRoundKey"]),  # Final round: no MixColumns
]


class UnprotectedHTModel:
    """
    Unprotected High-Throughput AES-128 encryption model.

    Processes one full AES round per cycle using 16 parallel S-box LUTs.
    """

    def __init__(
        self,
        tracer: TraceRecorder | None = None,
    ):
        """
        Initialize the model.

        Args:
            tracer: Optional trace recorder for verbose output
        """
        self.tracer = tracer
        self.cycle_counter = CycleCounter()

        # Will be set during encryption
        self._round_keys: list[list[list[int]]] = []
        self._state: list[list[int]] = []

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """
        Encrypt a single 16-byte block.

        Args:
            key: 16-byte AES key
            plaintext: 16-byte plaintext

        Returns:
            16-byte ciphertext
        """
        if len(key) != 16:
            raise ValueError(f"Key must be 16 bytes, got {len(key)}")
        if len(plaintext) != 16:
            raise ValueError(f"Plaintext must be 16 bytes, got {len(plaintext)}")

        # Reset state
        self.cycle_counter.reset()

        # Pre-compute all round keys
        self._round_keys = key_expansion(key)

        # Initialize state from plaintext
        self._state = bytes_to_state(plaintext)

        # Execute cycle schedule
        for cycle, round_num, operations in CYCLE_SCHEDULE:
            self._execute_cycle(cycle, round_num, operations)

        # Return ciphertext
        return state_to_bytes(self._state)

    def _execute_cycle(self, cycle: int, round_num: int, operations: list[str]) -> None:
        """
        Execute one cycle of the schedule.

        Args:
            cycle: Cycle number
            round_num: AES round number
            operations: List of operations to perform this cycle
        """
        self.cycle_counter.increment()

        round_key = self._round_keys[round_num]
        op_str = " -> ".join(operations)

        # Trace at start of cycle
        if self.tracer:
            self.tracer.record(
                cycle=cycle,
                round=round_num,
                operation=f"cycle_start: {op_str}",
                state=copy_state(self._state),
                round_key=copy_state(round_key),
            )

        # Execute operations in sequence
        for op in operations:
            if op == "SubBytes":
                self._state = sub_bytes(self._state)
            elif op == "ShiftRows":
                self._state = shift_rows(self._state)
            elif op == "MixColumns":
                self._state = mix_columns(self._state)
            elif op == "AddRoundKey":
                self._state = add_round_key(self._state, round_key)
            else:
                raise ValueError(f"Unknown operation: {op}")

            # Trace after each operation if verbose
            if self.tracer and self.tracer.verbose:
                self.tracer.record(
                    cycle=cycle,
                    round=round_num,
                    operation=op,
                    state=copy_state(self._state),
                )

    @property
    def cycles(self) -> int:
        """Get total cycles consumed."""
        return self.cycle_counter.count


def encrypt_unprotected_ht(
    key: bytes,
    plaintext: bytes,
    tracer: TraceRecorder | None = None,
) -> tuple[bytes, int]:
    """
    Convenience function to encrypt using unprotected high-throughput model.

    Args:
        key: 16-byte AES key
        plaintext: 16-byte plaintext
        tracer: Optional trace recorder

    Returns:
        Tuple of (ciphertext, cycles)
    """
    model = UnprotectedHTModel(tracer=tracer)
    ciphertext = model.encrypt(key, plaintext)
    return ciphertext, model.cycles
