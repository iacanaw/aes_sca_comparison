"""
Domain-Oriented Masking (DOM) AES-128 Model.

Features:
- d+1 shares for protection order d (d=1: 2 shares, d=2: 3 shares)
- Byte-serial datapath (16 bytes processed sequentially through S-box)
- Canright-style S-box with configurable pipeline (5 or 8 stages)
- Precise cycle and randomness tracking

Cycle costs (configurable):
- SubBytes: 16 + (pipeline_depth - 1) cycles (byte-serial with pipeline latency)
- ShiftRows: 1 cycle
- MixColumns: 1 cycle
- AddRoundKey: 1 cycle
"""

import random

from ..aes_core import (
    key_expansion,
    apply_shift_rows_to_shares,
    apply_mix_columns_to_shares,
    apply_add_round_key_to_shares,
)
from ..counters import CycleCounter, RandomnessCounter
from ..trace import TraceRecorder
from ..utils import (
    bytes_to_state,
    state_to_bytes,
    copy_state,
)
from ..dom.sbox_canright_dom import DomCanrightSBoxPipeline, share_value, recombine_shares


# Configurable cycle costs for linear operations
SHIFT_ROWS_CYCLES = 1
MIX_COLUMNS_CYCLES = 1
ADD_ROUND_KEY_CYCLES = 1


class DomModel:
    """
    Domain-Oriented Masking AES-128 encryption model.

    Processes SubBytes byte-serially through a pipelined Canright S-box.
    Linear operations (ShiftRows, MixColumns, AddRoundKey) are applied
    per-share.
    """

    def __init__(
        self,
        d: int = 1,
        sbox_variant: int = 5,
        seed: int | None = None,
        tracer: TraceRecorder | None = None,
    ):
        """
        Initialize the DOM model.

        Args:
            d: Protection order (1 or 2)
            sbox_variant: S-box pipeline variant (5 or 8)
            seed: RNG seed (random if None)
            tracer: Optional trace recorder
        """
        if d not in (1, 2):
            raise ValueError(f"Protection order d must be 1 or 2, got {d}")
        if sbox_variant not in (5, 8):
            raise ValueError(f"S-box variant must be 5 or 8, got {sbox_variant}")

        self.d = d
        self.num_shares = d + 1
        self.sbox_variant = sbox_variant
        self.tracer = tracer

        # Initialize RNG
        self.seed = seed if seed is not None else random.randint(0, 2**32 - 1)
        self.rng = random.Random(self.seed)

        # Counters
        self.cycle_counter = CycleCounter()
        self.randomness_counter = RandomnessCounter()

        # State shares: list of d+1 4x4 states
        self._state_shares: list[list[list[int]]] = []

        # Round keys (computed unmasked, applied as masked XOR)
        self._round_keys: list[list[list[int]]] = []

        # S-box pipeline
        self._sbox: DomCanrightSBoxPipeline | None = None

    def _create_sbox(self) -> DomCanrightSBoxPipeline:
        """Create a fresh S-box pipeline instance."""
        return DomCanrightSBoxPipeline(
            d=self.d,
            variant=self.sbox_variant,
            rng=self.rng,
            cycle_counter=self.cycle_counter,
            randomness_counter=self.randomness_counter,
            tracer=self.tracer,
        )

    def _share_state(self, state: list[list[int]]) -> list[list[list[int]]]:
        """
        Create d+1 shares of a state.

        Args:
            state: 4x4 state to share

        Returns:
            List of d+1 4x4 state shares
        """
        shares = [[[0 for _ in range(4)] for _ in range(4)] for _ in range(self.num_shares)]

        for row in range(4):
            for col in range(4):
                byte_val = state[row][col]
                byte_shares = share_value(byte_val, self.num_shares, 0xFF, self.rng)

                # Count randomness for initial sharing
                self.randomness_counter.add(
                    self.d * 8,
                    width=8,
                    operation="state_sharing"
                )

                for share_idx in range(self.num_shares):
                    shares[share_idx][row][col] = byte_shares[share_idx]

        return shares

    def _recombine_state(self, shares: list[list[list[int]]]) -> list[list[int]]:
        """
        Recombine state shares by XORing.

        Args:
            shares: List of d+1 4x4 state shares

        Returns:
            4x4 recombined state
        """
        result = [[0 for _ in range(4)] for _ in range(4)]
        for row in range(4):
            for col in range(4):
                val = 0
                for share_idx in range(self.num_shares):
                    val ^= shares[share_idx][row][col]
                result[row][col] = val
        return result

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """
        Encrypt a single 16-byte block with DOM protection.

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

        # Reset counters
        self.cycle_counter.reset()
        self.randomness_counter.reset()

        # Pre-compute round keys (unmasked)
        self._round_keys = key_expansion(key)

        # Initialize state and create shares
        initial_state = bytes_to_state(plaintext)
        self._state_shares = self._share_state(initial_state)

        # Trace initial state
        if self.tracer:
            self.tracer.record(
                cycle=0,
                round=0,
                operation="initial_state",
                shares=[copy_state(s) for s in self._state_shares],
                recombined=self._recombine_state(self._state_shares),
            )

        # Initial AddRoundKey (round 0)
        self._add_round_key(0)

        # Rounds 1-9: full rounds
        for rnd in range(1, 10):
            self._full_round(rnd)

        # Round 10: final round (no MixColumns)
        self._final_round(10)

        # Recombine and return ciphertext
        final_state = self._recombine_state(self._state_shares)
        return state_to_bytes(final_state)

    def _add_round_key(self, round_num: int) -> None:
        """
        Apply AddRoundKey to state shares.

        The round key is XORed only to the first share (share 0).
        """
        self.cycle_counter.increment(ADD_ROUND_KEY_CYCLES)

        round_key = self._round_keys[round_num]
        self._state_shares = apply_add_round_key_to_shares(self._state_shares, round_key)

        if self.tracer:
            self.tracer.record(
                cycle=self.cycle_counter.count,
                round=round_num,
                operation="AddRoundKey",
                shares=[copy_state(s) for s in self._state_shares],
                recombined=self._recombine_state(self._state_shares),
                round_key=copy_state(round_key),
                cycles_so_far=self.cycle_counter.count,
                random_bits_so_far=self.randomness_counter.total_bits,
            )

    def _sub_bytes(self, round_num: int) -> None:
        """
        Apply SubBytes to state shares using pipelined S-box.

        Processes 16 bytes serially through the pipeline.
        Total cycles = 16 + (pipeline_depth - 1)
        """
        sbox = self._create_sbox()

        # Collect input bytes (column-major order)
        input_shares_list = []
        for col in range(4):
            for row in range(4):
                byte_shares = [self._state_shares[s][row][col] for s in range(self.num_shares)]
                input_shares_list.append((row, col, byte_shares))

        # Output storage
        output_shares_list = []

        # Feed bytes into pipeline and collect outputs
        input_idx = 0
        byte_idx = 0

        # Feed all 16 bytes and process
        while input_idx < 16 or not sbox.is_empty():
            # Push new input if available and pipeline can accept
            if input_idx < 16 and sbox.can_accept():
                row, col, byte_shares = input_shares_list[input_idx]
                sbox.push(byte_shares, byte_index=input_idx)
                input_idx += 1

            # Step pipeline (this increments cycle counter)
            sbox.step()

            # Pop output if ready
            if sbox.is_ready():
                out_shares = sbox.pop()
                output_shares_list.append(out_shares)

        # Flush any remaining items
        remaining = sbox.flush()
        output_shares_list.extend(remaining)

        # Verify we got all 16 outputs
        if len(output_shares_list) != 16:
            raise RuntimeError(f"Expected 16 S-box outputs, got {len(output_shares_list)}")

        # Write outputs back to state shares (column-major order)
        for idx, out_shares in enumerate(output_shares_list):
            col = idx // 4
            row = idx % 4
            for s in range(self.num_shares):
                self._state_shares[s][row][col] = out_shares[s]

        if self.tracer:
            self.tracer.record(
                cycle=self.cycle_counter.count,
                round=round_num,
                operation="SubBytes",
                shares=[copy_state(s) for s in self._state_shares],
                recombined=self._recombine_state(self._state_shares),
                cycles_so_far=self.cycle_counter.count,
                random_bits_so_far=self.randomness_counter.total_bits,
            )

    def _shift_rows(self, round_num: int) -> None:
        """Apply ShiftRows to each share independently."""
        self.cycle_counter.increment(SHIFT_ROWS_CYCLES)

        self._state_shares = apply_shift_rows_to_shares(self._state_shares)

        if self.tracer:
            self.tracer.record(
                cycle=self.cycle_counter.count,
                round=round_num,
                operation="ShiftRows",
                shares=[copy_state(s) for s in self._state_shares],
                recombined=self._recombine_state(self._state_shares),
                cycles_so_far=self.cycle_counter.count,
                random_bits_so_far=self.randomness_counter.total_bits,
            )

    def _mix_columns(self, round_num: int) -> None:
        """Apply MixColumns to each share independently."""
        self.cycle_counter.increment(MIX_COLUMNS_CYCLES)

        self._state_shares = apply_mix_columns_to_shares(self._state_shares)

        if self.tracer:
            self.tracer.record(
                cycle=self.cycle_counter.count,
                round=round_num,
                operation="MixColumns",
                shares=[copy_state(s) for s in self._state_shares],
                recombined=self._recombine_state(self._state_shares),
                cycles_so_far=self.cycle_counter.count,
                random_bits_so_far=self.randomness_counter.total_bits,
            )

    def _full_round(self, round_num: int) -> None:
        """Execute a full AES round (SubBytes, ShiftRows, MixColumns, AddRoundKey)."""
        self._sub_bytes(round_num)
        self._shift_rows(round_num)
        self._mix_columns(round_num)
        self._add_round_key(round_num)

    def _final_round(self, round_num: int) -> None:
        """Execute final AES round (SubBytes, ShiftRows, AddRoundKey, no MixColumns)."""
        self._sub_bytes(round_num)
        self._shift_rows(round_num)
        self._add_round_key(round_num)

    @property
    def cycles(self) -> int:
        """Get total cycles consumed."""
        return self.cycle_counter.count

    @property
    def random_bits(self) -> int:
        """Get total random bits consumed."""
        return self.randomness_counter.total_bits


def encrypt_dom(
    key: bytes,
    plaintext: bytes,
    d: int = 1,
    sbox_variant: int = 5,
    seed: int | None = None,
    tracer: TraceRecorder | None = None,
) -> tuple[bytes, int, int]:
    """
    Convenience function to encrypt using DOM model.

    Args:
        key: 16-byte AES key
        plaintext: 16-byte plaintext
        d: Protection order (1 or 2)
        sbox_variant: S-box variant (5 or 8)
        seed: RNG seed
        tracer: Optional trace recorder

    Returns:
        Tuple of (ciphertext, cycles, random_bits)
    """
    model = DomModel(
        d=d,
        sbox_variant=sbox_variant,
        seed=seed,
        tracer=tracer,
    )
    ciphertext = model.encrypt(key, plaintext)
    return ciphertext, model.cycles, model.random_bits
