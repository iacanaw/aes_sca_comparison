"""Core interfaces and data structures for AES evaluation framework."""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .cycle_models import CycleModel
    from .randomness import RandomSource


@dataclass
class EvalConfig:
    """Configuration object for AES evaluation.

    This is passed to all components and drives accounting for cycles,
    randomness, and other metrics.
    """

    # AES mode (fixed for now, extendable later)
    aes_mode: str = "ecb_single_block"

    # Masking order: 0 = unmasked, 1 = 2 shares, 2 = 3 shares
    mask_order_d: int = 0

    # Number of S-boxes processed in parallel (1..16)
    # 1 = byte-serial, 16 = full 128-bit parallel SubBytes
    sbox_parallelism: int = 16

    # Round architecture: how rounds map to cycles
    round_arch: str = "iterative_rounds"

    # Clock frequency in Hz (for throughput/latency conversions)
    f_clk_hz: float = 200e6

    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.mask_order_d not in (0, 1, 2):
            raise ValueError(f"mask_order_d must be 0, 1, or 2, got {self.mask_order_d}")
        if not 1 <= self.sbox_parallelism <= 16:
            raise ValueError(f"sbox_parallelism must be 1..16, got {self.sbox_parallelism}")
        if self.round_arch not in ("iterative_rounds", "fully_unrolled", "pipelined_rounds"):
            raise ValueError(f"Unknown round_arch: {self.round_arch}")
        if self.f_clk_hz <= 0:
            raise ValueError(f"f_clk_hz must be positive, got {self.f_clk_hz}")

    @property
    def shares(self) -> int:
        """Number of shares for masking (d+1 when d>0, else 1)."""
        return self.mask_order_d + 1 if self.mask_order_d > 0 else 1

    @property
    def sbox_groups_per_round(self) -> int:
        """Number of S-box group evaluations per SubBytes (ceil(16/parallelism))."""
        return math.ceil(16 / self.sbox_parallelism)


@dataclass
class Result:
    """Result of an AES encryption operation with full accounting."""

    # Core result
    ciphertext: bytes
    correct: bool
    error_detail: str = ""

    # Cycle accounting
    cycle_count_total: int = 0
    cycle_breakdown: dict[str, int] = field(default_factory=dict)

    # Randomness accounting
    random_bits_total: int = 0
    random_bits_breakdown: dict[str, int] = field(default_factory=dict)

    # Operation counts
    op_counts: dict[str, int] = field(default_factory=dict)

    # Notes and warnings
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Ensure breakdown dicts have default keys."""
        default_cycle_keys = [
            "key_schedule",
            "add_round_key",
            "sub_bytes",
            "shift_rows",
            "mix_columns",
            "refresh",
        ]
        for key in default_cycle_keys:
            self.cycle_breakdown.setdefault(key, 0)

        default_random_keys = [
            "fresh_masks",
            "remasking",
            "refresh",
            "gadget_randomness",
        ]
        for key in default_random_keys:
            self.random_bits_breakdown.setdefault(key, 0)

        default_op_keys = [
            "sbox_calls",
            "xor_ops",
        ]
        for key in default_op_keys:
            self.op_counts.setdefault(key, 0)

    def add_note(self, note: str) -> None:
        """Add an informational note."""
        self.notes.append(note)

    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self.warnings.append(warning)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "ciphertext_hex": self.ciphertext.hex(),
            "correct": self.correct,
            "error_detail": self.error_detail,
            "cycle_count_total": self.cycle_count_total,
            "cycle_breakdown": self.cycle_breakdown,
            "random_bits_total": self.random_bits_total,
            "random_bits_breakdown": self.random_bits_breakdown,
            "op_counts": self.op_counts,
            "notes": self.notes,
            "warnings": self.warnings,
        }


class BaseTechnique(ABC):
    """Abstract base class for AES implementation techniques.

    All techniques must inherit from this class and implement encrypt_block().
    """

    # Class attributes to be overridden by subclasses
    name: str = "base"
    description: str = "Base technique (abstract)"

    @abstractmethod
    def encrypt_block(
        self,
        key: bytes,
        plaintext: bytes,
        rng: "RandomSource",
        cycle_model: "CycleModel",
        config: EvalConfig,
    ) -> Result:
        """Encrypt a single 16-byte block.

        Args:
            key: 16-byte AES key
            plaintext: 16-byte plaintext block
            rng: Random source for masking (tracks usage)
            cycle_model: Cycle model for accounting
            config: Evaluation configuration

        Returns:
            Result with ciphertext, correctness, and accounting data
        """
        raise NotImplementedError

    def validate_inputs(self, key: bytes, plaintext: bytes) -> None:
        """Validate key and plaintext sizes."""
        if len(key) != 16:
            raise ValueError(f"Key must be 16 bytes, got {len(key)}")
        if len(plaintext) != 16:
            raise ValueError(f"Plaintext must be 16 bytes, got {len(plaintext)}")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"
