"""Randomness source and accounting for masked AES implementations."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RandomnessModelConfig:
    """Configuration for randomness model estimates.

    These parameters model how randomness scales with shares and gadgets.
    Based on published literature for DOM and TI masking.
    """

    # Fresh mask bits per byte of state (initial masking)
    fresh_mask_bits_per_byte: int = 8

    # DOM-AND gadget: (s-1)*s/2 fresh bits per gadget for s shares
    # For s=2: 1 bit, for s=3: 3 bits
    dom_gadget_bits_base: int = 1  # multiplied by (s-1)*s/2

    # TI gadget: typically s*2 bits per gadget for s shares
    # (TI needs more randomness for re-sharing/correction terms)
    ti_gadget_bits_base: int = 2  # multiplied by s

    # Remasking bits per byte per round (refresh randomness)
    remasking_bits_per_byte: int = 8

    # Number of AND gadgets per S-box (AES S-box has ~4 AND gates in depth)
    and_gadgets_per_sbox: int = 4

    # Enable/disable refresh between rounds
    enable_refresh: bool = True


class RandomSource:
    """Random source with tracking for masked implementations.

    Provides deterministic randomness (from seed) for reproducibility
    while tracking usage by category.
    """

    def __init__(
        self,
        seed: int | None = None,
        config: RandomnessModelConfig | None = None,
    ):
        """Initialize random source.

        Args:
            seed: Optional seed for deterministic randomness
            config: Optional randomness model configuration
        """
        self._seed = seed
        self._config = config or RandomnessModelConfig()
        self._rng = self._create_rng(seed)

        # Tracking
        self._bits_used: dict[str, int] = {}
        self._bytes_used: dict[str, int] = {}
        self.reset()

    def _create_rng(self, seed: int | None) -> Any:
        """Create random number generator.

        Uses secrets for cryptographic randomness when no seed,
        or a simple PRNG for reproducibility when seeded.
        """
        if seed is None:
            return None  # Use secrets
        else:
            # Simple LCG for reproducibility
            return _SeededRNG(seed)

    def reset(self) -> None:
        """Reset usage counters."""
        self._bits_used = {
            "fresh_masks": 0,
            "remasking": 0,
            "refresh": 0,
            "gadget_randomness": 0,
            "other": 0,
        }
        self._bytes_used = {k: 0 for k in self._bits_used}
        if self._seed is not None:
            self._rng = self._create_rng(self._seed)

    @property
    def total_bits(self) -> int:
        """Total random bits used."""
        return sum(self._bits_used.values())

    @property
    def total_bytes(self) -> int:
        """Total random bytes used."""
        return sum(self._bytes_used.values())

    @property
    def bits_breakdown(self) -> dict[str, int]:
        """Get bits breakdown by category."""
        return self._bits_used.copy()

    @property
    def bytes_breakdown(self) -> dict[str, int]:
        """Get bytes breakdown by category."""
        return self._bytes_used.copy()

    def get_bytes(self, count: int, category: str = "other") -> bytes:
        """Get random bytes and track usage.

        Args:
            count: Number of bytes to generate
            category: Category for tracking

        Returns:
            Random bytes
        """
        if category not in self._bits_used:
            category = "other"

        self._bits_used[category] += count * 8
        self._bytes_used[category] += count

        if self._rng is None:
            return secrets.token_bytes(count)
        else:
            return self._rng.get_bytes(count)

    def get_bits(self, count: int, category: str = "other") -> int:
        """Get random bits as integer and track usage.

        Args:
            count: Number of bits to generate
            category: Category for tracking

        Returns:
            Random integer with `count` bits
        """
        if category not in self._bits_used:
            category = "other"

        self._bits_used[category] += count

        # For byte tracking, round up
        byte_count = (count + 7) // 8
        self._bytes_used[category] += byte_count

        if self._rng is None:
            return secrets.randbits(count)
        else:
            return self._rng.get_bits(count)

    def estimate_fresh_masks(self, shares: int, state_bytes: int = 16) -> int:
        """Estimate and consume randomness for fresh masks.

        Args:
            shares: Number of shares
            state_bytes: Size of state in bytes

        Returns:
            Bits consumed
        """
        if shares <= 1:
            return 0

        # Need (shares-1) random masks per byte
        bits = (shares - 1) * state_bytes * self._config.fresh_mask_bits_per_byte
        self._bits_used["fresh_masks"] += bits
        self._bytes_used["fresh_masks"] += (bits + 7) // 8

        return bits

    def estimate_dom_gadgets(self, shares: int, num_sboxes: int = 16) -> int:
        """Estimate and consume randomness for DOM AND gadgets.

        DOM AND gadgets need (s-1)*s/2 fresh bits per gadget for s shares.

        Args:
            shares: Number of shares
            num_sboxes: Number of S-box evaluations

        Returns:
            Bits consumed
        """
        if shares <= 1:
            return 0

        # (s-1)*s/2 bits per gadget
        bits_per_gadget = ((shares - 1) * shares) // 2 * self._config.dom_gadget_bits_base
        total_gadgets = num_sboxes * self._config.and_gadgets_per_sbox
        bits = total_gadgets * bits_per_gadget

        self._bits_used["gadget_randomness"] += bits
        self._bytes_used["gadget_randomness"] += (bits + 7) // 8

        return bits

    def estimate_ti_gadgets(self, shares: int, num_sboxes: int = 16) -> int:
        """Estimate and consume randomness for TI gadgets.

        TI gadgets typically need s bits per gadget for s shares
        (for re-sharing/re-masking within the gadget).

        Args:
            shares: Number of shares
            num_sboxes: Number of S-box evaluations

        Returns:
            Bits consumed
        """
        if shares <= 1:
            return 0

        bits_per_gadget = shares * self._config.ti_gadget_bits_base
        total_gadgets = num_sboxes * self._config.and_gadgets_per_sbox
        bits = total_gadgets * bits_per_gadget

        self._bits_used["gadget_randomness"] += bits
        self._bytes_used["gadget_randomness"] += (bits + 7) // 8

        return bits

    def estimate_remasking(self, shares: int, state_bytes: int = 16) -> int:
        """Estimate and consume randomness for remasking/refresh.

        Args:
            shares: Number of shares
            state_bytes: Size of state in bytes

        Returns:
            Bits consumed
        """
        if shares <= 1 or not self._config.enable_refresh:
            return 0

        bits = (shares - 1) * state_bytes * self._config.remasking_bits_per_byte
        self._bits_used["refresh"] += bits
        self._bytes_used["refresh"] += (bits + 7) // 8

        return bits

    def get_summary(self) -> dict[str, Any]:
        """Get summary of randomness usage."""
        return {
            "seed": self._seed,
            "total_bits": self.total_bits,
            "total_bytes": self.total_bytes,
            "bits_breakdown": self.bits_breakdown,
            "bytes_breakdown": self.bytes_breakdown,
            "config": {
                "fresh_mask_bits_per_byte": self._config.fresh_mask_bits_per_byte,
                "dom_gadget_bits_base": self._config.dom_gadget_bits_base,
                "ti_gadget_bits_base": self._config.ti_gadget_bits_base,
                "remasking_bits_per_byte": self._config.remasking_bits_per_byte,
                "and_gadgets_per_sbox": self._config.and_gadgets_per_sbox,
            },
        }


class _SeededRNG:
    """Simple seeded PRNG for reproducibility.

    Uses a linear congruential generator (LCG) for simplicity.
    NOT cryptographically secure - for testing/reproducibility only.
    """

    def __init__(self, seed: int):
        self._state = seed & 0xFFFFFFFFFFFFFFFF
        self._a = 6364136223846793005
        self._c = 1442695040888963407
        self._m = 2**64

    def _next(self) -> int:
        """Generate next random value."""
        self._state = (self._a * self._state + self._c) % self._m
        return self._state

    def get_bytes(self, count: int) -> bytes:
        """Generate random bytes."""
        result = bytearray(count)
        for i in range(count):
            result[i] = self._next() & 0xFF
        return bytes(result)

    def get_bits(self, count: int) -> int:
        """Generate random bits as integer."""
        if count <= 0:
            return 0
        value = self._next()
        # Mask to requested number of bits
        return value & ((1 << count) - 1)
