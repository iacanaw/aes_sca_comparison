"""Cycle model abstractions for AES evaluation.

Provides configurable cycle accounting based on S-box parallelism
and round architecture.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CycleModelConfig:
    """Configuration for cycle model costs.

    All costs are in cycles per operation/group.
    """

    # Cost per S-box group evaluation (group = sbox_parallelism S-boxes)
    sbox_cycles_per_group: int = 1

    # Fixed costs per round stage
    shift_rows_cycles: int = 1
    mix_columns_cycles: int = 1
    add_round_key_cycles: int = 1

    # Key schedule cost per round
    key_schedule_cycles_per_round: int = 1

    # Refresh/remasking cost (for masked implementations)
    refresh_cycles_per_round: int = 0

    # Initial round (just AddRoundKey, no SubBytes/ShiftRows/MixColumns)
    initial_round_cycles: int = 1

    # Final round (no MixColumns)
    final_round_skip_mixcolumns: bool = True


class CycleModel(ABC):
    """Abstract base class for cycle models.

    Provides cycle accounting based on S-box parallelism and stage costs.
    """

    def __init__(
        self,
        sbox_parallelism: int,
        config: CycleModelConfig | None = None,
    ):
        """Initialize cycle model.

        Args:
            sbox_parallelism: Number of S-boxes evaluated in parallel (1..16)
            config: Optional custom cycle costs
        """
        if not 1 <= sbox_parallelism <= 16:
            raise ValueError(f"sbox_parallelism must be 1..16, got {sbox_parallelism}")

        self.sbox_parallelism = sbox_parallelism
        self.config = config or CycleModelConfig()
        self._breakdown: dict[str, int] = {}
        self.reset()

    def reset(self) -> None:
        """Reset cycle counters."""
        self._breakdown = {
            "key_schedule": 0,
            "add_round_key": 0,
            "sub_bytes": 0,
            "shift_rows": 0,
            "mix_columns": 0,
            "refresh": 0,
        }

    @property
    def total_cycles(self) -> int:
        """Total cycles accumulated."""
        return sum(self._breakdown.values())

    @property
    def breakdown(self) -> dict[str, int]:
        """Get cycle breakdown by stage."""
        return self._breakdown.copy()

    def sbox_groups(self, num_bytes: int = 16) -> int:
        """Calculate number of S-box groups needed.

        Args:
            num_bytes: Number of bytes to process (default 16 for AES state)

        Returns:
            Number of groups = ceil(num_bytes / sbox_parallelism)
        """
        return math.ceil(num_bytes / self.sbox_parallelism)

    @abstractmethod
    def account_sub_bytes(self, num_bytes: int = 16) -> int:
        """Account cycles for SubBytes operation.

        Args:
            num_bytes: Number of bytes to process

        Returns:
            Cycles for this operation
        """
        raise NotImplementedError

    @abstractmethod
    def account_shift_rows(self) -> int:
        """Account cycles for ShiftRows operation."""
        raise NotImplementedError

    @abstractmethod
    def account_mix_columns(self) -> int:
        """Account cycles for MixColumns operation."""
        raise NotImplementedError

    @abstractmethod
    def account_add_round_key(self) -> int:
        """Account cycles for AddRoundKey operation."""
        raise NotImplementedError

    @abstractmethod
    def account_key_schedule(self, num_rounds: int = 10) -> int:
        """Account cycles for key schedule.

        Args:
            num_rounds: Number of rounds (default 10 for AES-128)

        Returns:
            Total cycles for key schedule
        """
        raise NotImplementedError

    @abstractmethod
    def account_refresh(self) -> int:
        """Account cycles for refresh/remasking (masked implementations)."""
        raise NotImplementedError

    def get_summary(self) -> dict[str, Any]:
        """Get summary of cycle model configuration and state."""
        return {
            "model_type": self.__class__.__name__,
            "sbox_parallelism": self.sbox_parallelism,
            "sbox_groups_per_round": self.sbox_groups(),
            "config": {
                "sbox_cycles_per_group": self.config.sbox_cycles_per_group,
                "shift_rows_cycles": self.config.shift_rows_cycles,
                "mix_columns_cycles": self.config.mix_columns_cycles,
                "add_round_key_cycles": self.config.add_round_key_cycles,
                "key_schedule_cycles_per_round": self.config.key_schedule_cycles_per_round,
                "refresh_cycles_per_round": self.config.refresh_cycles_per_round,
            },
            "total_cycles": self.total_cycles,
            "breakdown": self.breakdown,
        }


class IterativeRoundsCycleModel(CycleModel):
    """Cycle model for iterative round architecture.

    Each round executes sequentially, with SubBytes taking
    ceil(16/sbox_parallelism) cycles.
    """

    def account_sub_bytes(self, num_bytes: int = 16) -> int:
        """Account cycles for SubBytes.

        Cycles = ceil(num_bytes / sbox_parallelism) * cost_per_group
        """
        groups = self.sbox_groups(num_bytes)
        cycles = groups * self.config.sbox_cycles_per_group
        self._breakdown["sub_bytes"] += cycles
        return cycles

    def account_shift_rows(self) -> int:
        """Account cycles for ShiftRows (fixed cost)."""
        cycles = self.config.shift_rows_cycles
        self._breakdown["shift_rows"] += cycles
        return cycles

    def account_mix_columns(self) -> int:
        """Account cycles for MixColumns (fixed cost)."""
        cycles = self.config.mix_columns_cycles
        self._breakdown["mix_columns"] += cycles
        return cycles

    def account_add_round_key(self) -> int:
        """Account cycles for AddRoundKey (fixed cost)."""
        cycles = self.config.add_round_key_cycles
        self._breakdown["add_round_key"] += cycles
        return cycles

    def account_key_schedule(self, num_rounds: int = 10) -> int:
        """Account cycles for key schedule.

        Assumes key schedule is computed once at the start.
        """
        cycles = num_rounds * self.config.key_schedule_cycles_per_round
        self._breakdown["key_schedule"] += cycles
        return cycles

    def account_refresh(self) -> int:
        """Account cycles for refresh/remasking."""
        cycles = self.config.refresh_cycles_per_round
        self._breakdown["refresh"] += cycles
        return cycles

    def estimate_full_encryption(
        self,
        num_rounds: int = 10,
        include_refresh: bool = False,
    ) -> int:
        """Estimate total cycles for full AES encryption.

        Args:
            num_rounds: Number of rounds (default 10 for AES-128)
            include_refresh: Whether to include refresh cycles (masked only)

        Returns:
            Estimated total cycles

        Note:
            This is an estimate; actual accounting should use individual
            account_* methods during encryption.
        """
        self.reset()

        # Key schedule
        self.account_key_schedule(num_rounds)

        # Initial round (just AddRoundKey)
        self.account_add_round_key()

        # Main rounds 1-9
        for _ in range(num_rounds - 1):
            self.account_sub_bytes()
            self.account_shift_rows()
            self.account_mix_columns()
            self.account_add_round_key()
            if include_refresh:
                self.account_refresh()

        # Final round (no MixColumns)
        self.account_sub_bytes()
        self.account_shift_rows()
        self.account_add_round_key()

        return self.total_cycles


class PipelinedRoundsCycleModel(CycleModel):
    """Cycle model for pipelined round architecture.

    Provides initiation interval (II) for throughput calculations.
    Latency remains similar to iterative, but throughput is higher.
    """

    def __init__(
        self,
        sbox_parallelism: int,
        config: CycleModelConfig | None = None,
        pipeline_stages: int = 10,
    ):
        """Initialize pipelined model.

        Args:
            sbox_parallelism: Number of S-boxes in parallel
            config: Optional custom cycle costs
            pipeline_stages: Number of pipeline stages (typically num_rounds)
        """
        super().__init__(sbox_parallelism, config)
        self.pipeline_stages = pipeline_stages

    @property
    def initiation_interval(self) -> int:
        """Initiation interval: cycles between starting new blocks.

        For ideal pipelining, II = 1. Here we model based on the
        longest stage (typically SubBytes).
        """
        # Simplified: II = max stage latency
        sub_bytes_cycles = self.sbox_groups() * self.config.sbox_cycles_per_group
        return max(
            sub_bytes_cycles,
            self.config.shift_rows_cycles,
            self.config.mix_columns_cycles,
            self.config.add_round_key_cycles,
        )

    def account_sub_bytes(self, num_bytes: int = 16) -> int:
        groups = self.sbox_groups(num_bytes)
        cycles = groups * self.config.sbox_cycles_per_group
        self._breakdown["sub_bytes"] += cycles
        return cycles

    def account_shift_rows(self) -> int:
        cycles = self.config.shift_rows_cycles
        self._breakdown["shift_rows"] += cycles
        return cycles

    def account_mix_columns(self) -> int:
        cycles = self.config.mix_columns_cycles
        self._breakdown["mix_columns"] += cycles
        return cycles

    def account_add_round_key(self) -> int:
        cycles = self.config.add_round_key_cycles
        self._breakdown["add_round_key"] += cycles
        return cycles

    def account_key_schedule(self, num_rounds: int = 10) -> int:
        cycles = num_rounds * self.config.key_schedule_cycles_per_round
        self._breakdown["key_schedule"] += cycles
        return cycles

    def account_refresh(self) -> int:
        cycles = self.config.refresh_cycles_per_round
        self._breakdown["refresh"] += cycles
        return cycles


def create_cycle_model(
    arch: str,
    sbox_parallelism: int,
    config: CycleModelConfig | None = None,
) -> CycleModel:
    """Factory function to create cycle models.

    Args:
        arch: Architecture type ("iterative_rounds" or "pipelined_rounds")
        sbox_parallelism: Number of S-boxes in parallel
        config: Optional custom cycle costs

    Returns:
        Appropriate CycleModel instance

    Raises:
        ValueError: If arch is unknown
    """
    if arch == "iterative_rounds":
        return IterativeRoundsCycleModel(sbox_parallelism, config)
    elif arch == "pipelined_rounds":
        return PipelinedRoundsCycleModel(sbox_parallelism, config)
    elif arch == "fully_unrolled":
        # Fully unrolled is similar to pipelined with II=1
        return PipelinedRoundsCycleModel(sbox_parallelism, config, pipeline_stages=1)
    else:
        raise ValueError(f"Unknown round architecture: {arch}")
