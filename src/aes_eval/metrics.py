"""Metric calculations for AES evaluation.

Provides latency, throughput, and area proxy calculations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .interfaces import EvalConfig, Result


@dataclass
class AreaProxyConfig:
    """Configuration for area proxy calculations.

    Weights for composite area score:
    composite = alpha * sbox_area + beta * register_area + gamma * extra_ops_area
    """

    # Base area units per S-box instance
    sbox_base_area: float = 100.0

    # Base area units per state bit (for register estimation)
    register_bit_area: float = 1.0

    # Extra operations area multiplier
    extra_ops_multiplier: float = 0.5

    # Weights for composite score
    alpha: float = 1.0  # S-box weight
    beta: float = 0.1   # Register weight
    gamma: float = 0.05 # Extra ops weight


@dataclass
class PerformanceMetrics:
    """Performance metrics for a configuration."""

    # Latency
    latency_cycles: int = 0
    latency_seconds: float = 0.0

    # Throughput (non-pipelined)
    throughput_blocks_per_sec: float = 0.0
    throughput_bits_per_sec: float = 0.0
    throughput_gbps: float = 0.0

    # Throughput (pipelined, if applicable)
    pipelined_throughput_blocks_per_sec: float = 0.0
    pipelined_throughput_gbps: float = 0.0
    initiation_interval: int = 0

    # Randomness
    random_bits_per_block: int = 0
    random_bits_per_sec: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "latency_cycles": self.latency_cycles,
            "latency_seconds": self.latency_seconds,
            "throughput_blocks_per_sec": self.throughput_blocks_per_sec,
            "throughput_bits_per_sec": self.throughput_bits_per_sec,
            "throughput_gbps": self.throughput_gbps,
            "pipelined_throughput_blocks_per_sec": self.pipelined_throughput_blocks_per_sec,
            "pipelined_throughput_gbps": self.pipelined_throughput_gbps,
            "initiation_interval": self.initiation_interval,
            "random_bits_per_block": self.random_bits_per_block,
            "random_bits_per_sec": self.random_bits_per_sec,
        }


@dataclass
class AreaMetrics:
    """Area proxy metrics for a configuration."""

    # Individual components
    sbox_area_proxy: float = 0.0
    register_area_proxy: float = 0.0
    extra_ops_area_proxy: float = 0.0

    # Composite score
    composite_area_proxy: float = 0.0

    # Raw counts for reference
    sbox_count: int = 0
    state_bits: int = 0
    share_count: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "sbox_area_proxy": self.sbox_area_proxy,
            "register_area_proxy": self.register_area_proxy,
            "extra_ops_area_proxy": self.extra_ops_area_proxy,
            "composite_area_proxy": self.composite_area_proxy,
            "sbox_count": self.sbox_count,
            "state_bits": self.state_bits,
            "share_count": self.share_count,
        }


@dataclass
class FullMetrics:
    """Complete metrics for a configuration."""

    # Configuration info
    technique: str = ""
    sbox_parallelism: int = 0
    mask_order_d: int = 0
    shares: int = 1
    round_arch: str = ""
    f_clk_hz: float = 0.0

    # Core result
    correct: bool = False
    cycle_count_total: int = 0
    cycle_breakdown: dict[str, int] = field(default_factory=dict)
    random_bits_total: int = 0
    random_bits_breakdown: dict[str, int] = field(default_factory=dict)
    op_counts: dict[str, int] = field(default_factory=dict)

    # Derived metrics
    performance: PerformanceMetrics = field(default_factory=PerformanceMetrics)
    area: AreaMetrics = field(default_factory=AreaMetrics)

    # Notes and warnings
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "technique": self.technique,
            "sbox_parallelism": self.sbox_parallelism,
            "mask_order_d": self.mask_order_d,
            "shares": self.shares,
            "round_arch": self.round_arch,
            "f_clk_hz": self.f_clk_hz,
            "correct": self.correct,
            "cycle_count_total": self.cycle_count_total,
            "cycle_breakdown": self.cycle_breakdown,
            "random_bits_total": self.random_bits_total,
            "random_bits_breakdown": self.random_bits_breakdown,
            "op_counts": self.op_counts,
            "performance": self.performance.to_dict(),
            "area": self.area.to_dict(),
            "notes": self.notes,
            "warnings": self.warnings,
        }

    def to_flat_dict(self) -> dict[str, Any]:
        """Convert to flattened dictionary for CSV export."""
        flat = {
            "technique": self.technique,
            "sbox_parallelism": self.sbox_parallelism,
            "mask_order_d": self.mask_order_d,
            "shares": self.shares,
            "round_arch": self.round_arch,
            "f_clk_hz": self.f_clk_hz,
            "correct": self.correct,
            "cycle_count_total": self.cycle_count_total,
            "random_bits_total": self.random_bits_total,
        }

        # Flatten cycle breakdown
        for k, v in self.cycle_breakdown.items():
            flat[f"cycles_{k}"] = v

        # Flatten random breakdown
        for k, v in self.random_bits_breakdown.items():
            flat[f"random_{k}"] = v

        # Flatten op counts
        for k, v in self.op_counts.items():
            flat[f"ops_{k}"] = v

        # Flatten performance
        flat.update({
            "latency_cycles": self.performance.latency_cycles,
            "latency_seconds": self.performance.latency_seconds,
            "throughput_blocks_per_sec": self.performance.throughput_blocks_per_sec,
            "throughput_gbps": self.performance.throughput_gbps,
            "random_bits_per_sec": self.performance.random_bits_per_sec,
        })

        # Flatten area
        flat.update({
            "sbox_area_proxy": self.area.sbox_area_proxy,
            "register_area_proxy": self.area.register_area_proxy,
            "composite_area_proxy": self.area.composite_area_proxy,
        })

        return flat


def calculate_performance_metrics(
    result: Result,
    config: EvalConfig,
    initiation_interval: int | None = None,
) -> PerformanceMetrics:
    """Calculate performance metrics from result and config.

    Args:
        result: Encryption result with cycle counts
        config: Evaluation configuration with clock frequency
        initiation_interval: Optional II for pipelined throughput

    Returns:
        PerformanceMetrics instance
    """
    cycles = result.cycle_count_total
    f_clk = config.f_clk_hz

    # Latency
    latency_seconds = cycles / f_clk if f_clk > 0 else 0.0

    # Throughput (non-pipelined)
    throughput_blocks = f_clk / cycles if cycles > 0 else 0.0
    throughput_bits = throughput_blocks * 128  # 128 bits per block
    throughput_gbps = throughput_bits / 1e9

    # Pipelined throughput
    ii = initiation_interval or cycles  # Default to latency if no II provided
    pipelined_blocks = f_clk / ii if ii > 0 else 0.0
    pipelined_gbps = (pipelined_blocks * 128) / 1e9

    # Randomness rate
    random_per_sec = result.random_bits_total * throughput_blocks

    return PerformanceMetrics(
        latency_cycles=cycles,
        latency_seconds=latency_seconds,
        throughput_blocks_per_sec=throughput_blocks,
        throughput_bits_per_sec=throughput_bits,
        throughput_gbps=throughput_gbps,
        pipelined_throughput_blocks_per_sec=pipelined_blocks,
        pipelined_throughput_gbps=pipelined_gbps,
        initiation_interval=ii,
        random_bits_per_block=result.random_bits_total,
        random_bits_per_sec=random_per_sec,
    )


def calculate_area_metrics(
    config: EvalConfig,
    op_counts: dict[str, int] | None = None,
    area_config: AreaProxyConfig | None = None,
) -> AreaMetrics:
    """Calculate area proxy metrics from configuration.

    Args:
        config: Evaluation configuration
        op_counts: Optional operation counts for extra ops estimation
        area_config: Optional area proxy configuration

    Returns:
        AreaMetrics instance
    """
    area_cfg = area_config or AreaProxyConfig()
    op_counts = op_counts or {}

    # S-box area (based on parallelism)
    sbox_count = config.sbox_parallelism
    sbox_area = sbox_count * area_cfg.sbox_base_area

    # Register area (based on shares and state size)
    # AES state = 128 bits, key = 128 bits
    state_bits = 128 * 2  # State + key registers
    shares = config.shares
    register_area = state_bits * shares * area_cfg.register_bit_area

    # Extra operations area (from op_counts)
    extra_ops = sum(v for k, v in op_counts.items() if k not in ("sbox_calls", "xor_ops"))
    extra_ops_area = extra_ops * area_cfg.extra_ops_multiplier

    # Composite score
    composite = (
        area_cfg.alpha * sbox_area +
        area_cfg.beta * register_area +
        area_cfg.gamma * extra_ops_area
    )

    return AreaMetrics(
        sbox_area_proxy=sbox_area,
        register_area_proxy=register_area,
        extra_ops_area_proxy=extra_ops_area,
        composite_area_proxy=composite,
        sbox_count=sbox_count,
        state_bits=state_bits * shares,
        share_count=shares,
    )


def calculate_full_metrics(
    result: Result,
    config: EvalConfig,
    technique_name: str,
    initiation_interval: int | None = None,
    area_config: AreaProxyConfig | None = None,
) -> FullMetrics:
    """Calculate all metrics from result and config.

    Args:
        result: Encryption result
        config: Evaluation configuration
        technique_name: Name of the technique used
        initiation_interval: Optional II for pipelined throughput
        area_config: Optional area proxy configuration

    Returns:
        FullMetrics instance
    """
    perf = calculate_performance_metrics(result, config, initiation_interval)
    area = calculate_area_metrics(config, result.op_counts, area_config)

    return FullMetrics(
        technique=technique_name,
        sbox_parallelism=config.sbox_parallelism,
        mask_order_d=config.mask_order_d,
        shares=config.shares,
        round_arch=config.round_arch,
        f_clk_hz=config.f_clk_hz,
        correct=result.correct,
        cycle_count_total=result.cycle_count_total,
        cycle_breakdown=result.cycle_breakdown.copy(),
        random_bits_total=result.random_bits_total,
        random_bits_breakdown=result.random_bits_breakdown.copy(),
        op_counts=result.op_counts.copy(),
        performance=perf,
        area=area,
        notes=result.notes.copy(),
        warnings=result.warnings.copy(),
    )
