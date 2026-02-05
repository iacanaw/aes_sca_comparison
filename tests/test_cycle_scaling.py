"""Tests for cycle scaling with S-box parallelism."""

import pytest
import secrets

from aes_eval.interfaces import EvalConfig
from aes_eval.cycle_models import (
    CycleModel,
    CycleModelConfig,
    IterativeRoundsCycleModel,
    PipelinedRoundsCycleModel,
    create_cycle_model,
)
from aes_eval.randomness import RandomSource
from aes_eval.implementations import TECHNIQUES, get_technique


class TestCycleModelBasics:
    """Basic tests for cycle models."""

    def test_sbox_groups_calculation(self) -> None:
        """Test S-box group calculation."""
        model = IterativeRoundsCycleModel(sbox_parallelism=1)
        assert model.sbox_groups(16) == 16

        model = IterativeRoundsCycleModel(sbox_parallelism=4)
        assert model.sbox_groups(16) == 4

        model = IterativeRoundsCycleModel(sbox_parallelism=5)
        assert model.sbox_groups(16) == 4  # ceil(16/5) = 4

        model = IterativeRoundsCycleModel(sbox_parallelism=16)
        assert model.sbox_groups(16) == 1

    def test_reset_clears_counters(self) -> None:
        """Test that reset clears all counters."""
        model = IterativeRoundsCycleModel(sbox_parallelism=8)

        model.account_sub_bytes()
        model.account_shift_rows()
        assert model.total_cycles > 0

        model.reset()
        assert model.total_cycles == 0
        assert all(v == 0 for v in model.breakdown.values())

    def test_account_accumulates(self) -> None:
        """Test that accounting accumulates correctly."""
        model = IterativeRoundsCycleModel(sbox_parallelism=4)

        cycles1 = model.account_sub_bytes()
        cycles2 = model.account_sub_bytes()

        assert model.breakdown["sub_bytes"] == cycles1 + cycles2

    @pytest.mark.parametrize("sbox_par", [1, 2, 4, 8, 16])
    def test_valid_parallelism_values(self, sbox_par: int) -> None:
        """Test that valid parallelism values work."""
        model = IterativeRoundsCycleModel(sbox_parallelism=sbox_par)
        assert model.sbox_parallelism == sbox_par

    def test_invalid_parallelism_raises(self) -> None:
        """Test that invalid parallelism raises error."""
        with pytest.raises(ValueError):
            IterativeRoundsCycleModel(sbox_parallelism=0)

        with pytest.raises(ValueError):
            IterativeRoundsCycleModel(sbox_parallelism=17)


class TestCycleScalingWithParallelism:
    """Test that cycles scale inversely with S-box parallelism."""

    @pytest.mark.parametrize("technique_name", list(TECHNIQUES.keys()))
    def test_cycles_decrease_with_parallelism(self, technique_name: str) -> None:
        """Test that cycles decrease as parallelism increases."""
        technique_cls = get_technique(technique_name)
        technique = technique_cls()

        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        cycles_by_par: dict[int, int] = {}

        for sbox_par in [1, 4, 8, 16]:
            config = EvalConfig(sbox_parallelism=sbox_par, mask_order_d=0)
            rng = RandomSource(seed=42)
            cycle_model = create_cycle_model(config.round_arch, sbox_par)

            result = technique.encrypt_block(key, pt, rng, cycle_model, config)
            cycles_by_par[sbox_par] = result.cycle_count_total

        # Cycles should decrease (or stay same) as parallelism increases
        # sbox_par=1 should have most cycles
        # sbox_par=16 should have fewest
        assert cycles_by_par[1] >= cycles_by_par[4]
        assert cycles_by_par[4] >= cycles_by_par[8]
        assert cycles_by_par[8] >= cycles_by_par[16]

    def test_sub_bytes_cycles_scale_exactly(self) -> None:
        """Test that SubBytes cycles scale exactly with groups."""
        config_default = CycleModelConfig(sbox_cycles_per_group=1)

        for sbox_par in [1, 4, 8, 16]:
            model = IterativeRoundsCycleModel(sbox_par, config_default)

            cycles = model.account_sub_bytes(16)
            expected_groups = (16 + sbox_par - 1) // sbox_par
            expected_cycles = expected_groups * 1  # 1 cycle per group

            assert cycles == expected_cycles, (
                f"sbox_par={sbox_par}: expected {expected_cycles}, got {cycles}"
            )

    def test_full_encryption_estimate(self) -> None:
        """Test full encryption cycle estimate."""
        model = IterativeRoundsCycleModel(sbox_parallelism=16)
        total = model.estimate_full_encryption(num_rounds=10)

        # Should have non-zero cycles
        assert total > 0

        # Breakdown should sum to total
        assert sum(model.breakdown.values()) == total

        # Key schedule should be present
        assert model.breakdown["key_schedule"] > 0

        # 10 rounds of SubBytes
        assert model.breakdown["sub_bytes"] > 0


class TestCycleScalingMonotonicity:
    """Test monotonicity of cycle counts."""

    def test_more_parallelism_never_increases_cycles(self) -> None:
        """Test that increasing parallelism never increases total cycles."""
        technique = get_technique("unmasked_baseline")()

        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        prev_cycles = float("inf")

        for sbox_par in [1, 2, 4, 5, 8, 16]:
            config = EvalConfig(sbox_parallelism=sbox_par, mask_order_d=0)
            rng = RandomSource(seed=42)
            cycle_model = create_cycle_model(config.round_arch, sbox_par)

            result = technique.encrypt_block(key, pt, rng, cycle_model, config)

            assert result.cycle_count_total <= prev_cycles, (
                f"Cycles increased when parallelism went to {sbox_par}"
            )
            prev_cycles = result.cycle_count_total

    def test_sub_bytes_is_main_variable_cost(self) -> None:
        """Test that SubBytes is the main cost that varies with parallelism."""
        technique = get_technique("unmasked_baseline")()

        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        breakdown_par1 = None
        breakdown_par16 = None

        for sbox_par in [1, 16]:
            config = EvalConfig(sbox_parallelism=sbox_par, mask_order_d=0)
            rng = RandomSource(seed=42)
            cycle_model = create_cycle_model(config.round_arch, sbox_par)

            result = technique.encrypt_block(key, pt, rng, cycle_model, config)

            if sbox_par == 1:
                breakdown_par1 = result.cycle_breakdown.copy()
            else:
                breakdown_par16 = result.cycle_breakdown.copy()

        # SubBytes should change significantly
        assert breakdown_par1 is not None
        assert breakdown_par16 is not None
        assert breakdown_par1["sub_bytes"] > breakdown_par16["sub_bytes"]

        # Other stages should remain constant
        assert breakdown_par1["shift_rows"] == breakdown_par16["shift_rows"]
        assert breakdown_par1["add_round_key"] == breakdown_par16["add_round_key"]


class TestPipelinedCycleModel:
    """Tests for pipelined cycle model."""

    def test_initiation_interval(self) -> None:
        """Test initiation interval calculation."""
        model = PipelinedRoundsCycleModel(sbox_parallelism=16)
        ii = model.initiation_interval

        # II should be at least 1
        assert ii >= 1

    def test_pipelined_has_lower_effective_latency(self) -> None:
        """Test that pipelined model has lower effective per-block latency."""
        iterative = IterativeRoundsCycleModel(sbox_parallelism=16)
        pipelined = PipelinedRoundsCycleModel(sbox_parallelism=16)

        iter_total = iterative.estimate_full_encryption()

        # For pipelined, effective throughput is based on II
        # After filling pipeline, one block completes per II cycles
        assert pipelined.initiation_interval <= iter_total

    def test_create_cycle_model_factory(self) -> None:
        """Test cycle model factory function."""
        iter_model = create_cycle_model("iterative_rounds", 8)
        assert isinstance(iter_model, IterativeRoundsCycleModel)

        pipe_model = create_cycle_model("pipelined_rounds", 8)
        assert isinstance(pipe_model, PipelinedRoundsCycleModel)

        with pytest.raises(ValueError):
            create_cycle_model("unknown_arch", 8)
