"""Tests for randomness scaling with masking order."""

import pytest
import secrets

from aes_eval.interfaces import EvalConfig
from aes_eval.cycle_models import create_cycle_model
from aes_eval.randomness import RandomSource, RandomnessModelConfig
from aes_eval.implementations import TECHNIQUES, get_technique


class TestRandomSourceBasics:
    """Basic tests for RandomSource."""

    def test_default_initialization(self) -> None:
        """Test default initialization."""
        rng = RandomSource()
        assert rng.total_bits == 0
        assert rng.total_bytes == 0

    def test_seeded_determinism(self) -> None:
        """Test that seeded RNG is deterministic."""
        rng1 = RandomSource(seed=12345)
        rng2 = RandomSource(seed=12345)

        bytes1 = rng1.get_bytes(32, "other")
        bytes2 = rng2.get_bytes(32, "other")

        assert bytes1 == bytes2

    def test_different_seeds_different_output(self) -> None:
        """Test that different seeds produce different output."""
        rng1 = RandomSource(seed=12345)
        rng2 = RandomSource(seed=54321)

        bytes1 = rng1.get_bytes(32, "other")
        bytes2 = rng2.get_bytes(32, "other")

        assert bytes1 != bytes2

    def test_tracking_bytes(self) -> None:
        """Test byte tracking."""
        rng = RandomSource(seed=42)

        rng.get_bytes(10, "fresh_masks")
        rng.get_bytes(20, "gadget_randomness")

        assert rng.total_bytes == 30
        assert rng.bytes_breakdown["fresh_masks"] == 10
        assert rng.bytes_breakdown["gadget_randomness"] == 20

    def test_tracking_bits(self) -> None:
        """Test bit tracking."""
        rng = RandomSource(seed=42)

        rng.get_bits(32, "fresh_masks")
        rng.get_bits(64, "gadget_randomness")

        assert rng.total_bits == 96
        assert rng.bits_breakdown["fresh_masks"] == 32
        assert rng.bits_breakdown["gadget_randomness"] == 64

    def test_reset_clears_counters(self) -> None:
        """Test that reset clears counters."""
        rng = RandomSource(seed=42)

        rng.get_bytes(100, "fresh_masks")
        assert rng.total_bytes == 100

        rng.reset()
        assert rng.total_bytes == 0
        assert rng.total_bits == 0

    def test_unknown_category_goes_to_other(self) -> None:
        """Test that unknown categories go to 'other'."""
        rng = RandomSource(seed=42)

        rng.get_bytes(10, "unknown_category")

        assert rng.bytes_breakdown["other"] == 10


class TestRandomnessEstimates:
    """Tests for randomness estimation functions."""

    def test_fresh_masks_scales_with_shares(self) -> None:
        """Test that fresh mask randomness scales with shares."""
        config = RandomnessModelConfig()
        rng = RandomSource(seed=42, config=config)

        # For shares=1, no fresh masks needed
        bits_1 = rng.estimate_fresh_masks(shares=1, state_bytes=16)
        assert bits_1 == 0

        rng.reset()

        # For shares=2, need 1 mask per byte
        bits_2 = rng.estimate_fresh_masks(shares=2, state_bytes=16)
        assert bits_2 == 1 * 16 * 8  # (shares-1) * bytes * bits_per_byte

        rng.reset()

        # For shares=3, need 2 masks per byte
        bits_3 = rng.estimate_fresh_masks(shares=3, state_bytes=16)
        assert bits_3 == 2 * 16 * 8

        # Should scale: shares=3 > shares=2 > shares=1
        assert bits_3 > bits_2 > bits_1

    def test_dom_gadgets_scale_quadratically(self) -> None:
        """Test that DOM gadget randomness scales with shares."""
        rng = RandomSource(seed=42)

        # DOM needs (s-1)*s/2 bits per gadget
        # For s=2: 1 bit per gadget
        bits_2 = rng.estimate_dom_gadgets(shares=2, num_sboxes=16)

        rng.reset()

        # For s=3: 3 bits per gadget
        bits_3 = rng.estimate_dom_gadgets(shares=3, num_sboxes=16)

        # s=3 should use more randomness than s=2
        assert bits_3 > bits_2

    def test_ti_gadgets_scale_linearly(self) -> None:
        """Test that TI gadget randomness scales with shares."""
        rng = RandomSource(seed=42)

        # TI needs s bits per gadget
        bits_2 = rng.estimate_ti_gadgets(shares=2, num_sboxes=16)

        rng.reset()

        bits_3 = rng.estimate_ti_gadgets(shares=3, num_sboxes=16)

        # s=3 should use more randomness than s=2
        assert bits_3 > bits_2

    def test_remasking_scales_with_shares(self) -> None:
        """Test that remasking randomness scales with shares."""
        rng = RandomSource(seed=42)

        bits_1 = rng.estimate_remasking(shares=1)
        assert bits_1 == 0  # No remasking for unmasked

        rng.reset()

        bits_2 = rng.estimate_remasking(shares=2)

        rng.reset()

        bits_3 = rng.estimate_remasking(shares=3)

        assert bits_3 > bits_2 > bits_1


class TestRandomnessScalingWithMaskOrder:
    """Test that randomness scales correctly with masking order d."""

    @pytest.mark.parametrize("technique_name", ["masked_dom_skeleton", "masked_ti_skeleton"])
    def test_randomness_increases_with_d(self, technique_name: str) -> None:
        """Test that randomness strictly increases with masking order."""
        technique = get_technique(technique_name)()

        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        random_by_d: dict[int, int] = {}

        for d in [0, 1, 2]:
            config = EvalConfig(sbox_parallelism=16, mask_order_d=d)
            rng = RandomSource(seed=42)
            cycle_model = create_cycle_model(config.round_arch, 16)

            result = technique.encrypt_block(key, pt, rng, cycle_model, config)
            random_by_d[d] = result.random_bits_total

        # Strict increase with d
        assert random_by_d[1] > random_by_d[0], (
            f"d=1 ({random_by_d[1]}) should use more randomness than d=0 ({random_by_d[0]})"
        )
        assert random_by_d[2] > random_by_d[1], (
            f"d=2 ({random_by_d[2]}) should use more randomness than d=1 ({random_by_d[1]})"
        )

    def test_unmasked_baseline_uses_no_randomness(self) -> None:
        """Test that unmasked baseline uses no randomness regardless of d."""
        technique = get_technique("unmasked_baseline")()

        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        for d in [0, 1, 2]:
            config = EvalConfig(sbox_parallelism=16, mask_order_d=d)
            rng = RandomSource(seed=42)
            cycle_model = create_cycle_model(config.round_arch, 16)

            result = technique.encrypt_block(key, pt, rng, cycle_model, config)

            # Unmasked should use no randomness
            assert result.random_bits_total == 0

    @pytest.mark.parametrize("technique_name", ["masked_dom_skeleton", "masked_ti_skeleton"])
    def test_randomness_breakdown_populated(self, technique_name: str) -> None:
        """Test that randomness breakdown is properly populated."""
        technique = get_technique(technique_name)()

        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        config = EvalConfig(sbox_parallelism=16, mask_order_d=2)
        rng = RandomSource(seed=42)
        cycle_model = create_cycle_model(config.round_arch, 16)

        result = technique.encrypt_block(key, pt, rng, cycle_model, config)

        # Should have positive values in breakdown
        breakdown = result.random_bits_breakdown
        assert breakdown["fresh_masks"] > 0
        assert breakdown["gadget_randomness"] > 0
        assert breakdown["refresh"] > 0

        # Total should match sum of breakdown
        total_from_breakdown = sum(breakdown.values())
        assert result.random_bits_total == total_from_breakdown


class TestRandomnessMonotonicity:
    """Test monotonicity of randomness consumption."""

    @pytest.mark.parametrize("technique_name", ["masked_dom_skeleton", "masked_ti_skeleton"])
    def test_randomness_monotonic_in_d(self, technique_name: str) -> None:
        """Test that randomness is monotonically increasing in d."""
        technique = get_technique(technique_name)()

        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        prev_random = -1

        for d in [0, 1, 2]:
            config = EvalConfig(sbox_parallelism=16, mask_order_d=d)
            rng = RandomSource(seed=42)
            cycle_model = create_cycle_model(config.round_arch, 16)

            result = technique.encrypt_block(key, pt, rng, cycle_model, config)

            assert result.random_bits_total >= prev_random, (
                f"Randomness decreased when d went from {d-1} to {d}"
            )
            prev_random = result.random_bits_total

    def test_randomness_independent_of_sbox_parallelism(self) -> None:
        """Test that total randomness doesn't change with sbox parallelism."""
        technique = get_technique("masked_dom_skeleton")()

        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        random_by_par: dict[int, int] = {}

        for sbox_par in [1, 4, 16]:
            config = EvalConfig(sbox_parallelism=sbox_par, mask_order_d=1)
            rng = RandomSource(seed=42)
            cycle_model = create_cycle_model(config.round_arch, sbox_par)

            result = technique.encrypt_block(key, pt, rng, cycle_model, config)
            random_by_par[sbox_par] = result.random_bits_total

        # Randomness should be the same regardless of parallelism
        # (parallelism affects cycles, not randomness)
        assert random_by_par[1] == random_by_par[4] == random_by_par[16]


class TestDOMvsTIRandomness:
    """Compare DOM and TI randomness patterns."""

    def test_dom_vs_ti_both_scale_with_d(self) -> None:
        """Test that both DOM and TI scale with d."""
        dom = get_technique("masked_dom_skeleton")()
        ti = get_technique("masked_ti_skeleton")()

        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        for d in [1, 2]:
            config = EvalConfig(sbox_parallelism=16, mask_order_d=d)

            rng_dom = RandomSource(seed=42)
            cycle_dom = create_cycle_model(config.round_arch, 16)
            result_dom = dom.encrypt_block(key, pt, rng_dom, cycle_dom, config)

            rng_ti = RandomSource(seed=42)
            cycle_ti = create_cycle_model(config.round_arch, 16)
            result_ti = ti.encrypt_block(key, pt, rng_ti, cycle_ti, config)

            # Both should use randomness when d > 0
            assert result_dom.random_bits_total > 0
            assert result_ti.random_bits_total > 0

    def test_gadget_randomness_differs(self) -> None:
        """Test that gadget randomness differs between DOM and TI."""
        dom = get_technique("masked_dom_skeleton")()
        ti = get_technique("masked_ti_skeleton")()

        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        config = EvalConfig(sbox_parallelism=16, mask_order_d=2)

        rng_dom = RandomSource(seed=42)
        cycle_dom = create_cycle_model(config.round_arch, 16)
        result_dom = dom.encrypt_block(key, pt, rng_dom, cycle_dom, config)

        rng_ti = RandomSource(seed=42)
        cycle_ti = create_cycle_model(config.round_arch, 16)
        result_ti = ti.encrypt_block(key, pt, rng_ti, cycle_ti, config)

        # Gadget randomness should differ (different formulas)
        dom_gadgets = result_dom.random_bits_breakdown["gadget_randomness"]
        ti_gadgets = result_ti.random_bits_breakdown["gadget_randomness"]

        # They use different formulas, so values should differ
        # (DOM: (s-1)*s/2 per gadget, TI: s per gadget)
        assert dom_gadgets != ti_gadgets
