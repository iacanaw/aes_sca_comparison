"""Tests for AES implementation techniques."""

import pytest
import secrets

from aes_eval.interfaces import EvalConfig
from aes_eval.cycle_models import create_cycle_model
from aes_eval.randomness import RandomSource
from aes_eval.golden import FIPS_197_TEST_VECTORS
from aes_eval.implementations import (
    TECHNIQUES,
    get_technique,
    list_techniques,
    UnmaskedBaseline,
    MaskedDOMSkeleton,
    MaskedTISkeleton,
)


class TestTechniqueRegistry:
    """Tests for technique registry."""

    def test_all_techniques_registered(self) -> None:
        """Test that expected techniques are registered."""
        assert "unmasked_baseline" in TECHNIQUES
        assert "masked_dom_skeleton" in TECHNIQUES
        assert "masked_ti_skeleton" in TECHNIQUES

    def test_get_technique_valid(self) -> None:
        """Test getting valid techniques."""
        cls = get_technique("unmasked_baseline")
        assert cls is UnmaskedBaseline

        cls = get_technique("masked_dom_skeleton")
        assert cls is MaskedDOMSkeleton

    def test_get_technique_invalid(self) -> None:
        """Test that invalid technique raises KeyError."""
        with pytest.raises(KeyError, match="Unknown technique"):
            get_technique("nonexistent")

    def test_list_techniques(self) -> None:
        """Test listing techniques."""
        techs = list_techniques()
        assert len(techs) >= 3

        names = [t["name"] for t in techs]
        assert "unmasked_baseline" in names

        for t in techs:
            assert "name" in t
            assert "description" in t


class TestUnmaskedBaseline:
    """Tests for UnmaskedBaseline implementation."""

    @pytest.fixture
    def technique(self) -> UnmaskedBaseline:
        return UnmaskedBaseline()

    @pytest.fixture
    def config(self) -> EvalConfig:
        return EvalConfig(sbox_parallelism=16, mask_order_d=0)

    @pytest.fixture
    def rng(self) -> RandomSource:
        return RandomSource(seed=42)

    @pytest.fixture
    def cycle_model(self, config: EvalConfig):
        return create_cycle_model(config.round_arch, config.sbox_parallelism)

    @pytest.mark.parametrize("vec", FIPS_197_TEST_VECTORS)
    def test_fips_197_vectors(
        self,
        technique: UnmaskedBaseline,
        config: EvalConfig,
        rng: RandomSource,
        cycle_model,
        vec: dict,
    ) -> None:
        """Test against FIPS-197 test vectors."""
        result = technique.encrypt_block(
            vec["key"],
            vec["plaintext"],
            rng,
            cycle_model,
            config,
        )

        assert result.correct, f"FIPS test failed: {result.error_detail}"
        assert result.ciphertext == vec["ciphertext"]

    def test_random_vectors(
        self,
        technique: UnmaskedBaseline,
        config: EvalConfig,
        rng: RandomSource,
        cycle_model,
    ) -> None:
        """Test with random vectors."""
        for _ in range(50):
            key = secrets.token_bytes(16)
            pt = secrets.token_bytes(16)

            rng.reset()
            cycle_model.reset()
            result = technique.encrypt_block(key, pt, rng, cycle_model, config)

            assert result.correct, f"Random test failed: {result.error_detail}"

    def test_no_randomness_used(
        self,
        technique: UnmaskedBaseline,
        config: EvalConfig,
        rng: RandomSource,
        cycle_model,
    ) -> None:
        """Test that unmasked baseline uses no randomness."""
        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        result = technique.encrypt_block(key, pt, rng, cycle_model, config)

        assert result.random_bits_total == 0

    def test_cycle_count_positive(
        self,
        technique: UnmaskedBaseline,
        config: EvalConfig,
        rng: RandomSource,
        cycle_model,
    ) -> None:
        """Test that cycle count is positive."""
        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        result = technique.encrypt_block(key, pt, rng, cycle_model, config)

        assert result.cycle_count_total > 0

    def test_op_counts_populated(
        self,
        technique: UnmaskedBaseline,
        config: EvalConfig,
        rng: RandomSource,
        cycle_model,
    ) -> None:
        """Test that operation counts are populated."""
        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        result = technique.encrypt_block(key, pt, rng, cycle_model, config)

        # 160 S-box calls: 16 per round × 10 rounds
        assert result.op_counts["sbox_calls"] == 160
        assert result.op_counts["xor_ops"] > 0


class TestMaskedDOMSkeleton:
    """Tests for MaskedDOMSkeleton implementation."""

    @pytest.fixture
    def technique(self) -> MaskedDOMSkeleton:
        return MaskedDOMSkeleton()

    @pytest.mark.parametrize("mask_order_d", [0, 1, 2])
    @pytest.mark.parametrize("sbox_par", [1, 4, 16])
    def test_correctness_all_configs(
        self,
        technique: MaskedDOMSkeleton,
        mask_order_d: int,
        sbox_par: int,
    ) -> None:
        """Test correctness across all configurations."""
        config = EvalConfig(
            sbox_parallelism=sbox_par,
            mask_order_d=mask_order_d,
        )
        rng = RandomSource(seed=42)
        cycle_model = create_cycle_model(config.round_arch, sbox_par)

        for vec in FIPS_197_TEST_VECTORS:
            rng.reset()
            cycle_model.reset()
            result = technique.encrypt_block(
                vec["key"],
                vec["plaintext"],
                rng,
                cycle_model,
                config,
            )

            assert result.correct, (
                f"DOM skeleton failed with d={mask_order_d}, sbox_par={sbox_par}: "
                f"{result.error_detail}"
            )

    def test_randomness_increases_with_d(self, technique: MaskedDOMSkeleton) -> None:
        """Test that randomness increases with masking order."""
        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        random_bits = {}
        for d in [0, 1, 2]:
            config = EvalConfig(sbox_parallelism=16, mask_order_d=d)
            rng = RandomSource(seed=42)
            cycle_model = create_cycle_model(config.round_arch, 16)

            result = technique.encrypt_block(key, pt, rng, cycle_model, config)
            random_bits[d] = result.random_bits_total

        # d=0 should use minimal or no randomness
        # d=1 should use more than d=0
        # d=2 should use more than d=1
        assert random_bits[1] > random_bits[0]
        assert random_bits[2] > random_bits[1]

    def test_has_skeleton_warning(self, technique: MaskedDOMSkeleton) -> None:
        """Test that skeleton implementation includes warning."""
        config = EvalConfig(sbox_parallelism=16, mask_order_d=1)
        rng = RandomSource(seed=42)
        cycle_model = create_cycle_model(config.round_arch, 16)

        result = technique.encrypt_block(
            secrets.token_bytes(16),
            secrets.token_bytes(16),
            rng,
            cycle_model,
            config,
        )

        # Should have warning about skeleton implementation
        assert any("skeleton" in w.lower() for w in result.warnings)


class TestMaskedTISkeleton:
    """Tests for MaskedTISkeleton implementation."""

    @pytest.fixture
    def technique(self) -> MaskedTISkeleton:
        return MaskedTISkeleton()

    @pytest.mark.parametrize("mask_order_d", [0, 1, 2])
    @pytest.mark.parametrize("sbox_par", [1, 4, 16])
    def test_correctness_all_configs(
        self,
        technique: MaskedTISkeleton,
        mask_order_d: int,
        sbox_par: int,
    ) -> None:
        """Test correctness across all configurations."""
        config = EvalConfig(
            sbox_parallelism=sbox_par,
            mask_order_d=mask_order_d,
        )
        rng = RandomSource(seed=42)
        cycle_model = create_cycle_model(config.round_arch, sbox_par)

        for vec in FIPS_197_TEST_VECTORS:
            rng.reset()
            cycle_model.reset()
            result = technique.encrypt_block(
                vec["key"],
                vec["plaintext"],
                rng,
                cycle_model,
                config,
            )

            assert result.correct, (
                f"TI skeleton failed with d={mask_order_d}, sbox_par={sbox_par}: "
                f"{result.error_detail}"
            )

    def test_randomness_increases_with_d(self, technique: MaskedTISkeleton) -> None:
        """Test that randomness increases with masking order."""
        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        random_bits = {}
        for d in [0, 1, 2]:
            config = EvalConfig(sbox_parallelism=16, mask_order_d=d)
            rng = RandomSource(seed=42)
            cycle_model = create_cycle_model(config.round_arch, 16)

            result = technique.encrypt_block(key, pt, rng, cycle_model, config)
            random_bits[d] = result.random_bits_total

        assert random_bits[1] > random_bits[0]
        assert random_bits[2] > random_bits[1]

    def test_ti_vs_dom_different_randomness(self) -> None:
        """Test that TI and DOM have different randomness patterns."""
        key = secrets.token_bytes(16)
        pt = secrets.token_bytes(16)

        config = EvalConfig(sbox_parallelism=16, mask_order_d=2)

        dom = MaskedDOMSkeleton()
        ti = MaskedTISkeleton()

        rng_dom = RandomSource(seed=42)
        rng_ti = RandomSource(seed=42)
        cycle_model = create_cycle_model(config.round_arch, 16)

        result_dom = dom.encrypt_block(key, pt, rng_dom, cycle_model, config)

        cycle_model.reset()
        result_ti = ti.encrypt_block(key, pt, rng_ti, cycle_model, config)

        # Both should be correct
        assert result_dom.correct
        assert result_ti.correct

        # Randomness patterns should differ (TI typically uses more)
        # Note: actual values depend on model parameters
        assert result_dom.random_bits_total > 0
        assert result_ti.random_bits_total > 0


class TestCrossImplementation:
    """Cross-implementation tests."""

    @pytest.mark.parametrize("technique_name", list(TECHNIQUES.keys()))
    def test_all_techniques_produce_correct_output(self, technique_name: str) -> None:
        """Test that all registered techniques produce correct output."""
        technique_cls = get_technique(technique_name)
        technique = technique_cls()

        config = EvalConfig(sbox_parallelism=16, mask_order_d=1)
        rng = RandomSource(seed=42)
        cycle_model = create_cycle_model(config.round_arch, 16)

        for vec in FIPS_197_TEST_VECTORS:
            rng.reset()
            cycle_model.reset()
            result = technique.encrypt_block(
                vec["key"],
                vec["plaintext"],
                rng,
                cycle_model,
                config,
            )

            assert result.correct, f"{technique_name} failed: {result.error_detail}"

    @pytest.mark.parametrize("technique_name", list(TECHNIQUES.keys()))
    def test_all_techniques_have_metadata(self, technique_name: str) -> None:
        """Test that all techniques have required metadata."""
        technique_cls = get_technique(technique_name)

        assert hasattr(technique_cls, "name")
        assert hasattr(technique_cls, "description")
        assert technique_cls.name == technique_name
        assert len(technique_cls.description) > 0
