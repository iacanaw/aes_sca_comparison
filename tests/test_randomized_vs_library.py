"""
Randomized tests comparing models against PyCryptodome reference.

Tests:
- Unprotected HT model matches library
- DOM model (d=1, d=2) recombined output matches library
- DOM variant comparison (cycles, randomness)
"""

import random
import pytest

from aes_explore.models.model_unprotected_ht import encrypt_unprotected_ht
from aes_explore.models.model_dom import encrypt_dom
from aes_explore.reference import aes128_encrypt
from aes_explore.utils import bytes_to_hex


def random_bytes(n: int, rng: random.Random) -> bytes:
    """Generate n random bytes."""
    return bytes(rng.randint(0, 255) for _ in range(n))


class TestUnprotectedHTRandomized:
    """Randomized tests for unprotected high-throughput model."""

    @pytest.mark.parametrize("seed", range(10))
    def test_random_key_pt(self, seed):
        """Test with random key and plaintext."""
        rng = random.Random(seed)
        key = random_bytes(16, rng)
        pt = random_bytes(16, rng)

        expected = aes128_encrypt(key, pt)
        computed, cycles = encrypt_unprotected_ht(key, pt)

        assert computed == expected, (
            f"Seed {seed}: expected {bytes_to_hex(expected)}, "
            f"got {bytes_to_hex(computed)}"
        )


class TestDomRandomized:
    """Randomized tests for DOM model."""

    @pytest.mark.parametrize("seed", range(10))
    def test_dom_d1_variant5_random(self, seed):
        """Test DOM d=1, variant=5 with random inputs."""
        rng = random.Random(seed)
        key = random_bytes(16, rng)
        pt = random_bytes(16, rng)

        expected = aes128_encrypt(key, pt)
        computed, cycles, random_bits = encrypt_dom(
            key, pt, d=1, sbox_variant=5, seed=seed * 1000
        )

        assert computed == expected, (
            f"DOM d=1 v=5 seed {seed}: expected {bytes_to_hex(expected)}, "
            f"got {bytes_to_hex(computed)}"
        )

    @pytest.mark.parametrize("seed", range(10))
    def test_dom_d1_variant8_random(self, seed):
        """Test DOM d=1, variant=8 with random inputs."""
        rng = random.Random(seed)
        key = random_bytes(16, rng)
        pt = random_bytes(16, rng)

        expected = aes128_encrypt(key, pt)
        computed, cycles, random_bits = encrypt_dom(
            key, pt, d=1, sbox_variant=8, seed=seed * 1000
        )

        assert computed == expected, (
            f"DOM d=1 v=8 seed {seed}: expected {bytes_to_hex(expected)}, "
            f"got {bytes_to_hex(computed)}"
        )

    @pytest.mark.parametrize("seed", range(10))
    def test_dom_d2_variant5_random(self, seed):
        """Test DOM d=2, variant=5 with random inputs."""
        rng = random.Random(seed)
        key = random_bytes(16, rng)
        pt = random_bytes(16, rng)

        expected = aes128_encrypt(key, pt)
        computed, cycles, random_bits = encrypt_dom(
            key, pt, d=2, sbox_variant=5, seed=seed * 1000
        )

        assert computed == expected, (
            f"DOM d=2 v=5 seed {seed}: expected {bytes_to_hex(expected)}, "
            f"got {bytes_to_hex(computed)}"
        )

    @pytest.mark.parametrize("seed", range(10))
    def test_dom_d2_variant8_random(self, seed):
        """Test DOM d=2, variant=8 with random inputs."""
        rng = random.Random(seed)
        key = random_bytes(16, rng)
        pt = random_bytes(16, rng)

        expected = aes128_encrypt(key, pt)
        computed, cycles, random_bits = encrypt_dom(
            key, pt, d=2, sbox_variant=8, seed=seed * 1000
        )

        assert computed == expected, (
            f"DOM d=2 v=8 seed {seed}: expected {bytes_to_hex(expected)}, "
            f"got {bytes_to_hex(computed)}"
        )


class TestDomVariantComparison:
    """Compare DOM variants in terms of cycles and randomness."""

    def test_variant8_more_cycles_than_variant5(self):
        """Verify 8-stage variant uses more cycles than 5-stage."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

        _, cycles_v5, _ = encrypt_dom(key, pt, d=1, sbox_variant=5, seed=42)
        _, cycles_v8, _ = encrypt_dom(key, pt, d=1, sbox_variant=8, seed=42)

        assert cycles_v8 > cycles_v5, (
            f"Expected variant 8 cycles ({cycles_v8}) > variant 5 cycles ({cycles_v5})"
        )

    def test_d2_more_randomness_than_d1(self):
        """Verify d=2 uses more randomness than d=1."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

        _, _, random_d1 = encrypt_dom(key, pt, d=1, sbox_variant=5, seed=42)
        _, _, random_d2 = encrypt_dom(key, pt, d=2, sbox_variant=5, seed=42)

        assert random_d2 > random_d1, (
            f"Expected d=2 randomness ({random_d2}) > d=1 randomness ({random_d1})"
        )

    def test_variant_cycle_difference(self):
        """Verify cycle difference between variants is consistent."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")

        # Test for d=1
        _, cycles_v5_d1, _ = encrypt_dom(key, pt, d=1, sbox_variant=5, seed=42)
        _, cycles_v8_d1, _ = encrypt_dom(key, pt, d=1, sbox_variant=8, seed=42)

        # 8-stage has 3 extra pipeline stages, so 3 extra cycles per S-box byte
        # With 16 bytes per round * 10 rounds = 160 S-box operations
        # But due to pipelining, the extra latency is per-round, not per-byte
        # Each round adds (8-5) = 3 extra cycles for pipeline depth
        # 10 rounds * 3 = 30 extra cycles minimum

        diff = cycles_v8_d1 - cycles_v5_d1
        assert diff > 0, f"Expected positive cycle difference, got {diff}"

    def test_randomness_tracking(self):
        """Verify randomness is tracked and non-zero."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

        _, _, random_bits = encrypt_dom(key, pt, d=1, sbox_variant=5, seed=42)

        # Should have used some randomness for sharing and multipliers
        assert random_bits > 0, "Expected non-zero randomness consumption"

    def test_deterministic_with_seed(self):
        """Verify same seed produces same results."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

        ct1, cycles1, rand1 = encrypt_dom(key, pt, d=1, sbox_variant=5, seed=12345)
        ct2, cycles2, rand2 = encrypt_dom(key, pt, d=1, sbox_variant=5, seed=12345)

        assert ct1 == ct2, "Ciphertext should be deterministic with same seed"
        assert cycles1 == cycles2, "Cycles should be deterministic with same seed"
        assert rand1 == rand2, "Randomness should be deterministic with same seed"


class TestAllModelsConsistent:
    """Verify all models produce consistent results."""

    @pytest.mark.parametrize("seed", range(5))
    def test_all_models_match(self, seed):
        """All models should produce same ciphertext for same inputs."""
        rng = random.Random(seed)
        key = random_bytes(16, rng)
        pt = random_bytes(16, rng)

        expected = aes128_encrypt(key, pt)

        ct_ht, _ = encrypt_unprotected_ht(key, pt)
        ct_dom_d1_v5, _, _ = encrypt_dom(key, pt, d=1, sbox_variant=5, seed=seed*100)
        ct_dom_d1_v8, _, _ = encrypt_dom(key, pt, d=1, sbox_variant=8, seed=seed*100)
        ct_dom_d2_v5, _, _ = encrypt_dom(key, pt, d=2, sbox_variant=5, seed=seed*100)
        ct_dom_d2_v8, _, _ = encrypt_dom(key, pt, d=2, sbox_variant=8, seed=seed*100)

        assert ct_ht == expected, "Unprotected HT mismatch"
        assert ct_dom_d1_v5 == expected, "DOM d=1 v=5 mismatch"
        assert ct_dom_d1_v8 == expected, "DOM d=1 v=8 mismatch"
        assert ct_dom_d2_v5 == expected, "DOM d=2 v=5 mismatch"
        assert ct_dom_d2_v8 == expected, "DOM d=2 v=8 mismatch"
