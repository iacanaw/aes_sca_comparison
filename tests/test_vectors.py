"""
Test known AES-128 test vectors.

Uses vectors from FIPS-197 and other standard sources.
"""

import pytest

from aes_explore.models.model_unprotected_ht import encrypt_unprotected_ht
from aes_explore.models.model_dom import encrypt_dom
from aes_explore.reference import aes128_encrypt
from aes_explore.utils import hex_to_bytes, bytes_to_hex


# Known AES-128 test vectors
# Format: (key_hex, plaintext_hex, expected_ciphertext_hex, description)
TEST_VECTORS = [
    # FIPS-197 Appendix B
    (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "3243f6a8885a308d313198a2e0370734",
        "3925841d02dc09fbdc118597196a0b32",
        "FIPS-197 Appendix B",
    ),
    # FIPS-197 Appendix C.1
    (
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a",
        "FIPS-197 Appendix C.1",
    ),
    # Additional vector (all zeros)
    (
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "66e94bd4ef8a2c3b884cfa59ca342b2e",
        "All zeros",
    ),
    # Additional vector (all ones)
    (
        "ffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffff",
        "bcbf217cb280cf30b2517052193ab979",
        "All ones",
    ),
]


class TestReferenceVectors:
    """Test that PyCryptodome reference produces correct results."""

    @pytest.mark.parametrize("key_hex,pt_hex,ct_hex,desc", TEST_VECTORS)
    def test_reference_aes(self, key_hex, pt_hex, ct_hex, desc):
        """Verify PyCryptodome against known test vectors."""
        key = hex_to_bytes(key_hex)
        pt = hex_to_bytes(pt_hex)
        expected_ct = hex_to_bytes(ct_hex)

        result = aes128_encrypt(key, pt)

        assert result == expected_ct, f"Reference AES failed for {desc}"


class TestUnprotectedHTVectors:
    """Test unprotected high-throughput model against known vectors."""

    @pytest.mark.parametrize("key_hex,pt_hex,ct_hex,desc", TEST_VECTORS)
    def test_unprotected_ht(self, key_hex, pt_hex, ct_hex, desc):
        """Verify unprotected_ht model against known test vectors."""
        key = hex_to_bytes(key_hex)
        pt = hex_to_bytes(pt_hex)
        expected_ct = hex_to_bytes(ct_hex)

        ciphertext, cycles = encrypt_unprotected_ht(key, pt)

        assert ciphertext == expected_ct, (
            f"Unprotected HT failed for {desc}: "
            f"expected {ct_hex}, got {bytes_to_hex(ciphertext)}"
        )

    def test_cycle_count(self):
        """Verify unprotected_ht uses expected number of cycles."""
        key = hex_to_bytes(TEST_VECTORS[0][0])
        pt = hex_to_bytes(TEST_VECTORS[0][1])

        _, cycles = encrypt_unprotected_ht(key, pt)

        # 11 cycles: cycle 0 (AddRoundKey) + cycles 1-10 (rounds)
        assert cycles == 11, f"Expected 11 cycles, got {cycles}"


class TestDomVectors:
    """Test DOM model against known vectors."""

    @pytest.mark.parametrize("key_hex,pt_hex,ct_hex,desc", TEST_VECTORS)
    def test_dom_d1_variant5(self, key_hex, pt_hex, ct_hex, desc):
        """Verify DOM model (d=1, variant=5) against known vectors."""
        key = hex_to_bytes(key_hex)
        pt = hex_to_bytes(pt_hex)
        expected_ct = hex_to_bytes(ct_hex)

        ciphertext, cycles, random_bits = encrypt_dom(
            key, pt, d=1, sbox_variant=5, seed=42
        )

        assert ciphertext == expected_ct, (
            f"DOM d=1 v=5 failed for {desc}: "
            f"expected {ct_hex}, got {bytes_to_hex(ciphertext)}"
        )

    @pytest.mark.parametrize("key_hex,pt_hex,ct_hex,desc", TEST_VECTORS)
    def test_dom_d1_variant8(self, key_hex, pt_hex, ct_hex, desc):
        """Verify DOM model (d=1, variant=8) against known vectors."""
        key = hex_to_bytes(key_hex)
        pt = hex_to_bytes(pt_hex)
        expected_ct = hex_to_bytes(ct_hex)

        ciphertext, cycles, random_bits = encrypt_dom(
            key, pt, d=1, sbox_variant=8, seed=42
        )

        assert ciphertext == expected_ct, (
            f"DOM d=1 v=8 failed for {desc}: "
            f"expected {ct_hex}, got {bytes_to_hex(ciphertext)}"
        )

    @pytest.mark.parametrize("key_hex,pt_hex,ct_hex,desc", TEST_VECTORS)
    def test_dom_d2_variant5(self, key_hex, pt_hex, ct_hex, desc):
        """Verify DOM model (d=2, variant=5) against known vectors."""
        key = hex_to_bytes(key_hex)
        pt = hex_to_bytes(pt_hex)
        expected_ct = hex_to_bytes(ct_hex)

        ciphertext, cycles, random_bits = encrypt_dom(
            key, pt, d=2, sbox_variant=5, seed=42
        )

        assert ciphertext == expected_ct, (
            f"DOM d=2 v=5 failed for {desc}: "
            f"expected {ct_hex}, got {bytes_to_hex(ciphertext)}"
        )

    @pytest.mark.parametrize("key_hex,pt_hex,ct_hex,desc", TEST_VECTORS)
    def test_dom_d2_variant8(self, key_hex, pt_hex, ct_hex, desc):
        """Verify DOM model (d=2, variant=8) against known vectors."""
        key = hex_to_bytes(key_hex)
        pt = hex_to_bytes(pt_hex)
        expected_ct = hex_to_bytes(ct_hex)

        ciphertext, cycles, random_bits = encrypt_dom(
            key, pt, d=2, sbox_variant=8, seed=42
        )

        assert ciphertext == expected_ct, (
            f"DOM d=2 v=8 failed for {desc}: "
            f"expected {ct_hex}, got {bytes_to_hex(ciphertext)}"
        )


class TestCanrightSbox:
    """Test Canright S-box implementation."""

    def test_canright_matches_lut(self):
        """Verify Canright S-box matches LUT for all 256 inputs."""
        from aes_explore.dom.gf_canright import canright_sbox_unmasked
        from aes_explore.aes_core import SBOX

        for i in range(256):
            computed = canright_sbox_unmasked(i)
            expected = SBOX[i]
            assert computed == expected, (
                f"Canright S-box mismatch at 0x{i:02x}: "
                f"expected 0x{expected:02x}, got 0x{computed:02x}"
            )
