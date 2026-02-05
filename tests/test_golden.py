"""Tests for golden reference AES implementation."""

import pytest
from Crypto.Cipher import AES

from aes_eval.golden import golden_encrypt, validate_against_golden, FIPS_197_TEST_VECTORS


class TestGoldenEncrypt:
    """Tests for golden_encrypt function."""

    def test_fips_197_appendix_c1(self) -> None:
        """Test FIPS-197 Appendix C.1 AES-128 test vector."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        result = golden_encrypt(key, plaintext)
        assert result == expected

    @pytest.mark.parametrize("vec", FIPS_197_TEST_VECTORS)
    def test_fips_197_all_vectors(self, vec: dict) -> None:
        """Test all FIPS-197 test vectors."""
        result = golden_encrypt(vec["key"], vec["plaintext"])
        assert result == vec["ciphertext"]

    def test_all_zeros_key_and_plaintext(self) -> None:
        """Test encryption with all-zero key and plaintext."""
        key = bytes(16)
        plaintext = bytes(16)
        expected = bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e")

        result = golden_encrypt(key, plaintext)
        assert result == expected

    def test_all_ones_key_and_plaintext(self) -> None:
        """Test encryption with all-FF key and plaintext."""
        key = bytes([0xff] * 16)
        plaintext = bytes([0xff] * 16)
        expected = bytes.fromhex("bcbf217cb280cf30b2517052193ab979")

        result = golden_encrypt(key, plaintext)
        assert result == expected

    def test_invalid_key_length(self) -> None:
        """Test that invalid key length raises ValueError."""
        with pytest.raises(ValueError, match="Key must be 16 bytes"):
            golden_encrypt(bytes(15), bytes(16))

        with pytest.raises(ValueError, match="Key must be 16 bytes"):
            golden_encrypt(bytes(17), bytes(16))

    def test_invalid_plaintext_length(self) -> None:
        """Test that invalid plaintext length raises ValueError."""
        with pytest.raises(ValueError, match="Plaintext must be 16 bytes"):
            golden_encrypt(bytes(16), bytes(15))

        with pytest.raises(ValueError, match="Plaintext must be 16 bytes"):
            golden_encrypt(bytes(16), bytes(17))

    def test_matches_pycryptodome_directly(self) -> None:
        """Verify golden_encrypt matches direct PyCryptodome usage."""
        key = bytes(range(16))
        plaintext = bytes(range(16, 32))

        # Our golden function
        our_result = golden_encrypt(key, plaintext)

        # Direct PyCryptodome
        cipher = AES.new(key, AES.MODE_ECB)
        pycrypto_result = cipher.encrypt(plaintext)

        assert our_result == pycrypto_result


class TestValidateAgainstGolden:
    """Tests for validate_against_golden function."""

    def test_correct_ciphertext_passes(self) -> None:
        """Test that correct ciphertext validates successfully."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        is_correct, error = validate_against_golden(key, plaintext, ciphertext)

        assert is_correct is True
        assert error == ""

    def test_incorrect_ciphertext_fails(self) -> None:
        """Test that incorrect ciphertext fails validation."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        wrong_ciphertext = bytes(16)  # All zeros - wrong

        is_correct, error = validate_against_golden(key, plaintext, wrong_ciphertext)

        assert is_correct is False
        assert "mismatch" in error.lower()
        assert "expected" in error.lower()

    def test_single_bit_difference_fails(self) -> None:
        """Test that even a single bit difference fails."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        correct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        # Flip one bit
        wrong = bytearray(correct)
        wrong[0] ^= 0x01
        wrong = bytes(wrong)

        is_correct, error = validate_against_golden(key, plaintext, wrong)

        assert is_correct is False


class TestRandomVectors:
    """Test with random vectors."""

    def test_random_vectors_match_pycryptodome(self) -> None:
        """Test multiple random vectors against PyCryptodome."""
        import secrets

        for _ in range(100):
            key = secrets.token_bytes(16)
            plaintext = secrets.token_bytes(16)

            our_result = golden_encrypt(key, plaintext)

            cipher = AES.new(key, AES.MODE_ECB)
            expected = cipher.encrypt(plaintext)

            assert our_result == expected

    def test_deterministic_with_same_inputs(self) -> None:
        """Test that same inputs always produce same outputs."""
        key = bytes(range(16))
        plaintext = bytes(range(16, 32))

        result1 = golden_encrypt(key, plaintext)
        result2 = golden_encrypt(key, plaintext)
        result3 = golden_encrypt(key, plaintext)

        assert result1 == result2 == result3
