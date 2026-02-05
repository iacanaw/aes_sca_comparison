"""Golden reference AES implementation using PyCryptodome."""

from Crypto.Cipher import AES


def golden_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a single block using PyCryptodome as golden reference.

    Args:
        key: 16-byte AES-128 key
        plaintext: 16-byte plaintext block

    Returns:
        16-byte ciphertext block

    Raises:
        ValueError: If key or plaintext is not 16 bytes
    """
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(key)}")
    if len(plaintext) != 16:
        raise ValueError(f"Plaintext must be 16 bytes, got {len(plaintext)}")

    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def validate_against_golden(
    key: bytes, plaintext: bytes, candidate_ciphertext: bytes
) -> tuple[bool, str]:
    """Validate a candidate ciphertext against the golden reference.

    Args:
        key: 16-byte AES-128 key
        plaintext: 16-byte plaintext block
        candidate_ciphertext: 16-byte ciphertext to validate

    Returns:
        Tuple of (is_correct, error_detail)
    """
    expected = golden_encrypt(key, plaintext)
    if candidate_ciphertext == expected:
        return True, ""
    else:
        return False, (
            f"Ciphertext mismatch: expected {expected.hex()}, "
            f"got {candidate_ciphertext.hex()}"
        )


# FIPS-197 Appendix C Test Vectors for AES-128
FIPS_197_TEST_VECTORS = [
    # Appendix C.1 - AES-128
    {
        "key": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "plaintext": bytes.fromhex("00112233445566778899aabbccddeeff"),
        "ciphertext": bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
    },
    # Additional test vectors from NIST
    {
        "key": bytes.fromhex("00000000000000000000000000000000"),
        "plaintext": bytes.fromhex("00000000000000000000000000000000"),
        "ciphertext": bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e"),
    },
    {
        "key": bytes.fromhex("00000000000000000000000000000000"),
        "plaintext": bytes.fromhex("f34481ec3cc627bacd5dc3fb08f273e6"),
        "ciphertext": bytes.fromhex("0336763e966d92595a567cc9ce537f5e"),
    },
    {
        "key": bytes.fromhex("00000000000000000000000000000000"),
        "plaintext": bytes.fromhex("9798c4640bad75c7c3227db910174e72"),
        "ciphertext": bytes.fromhex("a9a1631bf4996954ebc093957b234589"),
    },
    {
        "key": bytes.fromhex("ffffffffffffffffffffffffffffffff"),
        "plaintext": bytes.fromhex("00000000000000000000000000000000"),
        "ciphertext": bytes.fromhex("a1f6258c877d5fcd8964484538bfc92c"),
    },
    {
        "key": bytes.fromhex("ffffffffffffffffffffffffffffffff"),
        "plaintext": bytes.fromhex("ffffffffffffffffffffffffffffffff"),
        "ciphertext": bytes.fromhex("bcbf217cb280cf30b2517052193ab979"),
    },
]
