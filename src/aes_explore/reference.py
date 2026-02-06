"""
Reference AES implementation using PyCryptodome for verification.
"""

from Crypto.Cipher import AES


def aes128_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt a single 16-byte block using AES-128 ECB.

    Args:
        key: 16-byte AES key
        plaintext: 16-byte plaintext block

    Returns:
        16-byte ciphertext
    """
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(key)}")
    if len(plaintext) != 16:
        raise ValueError(f"Plaintext must be 16 bytes, got {len(plaintext)}")

    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def verify_ciphertext(computed: bytes, key: bytes, plaintext: bytes) -> bool:
    """
    Verify computed ciphertext against PyCryptodome reference.

    Args:
        computed: Ciphertext to verify
        key: AES key used
        plaintext: Plaintext used

    Returns:
        True if computed matches reference, False otherwise
    """
    expected = aes128_encrypt(key, plaintext)
    return computed == expected


def get_expected_ciphertext(key: bytes, plaintext: bytes) -> bytes:
    """
    Get expected ciphertext for given key and plaintext.

    Args:
        key: 16-byte AES key
        plaintext: 16-byte plaintext

    Returns:
        16-byte expected ciphertext
    """
    return aes128_encrypt(key, plaintext)
