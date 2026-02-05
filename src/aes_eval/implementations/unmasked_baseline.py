"""Unmasked baseline AES implementation.

This implementation provides a correct AES encryption that matches
the golden reference, with full cycle accounting based on S-box
parallelism.
"""

from __future__ import annotations

from aes_eval.interfaces import BaseTechnique, Result, EvalConfig
from aes_eval.cycle_models import CycleModel
from aes_eval.randomness import RandomSource
from aes_eval.golden import validate_against_golden


# AES S-box lookup table
SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
])

# Round constants
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def xtime(a: int) -> int:
    """Multiply by x in GF(2^8)."""
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def mix_single_column(col: list[int]) -> list[int]:
    """Mix a single column."""
    a = col[:]
    c = [xtime(x) for x in a]
    return [
        c[0] ^ a[1] ^ c[1] ^ a[2] ^ a[3],
        a[0] ^ c[1] ^ a[2] ^ c[2] ^ a[3],
        a[0] ^ a[1] ^ c[2] ^ a[3] ^ c[3],
        c[0] ^ a[0] ^ a[1] ^ a[2] ^ c[3],
    ]


class UnmaskedBaseline(BaseTechnique):
    """Unmasked baseline AES-128 implementation.

    Provides correct AES encryption with cycle accounting based on
    S-box parallelism. No side-channel protection.
    """

    name = "unmasked_baseline"
    description = "Unmasked AES-128 baseline (no side-channel protection)"

    def encrypt_block(
        self,
        key: bytes,
        plaintext: bytes,
        rng: RandomSource,
        cycle_model: CycleModel,
        config: EvalConfig,
    ) -> Result:
        """Encrypt a single 16-byte block.

        Args:
            key: 16-byte AES key
            plaintext: 16-byte plaintext block
            rng: Random source (unused for unmasked)
            cycle_model: Cycle model for accounting
            config: Evaluation configuration

        Returns:
            Result with ciphertext and accounting data
        """
        self.validate_inputs(key, plaintext)
        cycle_model.reset()

        # Track operations
        op_counts = {
            "sbox_calls": 0,
            "xor_ops": 0,
        }

        # Convert to state array (column-major order)
        state = list(plaintext)

        # Key expansion
        round_keys = self._key_expansion(key)
        cycle_model.account_key_schedule(10)

        # Initial round (just AddRoundKey)
        state = self._add_round_key(state, round_keys[0])
        cycle_model.account_add_round_key()
        op_counts["xor_ops"] += 16

        # Main rounds 1-9
        for round_num in range(1, 10):
            state = self._sub_bytes(state)
            cycle_model.account_sub_bytes()
            op_counts["sbox_calls"] += 16

            state = self._shift_rows(state)
            cycle_model.account_shift_rows()

            state = self._mix_columns(state)
            cycle_model.account_mix_columns()
            op_counts["xor_ops"] += 16 * 4  # 4 XORs per byte in MixColumns

            state = self._add_round_key(state, round_keys[round_num])
            cycle_model.account_add_round_key()
            op_counts["xor_ops"] += 16

        # Final round (no MixColumns)
        state = self._sub_bytes(state)
        cycle_model.account_sub_bytes()
        op_counts["sbox_calls"] += 16

        state = self._shift_rows(state)
        cycle_model.account_shift_rows()

        state = self._add_round_key(state, round_keys[10])
        cycle_model.account_add_round_key()
        op_counts["xor_ops"] += 16

        # Convert state back to bytes
        ciphertext = bytes(state)

        # Validate against golden reference
        correct, error_detail = validate_against_golden(key, plaintext, ciphertext)

        return Result(
            ciphertext=ciphertext,
            correct=correct,
            error_detail=error_detail,
            cycle_count_total=cycle_model.total_cycles,
            cycle_breakdown=cycle_model.breakdown,
            random_bits_total=0,  # No randomness for unmasked
            random_bits_breakdown=rng.bits_breakdown,
            op_counts=op_counts,
            notes=["Unmasked implementation - no side-channel protection"],
        )

    def _key_expansion(self, key: bytes) -> list[list[int]]:
        """Expand key to 11 round keys."""
        # Initialize with original key
        w = [list(key[i:i+4]) for i in range(0, 16, 4)]

        for i in range(4, 44):
            temp = w[i - 1][:]
            if i % 4 == 0:
                # RotWord + SubWord + Rcon
                temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
                temp[0] ^= RCON[i // 4 - 1]
            w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

        # Group into round keys (each is 16 bytes)
        round_keys = []
        for round_num in range(11):
            rk = []
            for col in range(4):
                rk.extend(w[round_num * 4 + col])
            round_keys.append(rk)

        return round_keys

    def _sub_bytes(self, state: list[int]) -> list[int]:
        """Apply S-box to each byte."""
        return [SBOX[b] for b in state]

    def _shift_rows(self, state: list[int]) -> list[int]:
        """Shift rows of state.

        State is in column-major order:
        [0, 4, 8, 12]
        [1, 5, 9, 13]
        [2, 6, 10, 14]
        [3, 7, 11, 15]
        """
        return [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11],
        ]

    def _mix_columns(self, state: list[int]) -> list[int]:
        """Mix columns."""
        result = []
        for col in range(4):
            col_data = [state[col * 4 + row] for row in range(4)]
            mixed = mix_single_column(col_data)
            result.extend(mixed)
        return result

    def _add_round_key(self, state: list[int], round_key: list[int]) -> list[int]:
        """XOR state with round key."""
        return [s ^ k for s, k in zip(state, round_key)]
