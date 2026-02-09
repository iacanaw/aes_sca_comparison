"""
Tests for the didactic round mode (Round 0 + Round 1 walkthrough).

Verifies:
- Unprotected round-mode output matches manually-computed intermediate state
- DOM recombined state matches unprotected for same key/plaintext
- FIPS-197 known vector with stable hex assertions
- Deterministic DOM output given same seed
- JSONL trace output is well-formed
"""

import io
import json
import random

import pytest

from aes_explore.aes_core import (
    key_expansion,
    sub_bytes,
    shift_rows,
    mix_columns,
    add_round_key,
)
from aes_explore.utils import (
    bytes_to_state,
    hex_to_bytes,
    state_to_hex,
    copy_state,
)
from aes_explore.round_didactic import run_unprotected_round, run_dom_round


# ─── helpers ───────────────────────────────────────────────────────

def _compute_round1_state(key: bytes, plaintext: bytes) -> tuple[list, list]:
    """
    Manually compute state entering Round 1 and state after Round 1.

    This uses the raw AES primitives directly (no model), so it serves
    as an independent reference.
    """
    round_keys = key_expansion(key)
    pt_state = bytes_to_state(plaintext)

    # Round 0: initial AddRoundKey
    state_in = add_round_key(pt_state, round_keys[0])

    # Round 1: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    s = sub_bytes(state_in)
    s = shift_rows(s)
    s = mix_columns(s)
    state_out = add_round_key(s, round_keys[1])

    return state_in, state_out


# ─── FIPS-197 known vector ─────────────────────────────────────────

FIPS_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
FIPS_PT = "3243f6a8885a308d313198a2e0370734"

# Pre-computed expected states (column-major hex)
# State entering Round 1 = plaintext XOR round_key[0]
FIPS_STATE_IN_HEX = state_to_hex(
    _compute_round1_state(
        hex_to_bytes(FIPS_KEY), hex_to_bytes(FIPS_PT)
    )[0]
)
FIPS_STATE_OUT_HEX = state_to_hex(
    _compute_round1_state(
        hex_to_bytes(FIPS_KEY), hex_to_bytes(FIPS_PT)
    )[1]
)


class TestUnprotectedRound:
    """Tests for unprotected round mode."""

    def test_fips197_state_in_round1(self):
        """State entering Round 1 must match FIPS-197 intermediate."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)

        result = run_unprotected_round(key, pt, verbose=False)
        got = state_to_hex(result["state_in_round1"])
        assert got == FIPS_STATE_IN_HEX

    def test_fips197_state_out_round1(self):
        """State after Round 1 must match FIPS-197 intermediate."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)

        result = run_unprotected_round(key, pt, verbose=False)
        got = state_to_hex(result["state_out_round1"])
        assert got == FIPS_STATE_OUT_HEX

    def test_fips197_stable_hex(self):
        """Hard-coded hex values for FIPS-197 after round 1 (regression guard)."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)

        # Manually verified: PT XOR Key = state_in
        # Then SubBytes -> ShiftRows -> MixColumns -> AddRoundKey(rk1) = state_out
        result = run_unprotected_round(key, pt, verbose=False)

        state_in_hex = state_to_hex(result["state_in_round1"])
        state_out_hex = state_to_hex(result["state_out_round1"])

        # PT XOR Key[0] for FIPS-197 Appendix B is 00 for column 0:
        # 32^2b=19, 43^7e=3d, f6^15=e3, a8^28=80 (column-major)
        assert state_in_hex == "193de3bea0f4e22b9ac68d2ae9f84808"
        assert state_out_hex == "a49c7ff2689f352b6b5bea43026a5049"

    def test_cycles(self):
        """Unprotected round mode should report 2 cycles."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)
        result = run_unprotected_round(key, pt, verbose=False)
        assert result["cycles"] == 2

    @pytest.mark.parametrize("seed", range(10))
    def test_random_vectors_match_primitives(self, seed):
        """Round-mode output must match primitives for random key/pt pairs."""
        rng = random.Random(seed + 1000)
        key = bytes(rng.randint(0, 255) for _ in range(16))
        pt = bytes(rng.randint(0, 255) for _ in range(16))

        expected_in, expected_out = _compute_round1_state(key, pt)
        result = run_unprotected_round(key, pt, verbose=False)

        assert result["state_in_round1"] == expected_in
        assert result["state_out_round1"] == expected_out

    def test_verbose_output(self, capsys):
        """Verbose mode should print section headers."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)
        run_unprotected_round(key, pt, verbose=True)
        captured = capsys.readouterr().out

        assert "1. AES State Layout" in captured
        assert "2. Inputs" in captured
        assert "3. Pre-round" in captured
        assert "4. Round 1 Walkthrough" in captured
        assert "SubBytes" in captured
        assert "ShiftRows" in captured
        assert "MixColumns" in captured
        assert "AddRoundKey" in captured
        assert "5. Summary" in captured

    def test_jsonl_output(self):
        """JSONL trace should produce well-formed JSON lines with expected stages."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)
        buf = io.StringIO()
        run_unprotected_round(key, pt, verbose=False, trace_file=buf)

        buf.seek(0)
        records = [json.loads(line) for line in buf if line.strip()]
        assert len(records) > 0

        stages = [r["stage"] for r in records]
        assert "inputs" in stages
        assert "subbytes" in stages
        assert "shiftrows" in stages
        assert "mixcolumns" in stages
        assert "add_round_key_1" in stages
        assert "summary" in stages

        # All records should have model and mode fields
        for r in records:
            assert r["model"] == "unprotected_ht"
            assert r["mode"] == "round"


class TestDomRound:
    """Tests for DOM round mode."""

    def test_fips197_recombined_matches_unprotected(self):
        """DOM recombined state must match unprotected for FIPS-197 vector."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)

        unp = run_unprotected_round(key, pt, verbose=False)
        dom = run_dom_round(key, pt, d=1, seed=42, verbose=False)

        assert dom["state_in_round1"] == unp["state_in_round1"]
        assert dom["state_out_round1"] == unp["state_out_round1"]

    @pytest.mark.parametrize("seed", range(10))
    def test_random_vectors_dom_matches_unprotected(self, seed):
        """DOM recombined must match unprotected for random vectors."""
        rng = random.Random(seed + 2000)
        key = bytes(rng.randint(0, 255) for _ in range(16))
        pt = bytes(rng.randint(0, 255) for _ in range(16))

        unp = run_unprotected_round(key, pt, verbose=False)
        dom = run_dom_round(key, pt, d=1, seed=seed, verbose=False)

        assert dom["state_in_round1"] == unp["state_in_round1"], \
            f"state_in mismatch for seed={seed}"
        assert dom["state_out_round1"] == unp["state_out_round1"], \
            f"state_out mismatch for seed={seed}"

    def test_d2_recombined_matches_unprotected(self):
        """DOM d=2 (3 shares) recombined must also match unprotected."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)

        unp = run_unprotected_round(key, pt, verbose=False)
        dom = run_dom_round(key, pt, d=2, seed=99, verbose=False)

        assert dom["state_in_round1"] == unp["state_in_round1"]
        assert dom["state_out_round1"] == unp["state_out_round1"]

    def test_sbox_variant_8_matches(self):
        """8-stage S-box variant must produce same recombined result."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)

        unp = run_unprotected_round(key, pt, verbose=False)
        dom = run_dom_round(key, pt, d=1, sbox_variant=8, seed=7, verbose=False)

        assert dom["state_out_round1"] == unp["state_out_round1"]

    def test_deterministic_with_seed(self):
        """Same seed must produce identical shares."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)

        r1 = run_dom_round(key, pt, d=1, seed=42, verbose=False)
        r2 = run_dom_round(key, pt, d=1, seed=42, verbose=False)

        assert r1["shares_out"] == r2["shares_out"]
        assert r1["random_bits"] == r2["random_bits"]

    def test_different_seeds_different_shares(self):
        """Different seeds should produce different shares (with high probability)."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)

        r1 = run_dom_round(key, pt, d=1, seed=1, verbose=False)
        r2 = run_dom_round(key, pt, d=1, seed=2, verbose=False)

        # Shares should differ (recombined is the same)
        assert r1["shares_out"] != r2["shares_out"]
        assert r1["state_out_round1"] == r2["state_out_round1"]

    def test_shares_recombine_correctly(self):
        """Output shares XOR to the recombined state."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)

        result = run_dom_round(key, pt, d=1, seed=42, verbose=False)
        shares = result["shares_out"]
        expected = result["state_out_round1"]

        # XOR all shares
        recombined = [[0] * 4 for _ in range(4)]
        for s in shares:
            for row in range(4):
                for col in range(4):
                    recombined[row][col] ^= s[row][col]

        assert recombined == expected

    def test_random_bits_positive(self):
        """DOM should consume randomness."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)
        result = run_dom_round(key, pt, d=1, seed=42, verbose=False)
        assert result["random_bits"] > 0

    def test_verbose_output_dom(self, capsys):
        """DOM verbose mode should include share-specific output."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)
        run_dom_round(key, pt, d=1, seed=42, verbose=True)
        captured = capsys.readouterr().out

        assert "Share[0]" in captured
        assert "Share[1]" in captured
        assert "Recombined" in captured
        assert "Key Masking" in captured
        assert "State (Plaintext) Masking" in captured
        assert "SubBytes (DOM S-box Pipeline)" in captured

    def test_jsonl_output_dom(self):
        """DOM JSONL trace should contain expected stages."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)
        buf = io.StringIO()
        run_dom_round(key, pt, d=1, seed=42, verbose=False, trace_file=buf)

        buf.seek(0)
        records = [json.loads(line) for line in buf if line.strip()]
        assert len(records) > 0

        stages = [r["stage"] for r in records]
        assert "inputs" in stages
        assert "key_mask" in stages
        assert "state_mask_init" in stages
        assert "subbytes" in stages
        assert "summary" in stages

        for r in records:
            assert r["model"] == "dom"
            assert r["mode"] == "round"


class TestRoundMatchesFullRun:
    """Cross-check: round-mode state_out == full-run state after round 1."""

    @pytest.mark.parametrize("seed", range(10))
    def test_unprotected_round_vs_primitives(self, seed):
        """Round-mode matches direct primitive computation for random inputs."""
        rng = random.Random(seed + 3000)
        key = bytes(rng.randint(0, 255) for _ in range(16))
        pt = bytes(rng.randint(0, 255) for _ in range(16))

        expected_in, expected_out = _compute_round1_state(key, pt)
        result = run_unprotected_round(key, pt, verbose=False)

        assert result["state_in_round1"] == expected_in
        assert result["state_out_round1"] == expected_out

    @pytest.mark.parametrize("seed", range(10))
    def test_dom_round_vs_primitives(self, seed):
        """DOM round recombined matches direct primitive computation."""
        rng = random.Random(seed + 4000)
        key = bytes(rng.randint(0, 255) for _ in range(16))
        pt = bytes(rng.randint(0, 255) for _ in range(16))

        expected_in, expected_out = _compute_round1_state(key, pt)
        result = run_dom_round(key, pt, d=1, seed=seed, verbose=False)

        assert result["state_in_round1"] == expected_in
        assert result["state_out_round1"] == expected_out
