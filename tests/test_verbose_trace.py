"""
Regression tests for verbose trace output.

Verifies that:
- Ciphertext is unchanged with verbose tracing enabled
- Total RNG bits are accounted for (key_mask + state_mask_init + S-box ops)
- Trace contains expected structural markers (key_mask, state_mask_init, PIPE, POP)
- Cycle count is unchanged
"""

import io
import contextlib

from aes_explore.models.model_dom import encrypt_dom
from aes_explore.trace import TraceRecorder
from aes_explore.utils import hex_to_bytes, bytes_to_hex


FIPS_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
FIPS_PT = "3243f6a8885a308d313198a2e0370734"
FIPS_CT = "3925841d02dc09fbdc118597196a0b32"


class TestVerboseTraceStructure:
    """Verify structural properties of the verbose trace."""

    def _run_verbose(self, d=1, sbox_variant=8, seed=123):
        """Run DOM model with --verbose and capture stdout."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)
        tracer = TraceRecorder(verbose=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ct, cycles, rbits = encrypt_dom(
                key, pt, d=d, sbox_variant=sbox_variant, seed=seed, tracer=tracer,
            )
        return ct, cycles, rbits, buf.getvalue()

    def test_ciphertext_unchanged(self):
        """Verbose tracing must not alter the ciphertext."""
        ct, _, _, _ = self._run_verbose()
        assert bytes_to_hex(ct) == FIPS_CT

    def test_cycle_count_unchanged(self):
        """Cycle count must match non-verbose run."""
        _, cycles, _, _ = self._run_verbose()
        assert cycles == 250  # 8-stage pipeline, d=1

    def test_key_mask_in_trace(self):
        """Trace must contain key_mask init event."""
        _, _, _, output = self._run_verbose()
        assert "INIT key_mask" in output
        assert "purpose=key_mask" in output

    def test_state_mask_init_in_trace(self):
        """Trace must contain state_mask_init init event."""
        _, _, _, output = self._run_verbose()
        assert "INIT state_mask_init" in output
        assert "purpose=state_mask_init" in output

    def test_key_mask_randomness_128b(self):
        """Key masking for d=1 must consume exactly 128b."""
        _, _, _, output = self._run_verbose()
        # The key_mask init line should show +128b
        for line in output.splitlines():
            if "INIT key_mask" in line:
                break
        else:
            assert False, "INIT key_mask not found"
        # Next line is the RND line
        lines = output.splitlines()
        idx = next(i for i, l in enumerate(lines) if "INIT key_mask" in l)
        rnd_line = lines[idx + 1]
        assert "+128b" in rnd_line

    def test_total_rng_bits_includes_key_mask(self):
        """Total bits must include key_mask + state_mask_init + sbox ops."""
        _, _, rbits, _ = self._run_verbose()
        # key_mask=128, state_mask_init=128, rest is sbox operations
        assert rbits >= 256, f"Expected >= 256 bits total, got {rbits}"
        # For d=1, variant=8: 3456 bits (128 key + 128 state + 3200 sbox)
        assert rbits == 3456

    def test_pipe_lines_present(self):
        """Pipeline occupancy lines must appear during SubBytes."""
        _, _, _, output = self._run_verbose()
        pipe_lines = [l for l in output.splitlines() if "PIPE:" in l]
        assert len(pipe_lines) > 0, "No PIPE lines found in trace"

    def test_pop_lines_present(self):
        """POP lines must appear when bytes exit the pipeline."""
        _, _, _, output = self._run_verbose()
        pop_lines = [l for l in output.splitlines() if "POP:" in l]
        assert len(pop_lines) > 0, "No POP lines found in trace"

    def test_no_cycle_question_marks(self):
        """Every cycle line must have a real cycle number, never '?'."""
        _, _, _, output = self._run_verbose()
        for line in output.splitlines():
            if line.startswith("C") and "Cycle: ?" in line:
                assert False, f"Found 'Cycle: ?' in trace: {line}"

    def test_draw_ids_monotonic(self):
        """Draw IDs in the trace must be monotonically increasing."""
        _, _, _, output = self._run_verbose()
        import re
        ids = []
        for m in re.finditer(r'r(\d{6})', output):
            ids.append(int(m.group(1)))
        # Check monotonic (allowing duplicates in ranges)
        for i in range(1, len(ids)):
            assert ids[i] >= ids[i-1], (
                f"Draw IDs not monotonic: r{ids[i-1]:06d} -> r{ids[i]:06d}"
            )

    def test_deterministic_output(self):
        """Same seed must produce identical trace output."""
        _, _, _, out1 = self._run_verbose(seed=42)
        _, _, _, out2 = self._run_verbose(seed=42)
        assert out1 == out2

    def test_delta_view_present(self):
        """Delta markers must appear in cycle lines."""
        _, _, _, output = self._run_verbose()
        # Unicode delta char or "Δ"
        delta_lines = [l for l in output.splitlines() if "\u0394:" in l]
        assert len(delta_lines) > 0, "No delta markers found in cycle lines"

    def test_op_boundaries(self):
        """SubBytes begin/end markers must appear."""
        _, _, _, output = self._run_verbose()
        assert "SubBytes begin" in output
        assert "SubBytes end" in output


class TestVerboseTraceVariants:
    """Test verbose trace across different model configurations."""

    def test_d1_variant5(self):
        """d=1, variant=5 must produce correct ciphertext with verbose."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)
        tracer = TraceRecorder(verbose=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ct, cycles, rbits = encrypt_dom(
                key, pt, d=1, sbox_variant=5, seed=42, tracer=tracer,
            )
        assert bytes_to_hex(ct) == FIPS_CT
        assert "key_mask" in buf.getvalue()

    def test_d2_variant8(self):
        """d=2, variant=8 must produce correct ciphertext with verbose."""
        key = hex_to_bytes(FIPS_KEY)
        pt = hex_to_bytes(FIPS_PT)
        tracer = TraceRecorder(verbose=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ct, cycles, rbits = encrypt_dom(
                key, pt, d=2, sbox_variant=8, seed=42, tracer=tracer,
            )
        assert bytes_to_hex(ct) == FIPS_CT
        # d=2: key_mask = 256b, state_mask_init = 256b
        assert rbits >= 512
