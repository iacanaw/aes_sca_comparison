"""
Domain-Oriented Masking (DOM) Canright S-box with explicit pipeline stages.

Implements a staged pipeline where each stage corresponds to
a register boundary. The pipeline can process one byte per cycle
once filled.

Variants:
- 5-stage: Uses DOM-dep multipliers in stages 1-3, DOM-indep in stage 4
- 8-stage: Uses DOM-indep everywhere with extra register stages
"""

import random
from typing import Any

from ..counters import CycleCounter, RandomnessCounter
from ..trace import TraceRecorder
from .gf_canright import (
    input_transform, output_linear_transform,
    gf4_mult, gf4_square, gf4_inverse,
    gf2_mult, gf2_square, gf2_inverse, gf2_scaleN,
    AFFINE_CONST,
)
from .dom_gadgets import (
    create_gf2_dom_indep, create_gf4_dom_indep,
    create_gf2_dom_dep, create_gf4_dom_dep,
)


def share_value(value: int, num_shares: int, mask: int, rng: random.Random) -> list[int]:
    """Split a value into num_shares additive shares."""
    shares = []
    acc = 0
    for i in range(num_shares - 1):
        r = rng.randint(0, mask)
        shares.append(r)
        acc ^= r
    shares.append((value ^ acc) & mask)
    return shares


def recombine_shares(shares: list[int]) -> int:
    """XOR all shares to recover the original value."""
    result = 0
    for s in shares:
        result ^= s
    return result


def apply_linear_per_share(shares: list[int], func, mask: int) -> list[int]:
    """Apply a linear function to each share independently."""
    return [(func(s) & mask) for s in shares]


class DomCanrightSBoxPipeline:
    """
    Pipelined DOM Canright S-box.

    Variants:
    - 5-stage: Uses DOM-dep multipliers in stages 1-3, DOM-indep in stage 4
    - 8-stage: Uses DOM-indep everywhere with extra register stages
    """

    def __init__(
        self,
        d: int,
        variant: int = 5,
        rng: random.Random | None = None,
        cycle_counter: CycleCounter | None = None,
        randomness_counter: RandomnessCounter | None = None,
        tracer: TraceRecorder | None = None,
    ):
        if d not in (1, 2):
            raise ValueError(f"Protection order d must be 1 or 2, got {d}")
        if variant not in (5, 8):
            raise ValueError(f"Variant must be 5 or 8, got {variant}")

        self.d = d
        self.num_shares = d + 1
        self.variant = variant
        self.rng = rng if rng else random.Random()
        self.cycle_counter = cycle_counter
        self.randomness_counter = randomness_counter
        self.tracer = tracer

        self.num_stages = variant
        self._pipeline: list[dict[str, Any] | None] = [None] * self.num_stages
        self._init_multipliers()
        self._current_byte_idx = -1

    def _init_multipliers(self):
        """Initialize DOM multiplier gadgets based on variant."""
        d = self.d
        rng = self.rng
        rc = self.randomness_counter

        if self.variant == 5:
            self.gf4_mult_stage1 = create_gf4_dom_dep(d, rng, rc)
            self.gf4_mult_stage2 = create_gf4_dom_dep(d, rng, rc)
            self.gf2_mult_stage2 = create_gf2_dom_dep(d, rng, rc)
            self.gf2_mult_stage3 = create_gf2_dom_dep(d, rng, rc)
            self.gf4_mult_stage4 = create_gf4_dom_indep(d, rng, rc)
        else:
            self.gf4_mult_stage1 = create_gf4_dom_indep(d, rng, rc)
            self.gf4_mult_stage2 = create_gf4_dom_indep(d, rng, rc)
            self.gf2_mult_stage2 = create_gf2_dom_indep(d, rng, rc)
            self.gf2_mult_stage3 = create_gf2_dom_indep(d, rng, rc)
            self.gf4_mult_stage4 = create_gf4_dom_indep(d, rng, rc)

    def push(self, input_shares: list[int], byte_index: int = -1) -> None:
        """Push a new shared byte into the pipeline."""
        if len(input_shares) != self.num_shares:
            raise ValueError(f"Expected {self.num_shares} shares, got {len(input_shares)}")

        if self._pipeline[0] is not None:
            raise RuntimeError("Pipeline slot 0 occupied; call step() first")

        self._current_byte_idx = byte_index

        # Apply input transformation to each share (linear, preserves sharing)
        transformed_shares = apply_linear_per_share(input_shares, input_transform, 0xFF)

        self._pipeline[0] = {
            "shares_8": transformed_shares,
            "byte_index": byte_index,
            "stage": 0,
        }

    def step(self) -> None:
        """Advance the pipeline by one cycle."""
        if self.cycle_counter:
            self.cycle_counter.increment(1)

        for stage_idx in range(self.num_stages - 1, -1, -1):
            entry = self._pipeline[stage_idx]
            if entry is None:
                continue

            processed = self._process_stage(stage_idx, entry)

            if stage_idx < self.num_stages - 1:
                self._pipeline[stage_idx + 1] = processed
            else:
                self._pipeline[stage_idx] = processed

            if stage_idx < self.num_stages - 1:
                self._pipeline[stage_idx] = None

    def _process_stage(self, stage_idx: int, entry: dict[str, Any]) -> dict[str, Any]:
        """Process a single pipeline stage."""
        shares_8 = entry["shares_8"]
        byte_idx = entry["byte_index"]

        if self.variant == 5:
            return self._process_stage_5variant(stage_idx, shares_8, byte_idx, entry)
        else:
            return self._process_stage_8variant(stage_idx, shares_8, byte_idx, entry)

    def _process_stage_5variant(
        self, stage_idx: int, shares_8: list[int], byte_idx: int, entry: dict[str, Any]
    ) -> dict[str, Any]:
        """Process stage for 5-stage variant."""

        if stage_idx == 0:
            shares_h = [(s >> 4) & 0xF for s in shares_8]
            shares_l = [s & 0xF for s in shares_8]

            shares_h_sq = apply_linear_per_share(shares_h, gf4_square, 0xF)

            def scale_E(x):
                return gf4_mult(x, 0x9)
            shares_h_sq_E = apply_linear_per_share(shares_h_sq, scale_E, 0xF)

            shares_l_sq = apply_linear_per_share(shares_l, gf4_square, 0xF)
            shares_lh = self.gf4_mult_stage1.multiply(shares_l, shares_h)

            shares_delta = [
                (shares_l_sq[i] ^ shares_lh[i] ^ shares_h_sq_E[i]) & 0xF
                for i in range(self.num_shares)
            ]

            return {
                "shares_8": shares_8,
                "byte_index": byte_idx,
                "stage": 1,
                "shares_h": shares_h,
                "shares_l": shares_l,
                "shares_delta": shares_delta,
            }

        elif stage_idx == 1:
            shares_delta = entry["shares_delta"]

            shares_dh = [(d >> 2) & 0x3 for d in shares_delta]
            shares_dl = [d & 0x3 for d in shares_delta]

            shares_dl_sq = apply_linear_per_share(shares_dl, gf2_square, 0x3)
            shares_dh_sq = apply_linear_per_share(shares_dh, gf2_square, 0x3)
            shares_dh_sq_n = apply_linear_per_share(shares_dh_sq, gf2_scaleN, 0x3)

            shares_dl_dh = self.gf2_mult_stage2.multiply(shares_dl, shares_dh)

            shares_e = [
                (shares_dl_sq[i] ^ shares_dl_dh[i] ^ shares_dh_sq_n[i]) & 0x3
                for i in range(self.num_shares)
            ]

            return {
                "shares_8": entry["shares_8"],
                "byte_index": byte_idx,
                "stage": 2,
                "shares_h": entry["shares_h"],
                "shares_l": entry["shares_l"],
                "shares_dh": shares_dh,
                "shares_dl": shares_dl,
                "shares_e": shares_e,
            }

        elif stage_idx == 2:
            shares_e = entry["shares_e"]
            shares_dh = entry["shares_dh"]
            shares_dl = entry["shares_dl"]

            e_recombined = recombine_shares(shares_e)
            e_inv = gf2_inverse(e_recombined)

            shares_e_inv = share_value(e_inv, self.num_shares, 0x3, self.rng)
            if self.randomness_counter:
                self.randomness_counter.add(
                    self.d * 2,
                    width=2,
                    operation="gf2_inv_reshare"
                )

            shares_dl_plus_dh = [(shares_dl[i] ^ shares_dh[i]) & 0x3 for i in range(self.num_shares)]

            shares_dinv_l = self.gf2_mult_stage3.multiply(shares_e_inv, shares_dl_plus_dh)
            shares_dinv_h = self.gf2_mult_stage3.multiply(shares_e_inv, shares_dh)

            shares_delta_inv = [
                ((shares_dinv_h[i] << 2) | shares_dinv_l[i]) & 0xF
                for i in range(self.num_shares)
            ]

            return {
                "shares_8": entry["shares_8"],
                "byte_index": byte_idx,
                "stage": 3,
                "shares_h": entry["shares_h"],
                "shares_l": entry["shares_l"],
                "shares_delta_inv": shares_delta_inv,
            }

        elif stage_idx == 3:
            shares_delta_inv = entry["shares_delta_inv"]
            shares_h = entry["shares_h"]
            shares_l = entry["shares_l"]

            shares_l_plus_h = [(shares_l[i] ^ shares_h[i]) & 0xF for i in range(self.num_shares)]

            shares_inv_h = self.gf4_mult_stage4.multiply(shares_delta_inv, shares_h)
            shares_inv_l = self.gf4_mult_stage4.multiply(shares_delta_inv, shares_l_plus_h)

            shares_inv_8 = [
                ((shares_inv_h[i] << 4) | shares_inv_l[i]) & 0xFF
                for i in range(self.num_shares)
            ]

            shares_out = apply_linear_per_share(shares_inv_8, output_linear_transform, 0xFF)
            shares_out[0] = (shares_out[0] ^ AFFINE_CONST) & 0xFF

            return {
                "shares_8": shares_out,
                "byte_index": byte_idx,
                "stage": 4,
                "complete": True,
            }

        else:
            return entry

    def _process_stage_8variant(
        self, stage_idx: int, shares_8: list[int], byte_idx: int, entry: dict[str, Any]
    ) -> dict[str, Any]:
        """Process stage for 8-stage variant with extra register stages."""

        if stage_idx == 0:
            return {
                "shares_8": shares_8,
                "byte_index": byte_idx,
                "stage": 1,
            }

        elif stage_idx == 1:
            shares_h = [(s >> 4) & 0xF for s in shares_8]
            shares_l = [s & 0xF for s in shares_8]

            shares_h_sq = apply_linear_per_share(shares_h, gf4_square, 0xF)

            def scale_E(x):
                return gf4_mult(x, 0x9)
            shares_h_sq_E = apply_linear_per_share(shares_h_sq, scale_E, 0xF)

            shares_l_sq = apply_linear_per_share(shares_l, gf4_square, 0xF)
            shares_lh = self.gf4_mult_stage1.multiply(shares_l, shares_h)

            shares_delta = [
                (shares_l_sq[i] ^ shares_lh[i] ^ shares_h_sq_E[i]) & 0xF
                for i in range(self.num_shares)
            ]

            return {
                "shares_8": shares_8,
                "byte_index": byte_idx,
                "stage": 2,
                "shares_h": shares_h,
                "shares_l": shares_l,
                "shares_delta": shares_delta,
            }

        elif stage_idx == 2:
            shares_delta = entry["shares_delta"]

            shares_dh = [(d >> 2) & 0x3 for d in shares_delta]
            shares_dl = [d & 0x3 for d in shares_delta]

            shares_dl_sq = apply_linear_per_share(shares_dl, gf2_square, 0x3)
            shares_dh_sq = apply_linear_per_share(shares_dh, gf2_square, 0x3)
            shares_dh_sq_n = apply_linear_per_share(shares_dh_sq, gf2_scaleN, 0x3)

            shares_dl_dh = self.gf2_mult_stage2.multiply(shares_dl, shares_dh)

            shares_e = [
                (shares_dl_sq[i] ^ shares_dl_dh[i] ^ shares_dh_sq_n[i]) & 0x3
                for i in range(self.num_shares)
            ]

            return {
                "shares_8": entry["shares_8"],
                "byte_index": byte_idx,
                "stage": 3,
                "shares_h": entry["shares_h"],
                "shares_l": entry["shares_l"],
                "shares_dh": shares_dh,
                "shares_dl": shares_dl,
                "shares_e": shares_e,
            }

        elif stage_idx == 3:
            result = dict(entry)
            result["stage"] = 4
            return result

        elif stage_idx == 4:
            shares_e = entry["shares_e"]
            shares_dh = entry["shares_dh"]
            shares_dl = entry["shares_dl"]

            e_recombined = recombine_shares(shares_e)
            e_inv = gf2_inverse(e_recombined)

            shares_e_inv = share_value(e_inv, self.num_shares, 0x3, self.rng)
            if self.randomness_counter:
                self.randomness_counter.add(
                    self.d * 2,
                    width=2,
                    operation="gf2_inv_reshare"
                )

            shares_dl_plus_dh = [(shares_dl[i] ^ shares_dh[i]) & 0x3 for i in range(self.num_shares)]

            shares_dinv_l = self.gf2_mult_stage3.multiply(shares_e_inv, shares_dl_plus_dh)
            shares_dinv_h = self.gf2_mult_stage3.multiply(shares_e_inv, shares_dh)

            shares_delta_inv = [
                ((shares_dinv_h[i] << 2) | shares_dinv_l[i]) & 0xF
                for i in range(self.num_shares)
            ]

            return {
                "shares_8": entry["shares_8"],
                "byte_index": byte_idx,
                "stage": 5,
                "shares_h": entry["shares_h"],
                "shares_l": entry["shares_l"],
                "shares_delta_inv": shares_delta_inv,
            }

        elif stage_idx == 5:
            result = dict(entry)
            result["stage"] = 6
            return result

        elif stage_idx == 6:
            shares_delta_inv = entry["shares_delta_inv"]
            shares_h = entry["shares_h"]
            shares_l = entry["shares_l"]

            shares_l_plus_h = [(shares_l[i] ^ shares_h[i]) & 0xF for i in range(self.num_shares)]

            shares_inv_h = self.gf4_mult_stage4.multiply(shares_delta_inv, shares_h)
            shares_inv_l = self.gf4_mult_stage4.multiply(shares_delta_inv, shares_l_plus_h)

            shares_inv_8 = [
                ((shares_inv_h[i] << 4) | shares_inv_l[i]) & 0xFF
                for i in range(self.num_shares)
            ]

            shares_out = apply_linear_per_share(shares_inv_8, output_linear_transform, 0xFF)
            shares_out[0] = (shares_out[0] ^ AFFINE_CONST) & 0xFF

            return {
                "shares_8": shares_out,
                "byte_index": byte_idx,
                "stage": 7,
                "complete": True,
            }

        else:
            return entry

    # ------------------------------------------------------------------
    # Pipeline query (for verbose tracing from the model)
    # ------------------------------------------------------------------

    def get_occupancy(self) -> list[int | None]:
        """Return byte_index at each pipeline stage (None if empty)."""
        return [
            e["byte_index"] if e is not None else None
            for e in self._pipeline
        ]

    # ------------------------------------------------------------------
    # Output / control
    # ------------------------------------------------------------------

    def pop(self) -> list[int] | None:
        """Pop completed output from the pipeline."""
        last_entry = self._pipeline[self.num_stages - 1]
        if last_entry is not None and last_entry.get("complete"):
            self._pipeline[self.num_stages - 1] = None
            return last_entry["shares_8"]
        return None

    def peek(self) -> dict[str, Any] | None:
        """Peek at the output stage without removing."""
        return self._pipeline[self.num_stages - 1]

    def is_ready(self) -> bool:
        """Check if output is ready to be popped."""
        entry = self._pipeline[self.num_stages - 1]
        return entry is not None and entry.get("complete", False)

    def is_empty(self) -> bool:
        """Check if pipeline is completely empty."""
        return all(e is None for e in self._pipeline)

    def can_accept(self) -> bool:
        """Check if pipeline can accept new input."""
        return self._pipeline[0] is None

    @property
    def depth(self) -> int:
        """Get pipeline depth (number of stages)."""
        return self.num_stages

    def flush(self) -> list[list[int]]:
        """Flush remaining items from pipeline."""
        outputs = []
        while not self.is_empty():
            self.step()
            out = self.pop()
            if out is not None:
                outputs.append(out)
        return outputs
