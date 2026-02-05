"""DOM-style masked AES skeleton implementation.

This is a SKELETON implementation that:
- Produces correct ciphertext (using unmasked AES internally)
- Models cycle and randomness costs as if using DOM masking
- Does NOT provide actual side-channel protection

The purpose is architectural tradeoff evaluation, not secure implementation.
"""

from __future__ import annotations

from aes_eval.interfaces import BaseTechnique, Result, EvalConfig
from aes_eval.cycle_models import CycleModel, CycleModelConfig
from aes_eval.randomness import RandomSource
from aes_eval.golden import golden_encrypt, validate_against_golden


class MaskedDOMSkeleton(BaseTechnique):
    """DOM-style masked AES skeleton.

    Domain-Oriented Masking (DOM) characteristics modeled:
    - Fresh randomness for initial masking: (shares-1) * state_bytes * 8 bits
    - DOM AND gadgets: (s-1)*s/2 fresh bits per gadget for s shares
    - Per-round refresh randomness

    WARNING: This is a skeleton for cost modeling only.
    It does NOT provide side-channel protection.
    """

    name = "masked_dom_skeleton"
    description = "DOM-style masked AES skeleton (cost modeling only, not secure)"

    # DOM-specific cycle overhead factors
    # These model the additional cycles needed for masked operations
    DOM_SBOX_OVERHEAD_FACTOR = 2.5  # DOM S-box takes ~2.5x cycles
    DOM_REFRESH_CYCLES_PER_ROUND = 2  # Refresh operations per round

    def encrypt_block(
        self,
        key: bytes,
        plaintext: bytes,
        rng: RandomSource,
        cycle_model: CycleModel,
        config: EvalConfig,
    ) -> Result:
        """Encrypt a single 16-byte block with DOM cost modeling.

        Args:
            key: 16-byte AES key
            plaintext: 16-byte plaintext block
            rng: Random source for masking cost tracking
            cycle_model: Cycle model for accounting
            config: Evaluation configuration

        Returns:
            Result with ciphertext and accounting data
        """
        self.validate_inputs(key, plaintext)

        shares = config.shares
        rng.reset()
        cycle_model.reset()

        # Track operations
        op_counts = {
            "sbox_calls": 0,
            "xor_ops": 0,
            "dom_and_gadgets": 0,
            "refresh_ops": 0,
        }

        # Compute correct ciphertext using golden reference
        # (skeleton delegates correctness to verified implementation)
        ciphertext = golden_encrypt(key, plaintext)

        # Model randomness consumption for DOM masking
        if shares > 1:
            # Fresh masks for initial sharing
            rng.estimate_fresh_masks(shares, state_bytes=16)

            # Fresh masks for key sharing
            rng.estimate_fresh_masks(shares, state_bytes=16)

        # Key schedule cycles (slightly increased for masked key schedule)
        key_schedule_overhead = shares if shares > 1 else 1
        for _ in range(10 * key_schedule_overhead):
            cycle_model.account_key_schedule(1)

        # Initial AddRoundKey
        cycle_model.account_add_round_key()
        op_counts["xor_ops"] += 16 * shares  # XOR each share

        # Main rounds 1-9
        for round_num in range(1, 10):
            # SubBytes with DOM S-box
            # DOM S-box has overhead due to AND gadgets
            # Each S-box evaluation involves ~4 AND gadgets
            sbox_calls = 16
            op_counts["sbox_calls"] += sbox_calls

            # Model DOM AND gadget randomness
            if shares > 1:
                rng.estimate_dom_gadgets(shares, num_sboxes=sbox_calls)
                # Count gadget operations
                gadgets_per_sbox = 4  # Approximate AND depth
                op_counts["dom_and_gadgets"] += sbox_calls * gadgets_per_sbox

            # SubBytes cycles (with DOM overhead)
            for _ in range(int(self.DOM_SBOX_OVERHEAD_FACTOR)):
                cycle_model.account_sub_bytes()

            # ShiftRows (same for all shares, parallel)
            cycle_model.account_shift_rows()

            # MixColumns (linear, same cost per share)
            for _ in range(shares):
                cycle_model.account_mix_columns()
            op_counts["xor_ops"] += 16 * 4 * shares

            # AddRoundKey
            cycle_model.account_add_round_key()
            op_counts["xor_ops"] += 16 * shares

            # Per-round refresh/remasking
            if shares > 1:
                rng.estimate_remasking(shares, state_bytes=16)
                for _ in range(self.DOM_REFRESH_CYCLES_PER_ROUND):
                    cycle_model.account_refresh()
                op_counts["refresh_ops"] += 16

        # Final round (no MixColumns)
        sbox_calls = 16
        op_counts["sbox_calls"] += sbox_calls

        if shares > 1:
            rng.estimate_dom_gadgets(shares, num_sboxes=sbox_calls)
            op_counts["dom_and_gadgets"] += sbox_calls * 4

        for _ in range(int(self.DOM_SBOX_OVERHEAD_FACTOR)):
            cycle_model.account_sub_bytes()

        cycle_model.account_shift_rows()
        cycle_model.account_add_round_key()
        op_counts["xor_ops"] += 16 * shares

        # Validate (should always pass since we use golden)
        correct, error_detail = validate_against_golden(key, plaintext, ciphertext)

        warnings = [
            "Skeleton implementation: models DOM costs but does not provide actual masking",
            "Randomness and cycle estimates based on literature; specific implementations may vary",
        ]

        if shares > 1:
            notes = [
                f"DOM masking with d={config.mask_order_d} (shares={shares})",
                f"DOM AND gadgets consume {rng.bits_breakdown.get('gadget_randomness', 0)} bits",
            ]
        else:
            notes = ["d=0 requested: running unmasked with DOM cycle overhead model"]
            warnings.append("mask_order_d=0 means no masking; DOM overhead still modeled for comparison")

        return Result(
            ciphertext=ciphertext,
            correct=correct,
            error_detail=error_detail,
            cycle_count_total=cycle_model.total_cycles,
            cycle_breakdown=cycle_model.breakdown,
            random_bits_total=rng.total_bits,
            random_bits_breakdown=rng.bits_breakdown,
            op_counts=op_counts,
            notes=notes,
            warnings=warnings,
        )
