"""TI-style masked AES skeleton implementation.

This is a SKELETON implementation that:
- Produces correct ciphertext (using unmasked AES internally)
- Models cycle and randomness costs as if using Threshold Implementation (TI) masking
- Does NOT provide actual side-channel protection

The purpose is architectural tradeoff evaluation, not secure implementation.
"""

from __future__ import annotations

from aes_eval.interfaces import BaseTechnique, Result, EvalConfig
from aes_eval.cycle_models import CycleModel
from aes_eval.randomness import RandomSource
from aes_eval.golden import golden_encrypt, validate_against_golden


class MaskedTISkeleton(BaseTechnique):
    """TI-style masked AES skeleton.

    Threshold Implementation (TI) characteristics modeled:
    - Fresh randomness for initial masking: (shares-1) * state_bytes * 8 bits
    - TI gadgets: s fresh bits per gadget for s shares (re-sharing)
    - Higher share count typically needed for non-completeness (d+1 shares minimum)
    - Additional registers for pipelining TI stages

    Key differences from DOM:
    - TI requires more shares for same security level in some cases
    - TI gadgets have different randomness pattern
    - TI may have higher latency due to pipelining requirements

    WARNING: This is a skeleton for cost modeling only.
    It does NOT provide side-channel protection.
    """

    name = "masked_ti_skeleton"
    description = "TI-style masked AES skeleton (cost modeling only, not secure)"

    # TI-specific cycle overhead factors
    # TI typically requires more cycles due to pipeline stages
    TI_SBOX_OVERHEAD_FACTOR = 3.0  # TI S-box takes ~3x cycles (pipelined stages)
    TI_REFRESH_CYCLES_PER_ROUND = 3  # More refresh for TI
    TI_REGISTER_STAGES = 2  # Pipeline stages in TI gadgets

    def encrypt_block(
        self,
        key: bytes,
        plaintext: bytes,
        rng: RandomSource,
        cycle_model: CycleModel,
        config: EvalConfig,
    ) -> Result:
        """Encrypt a single 16-byte block with TI cost modeling.

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
            "ti_gadgets": 0,
            "refresh_ops": 0,
            "pipeline_stages": 0,
        }

        # Compute correct ciphertext using golden reference
        ciphertext = golden_encrypt(key, plaintext)

        # Model randomness consumption for TI masking
        if shares > 1:
            # Fresh masks for initial sharing
            rng.estimate_fresh_masks(shares, state_bytes=16)

            # Fresh masks for key sharing
            rng.estimate_fresh_masks(shares, state_bytes=16)

        # Key schedule cycles (increased for masked key schedule)
        # TI key schedule may be more complex due to non-completeness
        key_schedule_overhead = shares * self.TI_REGISTER_STAGES if shares > 1 else 1
        for _ in range(10 * key_schedule_overhead):
            cycle_model.account_key_schedule(1)

        # Initial AddRoundKey
        cycle_model.account_add_round_key()
        op_counts["xor_ops"] += 16 * shares

        # Main rounds 1-9
        for round_num in range(1, 10):
            # SubBytes with TI S-box
            # TI S-box requires pipeline stages for non-completeness
            sbox_calls = 16
            op_counts["sbox_calls"] += sbox_calls

            # Model TI gadget randomness
            if shares > 1:
                rng.estimate_ti_gadgets(shares, num_sboxes=sbox_calls)
                # Count gadget and pipeline operations
                gadgets_per_sbox = 4
                op_counts["ti_gadgets"] += sbox_calls * gadgets_per_sbox
                op_counts["pipeline_stages"] += sbox_calls * self.TI_REGISTER_STAGES

            # SubBytes cycles (with TI overhead for pipelining)
            for _ in range(int(self.TI_SBOX_OVERHEAD_FACTOR)):
                cycle_model.account_sub_bytes()

            # ShiftRows (same for all shares)
            cycle_model.account_shift_rows()

            # MixColumns (linear, cost per share)
            for _ in range(shares):
                cycle_model.account_mix_columns()
            op_counts["xor_ops"] += 16 * 4 * shares

            # AddRoundKey
            cycle_model.account_add_round_key()
            op_counts["xor_ops"] += 16 * shares

            # Per-round refresh/remasking (TI needs more refresh)
            if shares > 1:
                rng.estimate_remasking(shares, state_bytes=16)
                for _ in range(self.TI_REFRESH_CYCLES_PER_ROUND):
                    cycle_model.account_refresh()
                op_counts["refresh_ops"] += 16

        # Final round (no MixColumns)
        sbox_calls = 16
        op_counts["sbox_calls"] += sbox_calls

        if shares > 1:
            rng.estimate_ti_gadgets(shares, num_sboxes=sbox_calls)
            op_counts["ti_gadgets"] += sbox_calls * 4
            op_counts["pipeline_stages"] += sbox_calls * self.TI_REGISTER_STAGES

        for _ in range(int(self.TI_SBOX_OVERHEAD_FACTOR)):
            cycle_model.account_sub_bytes()

        cycle_model.account_shift_rows()
        cycle_model.account_add_round_key()
        op_counts["xor_ops"] += 16 * shares

        # Validate
        correct, error_detail = validate_against_golden(key, plaintext, ciphertext)

        warnings = [
            "Skeleton implementation: models TI costs but does not provide actual masking",
            "Randomness and cycle estimates based on literature; specific implementations may vary",
            "TI pipelining model is simplified; real TI may have different stage structures",
        ]

        if shares > 1:
            notes = [
                f"TI masking with d={config.mask_order_d} (shares={shares})",
                f"TI gadgets consume {rng.bits_breakdown.get('gadget_randomness', 0)} bits",
                f"Pipeline stages modeled: {op_counts['pipeline_stages']}",
            ]
        else:
            notes = ["d=0 requested: running unmasked with TI cycle overhead model"]
            warnings.append("mask_order_d=0 means no masking; TI overhead still modeled for comparison")

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
