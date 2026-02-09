"""
Didactic single-round AES walkthrough.

Performs ONLY Round 1 of AES-128 encryption (after the initial
AddRoundKey in Round 0) and explains every transformation step
in an educational manner.

Supports both the unprotected and DOM models, reusing the same
AES primitives as the full encryption path.
"""

from __future__ import annotations

import json
import random as _random_module
from typing import Any, TextIO

from .aes_core import (
    key_expansion,
    sub_bytes,
    shift_rows,
    mix_columns,
    add_round_key,
    xtime,
    SBOX,
    apply_shift_rows_to_shares,
    apply_mix_columns_to_shares,
    apply_add_round_key_to_shares,
)
from .counters import CycleCounter, RandomnessCounter
from .utils import (
    bytes_to_state,
    state_to_bytes,
    state_to_hex,
    copy_state,
    format_state_grid,
)
from .dom.sbox_canright_dom import (
    DomCanrightSBoxPipeline,
    share_value,
    recombine_shares,
)
from .trace import TraceRecorder


# ──────────────────────────────────────────────────────────────────
# Formatting helpers
# ──────────────────────────────────────────────────────────────────

def _fmt_matrix_labeled(state: list[list[int]], indent: str = "    ") -> str:
    """Format a 4x4 state with column headers and row labels."""
    lines: list[str] = []
    lines.append(f"{indent}       c0   c1   c2   c3")
    for row in range(4):
        vals = "   ".join(f"{state[row][col]:02x}" for col in range(4))
        lines.append(f"{indent}r{row}  [ {vals} ]")
    return "\n".join(lines)


def _byte_index(row: int, col: int) -> int:
    """Column-major linear index for byte at (row, col)."""
    return col * 4 + row


def _fmt_byte_table(
    rows: list[tuple[Any, ...]],
    headers: list[str],
    indent: str = "    ",
) -> str:
    """Format a list of row-tuples as an aligned table."""
    widths = [len(h) for h in headers]
    for r in rows:
        for i, v in enumerate(r):
            widths[i] = max(widths[i], len(str(v)))

    parts: list[str] = []
    hdr = indent + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    parts.append(hdr)
    parts.append(indent + "  ".join("-" * w for w in widths))
    for r in rows:
        parts.append(indent + "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(r)))
    return "\n".join(parts)


def _recombine(shares: list[list[list[int]]]) -> list[list[int]]:
    """XOR all shares to recover the unmasked state."""
    nshares = len(shares)
    result = [[0] * 4 for _ in range(4)]
    for row in range(4):
        for col in range(4):
            v = 0
            for s in range(nshares):
                v ^= shares[s][row][col]
            result[row][col] = v
    return result


# ──────────────────────────────────────────────────────────────────
# Unprotected round walkthrough
# ──────────────────────────────────────────────────────────────────

def run_unprotected_round(
    key: bytes,
    plaintext: bytes,
    verbose: bool = False,
    trace_file: TextIO | None = None,
) -> dict[str, Any]:
    """
    Execute Round 0 + Round 1 of unprotected AES-128 with didactic output.

    Returns a dict with:
        state_in_round1   – 4x4 state entering Round 1
        state_out_round1  – 4x4 state after Round 1
        cycles            – total cycles consumed
    """
    out = _Printer(verbose)
    jl = _JsonlWriter(trace_file, mode="round", model="unprotected_ht")

    round_keys = key_expansion(key)

    # ── 1. State layout primer ──────────────────────────────────
    out.section("1. AES State Layout")
    out.p("AES operates on a 4x4 byte matrix in COLUMN-MAJOR order.")
    out.p("state[row][col]  with row=0..3, col=0..3")
    out.p("")
    out.p("Linear byte index (column-major):")
    out.p("    b00 b01 b02 b03      col 0  col 1  col 2  col 3")
    out.p("    b04 b05 b06 b07  =>  r0[ b0   b4   b8   b12 ]")
    out.p("    b08 b09 b10 b11      r1[ b1   b5   b9   b13 ]")
    out.p("    b12 b13 b14 b15      r2[ b2   b6   b10  b14 ]")
    out.p("                         r3[ b3   b7   b11  b15 ]")

    # ── 2. Inputs ───────────────────────────────────────────────
    out.section("2. Inputs")
    out.p(f"Key (hex):       {key.hex()}")
    out.p(f"Plaintext (hex): {plaintext.hex()}")
    out.p("")
    out.p("RoundKey[0] (same as Key in AES-128):")
    out.p(_fmt_matrix_labeled(round_keys[0]))
    out.p("")
    out.p("RoundKey[1]:")
    out.p(_fmt_matrix_labeled(round_keys[1]))

    jl.emit(stage="inputs", round_key_0=_state_hex(round_keys[0]),
            round_key_1=_state_hex(round_keys[1]))

    # ── 3. Round 0: initial AddRoundKey ─────────────────────────
    out.section("3. Pre-round: Round 0 AddRoundKey")
    pt_state = bytes_to_state(plaintext)
    out.p("Plaintext state:")
    out.p(_fmt_matrix_labeled(pt_state))
    out.p("")
    out.p("RoundKey[0]:")
    out.p(_fmt_matrix_labeled(round_keys[0]))

    state_in = add_round_key(pt_state, round_keys[0])

    out.p("")
    out.p("AddRoundKey: Plaintext XOR RoundKey[0]")
    # per-byte table
    xor_rows: list[tuple[str, ...]] = []
    for col in range(4):
        for row in range(4):
            idx = _byte_index(row, col)
            pv = pt_state[row][col]
            kv = round_keys[0][row][col]
            rv = state_in[row][col]
            xor_rows.append((
                f"b{idx:02d}", f"({row},{col})",
                f"{pv:02x}", f"{kv:02x}", f"{rv:02x}",
                f"{pv:02x} ^ {kv:02x} = {rv:02x}",
            ))
            jl.emit(stage="add_round_key_0", i=idx, r=row, c=col,
                    pt=f"{pv:02x}", rk0=f"{kv:02x}", out=f"{rv:02x}")
    out.p(_fmt_byte_table(xor_rows,
                          ["idx", "(r,c)", "pt", "rk0", "out", "equation"]))

    out.p("")
    out.p("State entering Round 1:")
    out.p(_fmt_matrix_labeled(state_in))

    # ── 4. Round 1 walkthrough ──────────────────────────────────
    out.section("4. Round 1 Walkthrough")
    cycles = 2  # cycle 0 = AddRoundKey(r0), cycle 1 = Round 1

    # 4.1 SubBytes
    out.subsection("4.1  SubBytes")
    out.p("Each byte is replaced by its S-box lookup: out = S[in]")
    out.p("")
    out.p("Input state:")
    out.p(_fmt_matrix_labeled(state_in))

    after_sb = sub_bytes(state_in)

    sb_rows: list[tuple[str, ...]] = []
    for col in range(4):
        for row in range(4):
            idx = _byte_index(row, col)
            inv = state_in[row][col]
            outv = after_sb[row][col]
            sb_rows.append((
                f"b{idx:02d}", f"({row},{col})",
                f"{inv:02x}", f"{outv:02x}",
            ))
            jl.emit(stage="subbytes", i=idx, r=row, c=col,
                    **{"in": f"{inv:02x}", "out": f"{outv:02x}"})
    out.p(_fmt_byte_table(sb_rows, ["idx", "(r,c)", "in", "S[in]"]))
    out.p("")
    out.p("After SubBytes:")
    out.p(_fmt_matrix_labeled(after_sb))

    # 4.2 ShiftRows
    out.subsection("4.2  ShiftRows")
    out.p("Each row is cyclically shifted LEFT by its row index.")
    out.p("")
    for r in range(4):
        before_vals = [f"{after_sb[r][c]:02x}" for c in range(4)]
        after_vals = [f"{after_sb[r][(c + r) % 4]:02x}" for c in range(4)]
        mapping = ", ".join(
            f"c{c}<-c{(c+r)%4}" for c in range(4)
        )
        out.p(f"  Row {r} (shift left by {r}): [{' '.join(before_vals)}] -> [{' '.join(after_vals)}]")
        out.p(f"         positions: {mapping}")

    after_sr = shift_rows(after_sb)

    for col in range(4):
        for row in range(4):
            idx = _byte_index(row, col)
            inv = after_sb[row][col]
            outv = after_sr[row][col]
            src_col = (col + row) % 4
            jl.emit(stage="shiftrows", i=idx, r=row, c=col,
                    **{"in": f"{inv:02x}", "out": f"{outv:02x}",
                       "src_col": src_col})

    out.p("")
    out.p("After ShiftRows:")
    out.p(_fmt_matrix_labeled(after_sr))

    # 4.3 MixColumns
    out.subsection("4.3  MixColumns")
    out.p("Each column is multiplied by the fixed matrix in GF(2^8):")
    out.p("    [02 03 01 01]   [a0]   [r0]")
    out.p("    [01 02 03 01] x [a1] = [r1]")
    out.p("    [01 01 02 03]   [a2]   [r2]")
    out.p("    [03 01 01 02]   [a3]   [r3]")
    out.p("")
    out.p("where  *02 = xtime(a)")
    out.p("       *03 = xtime(a) XOR a")

    after_mc = mix_columns(after_sr)

    for col in range(4):
        a = [after_sr[row][col] for row in range(4)]
        r = [after_mc[row][col] for row in range(4)]

        out.p("")
        out.p(f"  --- Column {col} ---")
        out.p(f"  Input:  a0={a[0]:02x}  a1={a[1]:02x}  a2={a[2]:02x}  a3={a[3]:02x}")

        # Pre-compute GF multiplies
        xt = [xtime(v) for v in a]  # *02
        x3 = [xt[i] ^ a[i] for i in range(4)]  # *03

        out.p(f"  xtime:  {xt[0]:02x}      {xt[1]:02x}      {xt[2]:02x}      {xt[3]:02x}")
        out.p(f"  *03:    {x3[0]:02x}      {x3[1]:02x}      {x3[2]:02x}      {x3[3]:02x}")

        # Show each output byte equation
        eqs = [
            (xt[0], x3[1], a[2], a[3]),  # r0 = 02*a0 ^ 03*a1 ^ a2 ^ a3
            (a[0], xt[1], x3[2], a[3]),  # r1 = a0 ^ 02*a1 ^ 03*a2 ^ a3
            (a[0], a[1], xt[2], x3[3]),  # r2 = a0 ^ a1 ^ 02*a2 ^ 03*a3
            (x3[0], a[1], a[2], xt[3]),  # r3 = 03*a0 ^ a1 ^ a2 ^ 02*a3
        ]
        labels = [
            "02*a0 ^ 03*a1 ^   a2 ^   a3",
            "  a0 ^ 02*a1 ^ 03*a2 ^   a3",
            "  a0 ^   a1 ^ 02*a2 ^ 03*a3",
            "03*a0 ^   a1 ^   a2 ^ 02*a3",
        ]
        for ri in range(4):
            t0, t1, t2, t3 = eqs[ri]
            out.p(f"  r{ri} = {labels[ri]}")
            out.p(f"     = {t0:02x} ^ {t1:02x} ^ {t2:02x} ^ {t3:02x} = {r[ri]:02x}")

        jl.emit(stage="mixcolumns", col=col,
                a=[f"{v:02x}" for v in a],
                xtime=[f"{v:02x}" for v in xt],
                times3=[f"{v:02x}" for v in x3],
                result=[f"{v:02x}" for v in r])

    out.p("")
    out.p("After MixColumns:")
    out.p(_fmt_matrix_labeled(after_mc))

    # 4.4 AddRoundKey (Round 1)
    out.subsection("4.4  AddRoundKey (Round 1)")
    out.p("MixColumns output:")
    out.p(_fmt_matrix_labeled(after_mc))
    out.p("")
    out.p("RoundKey[1]:")
    out.p(_fmt_matrix_labeled(round_keys[1]))

    state_out = add_round_key(after_mc, round_keys[1])

    ark_rows: list[tuple[str, ...]] = []
    for col in range(4):
        for row in range(4):
            idx = _byte_index(row, col)
            sv = after_mc[row][col]
            kv = round_keys[1][row][col]
            rv = state_out[row][col]
            ark_rows.append((
                f"b{idx:02d}", f"({row},{col})",
                f"{sv:02x}", f"{kv:02x}", f"{rv:02x}",
                f"{sv:02x} ^ {kv:02x} = {rv:02x}",
            ))
            jl.emit(stage="add_round_key_1", i=idx, r=row, c=col,
                    state=f"{sv:02x}", rk1=f"{kv:02x}", out=f"{rv:02x}")
    out.p("")
    out.p("state XOR RoundKey[1]:")
    out.p(_fmt_byte_table(ark_rows,
                          ["idx", "(r,c)", "state", "rk1", "out", "equation"]))
    out.p("")
    out.p("State after Round 1:")
    out.p(_fmt_matrix_labeled(state_out))

    # ── 5. Summary ──────────────────────────────────────────────
    out.section("5. Summary")
    in_hex = state_to_hex(state_in)
    out_hex = state_to_hex(state_out)
    out.p(f"State entering Round 1: {in_hex}")
    out.p(f"State after   Round 1: {out_hex}")
    out.p("")
    out.p("Cycle breakdown:")
    out.p("  AddRoundKey (Round 0):                  1 cycle")
    out.p("  Round 1 (SubBytes+ShiftRows+MixColumns+AddRoundKey): 1 cycle")
    out.p(f"  Total:                                  {cycles} cycles")
    out.p("")
    out.p("Randomness: 0 bits (unprotected model)")

    jl.emit(stage="summary", state_in=in_hex, state_out=out_hex, cycles=cycles,
            cycle_breakdown={"add_round_key_0": 1, "round_1": 1},
            random_bits=0)

    return {
        "state_in_round1": state_in,
        "state_out_round1": state_out,
        "cycles": cycles,
    }


# ──────────────────────────────────────────────────────────────────
# DOM round walkthrough
# ──────────────────────────────────────────────────────────────────

def run_dom_round(
    key: bytes,
    plaintext: bytes,
    d: int = 1,
    sbox_variant: int = 5,
    seed: int | None = None,
    verbose: bool = False,
    trace_file: TextIO | None = None,
) -> dict[str, Any]:
    """
    Execute Round 0 + Round 1 of DOM-masked AES-128 with didactic output.

    Returns a dict with:
        state_in_round1   – 4x4 recombined state entering Round 1
        state_out_round1  – 4x4 recombined state after Round 1
        shares_out        – list of d+1 4x4 share matrices after Round 1
        cycles            – total cycles consumed
        random_bits       – total random bits consumed
    """
    out = _Printer(verbose)
    jl = _JsonlWriter(trace_file, mode="round", model="dom",
                      extra={"d": d, "sbox_variant": sbox_variant})

    num_shares = d + 1
    actual_seed = seed if seed is not None else _random_module.randint(0, 2**32 - 1)
    rng = _random_module.Random(actual_seed)
    cycle_counter = CycleCounter()
    rng_counter = RandomnessCounter(track_draws=verbose)

    round_keys = key_expansion(key)

    # ── 1. State layout primer ──────────────────────────────────
    out.section("1. AES State Layout")
    out.p("AES operates on a 4x4 byte matrix in COLUMN-MAJOR order.")
    out.p("state[row][col]  with row=0..3, col=0..3")
    out.p("Linear byte index = col*4 + row")

    # ── 2. Inputs ───────────────────────────────────────────────
    out.section("2. Inputs")
    out.p(f"Key (hex):       {key.hex()}")
    out.p(f"Plaintext (hex): {plaintext.hex()}")
    out.p(f"Protection order: d={d} ({num_shares} shares)")
    out.p(f"S-box variant: {sbox_variant}-stage pipeline")
    out.p(f"RNG seed: {actual_seed}")
    out.p("")
    out.p("RoundKey[0]:")
    out.p(_fmt_matrix_labeled(round_keys[0]))
    out.p("")
    out.p("RoundKey[1]:")
    out.p(_fmt_matrix_labeled(round_keys[1]))

    jl.emit(stage="inputs", round_key_0=_state_hex(round_keys[0]),
            round_key_1=_state_hex(round_keys[1]),
            d=d, shares=num_shares, seed=actual_seed)

    # ── 3. Initial masking + Round 0 AddRoundKey ────────────────
    out.section("3. Initial Masking + Round 0 AddRoundKey")

    pt_state = bytes_to_state(plaintext)
    key_state = bytes_to_state(key)

    # 3a. Key masking
    out.subsection("3a. Key Masking")
    rng_counter.snapshot()
    key_shares = _share_grid(key_state, num_shares, rng, rng_counter, "key_mask")
    key_recomb = _recombine(key_shares)
    out.p(f"Splitting key into {num_shares} shares (consuming {d}*128 = {d*128} random bits):")
    for si in range(num_shares):
        out.p(f"  KeyShare[{si}]: {_state_hex(key_shares[si])}")
    out.p(f"  XOR check:  {_state_hex(key_recomb)}")

    jl.emit(stage="key_mask", shares=[_state_hex(s) for s in key_shares],
            recombined=_state_hex(key_recomb),
            rnd_bits=rng_counter.bits_since_snapshot())

    # 3b. State masking
    out.subsection("3b. State (Plaintext) Masking")
    rng_counter.snapshot()
    state_shares = _share_grid(pt_state, num_shares, rng, rng_counter, "state_mask_init")
    state_recomb = _recombine(state_shares)
    out.p(f"Splitting plaintext into {num_shares} shares (consuming {d*128} random bits):")
    for si in range(num_shares):
        out.p(f"  StateShare[{si}]: {_state_hex(state_shares[si])}")
    out.p(f"  XOR check:  {_state_hex(state_recomb)}")

    jl.emit(stage="state_mask_init", shares=[_state_hex(s) for s in state_shares],
            recombined=_state_hex(state_recomb),
            rnd_bits=rng_counter.bits_since_snapshot())

    # 3c. Round 0 AddRoundKey (each state share XOR with corresponding key share)
    out.subsection("3c. Round 0 AddRoundKey (shared)")
    rng_counter.snapshot()
    cycle_counter.increment(1)

    for si in range(num_shares):
        state_shares[si] = add_round_key(state_shares[si], key_shares[si])

    state_in = _recombine(state_shares)
    out.p("AddRoundKey applied per-share: StateShare[i] ^= KeyShare[i]")
    for si in range(num_shares):
        out.p(f"  Share[{si}]: {_state_hex(state_shares[si])}")
    out.p(f"  Recombined (state entering Round 1): {_state_hex(state_in)}")
    out.p("")
    out.p("Recombined as matrix:")
    out.p(_fmt_matrix_labeled(state_in))

    jl.emit(stage="add_round_key_0",
            shares=[_state_hex(s) for s in state_shares],
            recombined=_state_hex(state_in))

    # ── 4. Round 1 walkthrough ──────────────────────────────────
    out.section("4. Round 1 Walkthrough (DOM)")

    # Track per-step costs
    cycles_before_r1 = cycle_counter.count
    rng_before_r1 = rng_counter.total_bits

    # 4.1 SubBytes
    out.subsection("4.1  SubBytes (DOM S-box Pipeline)")
    out.p(f"  Byte-serial through {sbox_variant}-stage Canright pipeline")
    out.p(f"  Processing 16 bytes in column-major order (b0..b15)")
    out.p("")

    cycles_before_sb = cycle_counter.count
    rng_before_sb = rng_counter.total_bits

    sbox = DomCanrightSBoxPipeline(
        d=d, variant=sbox_variant, rng=rng,
        cycle_counter=cycle_counter,
        randomness_counter=rng_counter,
    )

    # Collect input bytes
    input_list: list[tuple[int, int, int, list[int]]] = []
    for col in range(4):
        for row in range(4):
            idx = _byte_index(row, col)
            byte_shares = [state_shares[s][row][col] for s in range(num_shares)]
            input_list.append((idx, row, col, byte_shares))

    output_map: dict[int, list[int]] = {}
    input_ptr = 0

    # Run pipeline
    while input_ptr < 16 or not sbox.is_empty():
        rng_counter.snapshot()
        if input_ptr < 16 and sbox.can_accept():
            idx, row, col, byte_shares = input_list[input_ptr]
            sbox.push(byte_shares, byte_index=idx)
            input_ptr += 1
        sbox.step()
        if sbox.is_ready():
            entry = sbox.peek()
            bi = entry["byte_index"] if entry else -1
            out_shares = sbox.pop()
            if out_shares is not None:
                output_map[bi] = out_shares

    remaining = sbox.flush()
    rng_sb = rng_counter.total_bits - rng_before_sb
    cycles_sb = cycle_counter.count - cycles_before_sb

    # Write outputs back
    for idx, row, col, in_shares in input_list:
        out_sh = output_map[idx]
        for s in range(num_shares):
            state_shares[s][row][col] = out_sh[s]

    after_sb_recomb = _recombine(state_shares)

    # Print per-byte summary
    out.p("Per-byte S-box summary:")
    sb_rows: list[tuple[str, ...]] = []
    for idx, row, col, in_shares in input_list:
        out_sh = output_map[idx]
        in_recomb = 0
        for v in in_shares:
            in_recomb ^= v
        out_recomb = recombine_shares(out_sh)
        sb_rows.append((
            f"b{idx:02d}", f"({row},{col})",
            " ".join(f"{v:02x}" for v in in_shares),
            f"{in_recomb:02x}",
            " ".join(f"{v:02x}" for v in out_sh),
            f"{out_recomb:02x}",
        ))
        jl.emit(stage="subbytes", i=idx, r=row, c=col,
                shares_in=[f"{v:02x}" for v in in_shares],
                recombined_in=f"{in_recomb:02x}",
                shares_out=[f"{v:02x}" for v in out_sh],
                recombined_out=f"{out_recomb:02x}",
                rnd_bits=0)  # per-byte RNG not tracked individually

    out.p(_fmt_byte_table(
        sb_rows,
        ["idx", "(r,c)", "shares_in", "recomb_in", "shares_out", "recomb_out"],
    ))
    out.p(f"")
    out.p(f"  Total random bits consumed by SubBytes: {rng_sb}")
    out.p("")
    _print_shares_and_recomb(out, "After SubBytes", state_shares, after_sb_recomb)

    jl.emit(stage="subbytes_done",
            shares=[_state_hex(s) for s in state_shares],
            recombined=_state_hex(after_sb_recomb),
            cycles=cycles_sb, random_bits=rng_sb)

    # 4.2 ShiftRows
    out.subsection("4.2  ShiftRows (linear, per-share)")
    out.p("ShiftRows is linear => applied independently to each share.")
    out.p("Row i is shifted LEFT by i positions.")

    cycles_before_sr = cycle_counter.count
    rng_before_sr = rng_counter.total_bits

    state_shares = apply_shift_rows_to_shares(state_shares)
    after_sr_recomb = _recombine(state_shares)

    for r in range(4):
        before_vals = [f"{after_sb_recomb[r][c]:02x}" for c in range(4)]
        after_vals = [f"{after_sr_recomb[r][c]:02x}" for c in range(4)]
        out.p(f"  Row {r} (shift {r}): [{' '.join(before_vals)}] -> [{' '.join(after_vals)}]")

    cycle_counter.increment(1)
    cycles_sr = cycle_counter.count - cycles_before_sr
    rng_sr = rng_counter.total_bits - rng_before_sr
    out.p("")
    _print_shares_and_recomb(out, "After ShiftRows", state_shares, after_sr_recomb)

    jl.emit(stage="shiftrows",
            shares=[_state_hex(s) for s in state_shares],
            recombined=_state_hex(after_sr_recomb),
            cycles=cycles_sr, random_bits=rng_sr)

    # 4.3 MixColumns
    out.subsection("4.3  MixColumns (linear, per-share)")
    out.p("MixColumns is linear => applied independently to each share.")
    out.p("The recombined result matches unmasked MixColumns on recombined input.")

    cycles_before_mc = cycle_counter.count
    rng_before_mc = rng_counter.total_bits

    state_shares = apply_mix_columns_to_shares(state_shares)
    after_mc_recomb = _recombine(state_shares)

    cycle_counter.increment(1)
    cycles_mc = cycle_counter.count - cycles_before_mc
    rng_mc = rng_counter.total_bits - rng_before_mc

    # Show column details on recombined values
    for col in range(4):
        a = [after_sr_recomb[row][col] for row in range(4)]
        r = [after_mc_recomb[row][col] for row in range(4)]
        xt = [xtime(v) for v in a]
        x3 = [xt[i] ^ a[i] for i in range(4)]
        out.p(f"  Column {col}: [{a[0]:02x} {a[1]:02x} {a[2]:02x} {a[3]:02x}] "
              f"-> [{r[0]:02x} {r[1]:02x} {r[2]:02x} {r[3]:02x}]")

        jl.emit(stage="mixcolumns", col=col,
                a=[f"{v:02x}" for v in a],
                xtime=[f"{v:02x}" for v in xt],
                times3=[f"{v:02x}" for v in x3],
                result=[f"{v:02x}" for v in r])

    out.p("")
    _print_shares_and_recomb(out, "After MixColumns", state_shares, after_mc_recomb)

    # 4.4 AddRoundKey (Round 1)
    out.subsection("4.4  AddRoundKey (Round 1)")
    out.p("Round key XOR applied ONLY to Share 0 (masking semantics).")

    cycles_before_ark = cycle_counter.count
    rng_before_ark = rng_counter.total_bits

    state_shares = apply_add_round_key_to_shares(state_shares, round_keys[1])
    state_out = _recombine(state_shares)

    cycle_counter.increment(1)
    cycles_ark = cycle_counter.count - cycles_before_ark
    rng_ark = rng_counter.total_bits - rng_before_ark

    out.p("")
    out.p("RoundKey[1]:")
    out.p(_fmt_matrix_labeled(round_keys[1]))

    ark_rows: list[tuple[str, ...]] = []
    for col in range(4):
        for row in range(4):
            idx = _byte_index(row, col)
            sv = after_mc_recomb[row][col]
            kv = round_keys[1][row][col]
            rv = state_out[row][col]
            ark_rows.append((
                f"b{idx:02d}", f"({row},{col})",
                f"{sv:02x}", f"{kv:02x}", f"{rv:02x}",
            ))
            jl.emit(stage="add_round_key_1", i=idx, r=row, c=col,
                    recombined_state=f"{sv:02x}", rk1=f"{kv:02x}",
                    recombined_out=f"{rv:02x}")

    out.p("")
    out.p("Recombined state XOR RoundKey[1]:")
    out.p(_fmt_byte_table(ark_rows,
                          ["idx", "(r,c)", "state", "rk1", "out"]))
    out.p("")
    _print_shares_and_recomb(out, "After Round 1 AddRoundKey", state_shares, state_out)

    # ── 5. Summary ──────────────────────────────────────────────
    out.section("5. Summary")
    in_hex = _state_hex(state_in)
    out_hex = _state_hex(state_out)
    out.p(f"State entering Round 1 (recombined): {in_hex}")
    out.p(f"State after   Round 1 (recombined): {out_hex}")

    # Pre-round costs
    cycles_r0 = cycles_before_r1  # cycles consumed before Round 1 started
    rng_masking = rng_before_r1   # randomness consumed for key+state masking + ARK(R0)

    total_cycles = cycle_counter.count
    total_rng = rng_counter.total_bits

    out.p("")
    out.p("Cycle breakdown:")
    out.p(f"  Pre-round (masking + AddRoundKey R0):  {cycles_r0:>4} cycles")
    out.p(f"  SubBytes  (DOM S-box pipeline):        {cycles_sb:>4} cycles")
    out.p(f"  ShiftRows:                             {cycles_sr:>4} cycle{'s' if cycles_sr != 1 else ''}")
    out.p(f"  MixColumns:                            {cycles_mc:>4} cycle{'s' if cycles_mc != 1 else ''}")
    out.p(f"  AddRoundKey (Round 1):                 {cycles_ark:>4} cycle{'s' if cycles_ark != 1 else ''}")
    out.p(f"  Total:                                 {total_cycles:>4} cycles")

    out.p("")
    out.p("Randomness breakdown:")
    out.p(f"  Key masking + State masking:           {rng_masking:>5} bits")
    out.p(f"  SubBytes (DOM S-box pipeline):         {rng_sb:>5} bits")
    out.p(f"  ShiftRows:                             {rng_sr:>5} bits")
    out.p(f"  MixColumns:                            {rng_mc:>5} bits")
    out.p(f"  AddRoundKey (Round 1):                 {rng_ark:>5} bits")
    out.p(f"  Total:                                 {total_rng:>5} bits")

    cycle_breakdown = {
        "pre_round": cycles_r0,
        "subbytes": cycles_sb,
        "shiftrows": cycles_sr,
        "mixcolumns": cycles_mc,
        "add_round_key_1": cycles_ark,
    }
    rng_breakdown = {
        "masking": rng_masking,
        "subbytes": rng_sb,
        "shiftrows": rng_sr,
        "mixcolumns": rng_mc,
        "add_round_key_1": rng_ark,
    }

    jl.emit(stage="summary", state_in=in_hex, state_out=out_hex,
            cycles=total_cycles, random_bits=total_rng,
            cycle_breakdown=cycle_breakdown,
            random_bits_breakdown=rng_breakdown)

    return {
        "state_in_round1": state_in,
        "state_out_round1": state_out,
        "shares_out": [copy_state(s) for s in state_shares],
        "cycles": total_cycles,
        "random_bits": total_rng,
        "cycle_breakdown": cycle_breakdown,
        "random_bits_breakdown": rng_breakdown,
    }


# ──────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────

def _share_grid(
    state: list[list[int]],
    num_shares: int,
    rng: _random_module.Random,
    rng_counter: RandomnessCounter,
    purpose: str,
) -> list[list[list[int]]]:
    """Split a 4x4 state into *num_shares* additive shares."""
    d = num_shares - 1
    shares = [[[0] * 4 for _ in range(4)] for _ in range(num_shares)]
    for row in range(4):
        for col in range(4):
            byte_shares = share_value(state[row][col], num_shares, 0xFF, rng)
            rng_counter.add(d * 8, width=8, operation=purpose)
            for si in range(num_shares):
                shares[si][row][col] = byte_shares[si]
    return shares


def _state_hex(state: list[list[int]]) -> str:
    return state_to_hex(state)


def _print_shares_and_recomb(
    out: "_Printer",
    label: str,
    shares: list[list[list[int]]],
    recombined: list[list[int]],
) -> None:
    """Print all share matrices and the recombined matrix."""
    out.p(f"{label}:")
    for si, sh in enumerate(shares):
        out.p(f"  Share[{si}]:")
        out.p(_fmt_matrix_labeled(sh, indent="      "))
    out.p("  Recombined:")
    out.p(_fmt_matrix_labeled(recombined, indent="      "))


# ──────────────────────────────────────────────────────────────────
# Minimal output abstractions
# ──────────────────────────────────────────────────────────────────

class _Printer:
    """Conditional stdout printer (only when verbose)."""
    def __init__(self, enabled: bool):
        self._on = enabled

    def p(self, text: str = "") -> None:
        if self._on:
            print(text)

    def section(self, title: str) -> None:
        if self._on:
            print(f"\n{'='*70}")
            print(f"  {title}")
            print(f"{'='*70}")

    def subsection(self, title: str) -> None:
        if self._on:
            print(f"\n  --- {title} {'─'*max(0, 55-len(title))}")


class _JsonlWriter:
    """Emit deterministic JSONL events."""

    def __init__(
        self,
        fh: TextIO | None,
        mode: str = "round",
        model: str = "",
        extra: dict[str, Any] | None = None,
    ):
        self._fh = fh
        self._base: dict[str, Any] = {"mode": mode, "round_index": 1, "model": model}
        if extra:
            self._base.update(extra)
        self._seq = 0

    def emit(self, **kw: Any) -> None:
        if self._fh is None:
            return
        record = dict(self._base)
        record["seq"] = self._seq
        self._seq += 1
        record.update(kw)
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()
