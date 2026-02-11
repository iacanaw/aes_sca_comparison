#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
One-byte AES SubByte demo (unmasked + 2-share masked), with cycle-by-cycle tracing.

SubBytes(x) = Affine( InvGF256(x) ), where:
  - InvGF256(x) is multiplicative inverse in GF(2^8) modulo 0x11B (AES field)
  - Affine is the Rijndael affine transform (can be done via XOR + bit-rotations)

This script:
  1) Implements GF(2^8) multiplication using only bitwise operations (shift/XOR).
  2) Implements inversion as x^254 (fixed chain: powers of 2 via squaring, then multiply).
  3) Implements 2-share boolean masking for inversion using a simple masked multiplication gadget.
  4) Prints a clear trace with explicit "REGISTER BOUNDARY" separators to mimic HW pipelining.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from secrets import randbelow
from typing import Optional, List, Tuple


# -----------------------------
# Formatting helpers
# -----------------------------

def rotl8(x: int, n: int) -> int:
    """Rotate-left an 8-bit integer by n bits."""
    x &= 0xFF
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF


def fmt_byte(x: Optional[int]) -> str:
    """Format a byte as hex + binary."""
    if x is None:
        return ""
    return f"0x{x:02X} ({x:08b})"


# -----------------------------
# GF(2^8) arithmetic (AES field)
# -----------------------------

AES_REDUCTION = 0x1B  # because modulus is 0x11B; reduction step uses 0x1B for low 8 bits

def gf256_mul(a: int, b: int) -> int:
    """
    Multiply two bytes in GF(2^8) with AES modulus (0x11B), using only bitwise ops.

    Classic "Russian peasant" method:
      - Accumulate into p when LSB of b is 1
      - xtime() on a each step (shift left, reduce by 0x1B if overflow bit was set)
      - shift b right
    """
    a &= 0xFF
    b &= 0xFF
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= AES_REDUCTION
        b >>= 1
    return p & 0xFF

def gf256_mul_unrolled_bits(a: int, b: int) -> int:
    """
    Fully-unrolled GF(2^8) multiply using explicit gate-level bit equations.
    Only uses AND/XOR on individual bits, then packs p0..p7.

    Bit numbering: A0/B0/P0 = LSB, A7/B7/P7 = MSB.
    """
    a &= 0xFF
    b &= 0xFF

    A0=(a>>0)&1; A1=(a>>1)&1; A2=(a>>2)&1; A3=(a>>3)&1
    A4=(a>>4)&1; A5=(a>>5)&1; A6=(a>>6)&1; A7=(a>>7)&1
    B0=(b>>0)&1; B1=(b>>1)&1; B2=(b>>2)&1; B3=(b>>3)&1
    B4=(b>>4)&1; B5=(b>>5)&1; B6=(b>>6)&1; B7=(b>>7)&1

    def xorb(*bits: int) -> int:
        r = 0
        for t in bits:
            r ^= (t & 1)
        return r & 1

    def anb(x: int, y: int) -> int:
        return (x & y) & 1

    p0 = xorb(anb(B0,A0),
              anb(B1,A7),
              anb(B2,A6),
              anb(B3,A5),
              anb(B4,A4),
              anb(B5,xorb(A3,A7)),
              anb(B6,xorb(A2,A6,A7)),
              anb(B7,xorb(A1,A5,A6)))

    p1 = xorb(anb(B0,A1),
              anb(B1,xorb(A0,A7)),
              anb(B2,xorb(A6,A7)),
              anb(B3,xorb(A5,A6)),
              anb(B4,xorb(A4,A5)),
              anb(B5,xorb(A3,A4,A7)),
              anb(B6,xorb(A2,A3,A6)),
              anb(B7,xorb(A1,A2,A5,A7)))

    p2 = xorb(anb(B0,A2),
              anb(B1,A1),
              anb(B2,xorb(A0,A7)),
              anb(B3,xorb(A6,A7)),
              anb(B4,xorb(A5,A6)),
              anb(B5,xorb(A4,A5)),
              anb(B6,xorb(A3,A4,A7)),
              anb(B7,xorb(A2,A3,A6)))

    p3 = xorb(anb(B0,A3),
              anb(B1,xorb(A2,A7)),
              anb(B2,xorb(A1,A6)),
              anb(B3,xorb(A0,A5,A7)),
              anb(B4,xorb(A4,A6,A7)),
              anb(B5,xorb(A3,A5,A6,A7)),
              anb(B6,xorb(A2,A4,A5,A6,A7)),
              anb(B7,xorb(A1,A3,A4,A5,A6,A7)))

    p4 = xorb(anb(B0,A4),
              anb(B1,xorb(A3,A7)),
              anb(B2,xorb(A2,A6,A7)),
              anb(B3,xorb(A1,A5,A6)),
              anb(B4,xorb(A0,A4,A5,A7)),
              anb(B5,xorb(A3,A4,A6)),
              anb(B6,xorb(A2,A3,A5)),
              anb(B7,xorb(A1,A2,A4,A7)))

    p5 = xorb(anb(B0,A5),
              anb(B1,A4),
              anb(B2,xorb(A3,A7)),
              anb(B3,xorb(A2,A6,A7)),
              anb(B4,xorb(A1,A5,A6)),
              anb(B5,xorb(A0,A4,A5,A7)),
              anb(B6,xorb(A3,A4,A6)),
              anb(B7,xorb(A2,A3,A5)))

    p6 = xorb(anb(B0,A6),
              anb(B1,A5),
              anb(B2,A4),
              anb(B3,xorb(A3,A7)),
              anb(B4,xorb(A2,A6,A7)),
              anb(B5,xorb(A1,A5,A6)),
              anb(B6,xorb(A0,A4,A5,A7)),
              anb(B7,xorb(A3,A4,A6)))

    p7 = xorb(anb(B0,A7),
              anb(B1,A6),
              anb(B2,A5),
              anb(B3,A4),
              anb(B4,xorb(A3,A7)),
              anb(B5,xorb(A2,A6,A7)),
              anb(B6,xorb(A1,A5,A6)),
              anb(B7,xorb(A0,A4,A5,A7)))

    return ((p0<<0)|(p1<<1)|(p2<<2)|(p3<<3)|(p4<<4)|(p5<<5)|(p6<<6)|(p7<<7)) & 0xFF


def gf256_square(a: int) -> int:
    """Squaring in GF(2^8). Implemented via mul(a, a) for clarity."""
    return gf256_mul_unrolled_bits(a, a)


# -----------------------------
# AES affine transform for S-box
# -----------------------------

def aes_affine(u: int) -> int:
    """
    Rijndael affine transform:
      y = 0x63 ^ u ^ rotl(u,1) ^ rotl(u,2) ^ rotl(u,3) ^ rotl(u,4)

    This is HW-friendly: XOR + bit-rotates (wiring).
    """
    u &= 0xFF
    return (0x63 ^ u ^ rotl8(u, 1) ^ rotl8(u, 2) ^ rotl8(u, 3) ^ rotl8(u, 4)) & 0xFF


# -----------------------------
# Trace infrastructure
# -----------------------------

@dataclass
class TraceRow:
    cycle: int
    op: str
    v0: Optional[int] = None
    v1: Optional[int] = None
    recomb: Optional[int] = None
    note: str = ""


class Trace:
    def __init__(self, title: str):
        self.title = title
        self.rows: List[TraceRow] = []

    def add(self, cycle: int, op: str, v0: Optional[int] = None, v1: Optional[int] = None,
            recomb: Optional[int] = None, note: str = "") -> None:
        self.rows.append(TraceRow(cycle, op, v0, v1, recomb, note))

    def add_barrier(self, cycle: int, label: str = "REGISTER BOUNDARY") -> None:
        # Represent a pipeline register boundary as a special row
        self.rows.append(TraceRow(cycle, f"--- {label} ---", None, None, None, ""))

    def dump(self) -> None:
        print("\n" + "=" * 90)
        print(self.title)
        print("=" * 90)
        header = f"{'CY':>3} | {'OPERATION':<38} | {'SH0':<18} | {'SH1':<18} | {'XOR':<18} | NOTE"
        print(header)
        print("-" * len(header))
        for r in self.rows:
            if r.op.startswith("---"):
                print(f"{r.cycle:>3} | {r.op}")
                continue
            sh0 = fmt_byte(r.v0).ljust(18)
            sh1 = fmt_byte(r.v1).ljust(18)
            rx  = fmt_byte(r.recomb).ljust(18)
            print(f"{r.cycle:>3} | {r.op:<38} | {sh0} | {sh1} | {rx} | {r.note}")


# -----------------------------
# Unmasked SubByte (one byte)
# -----------------------------

def gf256_inv_unmasked(x: int, tr: Optional[Trace] = None, cycle0: int = 0) -> Tuple[int, int]:
    """
    Compute multiplicative inverse in GF(2^8) as x^254, using a fixed chain:
      x^2, x^4, x^8, x^16, x^32, x^64, x^128 (by squaring)
      then multiply: x^254 = x^128*x^64*x^32*x^16*x^8*x^4*x^2

    Returns (inv, last_cycle_used).
    """
    c = cycle0

    x &= 0xFF
    if tr:
        tr.add(c, "input x", recomb=x)
    # powers of two
    c += 1
    x2 = gf256_square(x)
    if tr: tr.add(c, "square: x^2", recomb=x2)

    c += 1
    x4 = gf256_square(x2)
    if tr: tr.add(c, "square: x^4", recomb=x4)

    c += 1
    x8 = gf256_square(x4)
    if tr: tr.add(c, "square: x^8", recomb=x8)

    c += 1
    x16 = gf256_square(x8)
    if tr: tr.add(c, "square: x^16", recomb=x16)

    c += 1
    x32 = gf256_square(x16)
    if tr: tr.add(c, "square: x^32", recomb=x32)

    c += 1
    x64 = gf256_square(x32)
    if tr: tr.add(c, "square: x^64", recomb=x64)

    c += 1
    x128 = gf256_square(x64)
    if tr: tr.add(c, "square: x^128", recomb=x128)

    # multiply chain for 254 = 128+64+32+16+8+4+2
    c += 1
    t = gf256_mul_unrolled_bits(x128, x64)
    if tr: tr.add(c, "mul: x^128 * x^64", recomb=t)

    c += 1
    t = gf256_mul_unrolled_bits(t, x32)
    if tr: tr.add(c, "mul: (..) * x^32", recomb=t)

    c += 1
    t = gf256_mul_unrolled_bits(t, x16)
    if tr: tr.add(c, "mul: (..) * x^16", recomb=t)

    c += 1
    t = gf256_mul_unrolled_bits(t, x8)
    if tr: tr.add(c, "mul: (..) * x^8", recomb=t)

    c += 1
    t = gf256_mul_unrolled_bits(t, x4)
    if tr: tr.add(c, "mul: (..) * x^4", recomb=t)

    c += 1
    t = gf256_mul_unrolled_bits(t, x2)
    if tr: tr.add(c, "mul: (..) * x^2  => x^254", recomb=t)

    return t & 0xFF, c


def subbyte_unmasked(x: int, tr: Optional[Trace] = None, cycle0: int = 0) -> Tuple[int, int]:
    """
    One-byte AES SubByte (unmasked):
      inv = x^-1 in GF(2^8)
      y   = affine(inv)
    Returns (y, last_cycle_used)
    """
    inv, c = gf256_inv_unmasked(x, tr=tr, cycle0=cycle0)
    c += 1
    y = aes_affine(inv)
    if tr:
        tr.add(c, "affine(inv) => S(x)", recomb=y, note="y = 0x63 ^ u ^ rotl(u,1..4)")
    return y & 0xFF, c


# -----------------------------
# 2-share masked multiplication (simple ISW for d=1)
# -----------------------------

def gf256_mul_masked_2share(a0: int, a1: int, b0: int, b1: int,
                           r: int, tr: Optional[Trace], cycle0: int,
                           label: str) -> Tuple[int, int, int]:
    """
    First-order (2-share) masked multiplication over GF(2^8).

    Inputs:
      a = a0 ^ a1
      b = b0 ^ b1

    Compute partial products:
      t00 = a0*b0
      t01 = a0*b1
      t10 = a1*b0
      t11 = a1*b1

    Then output shares (c0,c1) such that c0^c1 = a*b:
      c0 = t00 ^ r
      c1 = t01 ^ t10 ^ t11 ^ r

    Cycle split (pedagogical):
      - Cycle N: compute t00,t01,t10,t11 (combinational multipliers)
      - REGISTER BOUNDARY
      - Cycle N+1: XOR network + fresh mask injection r
    """
    c = cycle0

    # Cycle: compute partial products
    t00 = gf256_mul_unrolled_bits(a0, b0)
    t01 = gf256_mul_unrolled_bits(a0, b1)
    t10 = gf256_mul_unrolled_bits(a1, b0)
    t11 = gf256_mul_unrolled_bits(a1, b1)

    if tr:
        tr.add(c, f"{label}: partials t00..t11",
               v0=None, v1=None, recomb=None,
               note=f"t00={t00:02X} t01={t01:02X} t10={t10:02X} t11={t11:02X}")

    # Show where you'd typically register before combining (glitch reduction)
    if tr:
        tr.add_barrier(c, "REGISTER BOUNDARY (after partial products)")

    # Next cycle: combine with fresh randomness r
    c += 1
    c0 = (t00 ^ r) & 0xFF
    c1 = (t01 ^ t10 ^ t11 ^ r) & 0xFF

    if tr:
        tr.add(c, f"{label}: combine + mask r",
               v0=c0, v1=c1, recomb=(c0 ^ c1) & 0xFF,
               note=f"r=0x{r:02X}")

    return c0, c1, c


# -----------------------------
# Masked inversion: x^254 using squarings (linear) + masked multiplies (non-linear)
# -----------------------------

def gf256_inv_masked_2share(x0: int, x1: int, tr: Optional[Trace], cycle0: int,
                           rng_seed: Optional[int] = None) -> Tuple[int, int, int]:
    """
    Compute inverse shares (u0,u1) such that (u0^u1) = (x0^x1)^(-1) in GF(2^8),
    using fixed chain for exponent 254.

    Squaring is linear => do per share.
    Multiplication is non-linear => use masked multiplication gadget with fresh r each time.

    Returns (u0, u1, last_cycle_used).
    """
    c = cycle0
    x0 &= 0xFF
    x1 &= 0xFF
    if tr:
        tr.add(c, "input shares x0,x1", v0=x0, v1=x1, recomb=(x0 ^ x1) & 0xFF)

    # Linear squarings: (a0^a1)^2 = a0^2 ^ a1^2
    def sq_shares(a0: int, a1: int, op_label: str) -> Tuple[int, int]:
        nonlocal c
        c += 1
        o0 = gf256_square(a0)
        o1 = gf256_square(a1)
        if tr:
            tr.add(c, op_label, v0=o0, v1=o1, recomb=(o0 ^ o1) & 0xFF,
                   note="linear squaring => per-share")
        # You can imagine a register here too (pipeline), but squaring is linear so less critical.
        return o0, o1

    # Generate "fresh randomness" r per multiplication.
    # For reproducibility, allow a deterministic pseudo-source if seed provided.
    # (In real HW this comes from a TRNG / PRNG.)
    if rng_seed is not None:
        # Simple deterministic generator for demo (NOT cryptographic).
        # We keep it trivial and visible.
        state = rng_seed & 0xFFFFFFFF

        def next_r() -> int:
            nonlocal state
            # xorshift32
            state ^= (state << 13) & 0xFFFFFFFF
            state ^= (state >> 17) & 0xFFFFFFFF
            state ^= (state << 5) & 0xFFFFFFFF
            return state & 0xFF
    else:
        def next_r() -> int:
            return randbelow(256)

    # Build powers of two for x^(2^k)
    x2_0,   x2_1   = sq_shares(x0,    x1,    "square: x^2 shares")
    x4_0,   x4_1   = sq_shares(x2_0,  x2_1,  "square: x^4 shares")
    x8_0,   x8_1   = sq_shares(x4_0,  x4_1,  "square: x^8 shares")
    x16_0,  x16_1  = sq_shares(x8_0,  x8_1,  "square: x^16 shares")
    x32_0,  x32_1  = sq_shares(x16_0, x16_1, "square: x^32 shares")
    x64_0,  x64_1  = sq_shares(x32_0, x32_1, "square: x^64 shares")
    x128_0, x128_1 = sq_shares(x64_0, x64_1, "square: x^128 shares")

    # Multiply chain for x^254 = x^128*x^64*x^32*x^16*x^8*x^4*x^2
    c += 1
    t0, t1, c = gf256_mul_masked_2share(
        x128_0, x128_1, x64_0, x64_1,
        r=next_r(), tr=tr, cycle0=c, label="mul1"
    )

    c += 1
    t0, t1, c = gf256_mul_masked_2share(
        t0, t1, x32_0, x32_1,
        r=next_r(), tr=tr, cycle0=c, label="mul2"
    )

    c += 1
    t0, t1, c = gf256_mul_masked_2share(
        t0, t1, x16_0, x16_1,
        r=next_r(), tr=tr, cycle0=c, label="mul3"
    )

    c += 1
    t0, t1, c = gf256_mul_masked_2share(
        t0, t1, x8_0, x8_1,
        r=next_r(), tr=tr, cycle0=c, label="mul4"
    )

    c += 1
    t0, t1, c = gf256_mul_masked_2share(
        t0, t1, x4_0, x4_1,
        r=next_r(), tr=tr, cycle0=c, label="mul5"
    )

    c += 1
    u0, u1, c = gf256_mul_masked_2share(
        t0, t1, x2_0, x2_1,
        r=next_r(), tr=tr, cycle0=c, label="mul6 => x^254"
    )

    return u0 & 0xFF, u1 & 0xFF, c


def subbyte_masked_2share(x0: int, x1: int, tr: Optional[Trace], cycle0: int,
                          rng_seed: Optional[int] = None) -> Tuple[int, int, int]:
    """
    Masked SubByte:
      - masked inverse (u0,u1)
      - affine is linear/affine => apply per-share, inject constant into one share
    """
    u0, u1, c = gf256_inv_masked_2share(x0, x1, tr=tr, cycle0=cycle0, rng_seed=rng_seed)

    # Affine linear part (excluding constant) is linear => per-share
    c += 1
    v0 = (u0 ^ rotl8(u0, 1) ^ rotl8(u0, 2) ^ rotl8(u0, 3) ^ rotl8(u0, 4)) & 0xFF
    v1 = (u1 ^ rotl8(u1, 1) ^ rotl8(u1, 2) ^ rotl8(u1, 3) ^ rotl8(u1, 4)) & 0xFF
    if tr:
        tr.add(c, "affine-linear(u) per-share", v0=v0, v1=v1, recomb=(v0 ^ v1) & 0xFF,
               note="(no 0x63 yet)")

    # Inject constant 0x63 into ONE share (common choice)
    c += 1
    y0 = (v0 ^ 0x63) & 0xFF
    y1 = v1
    if tr:
        tr.add(c, "add constant 0x63 into share0", v0=y0, v1=y1, recomb=(y0 ^ y1) & 0xFF)

    return y0, y1, c


# -----------------------------
# Main demo
# -----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="One-byte AES SubByte demo (unmasked + 2-share masked).")
    ap.add_argument("--x", default="53", help="Input byte x in hex (default: 53)")
    ap.add_argument("--mask", default=None, help="Mask byte m in hex. If omitted, random mask is used.")
    ap.add_argument("--seed", default=None, type=int,
                    help="Seed for deterministic masked randomness (demo only). If omitted, uses secrets.")
    args = ap.parse_args()

    x = int(args.x, 16) & 0xFF

    # Choose mask and shares: x = x0 ^ x1
    if args.mask is None:
        m = randbelow(256)
    else:
        m = int(args.mask, 16) & 0xFF

    x0 = m
    x1 = x ^ m

    # Unmasked trace
    tr_u = Trace("UNMASKED SubByte (one byte)")
    y_u, last_c_u = subbyte_unmasked(x, tr=tr_u, cycle0=0)

    # Masked trace
    tr_m = Trace("MASKED SubByte (2-share boolean masking, one byte)")
    y0, y1, last_c_m = subbyte_masked_2share(x0, x1, tr=tr_m, cycle0=0, rng_seed=args.seed)
    y_m = (y0 ^ y1) & 0xFF

    # Print traces
    tr_u.dump()
    tr_m.dump()

    # Summary check
    print("\n" + "=" * 90)
    print("SUMMARY / CONSISTENCY CHECK")
    print("=" * 90)
    print(f"Input x                = {fmt_byte(x)}")
    print(f"Shares: x0, x1         = {fmt_byte(x0)}  ,  {fmt_byte(x1)}   (x0^x1={fmt_byte(x0^x1)})")
    print(f"Unmasked S(x)          = {fmt_byte(y_u)}")
    print(f"Masked output shares   = {fmt_byte(y0)}  ,  {fmt_byte(y1)}   (y0^y1={fmt_byte(y_m)})")
    print(f"Match?                 = {'YES' if y_u == y_m else 'NO'}")
    print("\nNotes:")
    print("  - Linear steps (squaring, affine-linear) are done per-share.")
    print("  - Non-linear steps (multiplications) use fresh randomness r each time.")
    print("  - 'REGISTER BOUNDARY' lines show where you would typically pipeline to reduce glitch leakage.")


if __name__ == "__main__":
    main()
