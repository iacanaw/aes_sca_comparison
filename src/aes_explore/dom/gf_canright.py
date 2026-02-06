"""
Galois Field arithmetic for Canright-style AES S-box.

Implements GF(2^2), GF(2^4), and GF(2^8) operations with
tower field decomposition.

Tower construction:
  GF(2^8) = GF((2^4)^2) with irreducible x^2 + x + E (E = 0x9)
  GF(2^4) = GF((2^2)^2) with irreducible x^2 + x + N (N = 0x2)
  GF(2^2) = GF(2)[X] / (X^2 + X + 1)
"""

# ===========================================================================
# GF(2^2) Arithmetic (2-bit elements)
# Polynomial: X^2 + X + 1, basis {1, W} where W^2 + W + 1 = 0
# ===========================================================================

def gf2_mult(a: int, b: int) -> int:
    """Multiply in GF(2^2) with polynomial X^2 + X + 1."""
    a = a & 0x3
    b = b & 0x3

    a0 = a & 1
    a1 = (a >> 1) & 1
    b0 = b & 1
    b1 = (b >> 1) & 1

    p_const = (a0 & b0) ^ (a1 & b1)
    p_w = (a1 & b0) ^ (a0 & b1) ^ (a1 & b1)

    return (p_w << 1) | p_const


def gf2_square(a: int) -> int:
    """Square in GF(2^2)."""
    a = a & 0x3
    a0 = a & 1
    a1 = (a >> 1) & 1
    return (a1 << 1) | (a0 ^ a1)


def gf2_scaleN(a: int) -> int:
    """Scale by N in GF(2^2) where N = W (0x2)."""
    a = a & 0x3
    a0 = a & 1
    a1 = (a >> 1) & 1
    return ((a0 ^ a1) << 1) | a1


def gf2_inverse(a: int) -> int:
    """Inverse in GF(2^2)."""
    return [0, 1, 3, 2][a & 0x3]


# ===========================================================================
# GF(2^4) Arithmetic (4-bit elements)
# ===========================================================================

def gf4_mult(a: int, b: int) -> int:
    """Multiply in GF(2^4) = GF((2^2)^2)."""
    a = a & 0xF
    b = b & 0xF

    al = a & 0x3
    ah = (a >> 2) & 0x3
    bl = b & 0x3
    bh = (b >> 2) & 0x3

    ah_bh = gf2_mult(ah, bh)
    al_bl = gf2_mult(al, bl)
    cross = gf2_mult(ah, bl) ^ gf2_mult(al, bh)

    rl = al_bl ^ gf2_scaleN(ah_bh)
    rh = cross ^ ah_bh

    return (rh << 2) | rl


def gf4_square(a: int) -> int:
    """Square in GF(2^4)."""
    a = a & 0xF
    al = a & 0x3
    ah = (a >> 2) & 0x3

    al_sq = gf2_square(al)
    ah_sq = gf2_square(ah)

    rl = al_sq ^ gf2_scaleN(ah_sq)
    rh = ah_sq

    return (rh << 2) | rl


def gf4_scaleN(a: int) -> int:
    """Scale by N = 0x2 in GF(2^4)."""
    a = a & 0xF
    al = a & 0x3
    ah = (a >> 2) & 0x3
    return (gf2_scaleN(ah) << 2) | gf2_scaleN(al)


def gf4_scaleN2(a: int) -> int:
    """Scale by N^2 in GF(2^4)."""
    a = a & 0xF
    al = a & 0x3
    ah = (a >> 2) & 0x3
    return (gf2_mult(ah, 3) << 2) | gf2_mult(al, 3)


def gf4_inverse(a: int) -> int:
    """Inverse in GF(2^4)."""
    a = a & 0xF
    if a == 0:
        return 0

    al = a & 0x3
    ah = (a >> 2) & 0x3

    al_sq = gf2_square(al)
    ah_sq = gf2_square(ah)
    al_ah = gf2_mult(al, ah)

    delta = al_sq ^ al_ah ^ gf2_scaleN(ah_sq)
    delta_inv = gf2_inverse(delta)

    rl = gf2_mult(delta_inv, al ^ ah)
    rh = gf2_mult(delta_inv, ah)

    return (rh << 2) | rl


# ===========================================================================
# GF(2^8) Arithmetic - Tower field representation
# ===========================================================================

def gf8_mult_tower(a: int, b: int) -> int:
    """Multiply in tower-field GF(2^8) representation."""
    a = a & 0xFF
    b = b & 0xFF

    al = a & 0xF
    ah = (a >> 4) & 0xF
    bl = b & 0xF
    bh = (b >> 4) & 0xF

    ah_bh = gf4_mult(ah, bh)
    al_bl = gf4_mult(al, bl)
    cross = gf4_mult(ah, bl) ^ gf4_mult(al, bh)

    E = 0x9
    ah_bh_E = gf4_mult(ah_bh, E)

    rl = al_bl ^ ah_bh_E
    rh = cross ^ ah_bh

    return (rh << 4) | rl


def gf8_square_tower(a: int) -> int:
    """Square in tower-field GF(2^8)."""
    a = a & 0xFF
    al = a & 0xF
    ah = (a >> 4) & 0xF

    al_sq = gf4_square(al)
    ah_sq = gf4_square(ah)

    E = 0x9
    ah_sq_E = gf4_mult(ah_sq, E)

    rl = al_sq ^ ah_sq_E
    rh = ah_sq

    return (rh << 4) | rl


def gf8_inverse_tower(a: int) -> int:
    """Inverse in tower-field GF(2^8)."""
    a = a & 0xFF
    if a == 0:
        return 0

    al = a & 0xF
    ah = (a >> 4) & 0xF

    al_sq = gf4_square(al)
    ah_sq = gf4_square(ah)
    al_ah = gf4_mult(al, ah)

    E = 0x9
    ah_sq_E = gf4_mult(ah_sq, E)

    delta = al_sq ^ al_ah ^ ah_sq_E
    delta_inv = gf4_inverse(delta)

    rl = gf4_mult(delta_inv, al ^ ah)
    rh = gf4_mult(delta_inv, ah)

    return (rh << 4) | rl


# ===========================================================================
# Linear Isomorphism between AES field and Tower field
#
# AES field: GF(2^8) with polynomial x^8 + x^4 + x^3 + x + 1
# Tower field: Our composite construction
#
# The isomorphism phi is LINEAR over GF(2), defined by phi(2) = 0x49
# where 0x49 is a root of x^8+x^4+x^3+x+1 in the tower field.
#
# Powers of phi(2) in tower field:
#   phi(2^0) = 0x01, phi(2^1) = 0x49, phi(2^2) = 0x6d, phi(2^3) = 0x67
#   phi(2^4) = 0x5c, phi(2^5) = 0x94, phi(2^6) = 0x52, phi(2^7) = 0xc0
# ===========================================================================

# Transformation matrix columns: phi(2^i) for i = 0..7
# These are what AES basis vectors map to in tower field
PHI_POWERS = [0x01, 0x49, 0x6d, 0x67, 0x5c, 0x94, 0x52, 0xc0]


def _build_linear_isomorphism():
    """Build lookup tables for the linear field isomorphism."""
    aes_to_tower = [0] * 256
    tower_to_aes = [0] * 256

    # phi(x) = sum over i where bit i of x is set: PHI_POWERS[i]
    for x in range(256):
        result = 0
        for i in range(8):
            if x & (1 << i):
                result ^= PHI_POWERS[i]
        aes_to_tower[x] = result

    # Build inverse lookup
    for x in range(256):
        tower_to_aes[aes_to_tower[x]] = x

    return aes_to_tower, tower_to_aes


# Precomputed lookup tables
AES_TO_TOWER, TOWER_TO_AES = _build_linear_isomorphism()


def aes_to_tower(byte_val: int) -> int:
    """Transform from AES polynomial representation to tower field (linear)."""
    return AES_TO_TOWER[byte_val & 0xFF]


def tower_to_aes(byte_val: int) -> int:
    """Transform from tower field to AES polynomial representation (linear)."""
    return TOWER_TO_AES[byte_val & 0xFF]


def aes_to_tower_linear(byte_val: int) -> int:
    """Linear transformation (without lookup) for per-share application."""
    result = 0
    for i in range(8):
        if byte_val & (1 << i):
            result ^= PHI_POWERS[i]
    return result


# Inverse transformation matrix columns (computed from PHI_POWERS)
def _compute_inverse_matrix():
    """Compute the inverse transformation columns."""
    # Build 8x8 matrix and invert over GF(2)
    # Row i of forward matrix: bit j of PHI_POWERS[i]

    # For 8x8 GF(2) matrix inversion, we use Gaussian elimination
    # Build augmented matrix [A | I]
    aug = [[0] * 16 for _ in range(8)]
    for i in range(8):
        for j in range(8):
            aug[i][j] = (PHI_POWERS[j] >> i) & 1
        aug[i][8 + i] = 1

    # Forward elimination
    for col in range(8):
        # Find pivot
        pivot_row = None
        for row in range(col, 8):
            if aug[row][col]:
                pivot_row = row
                break
        if pivot_row is None:
            raise ValueError("Matrix not invertible")

        # Swap rows
        aug[col], aug[pivot_row] = aug[pivot_row], aug[col]

        # Eliminate below
        for row in range(col + 1, 8):
            if aug[row][col]:
                for k in range(16):
                    aug[row][k] ^= aug[col][k]

    # Back substitution
    for col in range(7, -1, -1):
        for row in range(col):
            if aug[row][col]:
                for k in range(16):
                    aug[row][k] ^= aug[col][k]

    # Extract inverse matrix columns
    inv_powers = []
    for j in range(8):
        col_val = 0
        for i in range(8):
            col_val |= aug[i][8 + j] << i
        inv_powers.append(col_val)

    return inv_powers


PHI_INV_POWERS = _compute_inverse_matrix()


def tower_to_aes_linear(byte_val: int) -> int:
    """Linear transformation (without lookup) for per-share application."""
    result = 0
    for i in range(8):
        if byte_val & (1 << i):
            result ^= PHI_INV_POWERS[i]
    return result


# ===========================================================================
# AES S-box Affine Transformation
# ===========================================================================

AFFINE_MATRIX = [
    0b11111000,
    0b01111100,
    0b00111110,
    0b00011111,
    0b10001111,
    0b11000111,
    0b11100011,
    0b11110001,
]

AFFINE_CONST = 0x63


def mat_vec_mult(matrix: list[int], vec: int) -> int:
    """Multiply 8x8 bit matrix by 8-bit vector."""
    result = 0
    for i in range(8):
        product = matrix[i] & vec
        bit = bin(product).count('1') & 1
        result |= (bit << (7 - i))
    return result


def apply_affine(byte_val: int) -> int:
    """Apply AES affine transformation: y = M*x + 0x63."""
    return mat_vec_mult(AFFINE_MATRIX, byte_val) ^ AFFINE_CONST


def apply_affine_linear_part(byte_val: int) -> int:
    """Apply just the linear part of AES affine transformation: y = M*x."""
    return mat_vec_mult(AFFINE_MATRIX, byte_val)


# ===========================================================================
# Canright S-box Implementation
# ===========================================================================

def canright_sbox_unmasked(byte_val: int) -> int:
    """
    Compute AES S-box using Canright tower field decomposition.

    Steps:
    1. Convert from AES polynomial basis to tower basis (linear)
    2. Compute inverse in tower field
    3. Convert back to AES polynomial basis (linear)
    4. Apply AES affine transformation
    """
    tower = aes_to_tower(byte_val)
    inv_tower = gf8_inverse_tower(tower)
    inv_aes = tower_to_aes(inv_tower)
    result = apply_affine(inv_aes)
    return result


# Export functions for DOM S-box pipeline
def input_transform(byte_val: int) -> int:
    """Transform from AES representation to tower field (linear, per-share safe)."""
    return aes_to_tower_linear(byte_val)


def output_transform(byte_val: int) -> int:
    """Transform from tower field back to AES and apply affine."""
    aes_val = tower_to_aes_linear(byte_val)
    return apply_affine(aes_val)


def output_transform_no_affine(byte_val: int) -> int:
    """Transform from tower field back to AES without affine (linear, per-share safe)."""
    return tower_to_aes_linear(byte_val)


def output_linear_transform(byte_val: int) -> int:
    """Combined linear part: tower_to_aes + affine linear (for per-share application)."""
    aes_val = tower_to_aes_linear(byte_val)
    return apply_affine_linear_part(aes_val)


# ===========================================================================
# Verification
# ===========================================================================

def verify_canright_sbox():
    """Verify Canright S-box matches standard AES S-box."""
    from ..aes_core import SBOX

    mismatches = []
    for i in range(256):
        computed = canright_sbox_unmasked(i)
        expected = SBOX[i]
        if computed != expected:
            mismatches.append((i, computed, expected))

    return len(mismatches) == 0, mismatches


def verify_linearity():
    """Verify that input/output transforms are linear."""
    for a in range(256):
        for b in range(256):
            if input_transform(a ^ b) != (input_transform(a) ^ input_transform(b)):
                return False, "input_transform"
            if output_transform_no_affine(a ^ b) != (output_transform_no_affine(a) ^ output_transform_no_affine(b)):
                return False, "output_transform_no_affine"
    return True, None
