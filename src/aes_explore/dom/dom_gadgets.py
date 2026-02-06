"""
Domain-Oriented Masking (DOM) multiplier gadgets.

Implements:
- DOM-indep: For multiplying independent shared values
- DOM-dep: For multiplying potentially related shared values (glitch-resistant)

Both gadgets maintain d-probing security for protection order d.
"""

import random
from typing import Callable

from ..counters import RandomnessCounter
from .gf_canright import gf2_mult, gf4_mult, gf8_mult_tower


class DomIndepMultiplier:
    """
    DOM-independent multiplier for d+1 shares.

    Used when inputs x and y are statistically independent.

    For protection order d with d+1 shares:
    - Uses d*(d+1)/2 fresh random masks Z_ij
    - Each Z has width n bits (field size)
    """

    def __init__(
        self,
        d: int,
        field_width: int,
        gf_mult_func: Callable[[int, int], int],
        rng: random.Random,
        randomness_counter: RandomnessCounter | None = None
    ):
        """
        Initialize DOM-indep multiplier.

        Args:
            d: Protection order (1 or 2)
            field_width: Bit width of field elements (2, 4, or 8)
            gf_mult_func: GF multiplication function for this field
            rng: Random number generator
            randomness_counter: Optional counter for tracking randomness
        """
        self.d = d
        self.num_shares = d + 1
        self.field_width = field_width
        self.field_mask = (1 << field_width) - 1
        self.gf_mult = gf_mult_func
        self.rng = rng
        self.randomness_counter = randomness_counter

    def _sample_random(self) -> int:
        """Sample a random field element and count it."""
        r = self.rng.randint(0, self.field_mask)
        if self.randomness_counter:
            self.randomness_counter.add(
                self.field_width,
                width=self.field_width,
                operation=f"dom_indep_gf{self.field_width}"
            )
        return r

    def multiply(self, x_shares: list[int], y_shares: list[int]) -> list[int]:
        """
        Compute DOM-independent multiplication of shared values.

        z = x * y where x and y are each represented as d+1 shares.

        Algorithm:
        For each pair (i, j) with i < j:
            - Sample fresh random Z_ij
            - Compute partial products with masking
        Combine partial products respecting domain separation.

        Args:
            x_shares: d+1 shares of x
            y_shares: d+1 shares of y

        Returns:
            d+1 shares of x*y
        """
        n = self.num_shares

        # Compute all partial products x_i * y_j
        # partials[i][j] = x_i * y_j
        partials = [[0 for _ in range(n)] for _ in range(n)]
        for i in range(n):
            for j in range(n):
                partials[i][j] = self.gf_mult(x_shares[i], y_shares[j])

        # Generate fresh randomness for cross-domain terms
        # Z[i][j] for i < j
        z_masks = [[0 for _ in range(n)] for _ in range(n)]
        for i in range(n):
            for j in range(i + 1, n):
                z_masks[i][j] = self._sample_random()

        # Compute corrected cross-domain terms
        # For i < j:
        #   c_ij = (x_i * y_j) + Z_ij
        #   c_ji = (x_j * y_i) + Z_ij
        # These mask the cross-domain leakage

        # Accumulate result shares
        result = [0 for _ in range(n)]

        for i in range(n):
            # Same-domain term (no masking needed)
            acc = partials[i][i]

            # Cross-domain terms
            for j in range(n):
                if j == i:
                    continue

                if i < j:
                    # c_ij = x_i * y_j + Z_ij
                    cross_term = partials[i][j] ^ z_masks[i][j]
                else:
                    # c_ij = x_i * y_j + Z_ji (note: j < i)
                    cross_term = partials[i][j] ^ z_masks[j][i]

                acc ^= cross_term

            result[i] = acc & self.field_mask

        return result


class DomDepMultiplier:
    """
    DOM-dependent multiplier for potentially related shared values.

    Used when inputs x and y may be statistically related (e.g., due to
    glitches from shared linear computations).

    Uses blinding-based approach:
        x * y = x * (y + z) + x * z
    where z is a fresh random blinding value.

    This requires:
    - d+1 fresh random elements to blind y
    - A register stage to ensure blinding is complete
    - A DOM-indep multiplication for x * z
    """

    def __init__(
        self,
        d: int,
        field_width: int,
        gf_mult_func: Callable[[int, int], int],
        rng: random.Random,
        randomness_counter: RandomnessCounter | None = None
    ):
        """
        Initialize DOM-dep multiplier.

        Args:
            d: Protection order (1 or 2)
            field_width: Bit width of field elements
            gf_mult_func: GF multiplication function
            rng: Random number generator
            randomness_counter: Optional counter for tracking randomness
        """
        self.d = d
        self.num_shares = d + 1
        self.field_width = field_width
        self.field_mask = (1 << field_width) - 1
        self.gf_mult = gf_mult_func
        self.rng = rng
        self.randomness_counter = randomness_counter

        # Internal DOM-indep multiplier for x * z computation
        self._dom_indep = DomIndepMultiplier(
            d, field_width, gf_mult_func, rng, randomness_counter
        )

    def _sample_random(self) -> int:
        """Sample a random field element and count it."""
        r = self.rng.randint(0, self.field_mask)
        if self.randomness_counter:
            self.randomness_counter.add(
                self.field_width,
                width=self.field_width,
                operation=f"dom_dep_blind_gf{self.field_width}"
            )
        return r

    def multiply(self, x_shares: list[int], y_shares: list[int]) -> list[int]:
        """
        Compute DOM-dependent multiplication of potentially related shared values.

        Algorithm (blinding-based):
        1. Generate fresh random z as shared value (d+1 shares)
        2. Compute y_blinded = y + z (share-wise XOR)
        3. Recombine y_blinded to get public b = sum(y_blinded_shares)
        4. Compute x * b for each share of x (public multiplication)
        5. Compute x * z using DOM-indep
        6. Result = (x * b) + (x * z) = x * (y + z) + x * z = x * y

        Note: Step 2->3 requires a register stage in hardware to prevent glitches.
        We model this implicitly (cycle accounting happens at the S-box level).

        Args:
            x_shares: d+1 shares of x
            y_shares: d+1 shares of y

        Returns:
            d+1 shares of x*y
        """
        n = self.num_shares

        # Step 1: Generate z as d+1 shares summing to random value
        # All shares are random; their XOR is the actual z
        z_shares = [self._sample_random() for _ in range(n)]

        # Step 2: Blind y with z (share-wise)
        y_blinded = [(y_shares[i] ^ z_shares[i]) & self.field_mask for i in range(n)]

        # Step 3: Recombine y_blinded to get public b
        # b = y + z = sum(y_i + z_i) = sum(y_i) + sum(z_i) = y + z
        b = 0
        for i in range(n):
            b ^= y_blinded[i]

        # Step 4: Compute x * b for each share (b is public, no masking needed)
        xb_shares = [self.gf_mult(x_shares[i], b) for i in range(n)]

        # Step 5: Compute x * z using DOM-indep (both are properly shared)
        xz_shares = self._dom_indep.multiply(x_shares, z_shares)

        # Step 6: Result = x*b + x*z = x*(y+z) + x*z = x*y + x*z + x*z = x*y
        result = [(xb_shares[i] ^ xz_shares[i]) & self.field_mask for i in range(n)]

        return result


def create_gf2_dom_indep(
    d: int, rng: random.Random, counter: RandomnessCounter | None = None
) -> DomIndepMultiplier:
    """Create DOM-indep multiplier for GF(2^2)."""
    return DomIndepMultiplier(d, 2, gf2_mult, rng, counter)


def create_gf4_dom_indep(
    d: int, rng: random.Random, counter: RandomnessCounter | None = None
) -> DomIndepMultiplier:
    """Create DOM-indep multiplier for GF(2^4)."""
    return DomIndepMultiplier(d, 4, gf4_mult, rng, counter)


def create_gf8_dom_indep(
    d: int, rng: random.Random, counter: RandomnessCounter | None = None
) -> DomIndepMultiplier:
    """Create DOM-indep multiplier for GF(2^8)."""
    return DomIndepMultiplier(d, 8, gf8_mult_tower, rng, counter)


def create_gf2_dom_dep(
    d: int, rng: random.Random, counter: RandomnessCounter | None = None
) -> DomDepMultiplier:
    """Create DOM-dep multiplier for GF(2^2)."""
    return DomDepMultiplier(d, 2, gf2_mult, rng, counter)


def create_gf4_dom_dep(
    d: int, rng: random.Random, counter: RandomnessCounter | None = None
) -> DomDepMultiplier:
    """Create DOM-dep multiplier for GF(2^4)."""
    return DomDepMultiplier(d, 4, gf4_mult, rng, counter)


def create_gf8_dom_dep(
    d: int, rng: random.Random, counter: RandomnessCounter | None = None
) -> DomDepMultiplier:
    """Create DOM-dep multiplier for GF(2^8)."""
    return DomDepMultiplier(d, 8, gf8_mult_tower, rng, counter)
