"""
AETHER-CRYPTO: Mathematical Foundations
========================================

This module builds every cryptographic constant from scratch using finite field
arithmetic. Nothing is copied from a lookup table — we derive the S-Box, its
inverse, the permutation table, the MDS matrix, and round constants step by step
so you can see exactly where the security properties come from.

Key concepts:
- GF(2^8): The Galois Field with 256 elements, used because each element fits
  in one byte and the field has the algebraic structure we need for diffusion.
- Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B in hex). This is the
  same one AES uses. It's irreducible over GF(2), meaning it can't be factored
  — so we can do modular arithmetic with it just like we use primes in regular
  modular arithmetic.
"""

# ---------------------------------------------------------------------------
# GF(2^8) Arithmetic
# ---------------------------------------------------------------------------
# In GF(2^8), addition is XOR and multiplication is polynomial multiplication
# modulo the irreducible polynomial. There are no carries — everything is mod 2.

IRREDUCIBLE_POLY = 0x11B  # x^8 + x^4 + x^3 + x + 1


def gf_mult(a: int, b: int, mod: int = IRREDUCIBLE_POLY) -> int:
    """Multiply two elements in GF(2^8) using the Russian-peasant algorithm.

    How it works:
    - We process `b` one bit at a time (LSB first).
    - If the current bit of `b` is 1, we XOR the running product with `a`
      (this is "addition" in GF(2)).
    - We then shift `a` left by 1 (multiply by x). If the result overflows
      8 bits (bit 8 is set), we reduce modulo the irreducible polynomial by
      XORing with it.

    This is O(8) — always exactly 8 iterations for GF(2^8).
    """
    result = 0
    for _ in range(8):
        if b & 1:          # If the lowest bit of b is set...
            result ^= a    # ...add a to the result (GF(2) addition = XOR)
        b >>= 1            # Move to the next bit of b
        carry = a & 0x80   # Check if a will overflow 8 bits
        a = (a << 1) & 0xFF  # Multiply a by x, keep to 8 bits
        if carry:
            a ^= mod & 0xFF  # Reduce: subtract the irreducible polynomial
            # (In GF(2), subtraction = addition = XOR)
            # We XOR with 0x1B (low byte of 0x11B) because bit 8 was already
            # removed by the & 0xFF mask above.
    return result


def gf_inverse(a: int) -> int:
    """Find the multiplicative inverse of `a` in GF(2^8).

    Every nonzero element in GF(2^8) has a unique inverse such that
    a * a^(-1) = 1. Zero has no inverse (we define inv(0) = 0 by convention).

    We use the extended Euclidean algorithm adapted for binary polynomials.
    This computes gcd(a, irreducible_poly) and finds the Bezout coefficient
    that gives us the inverse.

    Why this matters for security: The multiplicative inverse is highly
    nonlinear — changing one input bit affects many output bits unpredictably.
    This is the core of S-Box security (confusion).
    """
    if a == 0:
        return 0

    # Extended Euclidean algorithm for binary polynomials
    # We want to find t such that a * t ≡ 1 (mod IRREDUCIBLE_POLY)
    r_old, r_new = IRREDUCIBLE_POLY, a
    t_old, t_new = 0, 1

    while r_new != 0:
        # Polynomial division: find quotient degree by degree
        deg_old = r_old.bit_length() - 1
        deg_new = r_new.bit_length() - 1

        if deg_old < deg_new:
            r_old, r_new = r_new, r_old
            t_old, t_new = t_new, t_old
            continue

        shift = deg_old - deg_new
        r_old ^= r_new << shift  # Subtract (= XOR) shifted divisor
        t_old ^= t_new << shift

    # r_old should be 1 (gcd = 1 for any nonzero element and irreducible poly)
    return t_old & 0xFF


# ---------------------------------------------------------------------------
# S-Box Construction
# ---------------------------------------------------------------------------
# The S-Box provides CONFUSION: it makes the relationship between the key and
# ciphertext as complex as possible. It's a nonlinear substitution.
#
# Construction (same approach as AES, with our own affine transform):
# 1. Compute the multiplicative inverse in GF(2^8) — this is highly nonlinear.
# 2. Apply an affine transformation over GF(2) — this adds algebraic complexity
#    and breaks the simple algebraic structure of the inverse.
#
# The affine transform is: b' = A * b + c, where A is a circulant matrix and
# c is a constant vector. We use a different constant than AES.


def _affine_transform(byte: int) -> int:
    """Apply the AETHER affine transformation to a byte.

    The affine transform uses:
    - A circulant matrix defined by the byte 0x1F (binary: 00011111)
      This means each output bit depends on 5 input bits — good diffusion
      within the byte.
    - A constant vector c = 0x03 (binary: 00000011)

    The transform computes: for each output bit i,
      out[i] = in[i] ^ in[(i+1)%8] ^ in[(i+2)%8] ^ in[(i+3)%8] ^ in[(i+4)%8] ^ c[i]

    This is a bijection (invertible), which is required so we can decrypt.
    The constant 0x03 was chosen (instead of AES's 0x63) to eliminate all
    fixed points (S[x] = x), which would be a cryptographic weakness.
    """
    result = 0
    for i in range(8):
        # XOR together bits at positions i, i+1, i+2, i+3, i+4 (mod 8)
        bit = 0
        for j in range(5):
            bit ^= (byte >> ((i + j) % 8)) & 1
        # XOR with the constant bit
        bit ^= (0x03 >> i) & 1
        result |= bit << i
    return result


def _inverse_affine_transform(byte: int) -> int:
    """Inverse of the AETHER affine transformation.

    To invert b' = A*b + c:
    1. Subtract the constant: b' ^ c
    2. Multiply by A^(-1)

    The inverse matrix for our circulant is defined by 0x4A (binary: 01001010).
    We can verify: A * A^(-1) = I (identity).
    """
    # First XOR with the constant to undo the addition
    byte ^= 0x03

    # Apply the inverse circulant matrix
    # The inverse matrix row is 0x4A = bits at positions 1, 3, 6
    result = 0
    for i in range(8):
        bit = 0
        for j in [1, 3, 6]:  # Positions where the inverse matrix has 1s
            bit ^= (byte >> ((i + j) % 8)) & 1
        result |= bit << i
    return result


def _build_sbox() -> list[int]:
    """Build the AETHER S-Box from scratch.

    For each byte value b (0-255):
    1. Compute inv = multiplicative inverse of b in GF(2^8)  [nonlinearity]
    2. Apply affine transform to inv                          [algebraic complexity]

    The result is a 256-byte lookup table: S[b] = affine(inv(b))
    """
    sbox = []
    for b in range(256):
        inv = gf_inverse(b)          # Step 1: GF(2^8) inverse
        transformed = _affine_transform(inv)  # Step 2: affine transform
        sbox.append(transformed)
    return sbox


def _build_inverse_sbox(sbox: list[int]) -> list[int]:
    """Build the inverse S-Box for decryption.

    If S[x] = y, then S_inv[y] = x.
    We simply reverse the lookup table.
    """
    inv_sbox = [0] * 256
    for i, val in enumerate(sbox):
        inv_sbox[val] = i
    return inv_sbox


# Build and export the S-Boxes
SBOX = _build_sbox()
INV_SBOX = _build_inverse_sbox(SBOX)


# ---------------------------------------------------------------------------
# S-Box Verification
# ---------------------------------------------------------------------------
# A good S-Box must satisfy several cryptographic properties:

def verify_sbox(sbox: list[int]) -> dict:
    """Verify cryptographic properties of the S-Box.

    Returns a dict with:
    - is_bijection: True if S-Box is a permutation (required for decryption)
    - fixed_points: list of x where S[x] = x (should be empty)
    - nonlinearity: minimum Walsh-spectrum nonlinearity (should be ≥ 112)
    - differential_uniformity: max entries in the DDT (should be ≤ 4)
    """
    results = {}

    # 1. Bijection check: every output value appears exactly once
    results["is_bijection"] = len(set(sbox)) == 256

    # 2. Fixed points: S[x] = x is bad because the byte passes through unchanged
    results["fixed_points"] = [x for x in range(256) if sbox[x] == x]

    # 3. Nonlinearity (Walsh transform)
    # The nonlinearity measures how far the S-Box is from any affine function.
    # Higher = more resistant to linear cryptanalysis.
    min_nonlinearity = 256
    for output_mask in range(1, 256):
        for input_mask in range(256):
            # Compute Walsh coefficient
            walsh_sum = 0
            for x in range(256):
                # input_bit = parity of (x AND input_mask)
                input_bit = bin(x & input_mask).count('1') % 2
                # output_bit = parity of (S[x] AND output_mask)
                output_bit = bin(sbox[x] & output_mask).count('1') % 2
                walsh_sum += (-1) ** (input_bit ^ output_bit)
            nl = (256 - abs(walsh_sum)) // 2
            if nl < min_nonlinearity:
                min_nonlinearity = nl
    results["nonlinearity"] = min_nonlinearity

    # 4. Differential uniformity
    # For each input/output difference pair (Δx, Δy), count how many x satisfy
    # S[x] ^ S[x^Δx] = Δy. The maximum count is the differential uniformity.
    # Lower = more resistant to differential cryptanalysis.
    max_count = 0
    for delta_x in range(1, 256):
        ddt_row = [0] * 256
        for x in range(256):
            delta_y = sbox[x] ^ sbox[x ^ delta_x]
            ddt_row[delta_y] += 1
        row_max = max(ddt_row)
        if row_max > max_count:
            max_count = row_max
    results["differential_uniformity"] = max_count

    return results


# ---------------------------------------------------------------------------
# P-Box (Permutation Box)
# ---------------------------------------------------------------------------
# The P-Box provides bit-level DIFFUSION: it spreads the output bits of each
# S-Box across different S-Box inputs in the next round. Combined with the
# S-Box (confusion), this ensures that after a few rounds, every output bit
# depends on every input bit.
#
# Our 128-bit permutation is designed so that the 8 output bits of each S-Box
# go to 8 different S-Boxes in the next round. This guarantees full diffusion
# after 2 rounds through the P-Box.

def _build_pbox() -> list[int]:
    """Build a 128-bit permutation table with full diffusion.

    Strategy: bit i of byte j maps to bit j of byte i (a transpose).
    For a 16-byte (128-bit) state, this means:
    - Bit position (byte_idx * 8 + bit_idx) maps to (bit_idx_in_group * 16 + byte_in_group)

    We use a structured approach: divide 128 bits into groups and interleave
    so each S-Box's outputs feed into all other S-Boxes.

    Specifically: bit at position (i*8 + j) for byte i, bit j goes to
    position (j*16 + i). This is a 16x8 → 8x16 transpose.
    """
    pbox = [0] * 128
    for byte_idx in range(16):       # 16 bytes
        for bit_idx in range(8):     # 8 bits per byte
            src = byte_idx * 8 + bit_idx
            dst = bit_idx * 16 + byte_idx
            pbox[src] = dst
    return pbox


def _build_inverse_pbox(pbox: list[int]) -> list[int]:
    """Build the inverse permutation: if P[i] = j, then P_inv[j] = i."""
    inv = [0] * 128
    for i, j in enumerate(pbox):
        inv[j] = i
    return inv


PBOX = _build_pbox()
INV_PBOX = _build_inverse_pbox(PBOX)


# ---------------------------------------------------------------------------
# MDS Matrix (Maximum Distance Separable)
# ---------------------------------------------------------------------------
# The MDS matrix provides DIFFUSION at the column level. When we multiply a
# 4-byte column by this matrix, every output byte depends on all 4 input bytes.
#
# "MDS" means the matrix has branch number = 5 (maximum for a 4×4 matrix).
# Branch number = min weight of nonzero input + output in the matrix equation.
# Branch number 5 means: if you change any k input bytes (1 ≤ k ≤ 4), at least
# (5 - k) output bytes will change. So changing 1 byte changes ≥ 4 outputs.
#
# We use a Cauchy matrix construction, which is guaranteed to be MDS.
# A Cauchy matrix C[i][j] = 1 / (x[i] + y[j]) in GF(2^8), where x and y
# are disjoint sets of field elements.

def _build_mds_matrix() -> list[list[int]]:
    """Construct a 4×4 MDS matrix over GF(2^8) using the Cauchy construction.

    We pick:
      x = [0x02, 0x03, 0x05, 0x07]  (distinct nonzero elements)
      y = [0x0B, 0x0D, 0x11, 0x13]  (distinct, and disjoint from x)

    Then M[i][j] = gf_inverse(x[i] XOR y[j])

    Any submatrix of a Cauchy matrix is invertible, which is exactly the MDS
    property. This guarantees our branch number = 5.
    """
    x = [0x02, 0x03, 0x05, 0x07]
    y = [0x0B, 0x0D, 0x11, 0x13]

    matrix = []
    for i in range(4):
        row = []
        for j in range(4):
            # x[i] ^ y[j] is addition in GF(2^8) (= XOR)
            val = gf_inverse(x[i] ^ y[j])
            row.append(val)
        matrix.append(row)
    return matrix


def _build_inverse_mds(mds: list[list[int]]) -> list[list[int]]:
    """Compute the inverse of the 4×4 MDS matrix over GF(2^8).

    We use Gauss-Jordan elimination in GF(2^8):
    1. Augment the matrix with the identity: [M | I]
    2. Row-reduce to get: [I | M^(-1)]

    All arithmetic is in GF(2^8): add = XOR, multiply = gf_mult.
    """
    n = 4
    # Build augmented matrix [M | I]
    aug = []
    for i in range(n):
        row = list(mds[i]) + [1 if j == i else 0 for j in range(n)]
        aug.append(row)

    for col in range(n):
        # Find pivot (nonzero element in this column)
        pivot = None
        for row in range(col, n):
            if aug[row][col] != 0:
                pivot = row
                break
        assert pivot is not None, "MDS matrix is singular (should never happen)"

        # Swap rows
        aug[col], aug[pivot] = aug[pivot], aug[col]

        # Scale pivot row so the diagonal element becomes 1
        inv_diag = gf_inverse(aug[col][col])
        for j in range(2 * n):
            aug[col][j] = gf_mult(aug[col][j], inv_diag)

        # Eliminate all other rows in this column
        for row in range(n):
            if row == col:
                continue
            factor = aug[row][col]
            if factor == 0:
                continue
            for j in range(2 * n):
                aug[row][j] ^= gf_mult(factor, aug[col][j])

    # Extract the inverse from the right half
    return [row[n:] for row in aug]


MDS_MATRIX = _build_mds_matrix()
INV_MDS_MATRIX = _build_inverse_mds(MDS_MATRIX)


# ---------------------------------------------------------------------------
# Round Constants
# ---------------------------------------------------------------------------
# Round constants are XORed into each round key to break symmetry and ensure
# that even if the master key has patterns (like repeated bytes), each round
# key is different.
#
# We derive them from the fractional parts of mathematical constants, similar
# to how AES derives RCON from powers of 2 in GF(2^8), or how SHA-256 uses
# fractional parts of prime square roots. This "nothing-up-my-sleeve" approach
# proves we didn't choose constants to hide a backdoor.

import math

def _derive_round_constants(num_rounds: int = 16) -> list[bytes]:
    """Derive round constants from fractional parts of math constants.

    For round i, we take bytes from the fractional expansion of:
    - sqrt(prime[i]) for the first 8 primes
    - cbrt(prime[i-8]) for the next 8

    Each round constant is 16 bytes (128 bits), matching the block size.
    We extract bytes by multiplying the fractional part by 2^128 and taking
    the first 16 bytes.

    These are deterministic and publicly verifiable — anyone can recompute
    them and confirm we didn't choose "magic" constants.
    """
    # First 16 primes
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
    constants = []

    for i in range(num_rounds):
        p = primes[i]
        if i < 8:
            # Fractional part of sqrt(prime)
            frac = math.sqrt(p) - int(math.sqrt(p))
        else:
            # Fractional part of cube root of prime
            cbrt = p ** (1 / 3)
            frac = cbrt - int(cbrt)

        # Convert fractional part to 16 bytes
        # Multiply by 2^128 and take integer part
        big_int = int(frac * (2 ** 128))
        rc = big_int.to_bytes(16, byteorder='big')
        constants.append(rc)

    return constants


ROUND_CONSTANTS = _derive_round_constants(16)

# Number of cipher rounds
NUM_ROUNDS = 16

# Block size in bytes and bits
BLOCK_SIZE = 16       # 128 bits
BLOCK_BITS = 128
