"""
AETHER-CRYPTO: Key Derivation & Scheduling
=============================================

This module handles the two-stage process of turning a human password into
the 17 round keys that the cipher needs:

Stage 1: Password → 256-bit master key (using Argon2id)
Stage 2: Master key → 17 × 128-bit round keys (custom key schedule)

Why two stages?
- Stage 1 is slow on purpose: Argon2id is memory-hard, making brute-force
  attacks on weak passwords extremely expensive. An attacker can't just try
  billions of passwords per second.
- Stage 2 is fast: once we have a strong master key, we need to expand it
  into enough key material for all rounds. This must be deterministic and
  efficient.
"""

from __future__ import annotations

import os
import hashlib
from argon2.low_level import hash_secret_raw, Type

from .constants import SBOX, ROUND_CONSTANTS, NUM_ROUNDS, BLOCK_SIZE


# ---------------------------------------------------------------------------
# Stage 1: Password → Master Key via Argon2id
# ---------------------------------------------------------------------------

# Argon2id parameters — these control how expensive it is to derive the key.
# Higher values = more resistant to brute-force, but slower for legitimate users.
ARGON2_MEMORY_KB = 65536    # 64 MB of memory — forces attacker to use lots of RAM
ARGON2_ITERATIONS = 3       # 3 passes over memory — increases time cost
ARGON2_PARALLELISM = 4      # 4 threads — uses multiple cores
ARGON2_KEY_LENGTH = 32      # 256-bit output (enough for two 128-bit halves)


def derive_master_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit master key from a password using Argon2id.

    Argon2id combines the best of:
    - Argon2d: data-dependent memory access (resists GPU attacks)
    - Argon2i: data-independent access (resists side-channel attacks)

    The salt ensures that the same password produces different keys each time.
    It's stored in the encrypted file header (it's not secret, just unique).

    Args:
        password: user's password (any string)
        salt: 16 random bytes (stored in file header)

    Returns:
        32 bytes (256 bits) of key material
    """
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY_KB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_KEY_LENGTH,
        type=Type.ID,  # Argon2id
    )


# ---------------------------------------------------------------------------
# Stage 2: Master Key → Round Keys (Key Schedule)
# ---------------------------------------------------------------------------
# The key schedule expands the 256-bit master key into 17 round keys, each
# 128 bits (16 bytes). This is critical for security:
# - Each round must use a different key (otherwise patterns emerge)
# - Related-key attacks must be prevented (knowing one round key shouldn't
#   help you find others)
#
# Our approach:
# 1. Split the 256-bit master key into two 128-bit halves: K_left, K_right
# 2. For each round i:
#    a. XOR with round constant RC[i] (breaks symmetry between rounds)
#    b. Rotate bytes (ensures different bytes affect different positions)
#    c. Apply S-Box to specific bytes (adds nonlinearity so the schedule
#       isn't just a linear function of the master key)
#    d. Mix the two halves together (prevents independent analysis)

def _rotate_bytes_left(data: list[int], n: int) -> list[int]:
    """Rotate a list of bytes left by n positions.

    This ensures that the same byte doesn't always influence the same position
    in the round key. After 16 rounds of rotation, every byte has appeared in
    every position.
    """
    n = n % len(data)
    return data[n:] + data[:n]


def _sub_bytes_partial(data: list[int], positions: list[int]) -> list[int]:
    """Apply S-Box substitution to specific byte positions.

    We don't substitute ALL bytes (that would be slow and unnecessary). Instead,
    we substitute a few strategic positions. This introduces nonlinearity into
    the key schedule — without it, the round keys would be linear combinations
    of the master key, which makes related-key attacks possible.
    """
    result = list(data)
    for pos in positions:
        result[pos] = SBOX[result[pos]]
    return result


def expand_key(master_key: bytes) -> list[list[int]]:
    """Expand a 256-bit master key into 17 round keys (each 128 bits).

    The key schedule ensures:
    1. Each round key is unique (via round constants)
    2. Nonlinearity (via S-Box substitution of select bytes)
    3. Full key dependency (each round key depends on both halves of master key)
    4. No simple relationship between round keys (prevents related-key attacks)

    Args:
        master_key: 32 bytes (256 bits) from Argon2id

    Returns:
        List of 17 round keys, each a list of 16 ints (bytes)
    """
    assert len(master_key) == 32, "Master key must be 256 bits (32 bytes)"

    # Split into two halves
    k_left = list(master_key[:16])
    k_right = list(master_key[16:])

    round_keys = []

    for i in range(NUM_ROUNDS + 1):  # 17 round keys (0..16)
        # --- Step 1: XOR with round constant ---
        # This makes each round key different even if the master key has patterns.
        rc = list(ROUND_CONSTANTS[i % NUM_ROUNDS])
        temp = [k_left[j] ^ rc[j] for j in range(BLOCK_SIZE)]

        # --- Step 2: Rotate bytes ---
        # Rotation amount increases with round number for variety.
        temp = _rotate_bytes_left(temp, i + 1)

        # --- Step 3: S-Box substitution of bytes at positions 0, 5, 10, 15 ---
        # These positions are the diagonal — they spread the nonlinearity across
        # all four columns of the state matrix.
        temp = _sub_bytes_partial(temp, [0, 5, 10, 15])

        # --- Step 4: Mix with the right half ---
        # XOR with k_right ensures both halves of the master key contribute
        # to every round key. This prevents attacks that only need to guess
        # half the key.
        round_key = [temp[j] ^ k_right[j] for j in range(BLOCK_SIZE)]
        round_keys.append(round_key)

        # --- Step 5: Update halves for next round ---
        # The left half becomes the old right half, and the right half becomes
        # the round key we just computed. This creates a "cascade" where each
        # round key depends on all previous round keys.
        k_left, k_right = k_right, round_key

    return round_keys


# ---------------------------------------------------------------------------
# Market-enhanced salt (optional)
# ---------------------------------------------------------------------------

def enhance_salt_with_market(random_salt: bytes, btc_input: bytes) -> bytes:
    """Mix market data into the random salt for additional entropy.

    The random salt is ALWAYS the primary source of uniqueness. The BTC price
    is just bonus entropy mixed in via XOR. Even if the BTC value is predictable
    or zero, the random salt alone provides full security.

    Args:
        random_salt: 16 random bytes (always generated fresh)
        btc_input: 16 bytes derived from BTC price (from signal module)

    Returns:
        16 bytes: random_salt XOR btc_input
    """
    assert len(random_salt) == 16 and len(btc_input) == 16
    return bytes(a ^ b for a, b in zip(random_salt, btc_input))


def generate_salt() -> bytes:
    """Generate a cryptographically random 16-byte salt."""
    return os.urandom(16)


def generate_nonce() -> bytes:
    """Generate a cryptographically random 12-byte nonce for CTR mode."""
    return os.urandom(12)
