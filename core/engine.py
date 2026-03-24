"""
AETHER-CRYPTO: SPN Cipher Engine
==================================

This module implements the actual encryption and decryption logic — a 16-round
Substitution-Permutation Network (SPN) operating on 128-bit blocks.

The state is organized as a 4×4 matrix of bytes (like AES), read column-first:

    [ b0  b4  b8  b12 ]
    [ b1  b5  b9  b13 ]
    [ b2  b6  b10 b14 ]
    [ b3  b7  b11 b15 ]

Each round applies four transformations in sequence:
1. SubBytes   — nonlinear substitution (confusion)
2. ShiftRows  — row-wise byte rotation (diffusion across rows)
3. MixColumns — column-wise matrix multiply in GF(2^8) (diffusion within columns)
4. AddRoundKey — XOR with the round key (key mixing)

After 16 rounds, every output bit depends on every input bit and every key bit.
This is called the "avalanche effect" and is what makes the cipher secure.
"""

from __future__ import annotations

import os
import struct

from .constants import (
    SBOX, INV_SBOX,
    MDS_MATRIX, INV_MDS_MATRIX,
    BLOCK_SIZE, NUM_ROUNDS,
    gf_mult,
)


# ---------------------------------------------------------------------------
# State representation
# ---------------------------------------------------------------------------
# The state is a flat list of 16 bytes, indexed as state[row + 4*col].
# This column-major layout matches the matrix diagram above.

def _idx(row: int, col: int) -> int:
    """Convert (row, col) to index in the flat state array (column-major)."""
    return row + 4 * col


# ---------------------------------------------------------------------------
# Round functions (encryption direction)
# ---------------------------------------------------------------------------

def add_round_key(state: list[int], round_key: list[int]) -> list[int]:
    """XOR the state with the round key, byte by byte.

    WHY: This is the only step that mixes in the secret key. Without it,
    the cipher would be a fixed (public) permutation — anyone could decrypt.
    XOR is used because it's its own inverse (simplifies decryption) and
    every key bit affects the state equally.
    """
    return [s ^ k for s, k in zip(state, round_key)]


def sub_bytes(state: list[int]) -> list[int]:
    """Replace each byte with its S-Box lookup.

    WHY (CONFUSION): The S-Box is a nonlinear function. Without it, the
    entire cipher would be a big system of linear equations (XOR and matrix
    multiply are both linear over GF(2)). Linear systems can be solved
    trivially, so the S-Box is essential for security.
    """
    return [SBOX[b] for b in state]


def inv_sub_bytes(state: list[int]) -> list[int]:
    """Inverse S-Box substitution for decryption."""
    return [INV_SBOX[b] for b in state]


def shift_rows(state: list[int]) -> list[int]:
    """Rotate each row left by its row index (0, 1, 2, 3 positions).

    WHY (DIFFUSION): This ensures that the four bytes in each column, after
    ShiftRows, came from four DIFFERENT columns before. Combined with
    MixColumns (which mixes within a column), this means after 2 rounds,
    every byte has influenced every other byte. Without ShiftRows, each
    column would be processed independently forever.

    Row 0: no shift         [b0,  b4,  b8,  b12] → [b0,  b4,  b8,  b12]
    Row 1: shift left by 1  [b1,  b5,  b9,  b13] → [b5,  b9,  b13, b1 ]
    Row 2: shift left by 2  [b2,  b6,  b10, b14] → [b10, b14, b2,  b6 ]
    Row 3: shift left by 3  [b3,  b7,  b11, b15] → [b15, b3,  b7,  b11]
    """
    new_state = [0] * 16
    for row in range(4):
        for col in range(4):
            # Read from column (col + row) % 4, write to column col
            new_state[_idx(row, col)] = state[_idx(row, (col + row) % 4)]
    return new_state


def inv_shift_rows(state: list[int]) -> list[int]:
    """Inverse: rotate each row RIGHT by its row index."""
    new_state = [0] * 16
    for row in range(4):
        for col in range(4):
            new_state[_idx(row, (col + row) % 4)] = state[_idx(row, col)]
    return new_state


def mix_columns(state: list[int]) -> list[int]:
    """Multiply each 4-byte column by the MDS matrix over GF(2^8).

    WHY (DIFFUSION): This makes every output byte of a column depend on ALL
    four input bytes. The MDS property (branch number = 5) guarantees that
    if you change k bytes in a column, at least 5-k output bytes will change.
    So changing 1 input byte changes at least 4 output bytes — maximum spread.

    The multiplication is in GF(2^8): add = XOR, multiply = gf_mult.
    """
    new_state = [0] * 16
    for col in range(4):
        # Extract the 4-byte column
        col_bytes = [state[_idx(row, col)] for row in range(4)]
        # Matrix-vector multiply in GF(2^8)
        for row in range(4):
            val = 0
            for k in range(4):
                val ^= gf_mult(MDS_MATRIX[row][k], col_bytes[k])
            new_state[_idx(row, col)] = val
    return new_state


def inv_mix_columns(state: list[int]) -> list[int]:
    """Multiply each column by the INVERSE MDS matrix (for decryption)."""
    new_state = [0] * 16
    for col in range(4):
        col_bytes = [state[_idx(row, col)] for row in range(4)]
        for row in range(4):
            val = 0
            for k in range(4):
                val ^= gf_mult(INV_MDS_MATRIX[row][k], col_bytes[k])
            new_state[_idx(row, col)] = val
    return new_state


# ---------------------------------------------------------------------------
# Full block encrypt / decrypt
# ---------------------------------------------------------------------------

def encrypt_block(plaintext: bytes, round_keys: list[list[int]]) -> bytes:
    """Encrypt a single 128-bit block through 16 rounds of the SPN.

    Round structure (for round i = 0..15):
      1. AddRoundKey(round_keys[i])
      2. SubBytes
      3. ShiftRows
      4. MixColumns (skipped in the last round — it would just be undone
         immediately by the inverse and adds no security after the final key)

    After all rounds: one final AddRoundKey(round_keys[16]) — the "whitening" key.

    Total round keys needed: 17 (one per round + one final).
    """
    assert len(plaintext) == BLOCK_SIZE
    assert len(round_keys) == NUM_ROUNDS + 1  # 17 round keys

    state = list(plaintext)

    for r in range(NUM_ROUNDS):
        state = add_round_key(state, round_keys[r])
        state = sub_bytes(state)
        state = shift_rows(state)
        if r < NUM_ROUNDS - 1:
            # Skip MixColumns in the last round (standard SPN practice —
            # the last MixColumns would be "canceled out" by the inverse
            # during decryption, so it adds complexity without security)
            state = mix_columns(state)

    # Final key whitening — prevents peeling off the last SubBytes/ShiftRows
    state = add_round_key(state, round_keys[NUM_ROUNDS])

    return bytes(state)


def decrypt_block(ciphertext: bytes, round_keys: list[list[int]]) -> bytes:
    """Decrypt a single 128-bit block by reversing the SPN.

    We undo each operation in reverse order:
    - AddRoundKey is its own inverse (XOR twice = identity)
    - InvSubBytes reverses SubBytes
    - InvShiftRows reverses ShiftRows
    - InvMixColumns reverses MixColumns
    """
    assert len(ciphertext) == BLOCK_SIZE
    assert len(round_keys) == NUM_ROUNDS + 1

    state = list(ciphertext)

    # Undo the final whitening key
    state = add_round_key(state, round_keys[NUM_ROUNDS])

    for r in range(NUM_ROUNDS - 1, -1, -1):
        # Reverse the operations of round r
        if r < NUM_ROUNDS - 1:
            state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])

    return bytes(state)


# ---------------------------------------------------------------------------
# CTR Mode (Counter Mode)
# ---------------------------------------------------------------------------
# CTR mode turns our block cipher into a stream cipher:
#
# 1. Concatenate a 96-bit nonce with a 32-bit counter: nonce || counter
# 2. Encrypt this 128-bit value to get a keystream block
# 3. XOR the keystream with plaintext to produce ciphertext
# 4. Increment counter, repeat for next block
#
# Advantages:
# - No padding needed (we only XOR as many bytes as we have plaintext)
# - Parallelizable (each block's keystream is independent)
# - Encryption = decryption (XOR is its own inverse)
#
# The 32-bit counter allows up to 2^32 blocks = 64 GB per nonce, which is
# more than enough for file encryption.

def ctr_encrypt(data: bytes, round_keys: list[list[int]], nonce: bytes) -> bytes:
    """Encrypt arbitrary-length data using CTR mode.

    Args:
        data: plaintext of any length
        round_keys: 17 round keys from the key schedule
        nonce: 12-byte (96-bit) random nonce — MUST be unique per encryption

    Returns:
        ciphertext (same length as data)

    SECURITY NOTE: Reusing a nonce with the same key completely breaks CTR mode,
    because XOR of two ciphertexts = XOR of two plaintexts (key cancels out).
    Always generate a fresh random nonce for each encryption.
    """
    assert len(nonce) == 12, "Nonce must be exactly 12 bytes (96 bits)"

    ciphertext = bytearray()
    num_blocks = (len(data) + BLOCK_SIZE - 1) // BLOCK_SIZE

    for counter in range(num_blocks):
        # Build the 128-bit counter block: nonce (12 bytes) || counter (4 bytes, big-endian)
        counter_block = nonce + struct.pack('>I', counter)

        # Encrypt the counter block to produce keystream
        keystream = encrypt_block(counter_block, round_keys)

        # XOR keystream with plaintext chunk
        start = counter * BLOCK_SIZE
        end = min(start + BLOCK_SIZE, len(data))
        chunk = data[start:end]

        for i, byte in enumerate(chunk):
            ciphertext.append(byte ^ keystream[i])

    return bytes(ciphertext)


def ctr_decrypt(data: bytes, round_keys: list[list[int]], nonce: bytes) -> bytes:
    """Decrypt CTR-mode ciphertext.

    CTR mode is symmetric: encryption and decryption are the same operation.
    XOR with the same keystream undoes the previous XOR.
    """
    return ctr_encrypt(data, round_keys, nonce)
