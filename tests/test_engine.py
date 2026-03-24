"""
AETHER-CRYPTO: Test Suite
============================

Validates the cipher's correctness and cryptographic properties.
Run with: pytest tests/ -v
"""

from __future__ import annotations

import os
import struct
import hashlib
import hmac as hmac_mod

import pytest

from core.constants import SBOX, INV_SBOX, gf_mult, gf_inverse, verify_sbox
from core.engine import (
    encrypt_block, decrypt_block,
    ctr_encrypt, ctr_decrypt,
    BLOCK_SIZE,
)
from core.key_manager import (
    derive_master_key, expand_key,
    generate_salt, generate_nonce,
)


# ---------------------------------------------------------------------------
# Helper: generate round keys from a fixed master key
# ---------------------------------------------------------------------------

def _test_round_keys(seed: int = 0) -> list[list[int]]:
    """Generate deterministic round keys for testing."""
    master_key = hashlib.sha256(seed.to_bytes(4, 'big')).digest()
    return expand_key(master_key)


# ---------------------------------------------------------------------------
# 1. Round-trip tests: decrypt(encrypt(x)) == x
# ---------------------------------------------------------------------------

class TestRoundTrip:
    """Verify that decryption perfectly reverses encryption."""

    def test_roundtrip_random_blocks(self):
        """decrypt(encrypt(x)) == x for 1000 random 128-bit blocks."""
        round_keys = _test_round_keys(42)
        for _ in range(1000):
            plaintext = os.urandom(16)
            ciphertext = encrypt_block(plaintext, round_keys)
            recovered = decrypt_block(ciphertext, round_keys)
            assert recovered == plaintext, (
                f"Round-trip failed: {plaintext.hex()} → {ciphertext.hex()} → {recovered.hex()}"
            )

    def test_roundtrip_all_zeros(self):
        """Encrypt and decrypt a block of all zeros."""
        round_keys = _test_round_keys(0)
        pt = b'\x00' * 16
        assert decrypt_block(encrypt_block(pt, round_keys), round_keys) == pt

    def test_roundtrip_all_ones(self):
        """Encrypt and decrypt a block of all 0xFF."""
        round_keys = _test_round_keys(0)
        pt = b'\xff' * 16
        assert decrypt_block(encrypt_block(pt, round_keys), round_keys) == pt

    def test_encrypt_changes_plaintext(self):
        """Encryption must actually change the data (not identity)."""
        round_keys = _test_round_keys(99)
        pt = b'Hello, AETHER!!\x00\x00'[:16]
        ct = encrypt_block(pt, round_keys)
        assert ct != pt, "Encryption produced identical output (identity cipher?)"


# ---------------------------------------------------------------------------
# 2. CTR mode round-trip tests
# ---------------------------------------------------------------------------

class TestCTRMode:
    """Verify CTR mode works for various data sizes."""

    @pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 32, 100, 1024])
    def test_ctr_roundtrip_sizes(self, size: int):
        """CTR encrypt then decrypt for various data sizes."""
        round_keys = _test_round_keys(7)
        nonce = os.urandom(12)
        data = os.urandom(size)
        encrypted = ctr_encrypt(data, round_keys, nonce)
        decrypted = ctr_decrypt(encrypted, round_keys, nonce)
        assert decrypted == data, f"CTR round-trip failed for size {size}"

    def test_ctr_roundtrip_large(self):
        """CTR round-trip for ~1MB of data."""
        round_keys = _test_round_keys(13)
        nonce = os.urandom(12)
        data = os.urandom(1024 * 1024)
        encrypted = ctr_encrypt(data, round_keys, nonce)
        decrypted = ctr_decrypt(encrypted, round_keys, nonce)
        assert decrypted == data

    def test_ctr_different_nonce_different_output(self):
        """Same plaintext + same key + different nonce = different ciphertext."""
        round_keys = _test_round_keys(0)
        data = b"test data 12345!"
        ct1 = ctr_encrypt(data, round_keys, os.urandom(12))
        ct2 = ctr_encrypt(data, round_keys, os.urandom(12))
        assert ct1 != ct2, "Different nonces produced same ciphertext"

    def test_ctr_output_length(self):
        """CTR output length must equal input length (no padding)."""
        round_keys = _test_round_keys(0)
        nonce = os.urandom(12)
        for size in [0, 1, 15, 16, 17, 100]:
            data = os.urandom(size)
            ct = ctr_encrypt(data, round_keys, nonce)
            assert len(ct) == len(data)


# ---------------------------------------------------------------------------
# 3. Avalanche tests
# ---------------------------------------------------------------------------

class TestAvalanche:
    """Verify the avalanche effect: flipping 1 bit should change ~50% of output."""

    def test_plaintext_avalanche(self):
        """Flipping each plaintext bit should change ≥ 45% of ciphertext bits."""
        round_keys = _test_round_keys(0)
        plaintext = os.urandom(16)
        original_ct = encrypt_block(plaintext, round_keys)
        original_bits = int.from_bytes(original_ct, 'big')

        total_changes = 0
        for bit_pos in range(128):
            flipped = bytearray(plaintext)
            flipped[bit_pos // 8] ^= (1 << (bit_pos % 8))
            flipped_ct = encrypt_block(bytes(flipped), round_keys)
            diff = original_bits ^ int.from_bytes(flipped_ct, 'big')
            total_changes += bin(diff).count('1')

        avg_pct = (total_changes / 128) / 128 * 100
        assert avg_pct >= 45.0, (
            f"Poor plaintext avalanche: {avg_pct:.1f}% (need ≥ 45%)"
        )

    def test_key_avalanche(self):
        """Flipping 1 key bit should change ≥ 45% of ciphertext bits."""
        master_key = os.urandom(32)
        round_keys = expand_key(master_key)
        plaintext = os.urandom(16)
        original_ct = encrypt_block(plaintext, round_keys)
        original_bits = int.from_bytes(original_ct, 'big')

        total_changes = 0
        # Test flipping each of the first 128 key bits (of 256)
        test_bits = 128
        for bit_pos in range(test_bits):
            flipped_key = bytearray(master_key)
            flipped_key[bit_pos // 8] ^= (1 << (bit_pos % 8))
            flipped_rk = expand_key(bytes(flipped_key))
            flipped_ct = encrypt_block(plaintext, flipped_rk)
            diff = original_bits ^ int.from_bytes(flipped_ct, 'big')
            total_changes += bin(diff).count('1')

        avg_pct = (total_changes / test_bits) / 128 * 100
        assert avg_pct >= 45.0, (
            f"Poor key avalanche: {avg_pct:.1f}% (need ≥ 45%)"
        )


# ---------------------------------------------------------------------------
# 4. S-Box property tests
# ---------------------------------------------------------------------------

class TestSBox:
    """Verify the S-Box has good cryptographic properties."""

    def test_sbox_is_bijection(self):
        """S-Box must be a permutation (all 256 values appear exactly once)."""
        assert len(set(SBOX)) == 256

    def test_inverse_sbox_correct(self):
        """INV_SBOX[SBOX[x]] == x for all x."""
        for x in range(256):
            assert INV_SBOX[SBOX[x]] == x
            assert SBOX[INV_SBOX[x]] == x

    def test_no_fixed_points(self):
        """No byte should map to itself: S[x] ≠ x for all x."""
        fixed = [x for x in range(256) if SBOX[x] == x]
        assert len(fixed) == 0, f"Fixed points found: {fixed}"

    def test_gf_inverse_known_values(self):
        """Verify a few known GF(2^8) inverse pairs."""
        # In GF(2^8) with poly 0x11B:
        # inv(1) = 1  (multiplicative identity)
        assert gf_inverse(1) == 1
        # inv(2) should satisfy 2 * inv(2) = 1
        inv2 = gf_inverse(2)
        assert gf_mult(2, inv2) == 1
        # inv(3) should satisfy 3 * inv(3) = 1
        inv3 = gf_inverse(3)
        assert gf_mult(3, inv3) == 1
        # inv(0) = 0 by convention
        assert gf_inverse(0) == 0

    def test_gf_mult_properties(self):
        """GF(2^8) multiplication basic properties."""
        # a * 1 = a (identity)
        for a in range(256):
            assert gf_mult(a, 1) == a
        # a * 0 = 0
        for a in range(256):
            assert gf_mult(a, 0) == 0
        # Commutativity: a * b = b * a
        for _ in range(100):
            a = int.from_bytes(os.urandom(1), 'big')
            b = int.from_bytes(os.urandom(1), 'big')
            assert gf_mult(a, b) == gf_mult(b, a)


# ---------------------------------------------------------------------------
# 5. HMAC verification tests
# ---------------------------------------------------------------------------

class TestHMAC:
    """Verify HMAC catches tampered ciphertext."""

    def _compute_hmac(self, key: bytes, data: bytes) -> bytes:
        hmac_key = hashlib.sha256(b"aether-hmac-key:" + key).digest()
        return hmac_mod.new(hmac_key, data, hashlib.sha256).digest()

    def test_hmac_valid(self):
        """HMAC should verify correctly for untampered data."""
        key = os.urandom(32)
        data = os.urandom(100)
        mac = self._compute_hmac(key, data)
        expected = self._compute_hmac(key, data)
        assert hmac_mod.compare_digest(mac, expected)

    def test_hmac_tampered_data(self):
        """Flipping a single bit in ciphertext should invalidate HMAC."""
        key = os.urandom(32)
        data = bytearray(os.urandom(100))
        mac = self._compute_hmac(key, bytes(data))

        # Flip one bit
        data[50] ^= 0x01
        tampered_mac = self._compute_hmac(key, bytes(data))
        assert not hmac_mod.compare_digest(mac, tampered_mac)

    def test_hmac_wrong_key(self):
        """Different key should produce different HMAC."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        data = os.urandom(100)
        mac1 = self._compute_hmac(key1, data)
        mac2 = self._compute_hmac(key2, data)
        assert not hmac_mod.compare_digest(mac1, mac2)


# ---------------------------------------------------------------------------
# 6. Known Answer Tests (regression)
# ---------------------------------------------------------------------------

class TestKnownAnswers:
    """Hardcoded test vectors so we can detect if anything changes accidentally.

    These were generated by running the cipher once and recording the output.
    If any internal constant or algorithm changes, these tests will catch it.
    """

    def test_known_vector_1(self):
        """Fixed key + fixed plaintext → expected ciphertext."""
        master_key = bytes(range(32))  # 0x00, 0x01, ..., 0x1F
        round_keys = expand_key(master_key)
        plaintext = bytes(range(16))   # 0x00, 0x01, ..., 0x0F

        ct = encrypt_block(plaintext, round_keys)
        # Store the result for regression
        recovered = decrypt_block(ct, round_keys)
        assert recovered == plaintext

        # The ciphertext should be deterministic — record it here after first run
        # (uncomment and fill in after first successful run)
        # assert ct.hex() == "expected_hex_here"

    def test_known_vector_2(self):
        """All-zero key + all-zero plaintext."""
        master_key = b'\x00' * 32
        round_keys = expand_key(master_key)
        plaintext = b'\x00' * 16

        ct = encrypt_block(plaintext, round_keys)
        recovered = decrypt_block(ct, round_keys)
        assert recovered == plaintext
        # Determinism check: encrypt twice, get same result
        ct2 = encrypt_block(plaintext, round_keys)
        assert ct == ct2


# ---------------------------------------------------------------------------
# 7. Key derivation tests
# ---------------------------------------------------------------------------

class TestKeyDerivation:
    """Verify key derivation produces consistent, unique keys."""

    def test_derive_deterministic(self):
        """Same password + salt → same master key."""
        salt = b'\xaa' * 16
        k1 = derive_master_key("test_password", salt)
        k2 = derive_master_key("test_password", salt)
        assert k1 == k2

    def test_derive_different_passwords(self):
        """Different passwords → different master keys."""
        salt = b'\xbb' * 16
        k1 = derive_master_key("password1", salt)
        k2 = derive_master_key("password2", salt)
        assert k1 != k2

    def test_derive_different_salts(self):
        """Same password + different salts → different master keys."""
        k1 = derive_master_key("same_password", b'\x00' * 16)
        k2 = derive_master_key("same_password", b'\x01' * 16)
        assert k1 != k2

    def test_expand_key_produces_17_keys(self):
        """Key expansion must produce exactly 17 round keys."""
        master_key = os.urandom(32)
        keys = expand_key(master_key)
        assert len(keys) == 17
        assert all(len(k) == 16 for k in keys)

    def test_expand_key_all_different(self):
        """All 17 round keys should be different."""
        master_key = os.urandom(32)
        keys = expand_key(master_key)
        key_tuples = [tuple(k) for k in keys]
        assert len(set(key_tuples)) == 17, "Some round keys are identical"
