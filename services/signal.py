"""
AETHER-CRYPTO: Market Data Signal
====================================

Optional enhancement that mixes Bitcoin price data into the encryption salt.
This adds a layer of environmental entropy — the salt depends not just on
random bytes but also on real-world state at the time of encryption.

IMPORTANT DESIGN DECISIONS:
- This is NEVER required for decryption. The salt (possibly enhanced) is stored
  in the file header. Decryption reads it directly — no API calls.
- If the API fails for any reason, encryption falls back to a pure random salt.
  The file is still perfectly secure.
- The BTC price is deterministically converted to bytes so that the same price
  always produces the same enhancement (important for reproducibility during
  the same session).
"""

from __future__ import annotations

import hashlib
import logging
import struct

import httpx

logger = logging.getLogger(__name__)

# CoinGecko public API — no API key needed
COINGECKO_URL = "https://api.coingecko.com/api/v3/simple/price"
COINGECKO_PARAMS = {"ids": "bitcoin", "vs_currencies": "usd"}
REQUEST_TIMEOUT = 10.0  # seconds


def fetch_btc_price() -> float | None:
    """Fetch the current BTC/USD price from CoinGecko.

    Returns:
        The price as a float, or None if the request fails.
    """
    try:
        response = httpx.get(
            COINGECKO_URL,
            params=COINGECKO_PARAMS,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        price = data["bitcoin"]["usd"]
        logger.info(f"Fetched BTC price: ${price:,.2f}")
        return float(price)
    except (httpx.HTTPError, KeyError, ValueError, TypeError) as e:
        logger.warning(f"Failed to fetch BTC price: {e}")
        return None


def price_to_salt_input(price: float) -> bytes:
    """Convert a BTC price to a deterministic 16-byte value.

    Process:
    1. Convert the price to a fixed-point integer (multiply by 100 to preserve
       cents, then truncate). This avoids floating-point representation issues.
    2. Pack as a big-endian 8-byte integer.
    3. SHA-256 hash the result — this spreads the bits uniformly across all 32
       bytes (a small price change flips ~50% of hash bits).
    4. Take the first 16 bytes (we only need 128 bits for XOR with the salt).

    Args:
        price: BTC price in USD (e.g., 67432.15)

    Returns:
        16 bytes derived from the price
    """
    # Fixed-point: multiply by 100 to keep cents, convert to integer
    price_cents = int(price * 100)
    # Pack as big-endian unsigned 64-bit
    price_bytes = struct.pack('>Q', price_cents)
    # Hash for uniform distribution
    digest = hashlib.sha256(price_bytes).digest()
    # Return first 16 bytes
    return digest[:16]


def get_enhanced_salt(random_salt: bytes, btc_price: float | None = None) -> bytes:
    """Produce a salt, optionally enhanced with BTC price data.

    If a BTC price is provided, it's mixed into the random salt via XOR.
    If not (None), the random salt is returned unchanged.

    This function does NOT call any APIs — it expects the price to be
    pre-fetched (or None). This keeps the enhancement logic pure.

    Args:
        random_salt: 16 cryptographically random bytes
        btc_price: optional BTC/USD price

    Returns:
        16-byte salt (enhanced if price provided, random otherwise)
    """
    if btc_price is None:
        return random_salt

    btc_input = price_to_salt_input(btc_price)
    enhanced = bytes(a ^ b for a, b in zip(random_salt, btc_input))
    logger.info("Salt enhanced with BTC market data")
    return enhanced
