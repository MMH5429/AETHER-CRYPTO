# AETHER-CRYPTO

A custom 128-bit SPN (Substitution-Permutation Network) block cipher built entirely from scratch. This is a **learning-first** project — every component (S-Box, MDS matrix, key schedule) is derived from raw math with detailed comments explaining the cryptographic reasoning.

> **Disclaimer**: This is an educational cipher. For production use, stick with AES-256-GCM or ChaCha20-Poly1305.

---

## How It Works

```
Password
   |
   v
Argon2id (64MB, 3 iter)  +  Salt (16B random, optionally BTC-enhanced)
   |
   v
256-bit Master Key
   |
   v
Key Schedule --> 17 x 128-bit Round Keys
   |
   v
16-Round SPN Cipher (CTR Mode)
   |
   +-- SubBytes    (GF(2^8) inverse + affine transform)
   +-- ShiftRows   (row-wise byte rotation)
   +-- MixColumns  (4x4 MDS matrix, branch number = 5)
   +-- AddRoundKey (XOR with round key)
   |
   v
Ciphertext + HMAC-SHA256 integrity tag
```

### Encrypted File Format

```
Offset  Size   Field
0       4      Magic bytes: b"AETH"
4       1      Version: 0x01
5       16     Salt
21      12     Nonce
33      32     HMAC-SHA256(key, nonce || ciphertext)
65      var    Ciphertext
```

---

## Installation

```bash
git clone https://github.com/MMH5429/AETHER-CRYPTO.git
cd AETHER-CRYPTO
pip install -r requirements.txt
```

## Usage

### Encrypt a file

```bash
python -m cli.main enc <file> --key "your-password"
```

Options:
- `-o / --output` — custom output path
- `-m / --use-market-salt` — mix live BTC price into the salt for extra entropy

```bash
# Example
python -m cli.main enc secret.docx --key "strongpassword"
# Output: secret.docx.aeth

# With market salt
python -m cli.main enc secret.docx --key "strongpassword" --use-market-salt
```

### Decrypt a file

```bash
python -m cli.main dec <file>.aeth --key "your-password"
```

```bash
# Example
python -m cli.main dec secret.docx.aeth --key "strongpassword"
# Output: secret.docx
```

Wrong password or tampered file? HMAC catches it immediately:

```
Error: HMAC verification failed!
  The password is wrong or the file has been tampered with.
```

### Avalanche test

Visualize the avalanche effect — flip each input bit and measure how many output bits change (ideal: ~50%).

```bash
python -m cli.main avalanche "Hello World"
```

```
Avalanche Test for: 'Hello World'
Input (padded): 48656c6c6f20576f726c640000000000
Output:         b27b4933d45a9cf4a4114b1f10895e52

Results (128 single-bit flips):
  Average bits changed: 63.9 / 128 (49.9%)
  Min bits changed:     47 / 128 (36.7%)
  Max bits changed:     78 / 128 (60.9%)

PASS: Good avalanche effect! (>= 45% average)
```

---

## Architecture

```
AETHER-CRYPTO/
|-- core/
|   |-- constants.py    # S-Box, MDS matrix, P-Box, round constants (all from scratch)
|   |-- engine.py       # 16-round SPN cipher + CTR mode
|   |-- key_manager.py  # Argon2id KDF + key schedule
|-- services/
|   |-- signal.py       # Optional BTC price salt enhancement
|-- cli/
|   |-- main.py         # Typer CLI (enc / dec / avalanche)
|-- tests/
|   |-- test_engine.py  # 33 tests covering all crypto properties
|-- requirements.txt
```

### What's built from scratch

| Component | How it's built | Why it matters |
|---|---|---|
| **S-Box** | GF(2^8) multiplicative inverse + affine transform (constant 0x03) | Confusion — makes key-ciphertext relationship complex |
| **Inverse S-Box** | Reversed lookup table | Required for decryption |
| **MDS Matrix** | 4x4 Cauchy matrix over GF(2^8) with branch number 5 | Diffusion — 1 byte change affects all 4 column bytes |
| **P-Box** | 128-bit transpose permutation | Spreads each S-Box output across all S-Boxes |
| **Round Constants** | Fractional parts of sqrt/cbrt of first 16 primes | Nothing-up-my-sleeve: publicly verifiable, no backdoors |
| **Key Schedule** | XOR + rotation + S-Box substitution + half-mixing | Prevents related-key attacks |

---

## Security Properties

| Property | Target | Achieved |
|---|---|---|
| S-Box bijection | All 256 values unique | Yes |
| Fixed points | 0 | 0 |
| Plaintext avalanche | >= 45% | ~49.9% |
| Key avalanche | >= 45% | ~49.9% |
| MDS branch number | 5 (maximum) | 5 |
| HMAC integrity | Detect any tampering | Yes |
| KDF memory-hardness | Resist GPU brute-force | Argon2id, 64MB |
| Block size | 128 bits | 128 bits |
| Key size | 256 bits | 256 bits |
| Rounds | 16 | 16 |

---

## Testing

```bash
pytest tests/ -v
```

33 tests covering:
- **Round-trip**: encrypt then decrypt 1000 random blocks
- **CTR mode**: sizes from 0 bytes to 1 MB
- **Avalanche**: single-bit input/key changes flip ~50% of output bits
- **S-Box**: bijection, no fixed points, GF(2^8) inverse correctness
- **HMAC**: tampered data and wrong keys are rejected
- **Key derivation**: determinism, uniqueness, 17 distinct round keys
- **Known answer tests**: regression vectors

---

## Dependencies

| Package | Purpose |
|---|---|
| `typer` | CLI framework |
| `rich` | Progress bars and formatted output |
| `argon2-cffi` | Argon2id key derivation |
| `httpx` | BTC price fetching (optional feature) |
| `pytest` | Test suite |

---

## How the BTC salt enhancement works

When you pass `--use-market-salt`, the current Bitcoin price is fetched from CoinGecko and mixed into the random salt via XOR. This adds environmental entropy — the salt depends on real-world state at encryption time.

- The random salt is **always** the primary entropy source
- BTC data is **bonus** entropy, never required
- The final salt (enhanced or not) is stored in the file header
- **Decryption never calls any API** — it reads the salt from the header

---

## License

MIT
