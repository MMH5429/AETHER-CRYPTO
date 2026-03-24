"""
AETHER-CRYPTO: CLI Interface
===============================

Provides three commands:
  aether enc <file> --key <password>  — encrypt a file
  aether dec <file> --key <password>  — decrypt a file
  aether avalanche <text>             — run avalanche test

Encrypted file format:
  [AETH][v1][salt:16B][nonce:12B][hmac:32B][ciphertext]
  Total header: 65 bytes
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

from core.engine import ctr_encrypt, ctr_decrypt, encrypt_block, BLOCK_SIZE
from core.key_manager import (
    derive_master_key, expand_key,
    generate_salt, generate_nonce,
)
from services.signal import fetch_btc_price, get_enhanced_salt

app = typer.Typer(name="aether", help="AETHER-CRYPTO: 128-bit SPN cipher tool")
console = Console()

# File format constants
MAGIC = b"AETH"
VERSION = b"\x01"
HEADER_SIZE = 4 + 1 + 16 + 12 + 32  # 65 bytes


def _compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 for integrity verification.

    We use a separate HMAC key derived from the master key to prevent any
    interaction between the encryption key and the authentication key.
    The HMAC covers (nonce || ciphertext) so that both are authenticated.
    """
    # Derive a separate HMAC key from the master key
    hmac_key = hashlib.sha256(b"aether-hmac-key:" + key).digest()
    return hmac_mod.new(hmac_key, data, hashlib.sha256).digest()


@app.command()
def enc(
    file: Path = typer.Argument(..., help="File to encrypt"),
    key: str = typer.Option(..., "--key", "-k", prompt="Encryption password",
                            hide_input=True, help="Encryption password"),
    use_market_salt: bool = typer.Option(False, "--use-market-salt", "-m",
                                          help="Mix BTC price into salt"),
    output: Path | None = typer.Option(None, "--output", "-o",
                                        help="Output file path"),
):
    """Encrypt a file with AETHER-CRYPTO."""
    if not file.exists():
        console.print(f"[red]Error:[/red] File not found: {file}")
        raise typer.Exit(1)

    out_path = output or file.with_suffix(file.suffix + ".aeth")

    with console.status("[bold blue]Generating keys..."):
        # Generate random salt and nonce
        salt = generate_salt()
        nonce = generate_nonce()

        # Optionally enhance salt with market data
        if use_market_salt:
            console.print("[dim]Fetching BTC price for salt enhancement...[/dim]")
            btc_price = fetch_btc_price()
            if btc_price is not None:
                console.print(f"[dim]BTC price: ${btc_price:,.2f}[/dim]")
            else:
                console.print("[yellow]Warning:[/yellow] Could not fetch BTC price, using random salt only")
            salt = get_enhanced_salt(salt, btc_price)

        # Derive master key and expand to round keys
        master_key = derive_master_key(key, salt)
        round_keys = expand_key(master_key)

    # Read plaintext
    plaintext = file.read_bytes()
    file_size = len(plaintext)

    # Encrypt with progress bar for large files
    if file_size > 1024 * 1024:  # > 1MB: show progress
        with Progress(
            TextColumn("[bold blue]Encrypting..."),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Encrypting", total=file_size)
            ciphertext = bytearray()
            chunk_size = 64 * 1024  # 64KB chunks for progress reporting
            for i in range(0, file_size, chunk_size):
                chunk = plaintext[i:i + chunk_size]
                # For CTR mode, we need to process from the correct counter offset
                # So we encrypt the whole thing at once and just report progress
                progress.update(task, advance=len(chunk))
            ciphertext = ctr_encrypt(plaintext, round_keys, nonce)
    else:
        ciphertext = ctr_encrypt(plaintext, round_keys, nonce)

    # Compute HMAC over (nonce || ciphertext)
    hmac_value = _compute_hmac(master_key, nonce + ciphertext)

    # Write output file: [MAGIC][VERSION][SALT][NONCE][HMAC][CIPHERTEXT]
    with open(out_path, "wb") as f:
        f.write(MAGIC)
        f.write(VERSION)
        f.write(salt)
        f.write(nonce)
        f.write(hmac_value)
        f.write(ciphertext)

    console.print(f"[green]Encrypted:[/green] {file} -> {out_path}")
    console.print(f"[dim]  Size: {file_size:,} -> {os.path.getsize(out_path):,} bytes[/dim]")


@app.command()
def dec(
    file: Path = typer.Argument(..., help="File to decrypt (.aeth)"),
    key: str = typer.Option(..., "--key", "-k", prompt="Decryption password",
                            hide_input=True, help="Decryption password"),
    output: Path | None = typer.Option(None, "--output", "-o",
                                        help="Output file path"),
):
    """Decrypt an AETHER-CRYPTO encrypted file."""
    if not file.exists():
        console.print(f"[red]Error:[/red] File not found: {file}")
        raise typer.Exit(1)

    raw = file.read_bytes()
    if len(raw) < HEADER_SIZE:
        console.print("[red]Error:[/red] File too small to be an AETHER file")
        raise typer.Exit(1)

    # Parse header
    magic = raw[0:4]
    version = raw[4:5]
    salt = raw[5:21]
    nonce = raw[21:33]
    stored_hmac = raw[33:65]
    ciphertext = raw[65:]

    if magic != MAGIC:
        console.print("[red]Error:[/red] Not an AETHER encrypted file (bad magic bytes)")
        raise typer.Exit(1)
    if version != VERSION:
        console.print(f"[red]Error:[/red] Unsupported version: {version.hex()}")
        raise typer.Exit(1)

    with console.status("[bold blue]Deriving keys..."):
        master_key = derive_master_key(key, salt)
        round_keys = expand_key(master_key)

    # Verify HMAC BEFORE decryption — reject tampered files without wasting time
    computed_hmac = _compute_hmac(master_key, nonce + ciphertext)
    if not hmac_mod.compare_digest(stored_hmac, computed_hmac):
        console.print("[red]Error:[/red] HMAC verification failed!")
        console.print("[dim]  The password is wrong or the file has been tampered with.[/dim]")
        raise typer.Exit(1)

    # Decrypt
    plaintext = ctr_decrypt(ciphertext, round_keys, nonce)

    # Determine output path
    if output:
        out_path = output
    else:
        name = str(file)
        if name.endswith(".aeth"):
            out_path = Path(name[:-5])
        else:
            out_path = file.with_suffix(".dec")

    out_path.write_bytes(plaintext)
    console.print(f"[green]Decrypted:[/green] {file} -> {out_path}")
    console.print(f"[dim]  Size: {len(ciphertext):,} -> {len(plaintext):,} bytes[/dim]")


@app.command()
def avalanche(
    text: str = typer.Argument(..., help="Text to test avalanche effect"),
):
    """Run avalanche test: flip each bit of the input and show how many output bits change.

    A good cipher should change ~50% of output bits when a single input bit
    is flipped. This is the "avalanche effect" — small changes cascade into
    large, unpredictable differences.
    """
    from core.key_manager import expand_key

    # Use a fixed test key so results are reproducible
    test_key = bytes(range(32))
    round_keys = expand_key(test_key)

    # Pad or truncate input to 16 bytes
    input_bytes = text.encode('utf-8')[:16].ljust(16, b'\x00')

    # Encrypt the original
    original_ct = encrypt_block(input_bytes, round_keys)
    original_bits = int.from_bytes(original_ct, 'big')

    total_flips = 0
    num_tests = 128  # Test all 128 input bits

    console.print(f"\n[bold]Avalanche Test for:[/bold] {text!r}")
    console.print(f"[dim]Input (padded): {input_bytes.hex()}[/dim]")
    console.print(f"[dim]Output:         {original_ct.hex()}[/dim]\n")

    bit_changes = []
    for bit_pos in range(128):
        # Flip one bit in the input
        flipped = bytearray(input_bytes)
        byte_idx = bit_pos // 8
        bit_idx = bit_pos % 8
        flipped[byte_idx] ^= (1 << bit_idx)

        # Encrypt with the flipped input
        flipped_ct = encrypt_block(bytes(flipped), round_keys)
        flipped_bits = int.from_bytes(flipped_ct, 'big')

        # Count differing bits
        diff = original_bits ^ flipped_bits
        changed = bin(diff).count('1')
        bit_changes.append(changed)
        total_flips += changed

    avg_change = total_flips / num_tests
    avg_pct = (avg_change / 128) * 100
    min_change = min(bit_changes)
    max_change = max(bit_changes)
    min_pct = (min_change / 128) * 100
    max_pct = (max_change / 128) * 100

    console.print(f"[bold]Results (128 single-bit flips):[/bold]")
    console.print(f"  Average bits changed: {avg_change:.1f} / 128 ({avg_pct:.1f}%)")
    console.print(f"  Min bits changed:     {min_change} / 128 ({min_pct:.1f}%)")
    console.print(f"  Max bits changed:     {max_change} / 128 ({max_pct:.1f}%)")

    if avg_pct >= 45:
        console.print(f"\n[green]PASS: Good avalanche effect![/green] (>= 45% average)")
    else:
        console.print(f"\n[red]FAIL: Poor avalanche effect[/red] ({avg_pct:.1f}% < 45%)")


def main():
    app()


if __name__ == "__main__":
    main()
