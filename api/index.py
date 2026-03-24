"""
AETHER-CRYPTO: Vercel Serverless Entry Point
==============================================
Flask app adapted for Vercel's serverless Python runtime.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import io
import os
import sys
from pathlib import Path

# Ensure core modules are importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, request, send_file, jsonify, Response

from core.engine import ctr_encrypt, ctr_decrypt
from core.key_manager import derive_master_key, expand_key, generate_salt, generate_nonce
from services.signal import fetch_btc_price, get_enhanced_salt

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max (Vercel limit)

# File format constants
MAGIC = b"AETH"
VERSION = b"\x01"
HEADER_SIZE = 65

# Read the HTML template once at import time
TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "web" / "templates" / "index.html"
HTML_CONTENT = TEMPLATE_PATH.read_text(encoding="utf-8")


def _compute_hmac(key: bytes, data: bytes) -> bytes:
    hmac_key = hashlib.sha256(b"aether-hmac-key:" + key).digest()
    return hmac_mod.new(hmac_key, data, hashlib.sha256).digest()


@app.route("/")
def index():
    return Response(HTML_CONTENT, mimetype="text/html")


@app.route("/encrypt", methods=["POST"])
def encrypt():
    file = request.files.get("file")
    password = request.form.get("password", "")
    use_market = request.form.get("use_market_salt") == "true"

    if not file or not file.filename:
        return jsonify({"error": "No file selected"}), 400
    if not password:
        return jsonify({"error": "Password is required"}), 400

    try:
        plaintext = file.read()
        original_name = file.filename

        # Generate salt and nonce
        salt = generate_salt()
        nonce = generate_nonce()

        # Optional market enhancement
        if use_market:
            btc_price = fetch_btc_price()
            if btc_price is not None:
                salt = get_enhanced_salt(salt, btc_price)

        # Derive keys and encrypt
        master_key = derive_master_key(password, salt)
        round_keys = expand_key(master_key)
        ciphertext = ctr_encrypt(plaintext, round_keys, nonce)

        # Compute HMAC
        hmac_value = _compute_hmac(master_key, nonce + ciphertext)

        # Build .aeth file in memory
        output = io.BytesIO()
        output.write(MAGIC)
        output.write(VERSION)
        output.write(salt)
        output.write(nonce)
        output.write(hmac_value)
        output.write(ciphertext)
        output.seek(0)

        return send_file(
            output,
            as_attachment=True,
            download_name=f"{original_name}.aeth",
            mimetype="application/octet-stream",
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files.get("file")
    password = request.form.get("password", "")

    if not file or not file.filename:
        return jsonify({"error": "No file selected"}), 400
    if not password:
        return jsonify({"error": "Password is required"}), 400

    try:
        raw = file.read()
        original_name = file.filename

        if len(raw) < HEADER_SIZE:
            return jsonify({"error": "File too small to be an AETHER file"}), 400

        # Parse header
        magic = raw[0:4]
        version = raw[4:5]
        salt = raw[5:21]
        nonce = raw[21:33]
        stored_hmac = raw[33:65]
        ciphertext = raw[65:]

        if magic != MAGIC:
            return jsonify({"error": "Not an AETHER encrypted file (bad magic bytes)"}), 400
        if version != VERSION:
            return jsonify({"error": f"Unsupported version: {version.hex()}"}), 400

        # Derive keys
        master_key = derive_master_key(password, salt)
        round_keys = expand_key(master_key)

        # Verify HMAC before decryption
        computed_hmac = _compute_hmac(master_key, nonce + ciphertext)
        if not hmac_mod.compare_digest(stored_hmac, computed_hmac):
            return jsonify({
                "error": "HMAC verification failed! The password is wrong or the file has been tampered with."
            }), 403

        # Decrypt
        plaintext = ctr_decrypt(ciphertext, round_keys, nonce)

        # Determine output filename
        out_name = original_name
        if out_name.endswith(".aeth"):
            out_name = out_name[:-5]

        output = io.BytesIO(plaintext)

        return send_file(
            output,
            as_attachment=True,
            download_name=out_name,
            mimetype="application/octet-stream",
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
