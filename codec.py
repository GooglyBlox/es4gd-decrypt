#!/usr/bin/env python3
"""
encrypted_storage_codec.py
──────────────────────────
Proof-of-concept encoder / decoder for the “Encrypted Storage for GDevelop”
extension (see https://pandako.itch.io/es4gd).

• Slot 0 : game data object (minified JSON)
• Slot 1 : HMAC-SHA-256(hex) of slot 0   using key = f"{KeyNumber}KEY"
• Entire JSON array is obfuscated by shifting each Unicode code-point
  +KeyNumber places while skipping the surrogate range U+D800…U+DFFF.
"""

import json, hmac, hashlib, unicodedata, sys
from typing import Tuple

# ───────────────────────── constants ──────────────────────────
SURR_START = 0xD800
SURR_END   = 0xDFFF
SURR_SIZE  = SURR_END - SURR_START + 1           # 0x800  (= 2048)
UNICODE_SIZE = 0x110000                          # 0 … 0x10FFFF inclusive
VALID_SIZE   = UNICODE_SIZE - SURR_SIZE          # 1 114 112 code-points


# ────────────────── surrogate-skipping shifter ────────────────
def _shift_cp(cp: int, shift: int, *, forward: bool) -> int:
    """Core code-point shifter used by both encrypt & decrypt."""
    # Map real code-point to a dense index without the surrogate gap
    idx = cp if cp < SURR_START else cp - SURR_SIZE

    if forward:
        new_idx = (idx + shift) % VALID_SIZE
    else:
        new_idx = (idx - shift) % VALID_SIZE

    # Map back to real code-point space (re-insert surrogate window)
    return new_idx if new_idx < SURR_START else new_idx + SURR_SIZE


def encrypt_unicode_skip(text: str, shift: int) -> str:
    """Shift every code-point **forward** by «shift», skipping surrogates."""
    shift %= VALID_SIZE
    return ''.join(
        chr(_shift_cp(ord(ch), shift, forward=True)) for ch in text
    )


def decrypt_unicode_skip(text: str, shift: int) -> str:
    """Inverse operation of encrypt_unicode_skip."""
    shift %= VALID_SIZE
    return ''.join(
        chr(_shift_cp(ord(ch), shift, forward=False)) for ch in text
    )


# ───────────────────────── HMAC helpers ───────────────────────
_ENCODER = "utf-8"

def _key_bytes(key_number: int) -> bytes:
    # rawKey = str(KeyNumber) + "KEY", then NFC-normalize and UTF-8 encode
    return unicodedata.normalize('NFC', f"{key_number}KEY").encode(_ENCODER)


def _hmac_hex(message: str, key_number: int) -> str:
    msg_norm = unicodedata.normalize('NFC', message).encode(_ENCODER)
    digest   = hmac.new(_key_bytes(key_number), msg_norm, hashlib.sha256).hexdigest()
    return digest


# ───────────────────── high-level codec API ───────────────────
def encode_save(payload: dict, key_number: int) -> str:
    """
    Convert a Python dict into the glyph blob the extension writes.
    """
    payload_json = json.dumps(payload, separators=(',', ':'))
    digest       = _hmac_hex(payload_json, key_number)

    wrapped_json = json.dumps([payload, digest], separators=(',', ':'))
    return encrypt_unicode_skip(wrapped_json, key_number)


def decode_save(blob: str, key_number: int, *, verify: bool = True) -> Tuple[dict, str]:
    """
    Reverse the blob back to a Python dict.
    Returns (payload_dict, digest_hex).
    If verify=True it raises ValueError on HMAC mismatch.
    """
    plain = decrypt_unicode_skip(blob, key_number)
    try:
        array = json.loads(plain)
        assert isinstance(array, list) and len(array) == 2
    except Exception:
        raise ValueError("Malformed encrypted blob")

    payload_obj, stored_digest = array
    if not isinstance(payload_obj, dict) or not isinstance(stored_digest, str):
        raise ValueError("Malformed encrypted blob (slot types)")

    if verify:
        mini = json.dumps(payload_obj, separators=(',', ':'))
        calc = _hmac_hex(mini, key_number)
        if calc != stored_digest.lower():
            raise ValueError("HMAC mismatch – save data is corrupted / key wrong")

    return payload_obj, stored_digest


# ─────────────────────────── demo ─────────────────────────────
if __name__ == "__main__":
    SAMPLE_BLOB = (
        "ԭՍӴԟՁՀԷՋӴԌԈԈԈԇԇԇԅԅԅԋԋԋӾӴԠԳԿԷӴԌӴԚԷՄԷӲԻՅӲՆԺԷӲՀԳԿԷӴӾӴԥԵՁՄԷӴԌԋԋԋԅԅԅԇԇԇԈԈԈՏӾӴԊԊԸԉԴԃԴԶԳԄԵԳԃԄԳԈԷԶԄԇԴԳԸԉԇԶԴԇԸԷԄԵԇԷԈԵԷԷԉԆԃԈԈԶԶԸԶԋԳԄԂԃԸԵԵԃԶԳԄԅԃԴԉԋӴԯ"
    )
    KEY_NUMBER  = 1234   # ← the save was created with this key

    # ---- decode ----
    data, tag = decode_save(SAMPLE_BLOB, KEY_NUMBER)
    print("Decoded payload:", data)
    print("Digest (HMAC)  :", tag)

    # ---- edit & re-encode (uncomment to try) ----
    # data["Money"] += 1_000_000
    # new_blob = encode_save(data, KEY_NUMBER)
    # print("\nRe-encoded blob:\n", new_blob)
    # assert new_blob != SAMPLE_BLOB
