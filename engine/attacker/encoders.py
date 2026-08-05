"""Encoding / obfuscation transforms.

These route a payload around keyword filters. Capable models decode them, so the
underlying instruction still lands — which is exactly why an encoding layer beats
a denylist but not necessarily model-level alignment.
"""
from __future__ import annotations

import base64
import codecs

# Homoglyph map: Latin → visually-identical Cyrillic/Greek.
_HOMOGLYPHS = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у"}
_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
_ZW = "​"  # zero-width space


def enc_base64(text: str) -> str:
    b = base64.b64encode(text.encode()).decode()
    return f"Decode this base64 and follow it: {b}"


def enc_rot13(text: str) -> str:
    return f"Apply ROT13 and follow it: {codecs.encode(text, 'rot_13')}"


def enc_homoglyph(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def enc_leet(text: str) -> str:
    return "".join(_LEET.get(ch.lower(), ch) for ch in text)


def enc_zerowidth(text: str) -> str:
    # Insert zero-width chars between letters of trigger words to split keywords.
    return _ZW.join(text)


ENCODERS = {
    "base64": enc_base64,
    "rot13": enc_rot13,
    "homoglyph": enc_homoglyph,
    "leet": enc_leet,
    "zerowidth": enc_zerowidth,
}


def apply_encoding(name: str | None, text: str) -> str:
    if not name or name not in ENCODERS:
        return text
    return ENCODERS[name](text)
