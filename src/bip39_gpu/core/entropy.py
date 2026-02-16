"""Cryptographic entropy generation for BIP39."""

import secrets
from typing import Literal
from ..utils.exceptions import InvalidEntropyError


# BIP39 standard: entropy length must be 128-256 bits in steps of 32 bits
VALID_ENTROPY_BITS = {128, 160, 192, 224, 256}

# Word count to entropy bits mapping
WORDS_TO_ENTROPY_BITS = {
    12: 128,  # 128 bits entropy + 4 bits checksum = 132 bits = 12 words * 11 bits
    15: 160,  # 160 bits entropy + 5 bits checksum = 165 bits = 15 words * 11 bits
    18: 192,  # 192 bits entropy + 6 bits checksum = 198 bits = 18 words * 11 bits
    21: 224,  # 224 bits entropy + 7 bits checksum = 231 bits = 21 words * 11 bits
    24: 256,  # 256 bits entropy + 8 bits checksum = 264 bits = 24 words * 11 bits
}

EntropyBits = Literal[128, 160, 192, 224, 256]
WordCount = Literal[12, 15, 18, 21, 24]


def generate_entropy(bits: EntropyBits = 128) -> bytes:
    """Generate cryptographically secure random entropy.

    Uses Python's secrets module which is designed for cryptographic purposes.

    Args:
        bits: Number of entropy bits (128, 160, 192, 224, or 256)

    Returns:
        Random entropy bytes

    Raises:
        InvalidEntropyError: If bits value is not valid

    Example:
        >>> entropy = generate_entropy(128)  # 16 bytes
        >>> len(entropy)
        16
    """
    if bits not in VALID_ENTROPY_BITS:
        raise InvalidEntropyError(
            f"Invalid entropy bits: {bits}. "
            f"Must be one of {sorted(VALID_ENTROPY_BITS)}"
        )

    byte_count = bits // 8
    return secrets.token_bytes(byte_count)


def validate_entropy(entropy: bytes) -> None:
    """Validate entropy length.

    Args:
        entropy: Entropy bytes to validate

    Raises:
        InvalidEntropyError: If entropy length is invalid
    """
    bits = len(entropy) * 8

    if bits not in VALID_ENTROPY_BITS:
        raise InvalidEntropyError(
            f"Invalid entropy length: {len(entropy)} bytes ({bits} bits). "
            f"Must be one of {sorted([b // 8 for b in VALID_ENTROPY_BITS])} bytes "
            f"({sorted(VALID_ENTROPY_BITS)} bits)"
        )


def words_to_entropy_bits(words: int) -> int:
    """Convert word count to entropy bits.

    Args:
        words: Number of words (12, 15, 18, 21, or 24)

    Returns:
        Entropy bits

    Raises:
        InvalidEntropyError: If word count is invalid
    """
    if words not in WORDS_TO_ENTROPY_BITS:
        raise InvalidEntropyError(
            f"Invalid word count: {words}. "
            f"Must be one of {sorted(WORDS_TO_ENTROPY_BITS.keys())}"
        )

    return WORDS_TO_ENTROPY_BITS[words]


def entropy_bits_to_words(bits: int) -> int:
    """Convert entropy bits to word count.

    Args:
        bits: Entropy bits (128, 160, 192, 224, or 256)

    Returns:
        Number of words

    Raises:
        InvalidEntropyError: If entropy bits are invalid
    """
    if bits not in VALID_ENTROPY_BITS:
        raise InvalidEntropyError(
            f"Invalid entropy bits: {bits}. "
            f"Must be one of {sorted(VALID_ENTROPY_BITS)}"
        )

    # Reverse lookup in WORDS_TO_ENTROPY_BITS
    for words, entropy_bits in WORDS_TO_ENTROPY_BITS.items():
        if entropy_bits == bits:
            return words

    raise InvalidEntropyError(f"Cannot convert {bits} bits to word count")
