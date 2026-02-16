"""Checksum calculation for BIP39 mnemonics."""

import hashlib
from typing import Union


def calculate_checksum(entropy: bytes) -> int:
    """Calculate BIP39 checksum for entropy.

    The checksum is the first N bits of SHA256(entropy), where:
    - N = entropy_bits / 32
    - For 128 bits entropy: 4 bits checksum
    - For 160 bits entropy: 5 bits checksum
    - For 192 bits entropy: 6 bits checksum
    - For 224 bits entropy: 7 bits checksum
    - For 256 bits entropy: 8 bits checksum

    Args:
        entropy: Entropy bytes

    Returns:
        Checksum as integer (first N bits of SHA256)

    Example:
        >>> entropy = bytes.fromhex('00' * 16)  # 128 bits of zeros
        >>> checksum = calculate_checksum(entropy)
        >>> checksum  # First 4 bits of SHA256
        6
    """
    # Calculate SHA256 hash
    hash_bytes = hashlib.sha256(entropy).digest()

    # Get first byte (contains the checksum bits we need)
    first_byte = hash_bytes[0]

    # Calculate checksum length in bits (entropy_bits / 32)
    entropy_bits = len(entropy) * 8
    checksum_bits = entropy_bits // 32

    # Extract first N bits from first byte
    # Shift right to get only the needed bits
    checksum = first_byte >> (8 - checksum_bits)

    return checksum


def verify_checksum(entropy: bytes, checksum: int) -> bool:
    """Verify checksum against entropy.

    Args:
        entropy: Entropy bytes
        checksum: Checksum to verify

    Returns:
        True if checksum is valid, False otherwise
    """
    expected_checksum = calculate_checksum(entropy)
    return checksum == expected_checksum


def extract_checksum_bits(mnemonic_int: int, word_count: int) -> int:
    """Extract checksum bits from mnemonic integer representation.

    Args:
        mnemonic_int: Mnemonic represented as big integer (all words concatenated)
        word_count: Number of words in mnemonic

    Returns:
        Checksum bits as integer
    """
    # Calculate checksum length
    entropy_bits = (word_count * 11) - (word_count * 11 // 33)
    checksum_bits = word_count * 11 - entropy_bits

    # Extract last N bits (checksum)
    mask = (1 << checksum_bits) - 1
    return mnemonic_int & mask


def sha256(data: Union[bytes, str]) -> bytes:
    """Calculate SHA256 hash.

    Args:
        data: Data to hash (bytes or string)

    Returns:
        SHA256 hash bytes
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    return hashlib.sha256(data).digest()
