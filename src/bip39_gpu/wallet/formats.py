"""Bitcoin address format detection and validation."""

import re
from typing import Optional, Literal

AddressFormat = Literal["P2PKH", "P2SH", "Bech32", "Unknown"]


def detect_address_format(address: str) -> AddressFormat:
    """Detect Bitcoin address format.

    Args:
        address: Bitcoin address string

    Returns:
        Address format: "P2PKH", "P2SH", "Bech32", or "Unknown"

    Example:
        >>> detect_address_format("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        'P2PKH'
        >>> detect_address_format("3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy")
        'P2SH'
        >>> detect_address_format("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        'Bech32'
    """
    # P2PKH: Starts with '1'
    if address.startswith('1'):
        return "P2PKH"

    # P2SH: Starts with '3'
    elif address.startswith('3'):
        return "P2SH"

    # Bech32: Starts with 'bc1' (mainnet) or 'tb1' (testnet)
    elif address.startswith('bc1') or address.startswith('tb1'):
        return "Bech32"

    else:
        return "Unknown"


def validate_address_format(address: str, expected_format: AddressFormat) -> bool:
    """Validate that address matches expected format.

    Args:
        address: Bitcoin address string
        expected_format: Expected format ("P2PKH", "P2SH", or "Bech32")

    Returns:
        True if address matches expected format, False otherwise
    """
    detected = detect_address_format(address)
    return detected == expected_format


def is_valid_bitcoin_address(address: str) -> bool:
    """Check if address is a valid Bitcoin address (basic check).

    Args:
        address: Address string to validate

    Returns:
        True if address appears valid, False otherwise

    Note:
        This is a basic format check. Full validation requires checksum verification.
    """
    # P2PKH or P2SH: 26-35 characters, alphanumeric
    if address.startswith('1') or address.startswith('3'):
        if not (26 <= len(address) <= 35):
            return False
        # Base58 characters (no 0, O, I, l)
        base58_pattern = re.compile(r'^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$')
        return bool(base58_pattern.match(address))

    # Bech32: Starts with bc1 or tb1
    elif address.startswith('bc1') or address.startswith('tb1'):
        # Bech32 characters (lowercase letters and numbers)
        bech32_pattern = re.compile(r'^(bc1|tb1)[a-z0-9]{39,87}$')
        return bool(bech32_pattern.match(address.lower()))

    return False


def get_address_prefix(format: AddressFormat) -> str:
    """Get expected prefix for address format.

    Args:
        format: Address format

    Returns:
        Expected prefix string

    Example:
        >>> get_address_prefix("P2PKH")
        '1'
        >>> get_address_prefix("Bech32")
        'bc1'
    """
    prefixes = {
        "P2PKH": "1",
        "P2SH": "3",
        "Bech32": "bc1",
    }

    return prefixes.get(format, "")
