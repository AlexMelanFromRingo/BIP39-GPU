"""CLI utility functions for formatting and output."""

import json
from typing import Any, Dict, Optional


def format_json(data: Dict[str, Any], indent: int = 2) -> str:
    """Format data as pretty JSON.

    Args:
        data: Data to format
        indent: Indentation spaces (default: 2)

    Returns:
        Formatted JSON string
    """
    return json.dumps(data, indent=indent, ensure_ascii=False)


def format_mnemonic_info(
    mnemonic: str,
    valid: bool,
    entropy_bits: Optional[int] = None,
    as_json: bool = False
) -> str:
    """Format mnemonic information for display.

    Args:
        mnemonic: Mnemonic phrase
        valid: Whether mnemonic is valid
        entropy_bits: Entropy bits (optional)
        as_json: Output as JSON (default: False)

    Returns:
        Formatted string
    """
    words = mnemonic.split()
    word_count = len(words)

    if as_json:
        data = {
            "mnemonic": mnemonic,
            "words": word_count,
            "valid": valid,
        }
        if entropy_bits:
            data["entropy_bits"] = entropy_bits
        return format_json(data)

    # Text format
    lines = [
        f"Mnemonic ({word_count} words):",
        mnemonic,
        "",
        f"Valid: {'✓' if valid else '✗'}",
    ]

    if entropy_bits:
        lines.append(f"Entropy: {entropy_bits} bits")

    return "\n".join(lines)


def format_seed_info(
    seed: bytes,
    mnemonic: Optional[str] = None,
    passphrase: Optional[str] = None,
    as_json: bool = False,
    hex_output: bool = True
) -> str:
    """Format seed information for display.

    Args:
        seed: Seed bytes
        mnemonic: Original mnemonic (optional)
        passphrase: Passphrase used (optional)
        as_json: Output as JSON (default: False)
        hex_output: Output seed as hex instead of base64 (default: True)

    Returns:
        Formatted string
    """
    import base64

    seed_str = seed.hex() if hex_output else base64.b64encode(seed).decode()
    format_type = "hex" if hex_output else "base64"

    if as_json:
        data = {
            "seed": seed_str,
            "format": format_type,
            "length_bytes": len(seed),
        }
        if mnemonic:
            data["mnemonic"] = mnemonic
        if passphrase:
            data["passphrase_used"] = bool(passphrase)
        return format_json(data)

    # Text format
    lines = [
        f"Seed ({len(seed)} bytes, {format_type}):",
        seed_str,
    ]

    if mnemonic:
        lines.insert(0, f"Mnemonic: {mnemonic}")
        lines.insert(1, "")

    if passphrase:
        lines.append("")
        lines.append(f"Passphrase: {'<hidden>' if passphrase else '(none)'}")

    return "\n".join(lines)


def error_message(message: str, as_json: bool = False) -> str:
    """Format error message.

    Args:
        message: Error message
        as_json: Output as JSON (default: False)

    Returns:
        Formatted error string
    """
    if as_json:
        return format_json({"error": message})

    return f"Error: {message}"


def success_message(message: str) -> str:
    """Format success message.

    Args:
        message: Success message

    Returns:
        Formatted success string
    """
    return f"✓ {message}"
