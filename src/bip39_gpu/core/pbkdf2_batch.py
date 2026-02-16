"""Batch PBKDF2 operations for seed generation."""

from typing import List, Optional
import hashlib
from ..utils.exceptions import InvalidMnemonicError


def batch_mnemonic_to_seed(
    mnemonics: List[str],
    passphrases: Optional[List[str]] = None,
    use_gpu: bool = False,
) -> List[bytes]:
    """Convert multiple mnemonics to seeds (batch operation).

    Args:
        mnemonics: List of mnemonic phrases
        passphrases: Optional list of passphrases (one per mnemonic)
                    If None, empty passphrase used for all
        use_gpu: Use GPU acceleration if available (currently uses CPU)

    Returns:
        List of 64-byte seeds

    Raises:
        ValueError: If mnemonics and passphrases length mismatch

    Example:
        >>> mnemonics = ["word1 ... word12", "word1 ... word12"]
        >>> seeds = batch_mnemonic_to_seed(mnemonics)
        >>> len(seeds)
        2
    """
    if passphrases is None:
        passphrases = [""] * len(mnemonics)

    if len(mnemonics) != len(passphrases):
        raise ValueError(
            f"Length mismatch: {len(mnemonics)} mnemonics, "
            f"{len(passphrases)} passphrases"
        )

    # GPU acceleration coming soon
    if use_gpu:
        import warnings
        warnings.warn(
            "GPU PBKDF2 not yet implemented, using CPU fallback",
            UserWarning
        )

    # CPU batch processing
    seeds = []
    for mnemonic, passphrase in zip(mnemonics, passphrases):
        seed = _mnemonic_to_seed_cpu(mnemonic, passphrase)
        seeds.append(seed)

    return seeds


def _mnemonic_to_seed_cpu(mnemonic: str, passphrase: str = "") -> bytes:
    """Convert single mnemonic to seed using CPU PBKDF2.

    Args:
        mnemonic: BIP39 mnemonic phrase
        passphrase: Optional passphrase (default: "")

    Returns:
        64-byte seed

    Note:
        Uses PBKDF2-HMAC-SHA512 with 2048 iterations (BIP39 standard)
    """
    # Normalize inputs
    mnemonic_normalized = mnemonic.strip().lower()
    passphrase_normalized = passphrase

    # BIP39: salt = "mnemonic" + passphrase
    salt = ("mnemonic" + passphrase_normalized).encode("utf-8")
    mnemonic_bytes = mnemonic_normalized.encode("utf-8")

    # PBKDF2-HMAC-SHA512, 2048 iterations
    seed = hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic_bytes,
        salt,
        2048,
        dklen=64
    )

    return seed


def estimate_batch_time(count: int, per_seed_ms: float = 1.5) -> str:
    """Estimate time for batch seed generation.

    Args:
        count: Number of seeds to generate
        per_seed_ms: Average time per seed in milliseconds (default: 1.5ms)

    Returns:
        Human-readable time estimate
    """
    total_ms = count * per_seed_ms

    if total_ms < 1000:
        return f"{total_ms:.0f} milliseconds"
    elif total_ms < 60000:
        return f"{total_ms / 1000:.1f} seconds"
    elif total_ms < 3600000:
        return f"{total_ms / 60000:.1f} minutes"
    else:
        return f"{total_ms / 3600000:.1f} hours"
