"""Custom exceptions for bip39-gpu."""


class BIP39Error(Exception):
    """Base exception for all BIP39-related errors."""
    pass


class InvalidMnemonicError(BIP39Error):
    """Raised when a mnemonic phrase is invalid."""
    pass


class InvalidChecksumError(BIP39Error):
    """Raised when mnemonic checksum validation fails."""
    pass


class InvalidEntropyError(BIP39Error):
    """Raised when entropy is invalid (wrong length, etc.)."""
    pass


class InvalidWordCountError(BIP39Error):
    """Raised when word count is not supported (must be 12, 15, 18, 21, or 24)."""
    pass


class WordNotInListError(BIP39Error):
    """Raised when a word is not found in the BIP39 wordlist."""
    pass


class GPUNotAvailableError(BIP39Error):
    """Raised when GPU acceleration is requested but not available."""
    pass


class InvalidDerivationPathError(BIP39Error):
    """Raised when a BIP32/BIP44 derivation path is invalid."""
    pass
