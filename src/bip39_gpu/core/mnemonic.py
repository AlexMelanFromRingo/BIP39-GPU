"""BIP39 mnemonic generation, validation, and seed derivation."""

import hashlib
import hmac
from typing import Optional, Union

from .wordlist import get_wordlist, Wordlist
from .entropy import (
    generate_entropy,
    validate_entropy,
    words_to_entropy_bits,
    WORDS_TO_ENTROPY_BITS,
    WordCount,
)
from .checksum import calculate_checksum, verify_checksum
from ..utils.exceptions import (
    InvalidMnemonicError,
    InvalidChecksumError,
    InvalidWordCountError,
    WordNotInListError,
)


class BIP39Mnemonic:
    """BIP39 mnemonic phrase generator and validator."""

    def __init__(self, language: str = "english"):
        """Initialize BIP39 mnemonic handler.

        Args:
            language: Language for wordlist (default: "english")
        """
        self.wordlist = get_wordlist(language)

    @staticmethod
    def generate(words: WordCount = 12, language: str = "english") -> str:
        """Generate a random BIP39 mnemonic phrase.

        Args:
            words: Number of words (12, 15, 18, 21, or 24) - default: 12
            language: Language for wordlist (default: "english")

        Returns:
            Mnemonic phrase as space-separated string

        Raises:
            InvalidWordCountError: If word count is invalid

        Example:
            >>> mnemonic = BIP39Mnemonic.generate(12)
            >>> len(mnemonic.split())
            12
        """
        if words not in WORDS_TO_ENTROPY_BITS:
            raise InvalidWordCountError(
                f"Invalid word count: {words}. "
                f"Must be one of {sorted(WORDS_TO_ENTROPY_BITS.keys())}"
            )

        entropy_bits = WORDS_TO_ENTROPY_BITS[words]
        entropy = generate_entropy(entropy_bits)

        return BIP39Mnemonic.from_entropy(entropy, language)

    @staticmethod
    def from_entropy(entropy: bytes, language: str = "english") -> str:
        """Convert entropy to mnemonic phrase.

        Args:
            entropy: Entropy bytes (16, 20, 24, 28, or 32 bytes)
            language: Language for wordlist (default: "english")

        Returns:
            Mnemonic phrase as space-separated string

        Raises:
            InvalidEntropyError: If entropy length is invalid

        Example:
            >>> entropy = bytes.fromhex('00' * 16)
            >>> mnemonic = BIP39Mnemonic.from_entropy(entropy)
            >>> mnemonic.split()[0]
            'abandon'
        """
        validate_entropy(entropy)
        wordlist = get_wordlist(language)

        # Calculate checksum
        checksum = calculate_checksum(entropy)
        checksum_bits = (len(entropy) * 8) // 32

        # Convert entropy + checksum to big integer
        # Entropy bits + checksum bits
        entropy_int = int.from_bytes(entropy, byteorder="big")
        combined = (entropy_int << checksum_bits) | checksum

        # Convert to words (each word represents 11 bits)
        words = []
        word_count = (len(entropy) * 8 + checksum_bits) // 11

        for i in range(word_count):
            # Extract 11 bits for each word (from right to left)
            word_index = (combined >> (11 * (word_count - 1 - i))) & 0x7FF
            words.append(wordlist[word_index])

        return " ".join(words)

    @staticmethod
    def to_entropy(mnemonic: str, language: str = "english") -> bytes:
        """Extract entropy from mnemonic phrase.

        Args:
            mnemonic: Mnemonic phrase as space-separated string
            language: Language for wordlist (default: "english")

        Returns:
            Original entropy bytes

        Raises:
            InvalidMnemonicError: If mnemonic is invalid
            InvalidChecksumError: If checksum validation fails
        """
        words = mnemonic.strip().lower().split()
        wordlist = get_wordlist(language)

        # Validate word count
        if len(words) not in WORDS_TO_ENTROPY_BITS:
            raise InvalidMnemonicError(
                f"Invalid mnemonic: {len(words)} words. "
                f"Must be one of {sorted(WORDS_TO_ENTROPY_BITS.keys())} words"
            )

        # Validate all words exist in wordlist
        for word in words:
            if not wordlist.contains(word):
                raise WordNotInListError(f"Word not in wordlist: '{word}'")

        # Convert words to big integer
        combined = 0
        for word in words:
            word_index = wordlist.get_index(word)
            combined = (combined << 11) | word_index

        # Calculate entropy and checksum lengths
        total_bits = len(words) * 11
        checksum_bits = total_bits // 33
        entropy_bits = total_bits - checksum_bits
        entropy_bytes = entropy_bits // 8

        # Extract entropy and checksum
        checksum_mask = (1 << checksum_bits) - 1
        checksum = combined & checksum_mask
        entropy_int = combined >> checksum_bits

        # Convert entropy integer to bytes
        entropy = entropy_int.to_bytes(entropy_bytes, byteorder="big")

        # Verify checksum
        if not verify_checksum(entropy, checksum):
            raise InvalidChecksumError(
                "Invalid mnemonic: checksum validation failed"
            )

        return entropy

    @staticmethod
    def validate(mnemonic: str, language: str = "english") -> bool:
        """Validate a mnemonic phrase.

        Args:
            mnemonic: Mnemonic phrase to validate
            language: Language for wordlist (default: "english")

        Returns:
            True if mnemonic is valid, False otherwise

        Example:
            >>> mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            >>> BIP39Mnemonic.validate(mnemonic)
            True
        """
        try:
            BIP39Mnemonic.to_entropy(mnemonic, language)
            return True
        except (InvalidMnemonicError, InvalidChecksumError, WordNotInListError):
            return False

    @staticmethod
    def to_seed(
        mnemonic: str,
        passphrase: str = "",
        use_gpu: bool = False
    ) -> bytes:
        """Convert mnemonic to 64-byte seed using PBKDF2-HMAC-SHA512.

        BIP39 standard: 2048 iterations of PBKDF2-HMAC-SHA512
        Salt: "mnemonic" + passphrase (UTF-8)

        Args:
            mnemonic: Mnemonic phrase
            passphrase: Optional passphrase (default: "")
            use_gpu: Use GPU acceleration if available (default: False)

        Returns:
            64-byte seed

        Raises:
            InvalidMnemonicError: If mnemonic is invalid

        Example:
            >>> mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            >>> seed = BIP39Mnemonic.to_seed(mnemonic)
            >>> len(seed)
            64
        """
        # Validate mnemonic first
        if not BIP39Mnemonic.validate(mnemonic):
            raise InvalidMnemonicError("Invalid mnemonic phrase")

        # Normalize mnemonic and passphrase
        mnemonic_normalized = mnemonic.strip().lower()
        passphrase_normalized = passphrase

        # BIP39: salt = "mnemonic" + passphrase
        salt = ("mnemonic" + passphrase_normalized).encode("utf-8")
        password = mnemonic_normalized.encode("utf-8")

        # TODO: Add GPU acceleration when available
        if use_gpu:
            # For now, fall back to CPU
            # GPU implementation will be added in Phase 5
            pass

        # PBKDF2-HMAC-SHA512 with 2048 iterations (BIP39 standard)
        seed = hashlib.pbkdf2_hmac(
            "sha512",
            password,
            salt,
            iterations=2048,
            dklen=64
        )

        return seed

    @staticmethod
    def batch_to_seed(
        mnemonics: list[str],
        passphrases: Optional[list[str]] = None,
        use_gpu: bool = False
    ) -> list[bytes]:
        """Convert multiple mnemonics to seeds (batch operation).

        This method is useful for GPU acceleration where processing
        multiple seeds at once is more efficient.

        Args:
            mnemonics: List of mnemonic phrases
            passphrases: Optional list of passphrases (same length as mnemonics)
            use_gpu: Use GPU acceleration if available (default: False)

        Returns:
            List of 64-byte seeds

        Raises:
            ValueError: If passphrases length doesn't match mnemonics
        """
        if passphrases is None:
            passphrases = [""] * len(mnemonics)

        if len(passphrases) != len(mnemonics):
            raise ValueError(
                f"Passphrases length ({len(passphrases)}) must match "
                f"mnemonics length ({len(mnemonics)})"
            )

        # TODO: Add GPU batch processing in Phase 5
        if use_gpu:
            # For now, fall back to CPU
            pass

        # CPU: Process each mnemonic individually
        seeds = []
        for mnemonic, passphrase in zip(mnemonics, passphrases):
            seed = BIP39Mnemonic.to_seed(mnemonic, passphrase, use_gpu=False)
            seeds.append(seed)

        return seeds
