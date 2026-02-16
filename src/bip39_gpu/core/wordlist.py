"""BIP39 wordlist management."""

import os
from typing import Dict, List, Optional
from pathlib import Path


class Wordlist:
    """Manages BIP39 wordlist for mnemonic generation and validation."""

    def __init__(self, language: str = "english"):
        """Initialize wordlist for specified language.

        Args:
            language: Language of the wordlist (default: "english")

        Raises:
            FileNotFoundError: If wordlist file doesn't exist
            ValueError: If wordlist doesn't contain exactly 2048 words
        """
        self.language = language
        self._words: List[str] = []
        self._word_to_index: Dict[str, int] = {}
        self._load_wordlist()

    def _load_wordlist(self) -> None:
        """Load wordlist from file."""
        wordlist_path = Path(__file__).parent / "wordlists" / f"{self.language}.txt"

        if not wordlist_path.exists():
            raise FileNotFoundError(
                f"Wordlist file not found: {wordlist_path}. "
                f"Available languages: english"
            )

        with open(wordlist_path, "r", encoding="utf-8") as f:
            self._words = [line.strip() for line in f if line.strip()]

        if len(self._words) != 2048:
            raise ValueError(
                f"Invalid wordlist: expected 2048 words, got {len(self._words)}"
            )

        # Create index mapping for fast lookups
        self._word_to_index = {word: idx for idx, word in enumerate(self._words)}

    def get_word(self, index: int) -> str:
        """Get word by index (0-2047).

        Args:
            index: Word index (0-2047)

        Returns:
            Word at the given index

        Raises:
            IndexError: If index is out of range
        """
        if not 0 <= index < 2048:
            raise IndexError(f"Index must be 0-2047, got {index}")
        return self._words[index]

    def get_index(self, word: str) -> Optional[int]:
        """Get index of a word.

        Args:
            word: Word to look up

        Returns:
            Index of the word (0-2047) or None if not found
        """
        return self._word_to_index.get(word.lower())

    def contains(self, word: str) -> bool:
        """Check if word exists in wordlist.

        Args:
            word: Word to check

        Returns:
            True if word exists, False otherwise
        """
        return word.lower() in self._word_to_index

    def get_all_words(self) -> List[str]:
        """Get all words in the wordlist.

        Returns:
            List of all 2048 words
        """
        return self._words.copy()

    def __len__(self) -> int:
        """Get number of words in wordlist."""
        return len(self._words)

    def __getitem__(self, index: int) -> str:
        """Get word by index (allows wordlist[index] syntax)."""
        return self.get_word(index)


# Global wordlist instance for easy access
_default_wordlist: Optional[Wordlist] = None


def get_wordlist(language: str = "english") -> Wordlist:
    """Get wordlist instance (cached for performance).

    Args:
        language: Language of the wordlist (default: "english")

    Returns:
        Wordlist instance
    """
    global _default_wordlist

    if _default_wordlist is None or _default_wordlist.language != language:
        _default_wordlist = Wordlist(language)

    return _default_wordlist
