"""Pattern parsing for brute-force mnemonic recovery."""

from typing import List, Tuple, Optional
from dataclasses import dataclass
from ..core.wordlist import Wordlist


@dataclass
class SearchPattern:
    """Parsed search pattern with known and unknown word positions."""

    word_count: int
    known_words: List[Tuple[int, str]]  # [(position, word), ...]
    unknown_positions: List[int]  # [position, ...]
    search_space: int  # Total number of combinations to try

    def __str__(self) -> str:
        pattern = ["???"] * self.word_count
        for pos, word in self.known_words:
            pattern[pos] = word
        return " ".join(pattern)


class PatternParser:
    """Parse mnemonic patterns with unknown words (marked as ???)."""

    UNKNOWN_MARKER = "???"

    @staticmethod
    def parse(pattern: str) -> SearchPattern:
        """Parse a mnemonic pattern string.

        Args:
            pattern: Mnemonic pattern with ??? for unknown words
                    Example: "word1 ??? word3 ??? word5 ... word12"

        Returns:
            SearchPattern with known/unknown word positions

        Raises:
            ValueError: If pattern format is invalid

        Example:
            >>> parser = PatternParser()
            >>> result = parser.parse("abandon ??? about")
            >>> result.word_count
            3
            >>> result.unknown_positions
            [1]
        """
        if not pattern or not pattern.strip():
            raise ValueError("Pattern cannot be empty")

        words = pattern.strip().split()

        if len(words) not in [12, 15, 18, 21, 24]:
            raise ValueError(
                f"Invalid word count: {len(words)}. "
                f"Must be 12, 15, 18, 21, or 24 words."
            )

        known_words = []
        unknown_positions = []
        wordlist_obj = Wordlist()
        wordlist = wordlist_obj.get_all_words()

        for pos, word in enumerate(words):
            if word == PatternParser.UNKNOWN_MARKER:
                unknown_positions.append(pos)
            else:
                # Validate word is in BIP39 wordlist
                if word not in wordlist:
                    raise ValueError(f"Invalid BIP39 word at position {pos}: '{word}'")
                known_words.append((pos, word))

        if not unknown_positions:
            raise ValueError("Pattern must have at least one unknown word (???)")

        # Calculate search space (2048 possibilities per unknown word)
        search_space = 2048 ** len(unknown_positions)

        return SearchPattern(
            word_count=len(words),
            known_words=known_words,
            unknown_positions=unknown_positions,
            search_space=search_space,
        )

    @staticmethod
    def estimate_time(search_space: int, speed_per_second: int = 10000) -> str:
        """Estimate search time given search space and speed.

        Args:
            search_space: Number of combinations to try
            speed_per_second: Mnemonics validated per second (default: 10000)

        Returns:
            Human-readable time estimate
        """
        seconds = search_space / speed_per_second

        if seconds < 1:
            return f"{seconds * 1000:.0f} milliseconds"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds / 86400:.1f} days"
        else:
            return f"{seconds / 31536000:.1f} years"

    @staticmethod
    def is_feasible(search_space: int, max_feasible: int = 100_000_000) -> bool:
        """Check if search is computationally feasible.

        Args:
            search_space: Number of combinations
            max_feasible: Maximum feasible combinations (default: 100M)

        Returns:
            True if search is feasible
        """
        return search_space <= max_feasible
