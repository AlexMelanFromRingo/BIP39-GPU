"""Brute-force mnemonic search engine."""

from typing import Optional, Callable, Iterator
import itertools
from ..core.mnemonic import BIP39Mnemonic
from ..core.wordlist import Wordlist
from .pattern import SearchPattern, PatternParser


class BruteForceSearch:
    """Brute-force search engine for mnemonic recovery."""

    def __init__(self, pattern: str):
        """Initialize search with pattern.

        Args:
            pattern: Mnemonic pattern with ??? for unknown words
        """
        self.pattern_str = pattern
        self.pattern = PatternParser.parse(pattern)
        wordlist_obj = Wordlist()
        self.wordlist = wordlist_obj.get_all_words()

    def generate_candidates(self) -> Iterator[str]:
        """Generate all possible mnemonic candidates.

        Yields:
            Mnemonic candidate strings
        """
        # Get all possible words for unknown positions
        unknown_count = len(self.pattern.unknown_positions)

        # Generate all combinations of unknown words
        for unknown_words in itertools.product(self.wordlist, repeat=unknown_count):
            # Build complete mnemonic
            words = [""] * self.pattern.word_count

            # Fill in known words
            for pos, word in self.pattern.known_words:
                words[pos] = word

            # Fill in unknown words
            for i, pos in enumerate(self.pattern.unknown_positions):
                words[pos] = unknown_words[i]

            yield " ".join(words)

    def search(
        self,
        validate_only: bool = True,
        target_address: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        max_results: int = 1,
    ) -> list[str]:
        """Search for valid mnemonics matching the pattern.

        Args:
            validate_only: If True, return first valid mnemonic (checksum valid)
                          If False, also check against target_address
            target_address: Optional target Bitcoin address to match
            progress_callback: Optional callback(current, total) for progress
            max_results: Maximum number of results to return (default: 1)

        Returns:
            List of matching mnemonics

        Example:
            >>> search = BruteForceSearch("abandon ??? about")
            >>> results = search.search(max_results=1)
        """
        results = []
        total = self.pattern.search_space
        checked = 0

        for candidate in self.generate_candidates():
            checked += 1

            # Progress callback
            if progress_callback and checked % 1000 == 0:
                progress_callback(checked, total)

            # Validate mnemonic checksum
            if not BIP39Mnemonic.validate(candidate):
                continue

            # If validate_only, we found a match
            if validate_only:
                results.append(candidate)
                if len(results) >= max_results:
                    break
                continue

            # Check against target address if provided
            if target_address:
                try:
                    from ..wallet import HDWallet

                    wallet = HDWallet(candidate)
                    # Try common address formats
                    for fmt in ["P2PKH", "Bech32", "P2SH", "Taproot"]:
                        addr = wallet.derive_address(format=fmt, address_index=0)
                        if addr == target_address:
                            results.append(candidate)
                            if len(results) >= max_results:
                                return results
                except ImportError:
                    # bip-utils not available, skip address check
                    pass

        return results

    def estimate_feasibility(self) -> dict:
        """Estimate search feasibility and time.

        Returns:
            Dictionary with search statistics
        """
        return {
            "pattern": str(self.pattern),
            "word_count": self.pattern.word_count,
            "unknown_words": len(self.pattern.unknown_positions),
            "search_space": self.pattern.search_space,
            "estimated_time": PatternParser.estimate_time(self.pattern.search_space),
            "feasible": PatternParser.is_feasible(self.pattern.search_space),
            "recommendation": self._get_recommendation(),
        }

    def _get_recommendation(self) -> str:
        """Get recommendation based on search space."""
        unknown = len(self.pattern.unknown_positions)

        if unknown == 1:
            return "✅ Feasible - should complete quickly"
        elif unknown == 2:
            return "⚠️  Feasible but may take some time - consider GPU acceleration"
        elif unknown == 3:
            return "⚠️  Large search space - GPU acceleration strongly recommended"
        else:
            return "❌ Not feasible - too many unknown words (reduce to 3 or less)"
