"""Tests for brute-force mnemonic recovery."""

import pytest
from bip39_gpu.bruteforce import PatternParser, BruteForceSearch


class TestPatternParser:
    """Test pattern parsing."""

    def test_parse_simple_pattern(self):
        """Test parsing simple pattern with 1 unknown."""
        pattern = "abandon ??? abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        result = PatternParser.parse(pattern)

        assert result.word_count == 12
        assert len(result.unknown_positions) == 1
        assert result.unknown_positions == [1]
        assert len(result.known_words) == 11
        assert result.search_space == 2048  # 2048^1

    def test_parse_two_unknowns(self):
        """Test pattern with 2 unknown words."""
        pattern = "abandon ??? ??? abandon abandon abandon abandon abandon abandon abandon abandon about"
        result = PatternParser.parse(pattern)

        assert result.word_count == 12
        assert len(result.unknown_positions) == 2
        assert result.unknown_positions == [1, 2]
        assert result.search_space == 2048 ** 2  # 4,194,304

    def test_invalid_word_count(self):
        """Test invalid word count."""
        with pytest.raises(ValueError, match="Invalid word count"):
            PatternParser.parse("abandon ??? abandon")  # Only 3 words

    def test_invalid_word(self):
        """Test invalid BIP39 word."""
        with pytest.raises(ValueError, match="Invalid BIP39 word"):
            PatternParser.parse("abandon invalidword ??? about abandon abandon abandon abandon abandon abandon abandon about")

    def test_no_unknown_words(self):
        """Test pattern with no unknowns."""
        with pytest.raises(ValueError, match="at least one unknown"):
            PatternParser.parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

    def test_empty_pattern(self):
        """Test empty pattern."""
        with pytest.raises(ValueError, match="cannot be empty"):
            PatternParser.parse("")

    def test_estimate_time(self):
        """Test time estimation."""
        # Small search space
        time_str = PatternParser.estimate_time(2048)
        assert "millisecond" in time_str or "second" in time_str

        # Large search space
        time_str = PatternParser.estimate_time(2048 ** 3)
        assert "hour" in time_str or "day" in time_str or "year" in time_str

    def test_is_feasible(self):
        """Test feasibility check."""
        assert PatternParser.is_feasible(2048) == True  # 1 unknown
        assert PatternParser.is_feasible(2048 ** 2) == True  # 2 unknowns
        assert PatternParser.is_feasible(2048 ** 3) == False  # 3 unknowns (> 100M)
        assert PatternParser.is_feasible(2048 ** 4) == False  # 4 unknowns


class TestBruteForceSearch:
    """Test brute-force search engine."""

    def test_search_single_unknown(self):
        """Test search with 1 unknown word."""
        # Known valid mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        # Replace second "abandon" with ???
        pattern = "abandon ??? abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        search = BruteForceSearch(pattern)
        results = search.search(max_results=1)

        assert len(results) >= 1
        # Should find the original mnemonic
        assert "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" in results

    def test_generate_candidates(self):
        """Test candidate generation."""
        # Pattern with 1 unknown in 12-word mnemonic
        pattern = "abandon ??? about abandon abandon abandon abandon abandon abandon abandon abandon about"

        search = BruteForceSearch(pattern)
        candidates = list(search.generate_candidates())

        # Should generate 2048 candidates (one for each word in wordlist)
        assert len(candidates) == 2048

        # All should have correct structure
        for candidate in candidates[:10]:  # Check first 10
            words = candidate.split()
            assert len(words) == 12
            assert words[0] == "abandon"
            assert words[2] == "about"

    def test_estimate_feasibility(self):
        """Test feasibility estimation."""
        pattern = "abandon ??? about abandon abandon abandon abandon abandon abandon abandon abandon about"

        search = BruteForceSearch(pattern)
        stats = search.estimate_feasibility()

        assert stats['word_count'] == 12
        assert stats['unknown_words'] == 1
        assert stats['search_space'] == 2048
        assert stats['feasible'] == True
        assert '✅' in stats['recommendation']

    def test_estimate_large_search_space(self):
        """Test estimation for large search space."""
        pattern = "??? ??? ??? abandon abandon abandon abandon abandon abandon abandon abandon about"

        search = BruteForceSearch(pattern)
        stats = search.estimate_feasibility()

        assert stats['unknown_words'] == 3
        assert stats['search_space'] == 2048 ** 3
        assert '⚠️' in stats['recommendation']

    def test_estimate_infeasible(self):
        """Test estimation for infeasible search."""
        pattern = "??? ??? ??? ??? abandon abandon abandon abandon abandon abandon abandon about"

        search = BruteForceSearch(pattern)
        stats = search.estimate_feasibility()

        assert stats['unknown_words'] == 4
        assert stats['search_space'] == 2048 ** 4
        assert '❌' in stats['recommendation']


def test_integration_small_search():
    """Integration test with small search space."""
    # Real test: find mnemonic with last word unknown
    # We know "abandon abandon abandon ... abandon about" is valid
    # Let's search for it
    pattern = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ???"

    search = BruteForceSearch(pattern)
    results = search.search(max_results=1)

    # Should find "about" as the last word
    assert len(results) == 1
    assert results[0].endswith(" about")
