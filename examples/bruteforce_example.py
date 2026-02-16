#!/usr/bin/env python3
"""Brute-force mnemonic recovery example.

This example demonstrates:
- Recovering mnemonics with unknown words (??? placeholders)
- Feasibility estimation before searching
- Pattern parsing and validation
- Progress tracking during search
"""

from bip39_gpu.bruteforce import BruteForceSearch, PatternParser


def main():
    print("=" * 70)
    print("Brute-Force Mnemonic Recovery Example")
    print("=" * 70)
    print()

    # Example 1: Estimate feasibility
    print("1. Feasibility Estimation\n")

    patterns = [
        "abandon ??? abandon abandon abandon abandon abandon abandon abandon abandon abandon about",  # 1 unknown
        "abandon ??? ??? abandon abandon abandon abandon abandon abandon abandon abandon about",  # 2 unknowns
        "??? ??? ??? abandon abandon abandon abandon abandon abandon abandon abandon about",  # 3 unknowns
    ]

    for pattern in patterns:
        search = BruteForceSearch(pattern)
        stats = search.estimate_feasibility()

        print(f"Pattern: {pattern[:40]}...")
        print(f"  Unknown words:   {stats['unknown_words']}")
        print(f"  Search space:    {stats['search_space']:,} combinations")
        print(f"  Estimated time:  {stats['estimated_time']}")
        print(f"  {stats['recommendation']}")
        print()

    # Example 2: Recover with 1 unknown word (fast)
    print("2. Recovering Mnemonic with 1 Unknown Word\n")

    # We know the valid mnemonic is:
    # "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    # Let's "forget" the last word and recover it

    pattern = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ???"
    print(f"Pattern: {pattern[:60]}...")
    print("Searching...")

    search = BruteForceSearch(pattern)

    # Track progress
    progress_count = [0]

    def progress_callback(current, total):
        if current % 500 == 0:
            progress_count[0] = current

    results = search.search(
        validate_only=True,
        progress_callback=progress_callback,
        max_results=1
    )

    print(f"Checked: {progress_count[0] if progress_count[0] > 0 else 'all'} combinations")
    print(f"Found: {len(results)} valid mnemonic(s)")
    if results:
        print(f"\nRecovered mnemonic:")
        print(f"  {results[0]}")
    print()

    # Example 3: Multiple valid possibilities
    print("3. Finding All Valid Mnemonics\n")

    # Some patterns may have multiple valid checksums
    pattern_multi = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ???"

    search = BruteForceSearch(pattern_multi)
    results = search.search(
        validate_only=True,
        max_results=5  # Find up to 5 valid mnemonics
    )

    print(f"Pattern: {pattern_multi[:60]}...")
    print(f"Found {len(results)} valid mnemonic(s):")
    for i, mnemonic in enumerate(results, 1):
        print(f"  {i}. ...{mnemonic.split()[-1]}")
    print()

    # Example 4: Pattern validation
    print("4. Pattern Validation\n")

    invalid_patterns = [
        "abandon ??? abandon",  # Too few words
        "abandon invalidword ??? abandon abandon abandon abandon abandon abandon abandon abandon about",  # Invalid word
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",  # No unknowns
    ]

    for pattern in invalid_patterns:
        try:
            PatternParser.parse(pattern)
            print(f"✓ Valid:   {pattern[:40]}...")
        except ValueError as e:
            print(f"✗ Invalid: {pattern[:40]}...")
            print(f"   Error: {str(e)[:50]}")
    print()

    # Example 5: Search space warnings
    print("5. Search Space Warnings\n")

    large_patterns = {
        "1 unknown": "abandon ??? abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "2 unknowns": "abandon ??? ??? abandon abandon abandon abandon abandon abandon abandon abandon about",
        "3 unknowns": "??? ??? ??? abandon abandon abandon abandon abandon abandon abandon abandon about",
    }

    for desc, pattern in large_patterns.items():
        search = BruteForceSearch(pattern)
        stats = search.estimate_feasibility()

        print(f"{desc}:")
        print(f"  Search space: {stats['search_space']:,}")
        print(f"  Feasible:     {stats['feasible']}")
        print(f"  Time:         {stats['estimated_time']}")
    print()

    print("=" * 70)
    print("Example completed successfully!")
    print("=" * 70)
    print()
    print("Usage tips:")
    print("  • 1 unknown word: Very fast, almost instant")
    print("  • 2 unknown words: Feasible, may take seconds to minutes")
    print("  • 3 unknown words: Large search space, not recommended")
    print("  • 4+ unknown words: Computationally infeasible")
    print()
    print("Use --dry-run flag to check feasibility before searching:")
    print("  bip39-gpu bruteforce --pattern 'word1 ??? word3 ...' --dry-run")


if __name__ == "__main__":
    main()
