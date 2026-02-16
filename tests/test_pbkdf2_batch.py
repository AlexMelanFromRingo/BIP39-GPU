"""Tests for batch PBKDF2 operations."""

import pytest
from bip39_gpu.core.pbkdf2_batch import (
    batch_mnemonic_to_seed,
    estimate_batch_time,
)
from bip39_gpu import BIP39Mnemonic


class TestBatchPBKDF2:
    """Test batch PBKDF2 operations."""

    def test_batch_single_mnemonic(self):
        """Test batch with single mnemonic."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seeds = batch_mnemonic_to_seed([mnemonic])

        assert len(seeds) == 1
        assert len(seeds[0]) == 64
        assert isinstance(seeds[0], bytes)

    def test_batch_multiple_mnemonics(self):
        """Test batch with multiple mnemonics."""
        mnemonics = [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            BIP39Mnemonic.generate(12),
            BIP39Mnemonic.generate(12),
        ]

        seeds = batch_mnemonic_to_seed(mnemonics)

        assert len(seeds) == 3
        for seed in seeds:
            assert len(seed) == 64
            assert isinstance(seed, bytes)

    def test_batch_with_passphrases(self):
        """Test batch with different passphrases."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mnemonics = [mnemonic, mnemonic, mnemonic]
        passphrases = ["", "pass1", "pass2"]

        seeds = batch_mnemonic_to_seed(mnemonics, passphrases)

        assert len(seeds) == 3
        # Different passphrases should produce different seeds
        assert seeds[0] != seeds[1]
        assert seeds[1] != seeds[2]
        assert seeds[0] != seeds[2]

    def test_batch_consistency_with_single(self):
        """Test batch produces same result as single conversion."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        # Single conversion
        single_seed = BIP39Mnemonic.to_seed(mnemonic, passphrase="test")

        # Batch conversion
        batch_seeds = batch_mnemonic_to_seed([mnemonic], ["test"])

        assert batch_seeds[0] == single_seed

    def test_batch_length_mismatch(self):
        """Test error on mnemonic/passphrase length mismatch."""
        mnemonics = ["mnemonic1", "mnemonic2"]
        passphrases = ["pass1"]

        with pytest.raises(ValueError, match="Length mismatch"):
            batch_mnemonic_to_seed(mnemonics, passphrases)

    def test_batch_empty_list(self):
        """Test batch with empty list."""
        seeds = batch_mnemonic_to_seed([])
        assert seeds == []

    def test_gpu_flag_functionality(self):
        """Test GPU flag works (with CPU fallback)."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        # GPU flag should work (falls back to CPU if GPU unavailable)
        seeds_gpu = batch_mnemonic_to_seed([mnemonic], use_gpu=True)
        seeds_cpu = batch_mnemonic_to_seed([mnemonic], use_gpu=False)

        assert len(seeds_gpu) == 1
        assert len(seeds_cpu) == 1
        # Should produce same result
        assert seeds_gpu[0] == seeds_cpu[0]

    def test_estimate_batch_time(self):
        """Test batch time estimation."""
        # Small batch
        time_str = estimate_batch_time(10)
        assert "millisecond" in time_str

        # Medium batch
        time_str = estimate_batch_time(1000)
        assert "second" in time_str

        # Large batch
        time_str = estimate_batch_time(100000)
        assert "minute" in time_str or "hour" in time_str
