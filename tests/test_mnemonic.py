"""Tests for BIP39 mnemonic operations."""

import pytest
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.core.entropy import WORDS_TO_ENTROPY_BITS
from bip39_gpu.utils.exceptions import (
    InvalidMnemonicError,
    InvalidChecksumError,
    InvalidWordCountError,
)


class TestMnemonicGeneration:
    """Test mnemonic generation."""

    def test_generate_12_words(self):
        """Test generating 12-word mnemonic."""
        mnemonic = BIP39Mnemonic.generate(12)
        words = mnemonic.split()
        assert len(words) == 12
        assert BIP39Mnemonic.validate(mnemonic)

    def test_generate_24_words(self):
        """Test generating 24-word mnemonic."""
        mnemonic = BIP39Mnemonic.generate(24)
        words = mnemonic.split()
        assert len(words) == 24
        assert BIP39Mnemonic.validate(mnemonic)

    @pytest.mark.parametrize("word_count", [12, 15, 18, 21, 24])
    def test_generate_all_word_counts(self, word_count):
        """Test all valid word counts."""
        mnemonic = BIP39Mnemonic.generate(word_count)
        words = mnemonic.split()
        assert len(words) == word_count
        assert BIP39Mnemonic.validate(mnemonic)

    def test_generate_invalid_word_count(self):
        """Test invalid word count raises error."""
        with pytest.raises(InvalidWordCountError):
            BIP39Mnemonic.generate(13)


class TestMnemonicValidation:
    """Test mnemonic validation."""

    def test_validate_known_mnemonic(self):
        """Test validation of known test vector."""
        # BIP39 test vector (all 'abandon' + 'about')
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        assert BIP39Mnemonic.validate(mnemonic)

    def test_validate_invalid_checksum(self):
        """Test invalid checksum is rejected."""
        # Valid structure but wrong checksum (last word changed)
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        assert not BIP39Mnemonic.validate(mnemonic)

    def test_validate_invalid_word(self):
        """Test invalid word is rejected."""
        mnemonic = "invalid word test foo bar baz qux quux corge grault garply waldo"
        assert not BIP39Mnemonic.validate(mnemonic)

    def test_validate_wrong_word_count(self):
        """Test wrong word count is rejected."""
        # Only 11 words
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        assert not BIP39Mnemonic.validate(mnemonic)


class TestEntropyConversion:
    """Test entropy <-> mnemonic conversion."""

    def test_from_entropy_12_words(self):
        """Test creating mnemonic from 128-bit entropy."""
        entropy = bytes.fromhex("00" * 16)  # 128 bits of zeros
        mnemonic = BIP39Mnemonic.from_entropy(entropy)
        words = mnemonic.split()
        assert len(words) == 12
        assert BIP39Mnemonic.validate(mnemonic)

    def test_to_entropy_12_words(self):
        """Test extracting entropy from 12-word mnemonic."""
        # Known test vector
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        entropy = BIP39Mnemonic.to_entropy(mnemonic)
        assert len(entropy) == 16  # 128 bits

    def test_entropy_roundtrip(self):
        """Test entropy -> mnemonic -> entropy roundtrip."""
        import secrets

        for word_count in [12, 15, 18, 21, 24]:
            entropy_bits = WORDS_TO_ENTROPY_BITS[word_count]
            original_entropy = secrets.token_bytes(entropy_bits // 8)

            mnemonic = BIP39Mnemonic.from_entropy(original_entropy)
            extracted_entropy = BIP39Mnemonic.to_entropy(mnemonic)

            assert original_entropy == extracted_entropy


class TestSeedGeneration:
    """Test seed generation from mnemonics."""

    def test_to_seed_no_passphrase(self):
        """Test seed generation without passphrase."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed = BIP39Mnemonic.to_seed(mnemonic, passphrase="")
        assert len(seed) == 64

    def test_to_seed_with_passphrase(self):
        """Test seed generation with passphrase."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed1 = BIP39Mnemonic.to_seed(mnemonic, passphrase="")
        seed2 = BIP39Mnemonic.to_seed(mnemonic, passphrase="test")

        # Different passphrases should produce different seeds
        assert seed1 != seed2
        assert len(seed1) == 64
        assert len(seed2) == 64

    def test_to_seed_deterministic(self):
        """Test seed generation is deterministic."""
        mnemonic = BIP39Mnemonic.generate(12)
        seed1 = BIP39Mnemonic.to_seed(mnemonic, passphrase="test")
        seed2 = BIP39Mnemonic.to_seed(mnemonic, passphrase="test")
        assert seed1 == seed2

    def test_batch_to_seed(self):
        """Test batch seed generation."""
        mnemonics = [BIP39Mnemonic.generate(12) for _ in range(5)]
        seeds = BIP39Mnemonic.batch_to_seed(mnemonics)

        assert len(seeds) == 5
        for seed in seeds:
            assert len(seed) == 64

    def test_to_seed_with_gpu_flag(self):
        """Test seed generation with GPU flag (falls back to CPU if unavailable)."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        # CPU seed
        seed_cpu = BIP39Mnemonic.to_seed(mnemonic, passphrase="", use_gpu=False)

        # GPU seed (will fallback to CPU if GPU unavailable)
        seed_gpu = BIP39Mnemonic.to_seed(mnemonic, passphrase="", use_gpu=True)

        # Should produce same result
        assert seed_cpu == seed_gpu
        assert len(seed_cpu) == 64

    def test_batch_to_seed_with_gpu_flag(self):
        """Test batch seed generation with GPU flag."""
        mnemonics = ["abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"] * 3
        passphrases = ["", "test1", "test2"]

        # CPU batch
        seeds_cpu = BIP39Mnemonic.batch_to_seed(mnemonics, passphrases, use_gpu=False)

        # GPU batch (will fallback to CPU if GPU unavailable)
        seeds_gpu = BIP39Mnemonic.batch_to_seed(mnemonics, passphrases, use_gpu=True)

        # Should produce same results
        assert seeds_cpu == seeds_gpu
        assert len(seeds_cpu) == 3

        # Different passphrases should produce different seeds
        assert seeds_cpu[0] != seeds_cpu[1]
        assert seeds_cpu[1] != seeds_cpu[2]
