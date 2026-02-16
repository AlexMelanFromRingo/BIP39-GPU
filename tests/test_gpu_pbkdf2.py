"""Tests for GPU PBKDF2-HMAC-SHA512."""

import pytest
from bip39_gpu import BIP39Mnemonic


def test_gpu_pbkdf2_import():
    """Test GPU PBKDF2 module imports."""
    try:
        from bip39_gpu.gpu.pbkdf2_gpu import pbkdf2_hmac_sha512_gpu, batch_mnemonic_to_seed_gpu
        assert pbkdf2_hmac_sha512_gpu is not None
        assert batch_mnemonic_to_seed_gpu is not None
    except ImportError:
        pytest.skip("GPU modules not available")


def test_gpu_pbkdf2_cpu_fallback():
    """Test GPU PBKDF2 with CPU fallback."""
    try:
        from bip39_gpu.gpu.pbkdf2_gpu import batch_mnemonic_to_seed_gpu
    except ImportError:
        pytest.skip("GPU modules not available")

    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    # GPU (will fallback to CPU if no GPU available)
    seeds_gpu = batch_mnemonic_to_seed_gpu([mnemonic], [""])

    # CPU reference
    seed_cpu = BIP39Mnemonic.to_seed(mnemonic, "")

    assert len(seeds_gpu) == 1
    assert len(seeds_gpu[0]) == 64
    assert seeds_gpu[0] == seed_cpu


def test_gpu_pbkdf2_multiple_mnemonics():
    """Test GPU PBKDF2 with multiple mnemonics."""
    try:
        from bip39_gpu.gpu.pbkdf2_gpu import batch_mnemonic_to_seed_gpu
    except ImportError:
        pytest.skip("GPU modules not available")

    mnemonics = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        BIP39Mnemonic.generate(12),
        BIP39Mnemonic.generate(12),
    ]

    seeds = batch_mnemonic_to_seed_gpu(mnemonics, ["", "", ""])

    assert len(seeds) == 3
    for seed in seeds:
        assert len(seed) == 64
        assert isinstance(seed, bytes)


def test_gpu_pbkdf2_with_passphrases():
    """Test GPU PBKDF2 with different passphrases."""
    try:
        from bip39_gpu.gpu.pbkdf2_gpu import batch_mnemonic_to_seed_gpu
    except ImportError:
        pytest.skip("GPU modules not available")

    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    passphrases = ["", "pass1", "pass2"]

    seeds = batch_mnemonic_to_seed_gpu([mnemonic] * 3, passphrases)

    assert len(seeds) == 3
    # Different passphrases should produce different seeds
    assert seeds[0] != seeds[1]
    assert seeds[1] != seeds[2]
    assert seeds[0] != seeds[2]


def test_gpu_bruteforce_import():
    """Test GPU brute-force module imports."""
    try:
        from bip39_gpu.bruteforce.gpu_bruteforce import GPUBruteForce
        assert GPUBruteForce is not None
    except ImportError:
        pytest.skip("GPU brute-force not available")


def test_gpu_bruteforce_initialization():
    """Test GPU brute-force initialization."""
    try:
        from bip39_gpu.bruteforce.gpu_bruteforce import GPUBruteForce
    except ImportError:
        pytest.skip("GPU brute-force not available")

    searcher = GPUBruteForce(word_count=12)
    assert searcher.word_count == 12
    assert searcher.entropy_bits == 128
    assert searcher.entropy_bytes == 16


def test_gpu_bruteforce_entropy_generation():
    """Test entropy generation."""
    try:
        from bip39_gpu.bruteforce.gpu_bruteforce import GPUBruteForce
    except ImportError:
        pytest.skip("GPU brute-force not available")

    searcher = GPUBruteForce(word_count=12)
    entropies = searcher.generate_random_entropies(10)

    assert len(entropies) == 10
    for entropy in entropies:
        assert len(entropy) == 16
        assert isinstance(entropy, bytes)


def test_gpu_bruteforce_entropy_to_mnemonic():
    """Test entropy to mnemonic conversion."""
    try:
        from bip39_gpu.bruteforce.gpu_bruteforce import GPUBruteForce
    except ImportError:
        pytest.skip("GPU brute-force not available")

    searcher = GPUBruteForce(word_count=12)
    entropies = searcher.generate_random_entropies(5)

    for entropy in entropies:
        mnemonic = searcher.entropy_to_mnemonic(entropy)
        assert isinstance(mnemonic, str)
        assert len(mnemonic.split()) == 12
        # Should be valid
        assert BIP39Mnemonic.validate(mnemonic)
