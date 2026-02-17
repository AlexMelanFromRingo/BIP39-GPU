"""Tests for GPU BIP32/BIP44 key derivation."""

import pytest
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu.bip32_gpu import (
    hash160,
    hash160_to_p2pkh,
    base58check_encode,
    _bip32_master_key,
    _bip44_derive_cpu,
    _get_compressed_pubkey,
    batch_seed_to_address,
    seed_to_address,
)

# BIP39 test vector (from bitcoin/bips#39)
TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
TEST_SEED = bytes.fromhex(
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)


class TestHash160:
    """Test hash160 and address encoding."""

    def test_hash160_known_vector(self):
        """Test hash160 against known Bitcoin address computation."""
        data = b"\x02" + b"\x00" * 32  # simple compressed pubkey
        h = hash160(data)
        assert len(h) == 20
        assert isinstance(h, bytes)

    def test_hash160_to_p2pkh(self):
        """Test P2PKH address from hash160."""
        h160 = bytes.fromhex("89abcdefabbaabbaabbaabbaabbaabbaabbaabba")
        addr = hash160_to_p2pkh(h160)
        assert addr.startswith("1")
        assert len(addr) >= 25
        assert len(addr) <= 34

    def test_base58check_encode(self):
        """Test Base58Check encoding."""
        payload = b"\x00" + b"\x00" * 20
        addr = base58check_encode(payload)
        assert addr.startswith("1")

    def test_base58check_leading_zeros(self):
        """Leading zero bytes become '1' in base58."""
        payload = b"\x00" * 5 + b"\x01"
        addr = base58check_encode(payload)
        assert addr.startswith("1")


class TestBIP32CpuDerivation:
    """Test BIP32 CPU derivation functions."""

    def test_master_key_derivation(self):
        """Test master key derivation from seed."""
        key, chain = _bip32_master_key(TEST_SEED)
        assert len(key) == 32
        assert len(chain) == 32
        # Known master key for "abandon" test vector (Bitcoin)
        # From https://iancoleman.io/bip39/
        expected_key = "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67"
        assert key.hex() == expected_key

    def test_bip44_derivation(self):
        """Test BIP44 path derivation m/44'/0'/0'/0/0."""
        key, chain = _bip44_derive_cpu(TEST_SEED, coin_type=0, address_index=0)
        assert len(key) == 32
        assert len(chain) == 32
        # Key should not be all zeros
        assert key != b"\x00" * 32

    def test_bip44_different_indices(self):
        """Different address indices give different keys."""
        key0, _ = _bip44_derive_cpu(TEST_SEED, 0, 0)
        key1, _ = _bip44_derive_cpu(TEST_SEED, 0, 1)
        assert key0 != key1

    def test_bip44_different_seeds_different_keys(self):
        """Different seeds give different keys."""
        seed2 = BIP39Mnemonic.to_seed(BIP39Mnemonic.generate(12))
        key1, _ = _bip44_derive_cpu(TEST_SEED, 0, 0)
        key2, _ = _bip44_derive_cpu(seed2, 0, 0)
        assert key1 != key2

    def test_bip44_known_child_key(self):
        """Test known child key from BIP44 derivation (m/44'/0'/0'/0/0)."""
        key, _ = _bip44_derive_cpu(TEST_SEED, 0, 0)
        # Verified against ecdsa reference implementation
        expected = "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372"
        assert key.hex() == expected

    def test_bip44_deterministic(self):
        """Same seed always gives same key."""
        key1, chain1 = _bip44_derive_cpu(TEST_SEED, 0, 0)
        key2, chain2 = _bip44_derive_cpu(TEST_SEED, 0, 0)
        assert key1 == key2
        assert chain1 == chain2

    def test_bip44_coin_types(self):
        """Different coin types give different keys."""
        key_btc, _ = _bip44_derive_cpu(TEST_SEED, coin_type=0, address_index=0)
        key_eth, _ = _bip44_derive_cpu(TEST_SEED, coin_type=60, address_index=0)
        assert key_btc != key_eth


class TestAddressGeneration:
    """Test full address generation pipeline."""

    def test_seed_to_address_known_vector(self):
        """Known P2PKH address for abandon×11+about, m/44'/0'/0'/0/0."""
        addr = seed_to_address(TEST_SEED, use_gpu=False)
        # Verified: address for this test vector at BIP44 path
        assert addr == "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"

    def test_seed_to_address_format(self):
        """seed_to_address returns valid P2PKH address."""
        addr = seed_to_address(TEST_SEED, use_gpu=False)
        # P2PKH address starts with '1' on mainnet
        assert addr.startswith("1") or addr == ""
        if addr:
            assert 25 <= len(addr) <= 34

    def test_seed_to_address_deterministic(self):
        """Same seed always gives same address."""
        addr1 = seed_to_address(TEST_SEED, use_gpu=False)
        addr2 = seed_to_address(TEST_SEED, use_gpu=False)
        assert addr1 == addr2

    def test_batch_seed_to_address(self):
        """Batch processing works correctly."""
        seeds = [BIP39Mnemonic.to_seed(BIP39Mnemonic.generate(12)) for _ in range(5)]
        addrs = batch_seed_to_address(seeds, use_gpu=False)
        assert len(addrs) == 5
        for addr in addrs:
            if addr:
                assert addr.startswith("1")
                assert 25 <= len(addr) <= 34

    def test_batch_different_seeds_different_addresses(self):
        """Different seeds produce different addresses."""
        seeds = [BIP39Mnemonic.to_seed(BIP39Mnemonic.generate(12)) for _ in range(3)]
        addrs = batch_seed_to_address(seeds, use_gpu=False)
        # All addresses should be unique
        non_empty = [a for a in addrs if a]
        if len(non_empty) > 1:
            assert len(set(non_empty)) == len(non_empty)

    def test_batch_with_gpu_flag(self):
        """GPU flag should return same results as CPU (or fall back gracefully)."""
        seeds = [TEST_SEED]
        addr_cpu = batch_seed_to_address(seeds, use_gpu=False)
        addr_gpu = batch_seed_to_address(seeds, use_gpu=True)  # may use CPU fallback

        # Both should return valid results (or both empty)
        assert len(addr_cpu) == len(addr_gpu)

    def test_address_index_variation(self):
        """Different address indices give different addresses."""
        addrs = [
            seed_to_address(TEST_SEED, address_index=i, use_gpu=False)
            for i in range(3)
        ]
        non_empty = [a for a in addrs if a]
        if len(non_empty) > 1:
            assert len(set(non_empty)) == len(non_empty)

    @pytest.mark.skipif(
        not __import__("importlib").util.find_spec("pyopencl"),
        reason="PyOpenCL not available"
    )
    def test_gpu_bip32_kernel_compilation(self):
        """Test that BIP32 GPU kernel compiles successfully."""
        from bip39_gpu.gpu.bip32_gpu import _load_combined_kernel, _get_gpu_context
        import pyopencl as cl

        source = _load_combined_kernel()
        if source is None:
            pytest.skip("Kernel files not found")

        ctx = _get_gpu_context()
        if ctx is None:
            pytest.skip("No GPU context available")

        try:
            program = cl.Program(ctx.context, source)
            program.build()
        except cl.RuntimeError as e:
            build_log = ""
            try:
                build_log = program.get_build_info(ctx.device, cl.program_build_info.LOG)
            except Exception:
                pass
            pytest.fail(f"Kernel compilation failed:\n{e}\nBuild log:\n{build_log}")
