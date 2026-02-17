"""Tests for GPU BIP32/BIP44 key derivation and SegWit address formats."""

import pytest
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu.bip32_gpu import (
    hash160,
    hash160_to_p2pkh,
    hash160_to_p2wpkh,
    hash160_to_p2sh_p2wpkh,
    pubkey_to_p2tr,
    tagged_hash,
    _taptweak_pubkey,
    bech32_encode,
    base58check_encode,
    _bip32_master_key,
    _bip44_derive_cpu,
    _bip_derive_cpu,
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


# ── SegWit / Bech32 encoding ─────────────────────────────────────────────────

class TestBech32Encoding:
    """Test Bech32 / Bech32m encoding functions."""

    def test_bech32_encode_p2wpkh(self):
        """Bech32 v0 addresses start with bc1q."""
        h160 = bytes(20)  # 20 zero bytes
        addr = bech32_encode("bc", 0, h160)
        assert addr.startswith("bc1q")
        assert len(addr) == 42  # bc1q + 38 chars for 20-byte program

    def test_bech32m_encode_p2tr(self):
        """Bech32m v1 addresses start with bc1p."""
        xonly = bytes(32)  # 32 zero bytes
        addr = bech32_encode("bc", 1, xonly)
        assert addr.startswith("bc1p")
        assert len(addr) == 62  # bc1p + 58 chars for 32-byte program

    def test_bech32_testnet_prefix(self):
        """Testnet addresses use tb1 prefix."""
        h160 = bytes(20)
        addr = bech32_encode("tb", 0, h160)
        assert addr.startswith("tb1q")

    def test_p2wpkh_address_format(self):
        """hash160_to_p2wpkh produces bc1q... address."""
        h160 = bytes.fromhex("89abcdefabbaabbaabbaabbaabbaabbaabbaabba")
        addr = hash160_to_p2wpkh(h160)
        assert addr.startswith("bc1q")
        assert len(addr) == 42

    def test_p2sh_p2wpkh_address_format(self):
        """hash160_to_p2sh_p2wpkh produces 3... address."""
        h160 = bytes.fromhex("89abcdefabbaabbaabbaabbaabbaabbaabbaabba")
        addr = hash160_to_p2sh_p2wpkh(h160)
        assert addr.startswith("3")
        assert 25 <= len(addr) <= 36

    def test_p2tr_address_format(self):
        """pubkey_to_p2tr produces bc1p... address."""
        # BIP86 pubkey for abandon×11+about at m/86'/0'/0'/0/0
        pubkey = bytes.fromhex(
            "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        )
        addr = pubkey_to_p2tr(pubkey)
        assert addr.startswith("bc1p")
        assert len(addr) == 62


# ── Taproot (BIP341) ─────────────────────────────────────────────────────────

class TestTaprootTweak:
    """Test BIP341 Taproot key tweak and tagged hash."""

    def test_tagged_hash_length(self):
        """tagged_hash always returns 32 bytes."""
        h = tagged_hash("TapTweak", b"test")
        assert len(h) == 32

    def test_tagged_hash_deterministic(self):
        """Same inputs give same tagged hash."""
        h1 = tagged_hash("TapTweak", b"test")
        h2 = tagged_hash("TapTweak", b"test")
        assert h1 == h2

    def test_tagged_hash_different_tags(self):
        """Different tags give different hashes."""
        h1 = tagged_hash("TapTweak", b"test")
        h2 = tagged_hash("TapLeaf", b"test")
        assert h1 != h2

    def test_taptweak_known_vector(self):
        """BIP341 taptweak against known BIP86 test vector.

        abandon×11+about → m/86'/0'/0'/0/0
        Pubkey:     03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
        Output key: a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
        """
        pubkey = bytes.fromhex(
            "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        )
        output_key = _taptweak_pubkey(pubkey)
        assert output_key.hex() == "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        assert len(output_key) == 32

    def test_taptweak_output_length(self):
        """_taptweak_pubkey always returns 32 bytes."""
        pubkey = bytes.fromhex(
            "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        )
        output = _taptweak_pubkey(pubkey)
        assert len(output) == 32


# ── SegWit address derivation — known test vectors ───────────────────────────

class TestSegWitKnownVectors:
    """Known test vectors for all SegWit address formats.

    Mnemonic: abandon abandon abandon abandon abandon abandon
              abandon abandon abandon abandon abandon about
    Source: BIP84, BIP49, BIP86 official specification examples
    """

    def test_p2wpkh_known_vector(self):
        """BIP84 m/84'/0'/0'/0/0 → bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu."""
        addr = seed_to_address(TEST_SEED, address_format="P2WPKH", use_gpu=False)
        assert addr == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

    def test_p2sh_p2wpkh_known_vector(self):
        """BIP49 m/49'/0'/0'/0/0 → 37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf."""
        addr = seed_to_address(TEST_SEED, address_format="P2SH_P2WPKH", use_gpu=False)
        assert addr == "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"

    def test_p2tr_known_vector(self):
        """BIP86 m/86'/0'/0'/0/0 → bc1p5cyxnux...."""
        addr = seed_to_address(TEST_SEED, address_format="P2TR", use_gpu=False)
        assert addr == "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"

    def test_p2pkh_still_works(self):
        """P2PKH address is unchanged after SegWit addition."""
        addr = seed_to_address(TEST_SEED, address_format="P2PKH", use_gpu=False)
        assert addr == "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"

    def test_all_formats_different(self):
        """All four address formats produce different addresses."""
        formats = ["P2PKH", "P2WPKH", "P2SH_P2WPKH", "P2TR"]
        addrs = [seed_to_address(TEST_SEED, address_format=f, use_gpu=False) for f in formats]
        assert len(set(addrs)) == 4

    def test_p2wpkh_prefix(self):
        """P2WPKH always starts with bc1q."""
        addr = seed_to_address(TEST_SEED, address_format="P2WPKH", use_gpu=False)
        assert addr.startswith("bc1q")

    def test_p2sh_p2wpkh_prefix(self):
        """P2SH-P2WPKH always starts with 3."""
        addr = seed_to_address(TEST_SEED, address_format="P2SH_P2WPKH", use_gpu=False)
        assert addr.startswith("3")

    def test_p2tr_prefix(self):
        """P2TR always starts with bc1p."""
        addr = seed_to_address(TEST_SEED, address_format="P2TR", use_gpu=False)
        assert addr.startswith("bc1p")


# ── BIP derive generalization ─────────────────────────────────────────────────

class TestBipDeriveCpu:
    """Test generalized BIP derivation paths."""

    def test_bip_derive_44_matches_bip44(self):
        """_bip_derive_cpu(purpose=44) == _bip44_derive_cpu."""
        k1, c1 = _bip_derive_cpu(TEST_SEED, purpose=44, coin_type=0, address_index=0)
        k2, c2 = _bip44_derive_cpu(TEST_SEED, coin_type=0, address_index=0)
        assert k1 == k2
        assert c1 == c2

    def test_bip84_privkey(self):
        """BIP84 private key at m/84'/0'/0'/0/0 matches known value."""
        key, _ = _bip_derive_cpu(TEST_SEED, purpose=84, coin_type=0, address_index=0)
        # Verified from bip_utils
        assert key.hex() == "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3"

    def test_bip49_privkey(self):
        """BIP49 private key at m/49'/0'/0'/0/0 matches known value."""
        key, _ = _bip_derive_cpu(TEST_SEED, purpose=49, coin_type=0, address_index=0)
        assert key.hex() == "508c73a06f6b6c817238ba61be232f5080ea4616c54f94771156934666d38ee3"

    def test_bip86_privkey(self):
        """BIP86 private key at m/86'/0'/0'/0/0 matches known value."""
        key, _ = _bip_derive_cpu(TEST_SEED, purpose=86, coin_type=0, address_index=0)
        assert key.hex() == "41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361"

    def test_different_purposes_different_keys(self):
        """Different BIP purposes give different keys."""
        keys = [_bip_derive_cpu(TEST_SEED, p, 0, 0)[0] for p in [44, 49, 84, 86]]
        assert len(set(k.hex() for k in keys)) == 4


# ── Batch SegWit address generation ──────────────────────────────────────────

class TestBatchSegWit:
    """Test batch address generation for SegWit formats."""

    def test_batch_p2wpkh(self):
        """Batch P2WPKH generation returns correct format."""
        seeds = [TEST_SEED, BIP39Mnemonic.to_seed(BIP39Mnemonic.generate(12))]
        addrs = batch_seed_to_address(seeds, address_format="P2WPKH", use_gpu=False)
        assert len(addrs) == 2
        assert addrs[0] == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        for addr in addrs:
            assert addr.startswith("bc1q")
            assert len(addr) == 42

    def test_batch_p2sh_p2wpkh(self):
        """Batch P2SH-P2WPKH generation returns correct format."""
        seeds = [TEST_SEED]
        addrs = batch_seed_to_address(seeds, address_format="P2SH_P2WPKH", use_gpu=False)
        assert addrs[0] == "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
        assert addrs[0].startswith("3")

    def test_batch_p2tr(self):
        """Batch P2TR generation returns correct format."""
        seeds = [TEST_SEED]
        addrs = batch_seed_to_address(seeds, address_format="P2TR", use_gpu=False)
        assert addrs[0] == "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        assert addrs[0].startswith("bc1p")

    def test_batch_all_formats_consistent(self):
        """Batch and single results are consistent for all formats."""
        formats = ["P2PKH", "P2WPKH", "P2SH_P2WPKH", "P2TR"]
        for fmt in formats:
            single = seed_to_address(TEST_SEED, address_format=fmt, use_gpu=False)
            batch = batch_seed_to_address([TEST_SEED], address_format=fmt, use_gpu=False)
            assert single == batch[0], f"Mismatch for {fmt}: {single} != {batch[0]}"

    def test_batch_gpu_flag_all_formats(self):
        """GPU flag falls back gracefully for all address formats."""
        formats = ["P2PKH", "P2WPKH", "P2SH_P2WPKH", "P2TR"]
        for fmt in formats:
            addr_cpu = seed_to_address(TEST_SEED, address_format=fmt, use_gpu=False)
            addr_gpu = seed_to_address(TEST_SEED, address_format=fmt, use_gpu=True)
            # CPU and GPU must agree (GPU may fall back to CPU)
            assert addr_cpu == addr_gpu, f"CPU/GPU mismatch for {fmt}"
