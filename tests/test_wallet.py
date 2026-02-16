"""Tests for wallet address generation."""

import pytest

try:
    from bip39_gpu.wallet import (
        HDWallet,
        DerivationPath,
        detect_address_format,
        is_valid_bitcoin_address,
    )
    from bip39_gpu import BIP39Mnemonic
    BIP_UTILS_AVAILABLE = True
except ImportError:
    BIP_UTILS_AVAILABLE = False
    pytest.skip("bip-utils not installed", allow_module_level=True)


# Test mnemonic (BIP39 standard test vector)
TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


class TestHDWallet:
    """Test HD wallet address generation."""

    def test_wallet_creation(self):
        """Test wallet can be created from mnemonic."""
        wallet = HDWallet(TEST_MNEMONIC)
        assert wallet.mnemonic == TEST_MNEMONIC
        assert wallet.passphrase == ""

    def test_wallet_with_passphrase(self):
        """Test wallet creation with passphrase."""
        wallet = HDWallet(TEST_MNEMONIC, passphrase="test")
        assert wallet.passphrase == "test"

    def test_invalid_mnemonic_raises_error(self):
        """Test invalid mnemonic raises error."""
        from bip39_gpu.utils.exceptions import InvalidMnemonicError

        with pytest.raises(InvalidMnemonicError):
            HDWallet("invalid mnemonic phrase")

    def test_derive_p2pkh_address(self):
        """Test P2PKH address derivation."""
        wallet = HDWallet(TEST_MNEMONIC)
        addr = wallet.derive_address(format="P2PKH")

        assert addr.startswith("1")
        assert len(addr) >= 26
        assert len(addr) <= 35

    def test_derive_p2sh_address(self):
        """Test P2SH address derivation."""
        wallet = HDWallet(TEST_MNEMONIC)
        addr = wallet.derive_address(format="P2SH")

        assert addr.startswith("3")
        assert len(addr) >= 26
        assert len(addr) <= 35

    def test_derive_bech32_address(self):
        """Test Bech32 address derivation."""
        wallet = HDWallet(TEST_MNEMONIC)
        addr = wallet.derive_address(format="Bech32")

        assert addr.startswith("bc1")
        assert len(addr) >= 42

    def test_derive_taproot_address(self):
        """Test Taproot address derivation."""
        wallet = HDWallet(TEST_MNEMONIC)
        addr = wallet.derive_address(format="Taproot")

        assert addr.startswith("bc1p")
        assert len(addr) == 62  # Taproot addresses are exactly 62 chars

    def test_derive_multiple_addresses(self):
        """Test deriving multiple addresses."""
        wallet = HDWallet(TEST_MNEMONIC)
        addrs = wallet.derive_addresses(count=5, format="P2PKH")

        assert len(addrs) == 5
        # All addresses should be unique
        assert len(set(addrs)) == 5
        # All should be P2PKH
        for addr in addrs:
            assert addr.startswith("1")

    def test_different_accounts_different_addresses(self):
        """Test different accounts produce different addresses."""
        wallet = HDWallet(TEST_MNEMONIC)

        addr0 = wallet.derive_address(account=0, format="P2PKH")
        addr1 = wallet.derive_address(account=1, format="P2PKH")

        assert addr0 != addr1

    def test_deterministic_address_generation(self):
        """Test address generation is deterministic."""
        wallet1 = HDWallet(TEST_MNEMONIC)
        wallet2 = HDWallet(TEST_MNEMONIC)

        addr1 = wallet1.derive_address(format="Bech32")
        addr2 = wallet2.derive_address(format="Bech32")

        assert addr1 == addr2


class TestDerivationPath:
    """Test derivation path utilities."""

    def test_parse_bip44_path(self):
        """Test parsing BIP44 path."""
        path = "m/44'/0'/0'/0/0"
        parsed = DerivationPath.parse(path)

        assert parsed == [
            (44, True),
            (0, True),
            (0, True),
            (0, False),
            (0, False),
        ]

    def test_build_bip44_path(self):
        """Test building BIP44 path."""
        path = DerivationPath.build_bip44(account=0, address_index=5)
        assert path == "m/44'/0'/0'/0/5"

    def test_build_bip49_path(self):
        """Test building BIP49 path."""
        path = DerivationPath.build_bip49(account=1, address_index=10)
        assert path == "m/49'/0'/1'/0/10"

    def test_build_bip84_path(self):
        """Test building BIP84 path."""
        path = DerivationPath.build_bip84(account=2, change=1, address_index=20)
        assert path == "m/84'/0'/2'/1/20"

    def test_build_bip86_path(self):
        """Test building BIP86 path."""
        path = DerivationPath.build_bip86(account=0, address_index=0)
        assert path == "m/86'/0'/0'/0/0"

        path2 = DerivationPath.build_bip86(account=1, change=1, address_index=5)
        assert path2 == "m/86'/0'/1'/1/5"

    def test_validate_path(self):
        """Test path validation."""
        assert DerivationPath.validate("m/44'/0'/0'/0/0")
        assert DerivationPath.validate("m/49'/0'/1'/0/5")
        assert DerivationPath.validate("m/44/0/0/0/0")  # Non-hardened (valid but uncommon)
        assert not DerivationPath.validate("invalid/path")
        assert not DerivationPath.validate("44'/0'/0'/0/0")  # Missing 'm/'


class TestAddressFormats:
    """Test address format detection and validation."""

    def test_detect_p2pkh(self):
        """Test P2PKH detection."""
        addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        assert detect_address_format(addr) == "P2PKH"

    def test_detect_p2sh(self):
        """Test P2SH detection."""
        addr = "3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy"
        assert detect_address_format(addr) == "P2SH"

    def test_detect_bech32(self):
        """Test Bech32 detection."""
        addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        assert detect_address_format(addr) == "Bech32"

    def test_detect_taproot(self):
        """Test Taproot detection."""
        addr = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        assert detect_address_format(addr) == "Taproot"

    def test_detect_unknown(self):
        """Test unknown format detection."""
        addr = "invalid_address"
        assert detect_address_format(addr) == "Unknown"

    def test_is_valid_bitcoin_address_p2pkh(self):
        """Test P2PKH address validation."""
        addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        assert is_valid_bitcoin_address(addr)

    def test_is_valid_bitcoin_address_bech32(self):
        """Test Bech32 address validation."""
        addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        assert is_valid_bitcoin_address(addr)

    def test_is_valid_bitcoin_address_invalid(self):
        """Test invalid address."""
        assert not is_valid_bitcoin_address("invalid")
        assert not is_valid_bitcoin_address("1A")  # Too short
        assert not is_valid_bitcoin_address("bc1")  # Too short
