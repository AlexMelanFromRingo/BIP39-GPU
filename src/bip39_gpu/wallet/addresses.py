"""Bitcoin address generation from BIP39 mnemonics using BIP32/BIP44."""

from typing import List, Optional, Literal
import warnings

try:
    from bip_utils import (
        Bip39SeedGenerator,
        Bip44,
        Bip44Coins,
        Bip44Changes,
        Bip49,
        Bip49Coins,
        Bip84,
        Bip84Coins,
    )
    BIP_UTILS_AVAILABLE = True
except ImportError:
    BIP_UTILS_AVAILABLE = False
    warnings.warn("bip-utils not installed. Address generation not available.")

from ..core.mnemonic import BIP39Mnemonic
from ..utils.exceptions import InvalidDerivationPathError

AddressFormat = Literal["P2PKH", "P2SH", "Bech32"]


class HDWallet:
    """Hierarchical Deterministic Wallet for address generation."""

    def __init__(self, mnemonic: str, passphrase: str = ""):
        """Initialize HD wallet from mnemonic.

        Args:
            mnemonic: BIP39 mnemonic phrase
            passphrase: Optional BIP39 passphrase (default: "")

        Raises:
            ImportError: If bip-utils is not installed
            InvalidMnemonicError: If mnemonic is invalid
        """
        if not BIP_UTILS_AVAILABLE:
            raise ImportError(
                "bip-utils is required for address generation. "
                "Install with: pip install bip-utils"
            )

        # Validate mnemonic
        if not BIP39Mnemonic.validate(mnemonic):
            from ..utils.exceptions import InvalidMnemonicError
            raise InvalidMnemonicError("Invalid mnemonic phrase")

        self.mnemonic = mnemonic
        self.passphrase = passphrase

        # Generate seed using bip-utils
        self.seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)

    def derive_address(
        self,
        path: Optional[str] = None,
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
        coin: str = "BTC",
        format: AddressFormat = "P2PKH"
    ) -> str:
        """Derive a single address.

        Args:
            path: Custom derivation path (e.g., "m/44'/0'/0'/0/0")
                  If None, uses account/change/address_index
            account: Account index (default: 0)
            change: Change type (0=external, 1=internal) (default: 0)
            address_index: Address index (default: 0)
            coin: Coin symbol (default: "BTC")
            format: Address format - "P2PKH" (1...), "P2SH" (3...), or "Bech32" (bc1...)

        Returns:
            Bitcoin address string

        Raises:
            ValueError: If format is invalid
            InvalidDerivationPathError: If path is invalid

        Example:
            >>> wallet = HDWallet(mnemonic)
            >>> addr = wallet.derive_address(address_index=0, format="P2PKH")
            >>> addr.startswith('1')
            True
        """
        if coin != "BTC":
            raise ValueError(f"Only BTC is currently supported, got: {coin}")

        try:
            # Select BIP standard based on format
            if format == "P2PKH":
                # BIP44: P2PKH addresses (1...)
                bip = Bip44.FromSeed(self.seed_bytes, Bip44Coins.BITCOIN)
                bip = bip.Purpose().Coin().Account(account)
                bip = bip.Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT)
                bip = bip.AddressIndex(address_index)
                return bip.PublicKey().ToAddress()

            elif format == "P2SH":
                # BIP49: P2SH-wrapped SegWit addresses (3...)
                bip = Bip49.FromSeed(self.seed_bytes, Bip49Coins.BITCOIN)
                bip = bip.Purpose().Coin().Account(account)
                bip = bip.Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT)
                bip = bip.AddressIndex(address_index)
                return bip.PublicKey().ToAddress()

            elif format == "Bech32":
                # BIP84: Native SegWit addresses (bc1...)
                bip = Bip84.FromSeed(self.seed_bytes, Bip84Coins.BITCOIN)
                bip = bip.Purpose().Coin().Account(account)
                bip = bip.Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT)
                bip = bip.AddressIndex(address_index)
                return bip.PublicKey().ToAddress()

            else:
                raise ValueError(
                    f"Invalid format: {format}. "
                    f"Must be one of: P2PKH, P2SH, Bech32"
                )

        except Exception as e:
            raise InvalidDerivationPathError(f"Failed to derive address: {e}")

    def derive_addresses(
        self,
        count: int = 10,
        start_index: int = 0,
        account: int = 0,
        change: int = 0,
        coin: str = "BTC",
        format: AddressFormat = "P2PKH"
    ) -> List[str]:
        """Derive multiple addresses.

        Args:
            count: Number of addresses to derive (default: 10)
            start_index: Starting address index (default: 0)
            account: Account index (default: 0)
            change: Change type (0=external, 1=internal) (default: 0)
            coin: Coin symbol (default: "BTC")
            format: Address format

        Returns:
            List of Bitcoin addresses

        Example:
            >>> wallet = HDWallet(mnemonic)
            >>> addrs = wallet.derive_addresses(count=5, format="Bech32")
            >>> len(addrs)
            5
        """
        addresses = []

        for i in range(start_index, start_index + count):
            address = self.derive_address(
                account=account,
                change=change,
                address_index=i,
                coin=coin,
                format=format
            )
            addresses.append(address)

        return addresses

    def get_extended_key(
        self,
        private: bool = False,
        account: int = 0,
        format: AddressFormat = "P2PKH"
    ) -> str:
        """Get extended public or private key.

        Args:
            private: Return private key if True, public if False (default: False)
            account: Account index (default: 0)
            format: Address format to determine BIP standard

        Returns:
            Extended key string (xpub/xprv, ypub/yprv, or zpub/zprv)
        """
        try:
            if format == "P2PKH":
                bip = Bip44.FromSeed(self.seed_bytes, Bip44Coins.BITCOIN)
                bip = bip.Purpose().Coin().Account(account)
            elif format == "P2SH":
                bip = Bip49.FromSeed(self.seed_bytes, Bip49Coins.BITCOIN)
                bip = bip.Purpose().Coin().Account(account)
            elif format == "Bech32":
                bip = Bip84.FromSeed(self.seed_bytes, Bip84Coins.BITCOIN)
                bip = bip.Purpose().Coin().Account(account)
            else:
                raise ValueError(f"Invalid format: {format}")

            if private:
                return bip.PrivateKey().Raw().ToHex()
            else:
                return bip.PublicKey().RawCompressed().ToHex()

        except Exception as e:
            raise InvalidDerivationPathError(f"Failed to get extended key: {e}")
