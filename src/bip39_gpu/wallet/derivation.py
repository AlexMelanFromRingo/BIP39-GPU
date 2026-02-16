"""BIP32/BIP44 derivation path utilities."""

import re
from typing import List, Tuple, Optional


class DerivationPath:
    """BIP32 derivation path parser and builder."""

    # BIP44 path format: m / purpose' / coin_type' / account' / change / address_index
    BIP44_TEMPLATE = "m/44'/0'/{account}'/{change}/{address_index}"
    BIP49_TEMPLATE = "m/49'/0'/{account}'/{change}/{address_index}"  # P2SH-SegWit
    BIP84_TEMPLATE = "m/84'/0'/{account}'/{change}/{address_index}"  # Native SegWit

    PATH_REGEX = re.compile(r"^m(/\d+'?)+$")

    @staticmethod
    def parse(path: str) -> List[Tuple[int, bool]]:
        """Parse derivation path string.

        Args:
            path: Derivation path (e.g., "m/44'/0'/0'/0/0")

        Returns:
            List of (index, hardened) tuples

        Raises:
            ValueError: If path format is invalid

        Example:
            >>> DerivationPath.parse("m/44'/0'/0'/0/0")
            [(44, True), (0, True), (0, True), (0, False), (0, False)]
        """
        if not DerivationPath.PATH_REGEX.match(path):
            raise ValueError(f"Invalid derivation path format: {path}")

        # Remove 'm/' prefix and split
        parts = path[2:].split('/')

        result = []
        for part in parts:
            hardened = part.endswith("'")
            index_str = part.rstrip("'")

            try:
                index = int(index_str)
            except ValueError:
                raise ValueError(f"Invalid index in path: {part}")

            result.append((index, hardened))

        return result

    @staticmethod
    def build_bip44(
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
        coin_type: int = 0
    ) -> str:
        """Build BIP44 derivation path.

        Args:
            account: Account index (default: 0)
            change: Change type (0=external, 1=internal) (default: 0)
            address_index: Address index (default: 0)
            coin_type: Coin type (0=BTC, 60=ETH, etc.) (default: 0)

        Returns:
            BIP44 path string

        Example:
            >>> DerivationPath.build_bip44(account=0, address_index=5)
            "m/44'/0'/0'/0/5"
        """
        return f"m/44'/{coin_type}'/{account}'/{change}/{address_index}"

    @staticmethod
    def build_bip49(
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
        coin_type: int = 0
    ) -> str:
        """Build BIP49 derivation path (P2SH-SegWit).

        Args:
            account: Account index (default: 0)
            change: Change type (default: 0)
            address_index: Address index (default: 0)
            coin_type: Coin type (default: 0)

        Returns:
            BIP49 path string
        """
        return f"m/49'/{coin_type}'/{account}'/{change}/{address_index}"

    @staticmethod
    def build_bip84(
        account: int = 0,
        change: int = 0,
        address_index: int = 0,
        coin_type: int = 0
    ) -> str:
        """Build BIP84 derivation path (Native SegWit).

        Args:
            account: Account index (default: 0)
            change: Change type (default: 0)
            address_index: Address index (default: 0)
            coin_type: Coin type (default: 0)

        Returns:
            BIP84 path string
        """
        return f"m/84'/{coin_type}'/{account}'/{change}/{address_index}"

    @staticmethod
    def validate(path: str) -> bool:
        """Validate derivation path format.

        Args:
            path: Derivation path to validate

        Returns:
            True if valid, False otherwise
        """
        return bool(DerivationPath.PATH_REGEX.match(path))
