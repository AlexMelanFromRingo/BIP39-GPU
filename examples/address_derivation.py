#!/usr/bin/env python3
"""Example: Bitcoin address derivation from BIP39 mnemonics."""

from bip39_gpu import BIP39Mnemonic
from bip39_gpu.wallet import HDWallet, DerivationPath


def main():
    print("=" * 70)
    print("Bitcoin Address Derivation Examples (BIP32/BIP44)")
    print("=" * 70)
    print()

    # Generate a test mnemonic
    mnemonic = BIP39Mnemonic.generate(12)
    print(f"Generated mnemonic:\n{mnemonic}\n")

    # Create HD wallet
    wallet = HDWallet(mnemonic)

    # Example 1: Derive P2PKH (Legacy) address
    print("1. P2PKH (Legacy) Address - starts with '1'")
    p2pkh_addr = wallet.derive_address(format="P2PKH", address_index=0)
    print(f"   Address: {p2pkh_addr}")
    print(f"   Path: {DerivationPath.build_bip44(address_index=0)}")
    print()

    # Example 2: Derive P2SH (SegWit-wrapped) address
    print("2. P2SH (SegWit-wrapped) Address - starts with '3'")
    p2sh_addr = wallet.derive_address(format="P2SH", address_index=0)
    print(f"   Address: {p2sh_addr}")
    print(f"   Path: {DerivationPath.build_bip49(address_index=0)}")
    print()

    # Example 3: Derive Bech32 (Native SegWit) address
    print("3. Bech32 (Native SegWit) Address - starts with 'bc1q'")
    bech32_addr = wallet.derive_address(format="Bech32", address_index=0)
    print(f"   Address: {bech32_addr}")
    print(f"   Path: {DerivationPath.build_bip84(address_index=0)}")
    print()

    # Example 4: Derive Taproot address
    print("4. Taproot Address - starts with 'bc1p'")
    taproot_addr = wallet.derive_address(format="Taproot", address_index=0)
    print(f"   Address: {taproot_addr}")
    print(f"   Path: {DerivationPath.build_bip86(address_index=0)}")
    print()

    # Example 5: Derive multiple addresses
    print("5. Multiple Addresses (first 5 Bech32 addresses)")
    addrs = wallet.derive_addresses(count=5, format="Bech32")
    for i, addr in enumerate(addrs):
        print(f"   [{i}] {addr}")
    print()

    # Example 6: Different accounts
    print("6. Multiple Accounts (account 0, 1, 2)")
    for account in range(3):
        addr = wallet.derive_address(account=account, format="Bech32")
        print(f"   Account {account}: {addr}")
    print()

    # Example 7: Change addresses (internal addresses)
    print("7. Change Addresses (internal chain)")
    print("   External (change=0):")
    ext_addr = wallet.derive_address(change=0, format="Bech32")
    print(f"     {ext_addr}")
    print("   Internal (change=1):")
    int_addr = wallet.derive_address(change=1, format="Bech32")
    print(f"     {int_addr}")
    print()

    # Example 8: Custom derivation paths
    print("8. Custom Derivation Paths")
    paths = [
        DerivationPath.build_bip44(account=0, address_index=0),
        DerivationPath.build_bip44(account=0, address_index=1),
        DerivationPath.build_bip44(account=1, address_index=0),
    ]
    for path in paths:
        print(f"   Path: {path}")
    print()

    # Example 9: With passphrase
    print("9. Addresses with BIP39 Passphrase")
    wallet_no_pass = HDWallet(mnemonic, passphrase="")
    wallet_with_pass = HDWallet(mnemonic, passphrase="my secret")

    addr_no_pass = wallet_no_pass.derive_address(format="Bech32")
    addr_with_pass = wallet_with_pass.derive_address(format="Bech32")

    print(f"   No passphrase:   {addr_no_pass}")
    print(f"   With passphrase: {addr_with_pass}")
    print(f"   Different: {addr_no_pass != addr_with_pass}")
    print()

    print("=" * 70)
    print("All examples completed successfully!")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except ImportError as e:
        print("Error: bip-utils is required for address generation.")
        print("Install with: pip install bip-utils")
        print(f"\nDetails: {e}")
