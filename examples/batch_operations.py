#!/usr/bin/env python3
"""Batch operations example.

This example demonstrates:
- Generating multiple mnemonics
- Batch seed generation
- Batch address derivation
- Performance considerations
"""

from bip39_gpu import BIP39Mnemonic
import time


def main():
    print("=" * 70)
    print("Batch Operations Example")
    print("=" * 70)
    print()

    # 1. Generate multiple mnemonics
    print("1. Generating 10 random mnemonics:")
    mnemonics = []
    for i in range(10):
        m = BIP39Mnemonic.generate(words=12)
        mnemonics.append(m)
        print(f"   [{i}] {m[:40]}...")
    print()

    # 2. Batch validation
    print("2. Batch validation:")
    start = time.time()
    valid_count = sum(1 for m in mnemonics if BIP39Mnemonic.validate(m))
    elapsed = time.time() - start
    print(f"   Total:     {len(mnemonics)}")
    print(f"   Valid:     {valid_count}")
    print(f"   Time:      {elapsed*1000:.2f}ms")
    print()

    # 3. Batch seed generation (CPU)
    print("3. Batch seed generation (no passphrase):")
    start = time.time()
    seeds = [BIP39Mnemonic.to_seed(m, passphrase="") for m in mnemonics]
    elapsed = time.time() - start

    print(f"   Seeds:      {len(seeds)}")
    print(f"   Total time: {elapsed*1000:.2f}ms")
    print(f"   Avg/seed:   {elapsed/len(seeds)*1000:.2f}ms")
    print(f"   First seed: {seeds[0].hex()[:32]}...")
    print()

    # 4. Different passphrases
    print("4. Same mnemonic, different passphrases:")
    test_mnemonic = mnemonics[0]
    passphrases = ["", "pass1", "pass2", "secret", "my passphrase"]

    for passphrase in passphrases:
        seed = BIP39Mnemonic.to_seed(test_mnemonic, passphrase=passphrase)
        label = f'"{passphrase}"' if passphrase else "(empty)"
        print(f"   {label:20} -> {seed.hex()[:32]}...")
    print()

    # 5. Batch address generation
    try:
        from bip39_gpu.wallet import HDWallet

        print("5. Batch address generation (first 20 Bech32 addresses):")
        wallet = HDWallet(mnemonics[0])

        start = time.time()
        addresses = wallet.derive_addresses(count=20, format="Bech32")
        elapsed = time.time() - start

        print(f"   Addresses: {len(addresses)}")
        print(f"   Time:      {elapsed*1000:.2f}ms")
        print(f"   Avg/addr:  {elapsed/len(addresses)*1000:.2f}ms")
        print(f"   First:     {addresses[0]}")
        print(f"   Last:      {addresses[-1]}")
        print()

        # 6. All formats for first 3 mnemonics
        print("6. First address for each mnemonic (all formats):")
        for i, m in enumerate(mnemonics[:3]):
            wallet = HDWallet(m)
            print(f"\n   Mnemonic {i}: {m[:30]}...")
            print(f"   P2PKH:   {wallet.derive_address(format='P2PKH')}")
            print(f"   Bech32:  {wallet.derive_address(format='Bech32')}")
            print(f"   Taproot: {wallet.derive_address(format='Taproot')}")

    except ImportError:
        print("5-6. Address generation: SKIPPED (bip-utils not installed)")

    print()
    print("=" * 70)
    print("Example completed successfully!")
    print("=" * 70)
    print()
    print("Performance tips:")
    print("  • Validation is fast (~1ms per mnemonic)")
    print("  • Seed generation is slower (~100-200ms per seed)")
    print("  • GPU acceleration helps most with batch operations")
    print("  • Address derivation is relatively fast")


if __name__ == "__main__":
    main()
