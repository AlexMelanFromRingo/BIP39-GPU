#!/usr/bin/env python3
"""Basic BIP39 mnemonic generation example."""

from bip39_gpu import BIP39Mnemonic


def main():
    print("=" * 60)
    print("BIP39 Mnemonic Generation Examples")
    print("=" * 60)
    print()

    # Example 1: Generate 12-word mnemonic
    print("1. Generate 12-word mnemonic:")
    mnemonic_12 = BIP39Mnemonic.generate(words=12)
    print(f"   {mnemonic_12}")
    print(f"   Valid: {BIP39Mnemonic.validate(mnemonic_12)}")
    print()

    # Example 2: Generate 24-word mnemonic
    print("2. Generate 24-word mnemonic:")
    mnemonic_24 = BIP39Mnemonic.generate(words=24)
    print(f"   {mnemonic_24}")
    print(f"   Valid: {BIP39Mnemonic.validate(mnemonic_24)}")
    print()

    # Example 3: Convert mnemonic to seed (no passphrase)
    print("3. Convert mnemonic to seed (no passphrase):")
    seed = BIP39Mnemonic.to_seed(mnemonic_12, passphrase="")
    print(f"   Seed (hex): {seed.hex()}")
    print(f"   Seed length: {len(seed)} bytes")
    print()

    # Example 4: Convert mnemonic to seed (with passphrase)
    print("4. Convert mnemonic to seed (with passphrase):")
    seed_with_pass = BIP39Mnemonic.to_seed(mnemonic_12, passphrase="my secret")
    print(f"   Seed (hex): {seed_with_pass.hex()}")
    print(f"   Note: Different seed due to passphrase!")
    print()

    # Example 5: Validate known mnemonic
    print("5. Validate a known test mnemonic:")
    test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    is_valid = BIP39Mnemonic.validate(test_mnemonic)
    print(f"   Mnemonic: {test_mnemonic}")
    print(f"   Valid: {is_valid}")
    print()

    # Example 6: Custom entropy
    print("6. Generate from custom entropy:")
    import secrets
    custom_entropy = secrets.token_bytes(16)  # 16 bytes = 128 bits = 12 words
    custom_mnemonic = BIP39Mnemonic.from_entropy(custom_entropy)
    print(f"   Entropy (hex): {custom_entropy.hex()}")
    print(f"   Mnemonic: {custom_mnemonic}")
    print()

    # Example 7: Extract entropy from mnemonic
    print("7. Extract entropy from mnemonic:")
    extracted_entropy = BIP39Mnemonic.to_entropy(custom_mnemonic)
    print(f"   Original entropy: {custom_entropy.hex()}")
    print(f"   Extracted entropy: {extracted_entropy.hex()}")
    print(f"   Match: {custom_entropy == extracted_entropy}")
    print()

    print("=" * 60)
    print("All examples completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
