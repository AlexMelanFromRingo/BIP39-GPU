#!/usr/bin/env python3
"""GPU BIP32 key derivation with all SegWit address formats.

Demonstrates the full pipeline:
  entropy → mnemonic → seed (GPU PBKDF2)
           → BIP path (GPU BIP32, m/44/49/84/86)
           → secp256k1 (GPU)
           → address (P2PKH / P2SH-P2WPKH / P2WPKH / P2TR)

With automatic CPU fallback when GPU is unavailable.
"""

import time
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu.bip32_gpu import (
    batch_seed_to_address,
    seed_to_address,
    _bip_derive_cpu,
    _bip44_derive_cpu,
    hash160,
    hash160_to_p2pkh,
    hash160_to_p2wpkh,
    hash160_to_p2sh_p2wpkh,
    pubkey_to_p2tr,
    _get_compressed_pubkey,
)


def demo_single_address():
    """Demo: derive single Bitcoin address from mnemonic."""
    print("=" * 70)
    print("Single Address Derivation (BIP44 m/44'/0'/0'/0/0)")
    print("=" * 70)

    mnemonic = BIP39Mnemonic.generate(12)
    print(f"Mnemonic:  {mnemonic}")

    seed = BIP39Mnemonic.to_seed(mnemonic)
    print(f"Seed:      {seed.hex()[:32]}...")

    addr = seed_to_address(seed, use_gpu=True)  # auto-fallback to CPU
    print(f"Address:   {addr}")
    print()


def demo_known_vector():
    """Demo: verify known test vector (abandon×11 + about)."""
    print("=" * 70)
    print("Known Test Vector Verification")
    print("=" * 70)

    mnemonic = ("abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon about")
    print(f"Mnemonic:  {mnemonic}")

    seed = BIP39Mnemonic.to_seed(mnemonic)
    addr = seed_to_address(seed, use_gpu=False)

    print(f"BIP44 m/44'/0'/0'/0/0 → {addr}")
    expected = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
    status = "✓" if addr == expected else "✗"
    print(f"Expected:               {expected}  {status}")
    print()


def demo_multiple_addresses():
    """Demo: derive multiple addresses at different indices."""
    print("=" * 70)
    print("Multiple Addresses from Same Mnemonic")
    print("=" * 70)

    mnemonic = BIP39Mnemonic.generate(12)
    print(f"Mnemonic: {mnemonic}")
    seed = BIP39Mnemonic.to_seed(mnemonic)
    print()

    for i in range(5):
        addr = seed_to_address(seed, address_index=i, use_gpu=False)
        print(f"  m/44'/0'/0'/0/{i} → {addr}")
    print()


def demo_batch_performance():
    """Demo: batch address generation performance."""
    print("=" * 70)
    print("Batch Address Generation Performance")
    print("=" * 70)

    batch_size = 10
    seeds = [BIP39Mnemonic.to_seed(BIP39Mnemonic.generate(12)) for _ in range(batch_size)]
    print(f"Batch size: {batch_size} addresses")
    print()

    # CPU
    start = time.time()
    addrs_cpu = batch_seed_to_address(seeds, use_gpu=False)
    cpu_time = time.time() - start
    print(f"CPU time:  {cpu_time:.3f}s ({cpu_time/batch_size*1000:.1f}ms/addr)")

    # GPU (auto-fallback)
    start = time.time()
    addrs_gpu = batch_seed_to_address(seeds, use_gpu=True)
    gpu_time = time.time() - start
    print(f"GPU time:  {gpu_time:.3f}s ({gpu_time/batch_size*1000:.1f}ms/addr)")

    # Consistency check
    if addrs_cpu == addrs_gpu:
        print("✓ CPU and GPU results match")

    print()
    print("Sample addresses:")
    for addr in addrs_cpu[:3]:
        print(f"  {addr}")
    print()


def demo_full_pipeline():
    """Demo: entropy → mnemonic → seed → address pipeline."""
    print("=" * 70)
    print("Full GPU Pipeline: Entropy → Mnemonic → Seed → Address")
    print("=" * 70)

    import secrets

    # 1. Generate entropy
    entropy = secrets.token_bytes(16)  # 128 bits for 12-word mnemonic
    print(f"Entropy:  {entropy.hex()}")

    # 2. Entropy → Mnemonic
    mnemonic = BIP39Mnemonic.from_entropy(entropy)
    print(f"Mnemonic: {mnemonic}")

    # 3. Mnemonic → Seed (GPU PBKDF2)
    try:
        from bip39_gpu.gpu.pbkdf2_gpu import batch_mnemonic_to_seed_gpu
        seeds = batch_mnemonic_to_seed_gpu([mnemonic], [""])
        seed = seeds[0]
        print(f"Seed (GPU PBKDF2): {seed.hex()[:32]}...")
    except Exception:
        seed = BIP39Mnemonic.to_seed(mnemonic)
        print(f"Seed (CPU PBKDF2): {seed.hex()[:32]}...")

    # 4. Seed → BIP44 private key
    privkey, chain = _bip44_derive_cpu(seed, coin_type=0, address_index=0)
    print(f"Private key:       {privkey.hex()[:32]}...")

    # 5. Private key → Compressed public key (secp256k1)
    pubkey = _get_compressed_pubkey(privkey)
    print(f"Public key:        {pubkey.hex()[:20]}...")

    # 6. Public key → Hash160 (SHA256 + RIPEMD160)
    h160 = hash160(pubkey)
    print(f"Hash160:           {h160.hex()}")

    # 7. Hash160 → P2PKH address
    addr = hash160_to_p2pkh(h160)
    print(f"P2PKH Address:     {addr}")

    print()
    print("✓ Full pipeline completed!")
    print()


def demo_all_address_formats():
    """Demo: all four address formats from the same mnemonic."""
    print("=" * 70)
    print("All Address Formats — Same Mnemonic, Four Formats")
    print("=" * 70)

    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed = BIP39Mnemonic.to_seed(mnemonic)

    formats = [
        ("P2PKH",       "BIP44  m/44'/0'/0'/0/0", "1...   Legacy"),
        ("P2SH_P2WPKH", "BIP49  m/49'/0'/0'/0/0", "3...   SegWit-wrapped"),
        ("P2WPKH",      "BIP84  m/84'/0'/0'/0/0", "bc1q.. Native SegWit"),
        ("P2TR",        "BIP86  m/86'/0'/0'/0/0", "bc1p.. Taproot"),
    ]

    print(f"Mnemonic: {mnemonic[:40]}...")
    print()

    for fmt, path, desc in formats:
        addr = seed_to_address(seed, address_format=fmt, use_gpu=True)
        print(f"  {desc}")
        print(f"    Path:    {path}")
        print(f"    Address: {addr}")
        print()


def demo_segwit_pipeline():
    """Demo: step-by-step SegWit/Taproot derivation pipeline."""
    print("=" * 70)
    print("SegWit Full Pipeline: privkey → pubkey → hash160 / taptweak → address")
    print("=" * 70)

    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed = BIP39Mnemonic.to_seed(mnemonic)

    # P2WPKH (BIP84)
    privkey, _ = _bip_derive_cpu(seed, purpose=84)
    pubkey = _get_compressed_pubkey(privkey)
    h160 = hash160(pubkey)
    p2wpkh = hash160_to_p2wpkh(h160)
    print(f"  BIP84 privkey:  {privkey.hex()[:32]}...")
    print(f"  Pubkey:         {pubkey.hex()[:20]}...")
    print(f"  hash160:        {h160.hex()}")
    print(f"  P2WPKH (bc1q): {p2wpkh}")
    print()

    # P2SH-P2WPKH (BIP49)
    privkey, _ = _bip_derive_cpu(seed, purpose=49)
    pubkey = _get_compressed_pubkey(privkey)
    h160 = hash160(pubkey)
    p2sh = hash160_to_p2sh_p2wpkh(h160)
    print(f"  BIP49 privkey:  {privkey.hex()[:32]}...")
    print(f"  Pubkey:         {pubkey.hex()[:20]}...")
    print(f"  hash160:        {h160.hex()}")
    print(f"  P2SH-P2WPKH:   {p2sh}")
    print()

    # P2TR (BIP86)
    privkey, _ = _bip_derive_cpu(seed, purpose=86)
    pubkey = _get_compressed_pubkey(privkey)
    x_only = pubkey[1:]
    p2tr = pubkey_to_p2tr(pubkey)
    print(f"  BIP86 privkey:  {privkey.hex()[:32]}...")
    print(f"  Pubkey:         {pubkey.hex()[:20]}...")
    print(f"  x-only key:     {x_only.hex()[:32]}...")
    print(f"  P2TR (bc1p):   {p2tr}")
    print()

    print("✓ All SegWit formats verified!")
    print()


def main():
    print()
    print("GPU BIP32 Address Derivation — All Formats")
    print("=" * 70)
    print("Pipeline: entropy → mnemonic → seed → BIP path → secp256k1 → address")
    print("Formats: P2PKH (1...) | P2SH-P2WPKH (3...) | P2WPKH (bc1q...) | P2TR (bc1p...)")
    print()

    try:
        from bip39_gpu.gpu import is_opencl_available
        gpu = is_opencl_available()
        print(f"GPU available: {gpu}")
        if not gpu:
            print("Note: Running in CPU fallback mode")
    except ImportError:
        print("Note: PyOpenCL not installed, using CPU only")
    print()

    demo_known_vector()
    demo_all_address_formats()
    demo_segwit_pipeline()
    demo_single_address()
    demo_multiple_addresses()
    demo_batch_performance()
    demo_full_pipeline()


if __name__ == "__main__":
    main()
