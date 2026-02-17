#!/usr/bin/env python3
"""GPU BIP32/BIP44 key derivation example.

Demonstrates the full pipeline running on GPU:
  entropy → mnemonic → seed (GPU PBKDF2)
           → BIP44 path (GPU BIP32)
           → secp256k1 (GPU)
           → hash160 (GPU SHA256 + RIPEMD160)
           → P2PKH address

With automatic CPU fallback when GPU is unavailable.
"""

import time
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu.bip32_gpu import (
    batch_seed_to_address,
    seed_to_address,
    _bip44_derive_cpu,
    hash160,
    hash160_to_p2pkh,
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


def main():
    print()
    print("GPU BIP32/BIP44 Address Derivation")
    print("=" * 70)
    print("Full pipeline: entropy → mnemonic → seed → BIP32 → secp256k1 → address")
    print("GPU kernels: SHA-256, SHA-512, RIPEMD-160, secp256k1, PBKDF2")
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
    demo_single_address()
    demo_multiple_addresses()
    demo_batch_performance()
    demo_full_pipeline()


if __name__ == "__main__":
    main()
