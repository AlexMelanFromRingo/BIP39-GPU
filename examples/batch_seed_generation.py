#!/usr/bin/env python3
"""Batch seed generation example.

This example demonstrates:
- Batch processing multiple mnemonics
- Performance benefits of batch operations
- Using different passphrases
- Comparing CPU performance
"""

from bip39_gpu import BIP39Mnemonic
from bip39_gpu.core.pbkdf2_batch import batch_mnemonic_to_seed, estimate_batch_time
import time


def main():
    print("=" * 70)
    print("Batch Seed Generation Example")
    print("=" * 70)
    print()

    # Example 1: Generate multiple mnemonics
    print("1. Generating 10 Random Mnemonics\n")

    mnemonics = [BIP39Mnemonic.generate(12) for _ in range(10)]
    for i, m in enumerate(mnemonics):
        print(f"  [{i}] {m[:40]}...")
    print()

    # Example 2: Batch seed generation (no passphrase)
    print("2. Batch Seed Generation (No Passphrase)\n")

    # Estimate time
    estimated = estimate_batch_time(len(mnemonics))
    print(f"Estimated time for {len(mnemonics)} seeds: {estimated}")

    start = time.time()
    seeds = batch_mnemonic_to_seed(mnemonics)
    elapsed = time.time() - start

    print(f"Actual time: {elapsed*1000:.2f}ms")
    print(f"Average: {elapsed/len(seeds)*1000:.2f}ms per seed")
    print(f"Generated {len(seeds)} seeds")
    print(f"First seed: {seeds[0].hex()[:64]}...")
    print()

    # Example 3: Single vs Batch comparison
    print("3. Single vs Batch Processing Comparison\n")

    test_mnemonics = [BIP39Mnemonic.generate(12) for _ in range(100)]

    # Single processing
    start_single = time.time()
    seeds_single = [BIP39Mnemonic.to_seed(m, "") for m in test_mnemonics]
    time_single = time.time() - start_single

    # Batch processing
    start_batch = time.time()
    seeds_batch = batch_mnemonic_to_seed(test_mnemonics)
    time_batch = time.time() - start_batch

    print(f"Processing 100 mnemonics:")
    print(f"  Single mode: {time_single*1000:.2f}ms ({time_single/100*1000:.2f}ms avg)")
    print(f"  Batch mode:  {time_batch*1000:.2f}ms ({time_batch/100*1000:.2f}ms avg)")
    print(f"  Speedup:     {time_single/time_batch:.2f}x")
    print()

    # Example 4: Batch with different passphrases
    print("4. Same Mnemonic, Different Passphrases\n")

    test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    passphrases = ["", "pass1", "pass2", "secret", "my secret passphrase"]

    mnemonics_repeat = [test_mnemonic] * len(passphrases)
    seeds_diff_pass = batch_mnemonic_to_seed(mnemonics_repeat, passphrases)

    print(f"Mnemonic: {test_mnemonic[:40]}...")
    print()
    for passphrase, seed in zip(passphrases, seeds_diff_pass):
        label = f'"{passphrase}"' if passphrase else "(empty)"
        print(f"  {label:25} -> {seed.hex()[:40]}...")
    print()

    # Example 5: Large batch estimation
    print("5. Large Batch Estimation\n")

    sizes = [100, 1000, 10000, 100000]
    for size in sizes:
        estimated = estimate_batch_time(size)
        print(f"  {size:,} seeds: ~{estimated}")
    print()

    # Example 6: GPU flag (shows warning)
    print("6. GPU Acceleration Status\n")

    import warnings
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        seeds_gpu = batch_mnemonic_to_seed([mnemonics[0]], use_gpu=True)
        if w:
            print(f"  Status: {w[0].message}")
        else:
            print("  GPU acceleration enabled")

    print()
    print("  Current: CPU-only implementation")
    print("  Future: GPU PBKDF2-HMAC-SHA512 acceleration")
    print("  Expected speedup: 20-50x for large batches")
    print()

    print("=" * 70)
    print("Example completed successfully!")
    print("=" * 70)
    print()
    print("Performance notes:")
    print("  • Batch processing currently uses CPU")
    print("  • Still faster than individual calls due to reduced overhead")
    print("  • GPU PBKDF2 acceleration coming soon")
    print("  • Best for processing 100+ mnemonics")


if __name__ == "__main__":
    main()
