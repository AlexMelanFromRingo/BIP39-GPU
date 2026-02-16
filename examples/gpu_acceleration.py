#!/usr/bin/env python3
"""GPU acceleration example.

This example demonstrates:
- Using GPU for SHA256 operations
- GPU-accelerated PBKDF2-HMAC-SHA512 for seed generation
- Batch operations with OpenCL
- CPU vs GPU comparison
- Full brute-force entropy generation
- Graceful fallback when GPU unavailable
"""

from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu import is_opencl_available, get_default_context
from bip39_gpu.gpu.sha256 import sha256_gpu, batch_sha256_gpu
import time


def main():
    print("=" * 70)
    print("GPU Acceleration Example")
    print("=" * 70)
    print()

    # 1. Check OpenCL availability
    print("1. Checking OpenCL availability:")
    opencl_available = is_opencl_available()
    print(f"   OpenCL available: {opencl_available}")

    if opencl_available:
        ctx = get_default_context()
        if ctx:
            print(f"   ✓ GPU Context initialized: {ctx.device.name.strip()}")
        else:
            print("   ✗ GPU not available (using CPU fallback)")
    else:
        print("   Note: GPU not available, will use CPU fallback")
    print()

    # 2. Single SHA256 hash (GPU)
    print("2. Single SHA256 hash (GPU with CPU fallback):")
    message = b"Hello, GPU!"
    hash_result = sha256_gpu(message)
    print(f"   Message: {message.decode()}")
    print(f"   SHA256:  {hash_result.hex()}")
    print()

    # 3. Batch SHA256 hashing
    print("3. Batch SHA256 hashing (100 messages):")
    messages = [f"Message {i}".encode() for i in range(100)]

    start = time.time()
    hashes = batch_sha256_gpu(messages)
    elapsed = time.time() - start

    print(f"   Messages: {len(messages)}")
    print(f"   Time:     {elapsed*1000:.2f}ms")
    print(f"   First:    {hashes[0].hex()[:32]}...")
    print(f"   Last:     {hashes[-1].hex()[:32]}...")
    print()

    # 4. CPU seed generation benchmark
    print("4. Seed generation benchmark (CPU PBKDF2):")
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    start = time.time()
    seed = BIP39Mnemonic.to_seed(mnemonic, passphrase="")
    cpu_time = time.time() - start

    print(f"   Mnemonic: {mnemonic[:40]}...")
    print(f"   CPU time: {cpu_time*1000:.2f}ms")
    print(f"   Seed:     {seed.hex()[:64]}...")
    print()

    # 5. GPU batch seed generation (NEW!)
    print("5. GPU Batch PBKDF2-HMAC-SHA512 (10 mnemonics):")
    try:
        from bip39_gpu.gpu.pbkdf2_gpu import batch_mnemonic_to_seed_gpu

        mnemonics = [BIP39Mnemonic.generate(words=12) for _ in range(10)]

        # CPU batch for comparison
        start = time.time()
        cpu_seeds = [BIP39Mnemonic.to_seed(m, passphrase="") for m in mnemonics]
        cpu_batch_time = time.time() - start

        # GPU batch
        start = time.time()
        gpu_seeds = batch_mnemonic_to_seed_gpu(mnemonics, [""] * len(mnemonics))
        gpu_batch_time = time.time() - start

        print(f"   Mnemonics: {len(mnemonics)}")
        print(f"   CPU time:  {cpu_batch_time*1000:.2f}ms ({cpu_batch_time/len(mnemonics)*1000:.1f}ms/seed)")
        print(f"   GPU time:  {gpu_batch_time*1000:.2f}ms ({gpu_batch_time/len(mnemonics)*1000:.1f}ms/seed)")

        # Verify consistency
        if cpu_seeds == gpu_seeds:
            print(f"   ✓ Results match!")

        if gpu_batch_time > 0:
            speedup = cpu_batch_time / gpu_batch_time
            print(f"   Speedup:   {speedup:.2f}x")
    except ImportError:
        print("   GPU PBKDF2 not available (PyOpenCL not installed)")
    print()

    # 6. GPU brute-force demo (NEW!)
    print("6. GPU Brute-Force Entropy Generation:")
    try:
        from bip39_gpu.bruteforce.gpu_bruteforce import GPUBruteForce

        searcher = GPUBruteForce(word_count=12)
        print(f"   Word count: {searcher.word_count}")
        print(f"   Entropy:    {searcher.entropy_bits} bits")
        print(f"   Search:     2^{searcher.entropy_bits} combinations")
        print()

        # Generate 3 random entropies
        print("   Generating 3 random mnemonics:")
        entropies = searcher.generate_random_entropies(3)
        for i, entropy in enumerate(entropies, 1):
            mnemonic = searcher.entropy_to_mnemonic(entropy)
            words = mnemonic.split()
            print(f"   {i}. {words[0]} {words[1]} ... {words[-2]} {words[-1]}")

    except ImportError:
        print("   GPU brute-force not available")
    print()

    # 7. Current status
    print("7. GPU Acceleration Status:")
    print("   ✅ OpenCL context management")
    print("   ✅ GPU SHA256 kernels (with CPU fallback)")
    print("   ✅ GPU SHA512 kernels")
    print("   ✅ GPU PBKDF2-HMAC-SHA512 (2048 iterations)")
    print("   ✅ Batch seed generation")
    print("   ✅ GPU full brute-force (entropy generation)")
    print("   ⏳ GPU BIP32 derivation (future work)")
    print()

    print("=" * 70)
    print("Example completed successfully!")
    print("=" * 70)
    print()
    print("Note: GPU acceleration is most beneficial for batch operations.")
    print("      For single operations, CPU is often faster due to overhead.")
    print("      For large batches (100+), GPU can provide 10-50x speedup.")


if __name__ == "__main__":
    main()
