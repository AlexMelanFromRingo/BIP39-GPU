#!/usr/bin/env python3
"""GPU acceleration example.

This example demonstrates:
- Using GPU for SHA256 operations
- Batch hashing with OpenCL
- CPU vs GPU comparison
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
            print("   ✓ GPU Context initialized")
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

    # 5. Batch seed generation
    print("5. Batch seed generation (10 mnemonics):")
    mnemonics = [BIP39Mnemonic.generate(words=12) for _ in range(10)]

    start = time.time()
    seeds = [BIP39Mnemonic.to_seed(m, passphrase="") for m in mnemonics]
    batch_time = time.time() - start

    print(f"   Mnemonics: {len(mnemonics)}")
    print(f"   CPU time:  {batch_time*1000:.2f}ms")
    print(f"   Avg/seed:  {batch_time/len(mnemonics)*1000:.2f}ms")
    print()

    # 6. Current status
    print("6. GPU Acceleration Status:")
    print("   ✅ OpenCL context management")
    print("   ✅ GPU SHA256 kernels (with CPU fallback)")
    print("   ✅ Batch hash operations")
    print("   ⏳ GPU PBKDF2-HMAC-SHA512 (coming soon)")
    print("   ⏳ GPU brute-force search (coming soon)")
    print()

    print("=" * 70)
    print("Example completed successfully!")
    print("=" * 70)
    print()
    print("Note: GPU acceleration is most beneficial for batch operations.")
    print("      For single operations, CPU is often faster due to overhead.")


if __name__ == "__main__":
    main()
