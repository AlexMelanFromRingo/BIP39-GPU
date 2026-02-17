# GPU Acceleration

BIP39 GPU uses OpenCL to accelerate cryptographic operations. This page explains how the GPU
pipeline works, how to set it up, and what to expect.

## How It Works

The library implements the following operations directly in OpenCL C kernels:

| Operation | Kernel file | Used in |
|-----------|------------|---------|
| SHA-256 | `gpu/cl/sha256.cl` | Checksum, BIP32 HMAC |
| SHA-512 | `gpu/cl/sha512.cl` | PBKDF2, HMAC-SHA512 |
| PBKDF2-HMAC-SHA512 | `gpu/cl/pbkdf2_hmac_sha512.cl` | Seed derivation |
| secp256k1 | `gpu/cl/secp256k1.cl` | Public key generation, BIP32 child keys |
| RIPEMD-160 | `gpu/cl/ripemd160.cl` | Bitcoin hash160 |
| BIP32 derivation | `gpu/cl/bip32.cl` | Full HD key derivation |

All operations are implemented in Jacobian coordinates for secp256k1 with full aliasing safety.

---

## POCL — CPU OpenCL

If you don't have a dedicated GPU, [POCL](http://portablecl.org/) provides an OpenCL
implementation that runs on your CPU. It works seamlessly and enables GPU code testing
without any hardware.

```bash
# Ubuntu / Debian
sudo apt install pocl-opencl-icd ocl-icd-opencl-dev
```

POCL 5.0 is supported and tested.

---

## Check GPU Availability

```python
import pyopencl as cl

platforms = cl.get_platforms()
for p in platforms:
    print(f"Platform: {p.name}")
    for d in p.get_devices():
        print(f"  {d.name}  ({cl.device_type.to_string(d.type)})")
```

```python
from bip39_gpu.gpu.context import get_gpu_context

ctx = get_gpu_context()
print("GPU available:", ctx is not None)
if ctx:
    print("Device:", ctx.devices[0].name)
```

---

## GPU vs CPU Fallback

All GPU functions gracefully fall back to CPU if OpenCL is unavailable:

```python
from bip39_gpu.gpu.bip32_gpu import batch_seed_to_address

# use_gpu=True tries GPU first, falls back to CPU silently
addresses = batch_seed_to_address(seeds, use_gpu=True)

# Force CPU
addresses = batch_seed_to_address(seeds, use_gpu=False)
```

---

## BIP32 GPU Pipeline

The full address derivation pipeline runs on GPU:

```
Seed (64 bytes)
    │
    ▼
Master key derivation (HMAC-SHA512)
    │
    ▼
Hardened child: m/purpose'/coin_type'/0'  (HMAC-SHA512)
    │
    ▼
Non-hardened child: /0/index  (HMAC-SHA512 + secp256k1 point add)
    │
    ▼
Public key compression (secp256k1)
    │
    ▼
hash160 = RIPEMD-160(SHA-256(pubkey))
    │
    ├─▶ P2PKH:      Base58Check(0x00 + hash160)
    ├─▶ P2SH-P2WPKH: Base58Check(0x05 + hash160(redeemScript))
    ├─▶ P2WPKH:     Bech32(0, hash160)
    └─▶ P2TR:       Bech32m(1, taptweak(pubkey).x)
```

The kernel `bip32_seed_to_hash160` runs this entire pipeline per seed,
outputting `hash160`, `privkey`, and `pubkey` for each input.

---

## Batch Processing

The GPU pipeline processes many seeds in parallel. Recommended batch sizes:

| Device | Recommended batch size |
|--------|----------------------|
| CPU (POCL) | 16–64 |
| Entry GPU (GTX 1060 / RX 580) | 256–1024 |
| High-end GPU (RTX 3090 / RX 6900) | 1024–8192 |

```python
BATCH = 64
seeds = [BIP39Mnemonic.to_seed(BIP39Mnemonic.generate(12)) for _ in range(BATCH)]
addresses = batch_seed_to_address(seeds, address_format="P2WPKH", use_gpu=True)
```

---

## secp256k1 Implementation Notes

The OpenCL secp256k1 implementation uses:

- **Jacobian coordinates** for point doubling and addition (avoids expensive modular inversion)
- **Double-and-add** algorithm for scalar multiplication
- **Aliasing-safe** operations: Z computed before Y in `jac_dbl`; `2*Y1*J` read before `ry` is
  overwritten in `jac_add_affine`
- **256-bit field arithmetic** with 8×32-bit limbs in little-endian order

The curve parameters:
```
p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
```

---

## Troubleshooting

**"No OpenCL platform found"**
```bash
sudo apt install pocl-opencl-icd ocl-icd-opencl-dev
```

**GPU results differ from CPU**

This can happen due to secp256k1 aliasing bugs. The implementation has been tested against BIP39
test vectors. If you suspect an issue, report it on [GitHub Issues](https://github.com/AlexMelanFromRingo/BIP39-GPU/issues).

**OpenCL build failure**

Enable verbose OpenCL compiler output:
```python
import os
os.environ["PYOPENCL_COMPILER_OUTPUT"] = "1"
```
