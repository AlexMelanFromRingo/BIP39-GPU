# BIP39 GPU

**GPU-accelerated BIP39 mnemonic operations using OpenCL**

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/AlexMelanFromRingo/BIP39-GPU/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/AlexMelanFromRingo/BIP39-GPU)](https://github.com/AlexMelanFromRingo/BIP39-GPU/releases)
[![Tests](https://img.shields.io/badge/tests-128%20passed-brightgreen)](https://github.com/AlexMelanFromRingo/BIP39-GPU)

---

## What is BIP39 GPU?

BIP39 GPU is a Python library and CLI tool for working with [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) mnemonics with GPU acceleration via OpenCL.

It supports the full pipeline from mnemonic generation to Bitcoin address derivation — including all modern address formats — entirely on the GPU.

## Features

### Core BIP39
- **Generate** mnemonics: 12, 15, 18, 21, or 24 words
- **Validate** mnemonics with checksum verification
- **Derive seeds**: PBKDF2-HMAC-SHA512, 2048 iterations (BIP39 standard)
- Cryptographic entropy using `secrets.token_bytes()`

### GPU Acceleration (OpenCL)
- SHA-256 and SHA-512 batch hashing
- PBKDF2-HMAC-SHA512 batch seed derivation
- secp256k1 elliptic curve operations (point multiplication)
- RIPEMD-160 hashing
- Full BIP32 key derivation pipeline on GPU
- Works with any OpenCL device: NVIDIA, AMD, Intel, or CPU via [POCL](http://portablecl.org/)

### Bitcoin Address Formats

| Format | Standard | Path | Prefix |
|--------|----------|------|--------|
| P2PKH | BIP44 | m/44'/0'/0'/0/n | `1...` |
| P2SH-P2WPKH | BIP49 | m/49'/0'/0'/0/n | `3...` |
| P2WPKH (Native SegWit) | BIP84 | m/84'/0'/0'/0/n | `bc1q...` |
| P2TR (Taproot) | BIP86 | m/86'/0'/0'/0/n | `bc1p...` |

### Brute-force / Wallet Recovery
- Pattern-based mnemonic recovery: `"word1 ??? word3 ???"`
- GPU-accelerated checksum validation
- Optional target address matching

---

## Quick Install

```bash
# Download the wheel from GitHub Releases
pip install bip39_gpu-0.1.0-py3-none-any.whl
```

Or from source:

```bash
git clone https://github.com/AlexMelanFromRingo/BIP39-GPU.git
cd BIP39-GPU && pip install -e .
```

See [Installation](installation.md) for full setup including OpenCL runtime.

---

## Quick Example

```python
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu.bip32_gpu import batch_seed_to_address

# Generate and validate a mnemonic
mnemonic = BIP39Mnemonic.generate(12)
assert BIP39Mnemonic.validate(mnemonic)

# Derive seed
seed = BIP39Mnemonic.to_seed(mnemonic)

# Derive all 4 address formats via GPU
for fmt in ["P2PKH", "P2SH_P2WPKH", "P2WPKH", "P2TR"]:
    addr = batch_seed_to_address([seed], address_format=fmt, use_gpu=True)[0]
    print(f"{fmt:15} {addr}")
```

---

## CLI

```bash
bip39-gpu generate --words 12
bip39-gpu validate "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
bip39-gpu address "mnemonic phrase" --format P2TR --count 5 --gpu
```

See [CLI Reference](cli.md) for all commands.
