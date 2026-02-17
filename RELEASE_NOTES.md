# v0.1.0 — Initial Release

**Date:** 2026-02-17

## Highlights

This is the first public release of **BIP39 GPU** — a Python library and CLI for GPU-accelerated
BIP39 mnemonic operations using OpenCL.

## Features

### Core BIP39
- Mnemonic generation: 12 / 15 / 18 / 21 / 24 words
- Mnemonic validation with checksum verification
- Seed derivation: PBKDF2-HMAC-SHA512, 2048 iterations (BIP39 standard)
- Cryptographic entropy via `secrets.token_bytes()`

### GPU Acceleration (OpenCL / POCL)
- SHA-256 and SHA-512 batch hashing on GPU
- PBKDF2-HMAC-SHA512 batch seed derivation
- secp256k1 elliptic curve point multiplication on GPU
- RIPEMD-160 on GPU
- Full BIP32 key derivation pipeline on GPU (hardened + non-hardened child keys)

### Bitcoin Address Formats
All four address formats derived via GPU pipeline:

| Format | BIP Path | Prefix |
|--------|----------|--------|
| P2PKH (Legacy) | m/44'/0'/0'/0/n | `1...` |
| P2SH-P2WPKH (SegWit compat.) | m/49'/0'/0'/0/n | `3...` |
| P2WPKH (Native SegWit) | m/84'/0'/0'/0/n | `bc1q...` |
| P2TR (Taproot) | m/86'/0'/0'/0/n | `bc1p...` |

Bech32 (BIP173) and Bech32m (BIP350) encoding implemented from scratch.
BIP341 Taproot key-path tweak with tagged hash (SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)).

### CLI
```bash
bip39-gpu generate --words 12
bip39-gpu validate "mnemonic phrase"
bip39-gpu seed "mnemonic" --passphrase "secret"
bip39-gpu address "mnemonic" --format P2TR --count 5
bip39-gpu bruteforce --pattern "word1 ??? word3" --gpu
```

### Python Library
```python
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu.bip32_gpu import batch_seed_to_address

mnemonic = BIP39Mnemonic.generate(12)
seed = BIP39Mnemonic.to_seed(mnemonic)
addresses = batch_seed_to_address([seed], address_format="P2TR", use_gpu=True)
```

### Brute-force / Recovery Engine
- Pattern-based search: `"word1 ??? word3 ???"`
- GPU-accelerated checksum validation
- Optional target address matching

## Test Coverage
- **128 tests**, 4 skipped (GPU not present)
- Coverage: 57%
- Verified against official BIP39 / BIP84 / BIP49 / BIP86 test vectors
- Known vector: `abandon × 11 + about` → correct addresses across all 4 formats

## Requirements
- Python 3.12+
- OpenCL runtime (POCL for CPU-only, any GPU for hardware acceleration)

## Installation

Download `bip39_gpu-0.1.0-py3-none-any.whl` from the release assets, then:

```bash
pip install bip39_gpu-0.1.0-py3-none-any.whl
```

Or install from source:
```bash
git clone https://github.com/AlexMelanFromRingo/BIP39-GPU.git
cd BIP39-GPU
pip install -e .
```
